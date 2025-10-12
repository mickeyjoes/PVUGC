use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{PrimeField, BigInteger};
use ark_ec::{pairing::PairingOutput, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

use groth_sahai::statement::PPE;
use groth_sahai::{Com1, Com2, ComT, BT};

use crate::bls12381_ops::Scalar;
use crate::gs_kem_eval::kdf_from_comt;
use crate::gs_kem_helpers::{deserialize_masked_u, deserialize_masked_v};
use crate::kem::{KEMError, KEMShare, ProductKeyKEM};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KEMShareDuo {
    pub index: u32,
    pub d1_masks: Vec<Vec<u8>>, // U^ρ (G1)
    pub d2_masks: Vec<Vec<u8>>, // V^ρ (G2)
    pub d1_inst: Vec<Vec<u8>>,  // D1_inst^ρ (G2)
    pub d2_inst: Vec<Vec<u8>>,  // D2_inst^ρ (G1)
    pub ct_rho: Vec<u8>,
    pub ct_rho_tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub auth_tag: Vec<u8>,
    pub t_i: Vec<u8>,
    pub h_i: Vec<u8>,
}

impl ProductKeyKEM {
    fn derive_instance_bases(
        &self,
        crs_u: &[Vec<u8>],
        crs_v: &[Vec<u8>],
        vk_hash: &[u8],
        x_hash: &[u8],
    ) -> Result<(Vec<Com2<Bls12_381>>, Vec<Com1<Bls12_381>>), KEMError> {
        // D1_inst from V (G2), D2_inst from U (G1)
        let mut d1_g2 = Vec::new();
        for (i, bytes) in crs_v.iter().enumerate() {
            let mut h = Sha256::new();
            h.update(b"PVUGC/INST-V");
            h.update(vk_hash);
            h.update(x_hash);
            h.update(&[i as u8]);
            let s = Fr::from_le_bytes_mod_order(&h.finalize());
            let mut com = Com2::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("V deser: {:?}", e)))?;
            com.0 = (com.0.into_group() * s).into_affine();
            com.1 = (com.1.into_group() * s).into_affine();
            d1_g2.push(com);
        }
        let mut d2_g1 = Vec::new();
        for (i, bytes) in crs_u.iter().enumerate() {
            let mut h = Sha256::new();
            h.update(b"PVUGC/INST-U");
            h.update(vk_hash);
            h.update(x_hash);
            h.update(&[i as u8]);
            let s = Fr::from_le_bytes_mod_order(&h.finalize());
            let mut com = Com1::<Bls12_381>::deserialize_compressed(bytes.as_slice())
                .map_err(|e| KEMError::Deserialization(format!("U deser: {:?}", e)))?;
            com.0 = (com.0.into_group() * s).into_affine();
            com.1 = (com.1.into_group() * s).into_affine();
            d2_g1.push(com);
        }
        Ok((d1_g2, d2_g1))
    }

    pub fn encapsulate_deposit_duo<R: ark_std::rand::Rng>(
        &self,
        rng: &mut R,
        share_index: u32,
        attestation_commitments_g1: &[Vec<u8>],
        attestation_commitments_g2: &[Vec<u8>],
        pi_elements: &[Vec<u8>],
        theta_elements: &[Vec<u8>],
        crs_u: &[Vec<u8>],
        crs_v: &[Vec<u8>],
        adaptor_share: Scalar,
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
        vk_hash: &[u8],
        x_hash: &[u8],
    ) -> Result<(KEMShareDuo, Vec<u8>), KEMError> {
        let (base, m_bytes) = self.encapsulate_deposit(
            rng,
            share_index,
            attestation_commitments_g1,
            attestation_commitments_g2,
            pi_elements,
            theta_elements,
            crs_u,
            crs_v,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
        )?;

        // Derive instance masks and encrypt rho
        let (d1_g2, d2_g1) = self.derive_instance_bases(crs_u, crs_v, vk_hash, x_hash)?;
        let rho = crate::bls12381_ops::BLS12381Ops::random_scalar(rng);
        let mut d1_inst = Vec::new();
        for d in d1_g2.iter() {
            let m = Com2::<Bls12_381>((d.0.into_group() * rho).into_affine(), (d.1.into_group() * rho).into_affine());
            let mut out = Vec::new(); m.serialize_compressed(&mut out).unwrap(); d1_inst.push(out);
        }
        let mut d2_inst = Vec::new();
        for c in d2_g1.iter() {
            let m = Com1::<Bls12_381>((c.0.into_group() * rho).into_affine(), (c.1.into_group() * rho).into_affine());
            let mut out = Vec::new(); m.serialize_compressed(&mut out).unwrap(); d2_inst.push(out);
        }

        let c1_coms: Vec<Com1<Bls12_381>> = attestation_commitments_g1
            .iter()
            .map(|b| Com1::<Bls12_381>::deserialize_compressed(b.as_slice()).unwrap())
            .collect();
        let c2_coms: Vec<Com2<Bls12_381>> = attestation_commitments_g2
            .iter()
            .map(|b| Com2::<Bls12_381>::deserialize_compressed(b.as_slice()).unwrap())
            .collect();
        let v_inst_r = deserialize_masked_v(&d1_inst)
            .map_err(|e| KEMError::Deserialization(format!("V_inst^ρ deser: {}", e)))?;
        let u_inst_r = deserialize_masked_u(&d2_inst)
            .map_err(|e| KEMError::Deserialization(format!("U_inst^ρ deser: {}", e)))?;
        let pk = ComT::<Bls12_381>::pairing_sum(&c1_coms, &v_inst_r)
            + ComT::<Bls12_381>::pairing_sum(&u_inst_r, &c2_coms);
        let k2 = kdf_from_comt(&pk, ctx_hash, gs_instance_digest, vk_hash, x_hash, b"pk2", 1);
        let rho_bytes = rho.into_bigint().to_bytes_be();
        let mut ad2 = Vec::new();
        ad2.extend_from_slice(&share_index.to_be_bytes());
        ad2.extend_from_slice(ctx_hash);
        ad2.extend_from_slice(gs_instance_digest);
        for m in &d1_inst { ad2.extend_from_slice(m); }
        for m in &d2_inst { ad2.extend_from_slice(m); }
        let (ct_rho, ct_rho_tag) = self.dem_encrypt(&k2, &rho_bytes, &ad2)?;

        let duo = KEMShareDuo {
            index: base.index,
            d1_masks: base.d1_masks,
            d2_masks: base.d2_masks,
            d1_inst,
            d2_inst,
            ct_rho,
            ct_rho_tag,
            ciphertext: base.ciphertext,
            auth_tag: base.auth_tag,
            t_i: base.t_i,
            h_i: base.h_i,
        };
        Ok((duo, m_bytes))
    }

    pub fn decapsulate_duo(
        &self,
        kem_share: &KEMShareDuo,
        ppe: &PPE<Bls12_381>,
        attestation_commitments_g1: &[Vec<u8>],
        attestation_commitments_g2: &[Vec<u8>],
        pi_elements: &[Vec<u8>],
        theta_elements: &[Vec<u8>],
        ctx_hash: &[u8],
        gs_instance_digest: &[u8],
        vk_hash: &[u8],
        x_hash: &[u8],
    ) -> Result<Fr, KEMError> {
        // Base decap (K1)
        let base = KEMShare {
            index: kem_share.index,
            d1_masks: kem_share.d1_masks.clone(),
            d2_masks: kem_share.d2_masks.clone(),
            ciphertext: kem_share.ciphertext.clone(),
            auth_tag: kem_share.auth_tag.clone(),
            t_i: kem_share.t_i.clone(),
            h_i: kem_share.h_i.clone(),
        };
        let v = self.decapsulate(
            &base,
            ppe,
            attestation_commitments_g1,
            attestation_commitments_g2,
            pi_elements,
            theta_elements,
            ctx_hash,
            gs_instance_digest,
        )?;

        // Phase-A ρ recovery (K2)
        if !kem_share.d1_inst.is_empty() && !kem_share.d2_inst.is_empty() && !kem_share.ct_rho.is_empty() {
            let c1_coms: Vec<Com1<Bls12_381>> = attestation_commitments_g1
                .iter()
                .map(|b| Com1::<Bls12_381>::deserialize_compressed(b.as_slice()).unwrap())
                .collect();
            let c2_coms: Vec<Com2<Bls12_381>> = attestation_commitments_g2
                .iter()
                .map(|b| Com2::<Bls12_381>::deserialize_compressed(b.as_slice()).unwrap())
                .collect();
            let v_inst = deserialize_masked_v(&kem_share.d1_inst)
                .map_err(|e| KEMError::Deserialization(format!("V_inst^ρ deser: {}", e)))?;
            let u_inst = deserialize_masked_u(&kem_share.d2_inst)
                .map_err(|e| KEMError::Deserialization(format!("U_inst^ρ deser: {}", e)))?;
            let pk = ComT::<Bls12_381>::pairing_sum(&c1_coms, &v_inst)
                + ComT::<Bls12_381>::pairing_sum(&u_inst, &c2_coms);
            let k2 = kdf_from_comt(&pk, ctx_hash, gs_instance_digest, vk_hash, x_hash, b"pk2", 1);
            let mut ad2 = Vec::new();
            ad2.extend_from_slice(&kem_share.index.to_be_bytes());
            ad2.extend_from_slice(ctx_hash);
            ad2.extend_from_slice(gs_instance_digest);
            for m in &kem_share.d1_inst { ad2.extend_from_slice(m); }
            for m in &kem_share.d2_inst { ad2.extend_from_slice(m); }
            let _rho = self.dem_decrypt(&k2, &kem_share.ct_rho, &kem_share.ct_rho_tag, &ad2)?;
        }
        Ok(v)
    }
}
