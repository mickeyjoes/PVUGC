use ark_bls12_381::{G1Affine, G2Affine, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::One;
use sha2::{Digest, Sha256};

use arkworks_groth16::ProductKeyKEM;

fn make_com1_bytes<R: ark_std::rand::Rng>(n: usize, rng: &mut R) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for _ in 0..n {
        let p0 = G1Affine::rand(rng);
        let p1 = G1Affine::rand(rng);
        let mut v = Vec::new();
        p0.serialize_compressed(&mut v).unwrap();
        p1.serialize_compressed(&mut v).unwrap();
        out.push(v);
    }
    out
}

fn make_com2_bytes<R: ark_std::rand::Rng>(n: usize, rng: &mut R) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for _ in 0..n {
        let p0 = G2Affine::rand(rng);
        let p1 = G2Affine::rand(rng);
        let mut v = Vec::new();
        p0.serialize_compressed(&mut v).unwrap();
        p1.serialize_compressed(&mut v).unwrap();
        out.push(v);
    }
    out
}

#[test]
fn test_duo_phase_a_positive_and_binding() {
    use ark_std::test_rng;
    let mut rng = test_rng();
    let kem = ProductKeyKEM::new();

    // Fake attestation components (1 commitment each side, 1 pi, 1 theta)
    let c1_bytes = make_com1_bytes(2, &mut rng);
    let c2_bytes = make_com2_bytes(2, &mut rng);
    let pi_bytes = make_com2_bytes(2, &mut rng);
    let theta_bytes = make_com1_bytes(2, &mut rng);

    // CRS primaries (2 pairs each)
    let u_bases = make_com1_bytes(2, &mut rng);
    let v_bases = make_com2_bytes(2, &mut rng);

    let adaptor_share = Fr::rand(&mut rng);
    let ctx_hash = b"ctx";
    let gs_instance_digest = b"ppe";
    let vk_hash = Sha256::digest(b"vk");
    let x_hash = Sha256::digest(b"x");

    // Encap Duo
    let (share, _mbytes) = kem
        .encapsulate_deposit_duo(
            &mut rng,
            0,
            &c1_bytes,
            &c2_bytes,
            &pi_bytes,
            &theta_bytes,
            &u_bases,
            &v_bases,
            adaptor_share,
            ctx_hash,
            gs_instance_digest,
            &vk_hash,
            &x_hash,
        )
        .expect("encap duo");

    // Decap Duo succeeds
    let ppe_stub = groth_sahai::statement::PPE::<ark_bls12_381::Bls12_381> {
        a_consts: vec![],
        b_consts: vec![],
        gamma: vec![vec![Fr::from(1u64), Fr::from(0u64)], vec![Fr::from(0u64), Fr::from(1u64)]],
        target: ark_ec::pairing::PairingOutput::<ark_bls12_381::Bls12_381>(ark_bls12_381::Fq12::one()),
    };
    let got = kem
        .decapsulate_duo(
            &share,
            &ppe_stub,
            &c1_bytes,
            &c2_bytes,
            &pi_bytes,
            &theta_bytes,
            ctx_hash,
            gs_instance_digest,
            &vk_hash,
            &x_hash,
        )
        .expect("decap duo");
    assert_eq!(got, adaptor_share);

    // Cross-statement binding: wrong vk_hash should fail (ρ recovery fails)
    let vk_hash_bad = Sha256::digest(b"vk-bad");
    let err = kem.decapsulate_duo(
        &share,
        &ppe_stub,
        &c1_bytes,
        &c2_bytes,
        &pi_bytes,
        &theta_bytes,
        ctx_hash,
        gs_instance_digest,
        &vk_hash_bad,
        &x_hash,
    );
    assert!(err.is_err());
}
