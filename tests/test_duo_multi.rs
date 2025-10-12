use ark_bls12_381::{G1Affine, G2Affine, Fr, Fq12};
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, One};
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
fn test_duo_phase_a_multiple_instances_and_cross_binding() {
    use ark_std::test_rng;
    let mut rng = test_rng();
    let kem = ProductKeyKEM::new();

    // PPE stub
    let ppe_stub = groth_sahai::statement::PPE::<ark_bls12_381::Bls12_381> {
        a_consts: vec![],
        b_consts: vec![],
        gamma: vec![vec![Fr::one(), Fr::from(0u64)], vec![Fr::from(0u64), Fr::one()]],
        target: ark_ec::pairing::PairingOutput::<ark_bls12_381::Bls12_381>(Fq12::one()),
    };

    let ctx_hash = b"ctx";
    let gs_instance_digest = b"ppe";

    let mut shares = Vec::new();
    let mut bundles = Vec::new();

    for i in 0..3 {
        let c1 = make_com1_bytes(2, &mut rng);
        let c2 = make_com2_bytes(2, &mut rng);
        let pi = make_com2_bytes(2, &mut rng);
        let th = make_com1_bytes(2, &mut rng);
        let u = make_com1_bytes(2, &mut rng);
        let v = make_com2_bytes(2, &mut rng);
        let adaptor_share = Fr::rand(&mut rng);
        let vk_hash = Sha256::digest(format!("vk_{i}").as_bytes());
        let x_hash = Sha256::digest(format!("x_{i}").as_bytes());

        let (share, _mbytes) = kem
            .encapsulate_deposit_duo(
                &mut rng,
                i as u32,
                &c1,
                &c2,
                &pi,
                &th,
                &u,
                &v,
                adaptor_share,
                ctx_hash,
                gs_instance_digest,
                &vk_hash,
                &x_hash,
            )
            .expect("encap duo");

        // Positive decap
        let got = kem
            .decapsulate_duo(
                &share,
                &ppe_stub,
                &c1,
                &c2,
                &pi,
                &th,
                ctx_hash,
                gs_instance_digest,
                &vk_hash,
                &x_hash,
            )
            .expect("decap duo");
        assert_eq!(got, adaptor_share);

        shares.push(share);
        bundles.push((c1, c2, pi, th, u, v, vk_hash.to_vec(), x_hash.to_vec()));
    }

    // Cross-binding negative: try to decap share[0] with bundle[1]
    let (ref c1b, ref c2b, ref pib, ref thb, _u, _v, ref vk_b, ref x_b) = &bundles[1];
    let err = kem.decapsulate_duo(
        &shares[0],
        &ppe_stub,
        c1b,
        c2b,
        pib,
        thb,
        ctx_hash,
        gs_instance_digest,
        vk_b,
        x_b,
    );
    assert!(err.is_err());
}
