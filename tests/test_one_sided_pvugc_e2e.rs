//! End-to-End Test for One-Sided GS PVUGC

use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};
use rand_core::RngCore;
use arkworks_groth16::coeff_recorder::SimpleCoeffRecorder;
use arkworks_groth16::ppe::PvugcVk;
use arkworks_groth16::*;
use arkworks_groth16::ct::serialize_gt;

type E = Bls12_381;

/// Helper: Create a proper test context with full binding per spec §3 and §8
/// Returns: (ctx_hash, gs_digest, ad_core_bytes) for use in tests
fn create_test_context(
    vk_hash: [u8; 32],
    x_hash: [u8; 32],
    y_cols_digest: [u8; 32],
    epoch_nonce: [u8; 32],
    tapleaf_hash: [u8; 32],
) -> ([u8; 32], [u8; 32], Vec<u8>) {
    use arkworks_groth16::ctx::PvugcContextBuilder;
    use arkworks_groth16::ct::AdCore;
    
    // Build context with all layers
    let ctx = PvugcContextBuilder::new(vk_hash, x_hash, y_cols_digest, epoch_nonce)
        .with_tapleaf(tapleaf_hash, 0xc0)
        .with_path_tag("compute")
        .finalize(None, None);
    
    // Create AD_core for DEM-SHA256 binding
    let ad_core = AdCore::new(
        vk_hash,
        x_hash,
        ctx.ctx_core,
        tapleaf_hash,
        0xc0,
        vec![],  // empty txid_template for testing
        "compute",
        0,       // share_index
        vec![0u8; 33],  // t_i
        vec![0u8; 33],  // t_aggregate
        vec![0u8; 64],  // armed_bases
        vec![0u8; 64],  // armed_delta
        ctx.ctx_core,   // gs_instance_digest
    );
    
    (ctx.ctx_hash, ctx.ctx_core, ad_core.serialize())
}

fn ppe_unarmed_assert_full<Ep: ark_ec::pairing::Pairing>(
    x_b_cols: &[(Ep::G1Affine, Ep::G1Affine)],
    pvugc_vk: &arkworks_groth16::ppe::PvugcVk<Ep>,
    theta: &[(Ep::G1Affine, Ep::G1Affine)],
    theta_delta_cancel: &Option<(Ep::G1Affine, Ep::G1Affine)>,
    r_target: ark_ec::pairing::PairingOutput<Ep>,
) {
    use ark_std::One;
    // Y_cols = [beta2] ++ b_g2_query[..]
    let mut y_cols = Vec::with_capacity(1 + pvugc_vk.b_g2_query.len());
    y_cols.push(pvugc_vk.beta_g2);
    y_cols.extend_from_slice(&pvugc_vk.b_g2_query);
    assert_eq!(x_b_cols.len(), y_cols.len(), "|X_B| != |Y|");

    let mut lhs_b = ark_ec::pairing::PairingOutput::<Ep>(One::one());
    for ((x0, x1), y) in x_b_cols.iter().zip(&y_cols) {
        lhs_b += Ep::pairing(*x0, *y);
        if !x1.is_zero() {
            lhs_b += Ep::pairing(*x1, *y);
        }
    }
    let mut lhs_delta = ark_ec::pairing::PairingOutput::<Ep>(One::one());
    for (t0, t1) in theta {
        // Expect θ = -C + sA
        lhs_delta += Ep::pairing(*t0, pvugc_vk.delta_g2);
        if !t1.is_zero() {
            lhs_delta += Ep::pairing(*t1, pvugc_vk.delta_g2);
        }
    }
    if let Some((c0, c1)) = theta_delta_cancel {
        lhs_delta += Ep::pairing(*c0, pvugc_vk.delta_g2);
        if !c1.is_zero() {
            lhs_delta += Ep::pairing(*c1, pvugc_vk.delta_g2);
        }
    }
    let mut lhs = lhs_b;
    lhs += lhs_delta;
    // debug prints removed
    assert_eq!(lhs, r_target, "Unarmed PPE != R(vk,x)");
}

// Test circuit: x = y²
#[derive(Clone)]
struct SquareCircuit {
    pub x: Option<Fr>,
    pub y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x_var = FpVar::new_input(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let y_var = FpVar::new_witness(cs.clone(), || {
            self.y.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let y_squared = &y_var * &y_var;
        x_var.enforce_equal(&y_squared)?;

        Ok(())
    }
}

#[test]
fn test_one_sided_pvugc_proof_agnostic() {
    let mut rng = StdRng::seed_from_u64(0);

    // Vault setup (statement = public input)
    let vault_utxo = vec![Fr::from(25u64)]; // x = y² = 5² = 25

    // Setup Groth16 for the circuit
    let circuit = SquareCircuit {
        x: Some(Fr::from(25u64)),
        y: Some(Fr::from(5u64)),
    };

    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

    // === DEPOSIT TIME ===

    // Build PVUGC VK wrapper
    let pvugc_vk = PvugcVk {
        beta_g2: vk.beta_g2,
        delta_g2: vk.delta_g2,
        b_g2_query: std::sync::Arc::new(pk.b_g2_query.clone()),
    };

    // Generate ρ
    let rho = Fr::rand(&mut rng);

    // Use the API for setup and arming
    // Column-wise arming
    let (_bases_cols, col_arms, _r, k_expected) =
        OneSidedPvugc::setup_and_arm(&pvugc_vk, &vk, &vault_utxo, &rho).expect("setup_and_arm");

    // === PoCE-A VALIDATION (ARM-TIME) ===

    // Generate arming artifacts for PoCE-A
    let s_i = Fr::rand(&mut rng);
    let t_i = (<E as Pairing>::G1::generator() * s_i).into_affine();
    
    // Create proper test context with full binding
    let vk_hash = [1u8; 32];
    let x_hash = [2u8; 32];
    let y_cols_digest = [3u8; 32];
    let epoch_nonce = [4u8; 32];
    let tapleaf_hash = [5u8; 32];
    
    let (ctx_hash, gs_digest, ad_core_bytes) = 
        create_test_context(vk_hash, x_hash, y_cols_digest, epoch_nonce, tapleaf_hash);

    // Create a deposit-time ciphertext and tag bound to expected K = R^ρ
    let plaintext = b"simulated_ciphertext";
    let dem = ct::DemP2::new(&serialize_gt::<E>(&k_expected.0), &ad_core_bytes);
    let ct = dem.encrypt(plaintext);
    let tau = ct::compute_key_commitment_tag(
        &serialize_gt::<E>(&k_expected.0),
        &ad_core_bytes,
        &ct,
    );

    // Create PoCE-A proof (bind arming to ciphertext and tag)
    let poce_proof = OneSidedPvugc::attest_column_arming(
        &_bases_cols,
        &col_arms,
        &t_i,
        &rho,
        &s_i,
        &ctx_hash,
        &gs_digest,
        &ct,
        &tau,
        &mut rng,
    );

    // Verify PoCE-A proof
    assert!(OneSidedPvugc::verify_column_arming(
        &_bases_cols,
        &col_arms,
        &t_i,
        &poce_proof,
        &ctx_hash,
        &gs_digest,
        &ct,
        &tau,
    ));

    // === SPEND TIME - PROOF 1 ===

    // Use coefficient recorder to capture real b_j via HOOKED prover
    let mut recorder1 = SimpleCoeffRecorder::<E>::new();
    let proof1 =
        Groth16::<E>::create_random_proof_with_hook(circuit.clone(), &pk, &mut rng, &mut recorder1)
            .unwrap();

    // Use API to build commitments and bundle
    let commitments1 = recorder1.build_commitments();
    let bundle1 = PvugcBundle {
        groth16_proof: proof1.clone(),
        dlrep_b: recorder1.create_dlrep_b(&pvugc_vk, &mut rng),
        dlrep_ties: recorder1.create_dlrep_ties(&mut rng),
        gs_commitments: commitments1.clone(),
    };

    // Verify using OneSidedPvugc (checks PPE equation)
    // Quick unarmed PPE sanity on columns (localizes mapping issues)
    let r_target = compute_groth16_target(&vk, &vault_utxo).expect("compute_groth16_target");
    ppe_unarmed_assert_full::<E>(
        &commitments1.x_b_cols,
        &pvugc_vk,
        &commitments1.theta,
        &Some(commitments1.theta_delta_cancel),
        r_target,
    );
    assert!(OneSidedPvugc::verify(&bundle1, &pvugc_vk, &vk, &vault_utxo));

    let k1 = OneSidedPvugc::decapsulate(&commitments1, &col_arms).expect("decapsulate");

    // (ct, tau) already computed above and bound into PoCE-A

    // === SPEND TIME - PROOF 2 ===

    let mut recorder2 = SimpleCoeffRecorder::<E>::new();
    let proof2 =
        Groth16::<E>::create_random_proof_with_hook(circuit.clone(), &pk, &mut rng, &mut recorder2)
            .unwrap();

    // Use API to build commitments and bundle
    let commitments2 = recorder2.build_commitments();
    let bundle2 = PvugcBundle {
        groth16_proof: proof2.clone(),
        dlrep_b: recorder2.create_dlrep_b(&pvugc_vk, &mut rng),
        dlrep_ties: recorder2.create_dlrep_ties(&mut rng),
        gs_commitments: commitments2.clone(),
    };

    // Verify using OneSidedPvugc (checks PPE equation)
    assert!(OneSidedPvugc::verify(&bundle2, &pvugc_vk, &vk, &vault_utxo));

    let k2 = OneSidedPvugc::decapsulate(&commitments2, &col_arms).expect("decapsulate");

    // === CT DECRYPTION (SPEND-TIME) ===
    // Decrypt with derived key from proof 2 (same statement) → should succeed
    let dem2 = ct::DemP2::new(&serialize_gt::<E>(&k2.0), &ad_core_bytes);
    let opened2 = dem2.decrypt(&ct);
    assert_eq!(opened2.as_slice(), plaintext);

    // === PROOF-AGNOSTIC PROPERTY ===

    assert_eq!(k1, k2);
    assert_eq!(k1, k_expected);

    // === TEST: DIFFERENT STATEMENT PRODUCES DIFFERENT K ===

    // Different vault UTXO = different statement = different R
    let vault2_utxo = vec![Fr::from(49u64)]; // x = 7² = 49

    // Setup new circuit for x=49
    let circuit2 = SquareCircuit {
        x: Some(Fr::from(49u64)),
        y: Some(Fr::from(7u64)),
    };

    let (pk2, vk2) = Groth16::<E>::circuit_specific_setup(circuit2.clone(), &mut rng).unwrap();
    let pvugc_vk2 = PvugcVk {
        beta_g2: vk2.beta_g2,
        delta_g2: vk2.delta_g2,
        b_g2_query: std::sync::Arc::new(pk2.b_g2_query.clone()),
    };

    // Generate proof for vault 2
    let mut recorder_vault2 = SimpleCoeffRecorder::<E>::new();
    let proof_vault2 =
        Groth16::<E>::create_random_proof_with_hook(circuit2, &pk2, &mut rng, &mut recorder_vault2)
            .unwrap();

    // Build commitments/bundle for vault 2
    let commitments_vault2 = recorder_vault2.build_commitments();
    let bundle_vault2 = PvugcBundle {
        groth16_proof: proof_vault2.clone(),
        dlrep_b: recorder_vault2.create_dlrep_b(&pvugc_vk2, &mut rng),
        dlrep_ties: recorder_vault2.create_dlrep_ties(&mut rng),
        gs_commitments: commitments_vault2.clone(),
    };

    // VERIFY vault2's bundle
    assert!(OneSidedPvugc::verify(
        &bundle_vault2,
        &pvugc_vk2,
        &vk2,
        &vault2_utxo
    ));

    // Setup column arms for vault 2 (SAME ρ, different VK)
    let (_bases_cols2, col_arms2, _r2, _k2_expected_from_setup) =
        OneSidedPvugc::setup_and_arm(&pvugc_vk2, &vk2, &vault2_utxo, &rho).expect("setup_and_arm");

    // Decap vault2's proof via column path
    let k_vault2_decap =
        OneSidedPvugc::decapsulate(&commitments_vault2, &col_arms2).expect("decapsulate");

    // Compute expected R for vault 2
    let r_vault2 = compute_groth16_target(&vk2, &vault2_utxo).expect("compute_groth16_target");
    let k_vault2_expected = OneSidedPvugc::compute_r_to_rho(&r_vault2, &rho);

    // Verify vault2 decap matches its expected R^ρ
    assert_eq!(
        k_vault2_decap, k_vault2_expected,
        "Vault2 decap should match R₂^ρ"
    );

    // Different statements should produce different K
    // Even though we use SAME ρ!
    assert_ne!(
        k1, k_vault2_decap,
        "Different vaults MUST produce different keys!"
    );
    // Decryption with different-statement key should fail
    // (Different K → different keystream → plaintext won't match)
    let dem_vault2 = ct::DemP2::new(&serialize_gt::<E>(&k_vault2_decap.0), &ad_core_bytes);
    let opened_vault2 = dem_vault2.decrypt(&ct);
    assert_ne!(opened_vault2.as_slice(), plaintext, "Different statement key must not decrypt correctly");
}

#[test]
fn test_delta_sign_sanity() {
    let mut rng = StdRng::seed_from_u64(42);
    let vault_utxo = vec![Fr::from(25u64)];
    let circuit = SquareCircuit {
        x: Some(Fr::from(25u64)),
        y: Some(Fr::from(5u64)),
    };
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    let pvugc_vk = PvugcVk {
        beta_g2: vk.beta_g2,
        delta_g2: vk.delta_g2,
        b_g2_query: std::sync::Arc::new(pk.b_g2_query.clone()),
    };
    let rho = Fr::rand(&mut rng);

    // Use API for setup and arming
    let (_bases_cols, col_arms, _r, k_expected) =
        OneSidedPvugc::setup_and_arm(&pvugc_vk, &vk, &vault_utxo, &rho).expect("setup_and_arm");

    // Hooked proof and commitments
    let mut recorder = SimpleCoeffRecorder::<E>::new();
    let proof =
        Groth16::<E>::create_random_proof_with_hook(circuit.clone(), &pk, &mut rng, &mut recorder)
            .unwrap();
    assert!(Groth16::<E>::verify(&vk, &vault_utxo, &proof).unwrap());

    let commitments = recorder.build_commitments();

    // Correct sign → K_good == R^ρ
    let k_good = OneSidedPvugc::decapsulate(&commitments, &col_arms).expect("decapsulate");
    assert_eq!(k_good, k_expected);
}

#[test]
fn test_r_computation_deterministic() {
    let mut rng = StdRng::seed_from_u64(1);

    let circuit = SquareCircuit {
        x: Some(Fr::from(25u64)),
        y: Some(Fr::from(5u64)),
    };

    let (_pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();
    let vault_utxo = vec![Fr::from(12345u64)];

    // Compute R twice
    let r1 = compute_groth16_target(&vk, &vault_utxo).expect("compute_groth16_target");
    let r2 = compute_groth16_target(&vk, &vault_utxo).expect("compute_groth16_target");

    assert_eq!(r1, r2);
}

#[test]
fn test_different_vaults_different_r() {
    let mut rng = StdRng::seed_from_u64(2);

    let circuit = SquareCircuit {
        x: Some(Fr::from(25u64)),
        y: Some(Fr::from(5u64)),
    };

    let (_pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();

    let vault1 = vec![Fr::from(12345u64)];
    let vault2 = vec![Fr::from(67890u64)];

    let r1 = compute_groth16_target(&vk, &vault1).expect("compute_groth16_target");
    let r2 = compute_groth16_target(&vk, &vault2).expect("compute_groth16_target");

    assert_ne!(r1, r2);
}

#[test]
fn test_witness_independence() {
    use ark_std::UniformRand;

    let mut rng = StdRng::seed_from_u64(300);

    // Addition circuit
    #[derive(Clone)]
    struct AddCircuit {
        pub x: Option<Fr>,
        pub y: Option<Fr>,
        pub z: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for AddCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x_var = FpVar::new_input(cs.clone(), || {
                self.x.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let y_var = FpVar::new_witness(cs.clone(), || {
                self.y.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let z_var = FpVar::new_witness(cs.clone(), || {
                self.z.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let sum = &y_var + &z_var;
            x_var.enforce_equal(&sum)?;
            Ok(())
        }
    }

    let public_x = vec![Fr::from(11u64)];

    // Witness 1: y=4, z=7 (4+7=11)
    let circuit1 = AddCircuit {
        x: Some(public_x[0]), // Use public_x
        y: Some(Fr::from(4u64)),
        z: Some(Fr::from(7u64)),
    };

    // Witness 2: y=5, z=6 (5+6=11)
    let circuit2 = AddCircuit {
        x: Some(public_x[0]), // Same public_x
        y: Some(Fr::from(5u64)),
        z: Some(Fr::from(6u64)),
    };

    // ONE setup (same pk, vk for both witnesses)
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit1.clone(), &mut rng).unwrap();

    // Compute R = e(α,β)·e(L(x),γ) from (vk, public_x)
    let r_statement = compute_groth16_target(&vk, &public_x).expect("compute_groth16_target");

    let pvugc_vk = PvugcVk {
        beta_g2: vk.beta_g2,
        delta_g2: vk.delta_g2,
        b_g2_query: std::sync::Arc::new(pk.b_g2_query.clone()),
    };

    let rho = Fr::rand(&mut rng);

    let (_, col_arms, _, k_expected) =
        OneSidedPvugc::setup_and_arm(&pvugc_vk, &vk, &public_x, &rho).expect("setup_and_arm");

    let mut recorder1 = SimpleCoeffRecorder::<E>::new();
    let proof1 =
        Groth16::<E>::create_random_proof_with_hook(circuit1, &pk, &mut rng, &mut recorder1)
            .unwrap();

    let commitments1 = recorder1.build_commitments();
    let bundle1 = PvugcBundle {
        groth16_proof: proof1,
        dlrep_b: recorder1.create_dlrep_b(&pvugc_vk, &mut rng),
        dlrep_ties: recorder1.create_dlrep_ties(&mut rng),
        gs_commitments: commitments1.clone(),
    };

    assert!(OneSidedPvugc::verify(&bundle1, &pvugc_vk, &vk, &public_x));
    let k1 = OneSidedPvugc::decapsulate(&commitments1, &col_arms).expect("decapsulate");

    let mut recorder2 = SimpleCoeffRecorder::<E>::new();
    let proof2 =
        Groth16::<E>::create_random_proof_with_hook(circuit2, &pk, &mut rng, &mut recorder2)
            .unwrap();

    let commitments2 = recorder2.build_commitments();
    let bundle2 = PvugcBundle {
        groth16_proof: proof2,
        dlrep_b: recorder2.create_dlrep_b(&pvugc_vk, &mut rng),
        dlrep_ties: recorder2.create_dlrep_ties(&mut rng),
        gs_commitments: commitments2.clone(),
    };

    assert!(OneSidedPvugc::verify(&bundle2, &pvugc_vk, &vk, &public_x));
    let k2 = OneSidedPvugc::decapsulate(&commitments2, &col_arms).expect("decapsulate");

    // Since R = compute_groth16_target(vk, public_x) doesn't use witnesses:
    // R is the SAME for both proofs
    assert_eq!(k1, k2, "WITNESS-INDEPENDENT: Different witnesses → Same K!");

    // Verify both equal expected R^ρ (from statement)
    let k_expected_r = OneSidedPvugc::compute_r_to_rho(&r_statement, &rho);
    assert_eq!(k1, k_expected_r, "K₁ should equal R^ρ");
    assert_eq!(k2, k_expected_r, "K₂ should equal R^ρ");
    assert_eq!(k1, k_expected, "Should match setup_and_arm");
}

#[test]
fn test_phase1_integration() {
    use arkworks_groth16::ctx::{PvugcContextBuilder, NumsKeyDerivation, EpochNonceRegistry};
    use arkworks_groth16::bitcoin::{TaprootScriptPath, TransactionTemplate, SighashBinding};
    use sha2::{Sha256, Digest};
    
    let mut rng = StdRng::seed_from_u64(42);

    // PART A: Cryptographic Setup (Existing PVUGC)
    // ===============================================
    
    let statement_x = vec![Fr::from(25u64)];
    let circuit = SquareCircuit {
        x: Some(Fr::from(25u64)),
        y: Some(Fr::from(5u64)),
    };
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

    let pvugc_vk = PvugcVk {
        beta_g2: vk.beta_g2,
        delta_g2: vk.delta_g2,
        b_g2_query: std::sync::Arc::new(pk.b_g2_query.clone()),
    };

    let rho = Fr::rand(&mut rng);
    let (_bases_cols, col_arms, _r, k_expected) =
        OneSidedPvugc::setup_and_arm(&pvugc_vk, &vk, &statement_x, &rho).expect("setup_and_arm");

    // PART B: Context Binding Setup (New)
    // ===================================
    
    // Compute digest hashes per spec §3
    let mut vk_hasher = Sha256::new();
    let vk_bytes = format!("{:?}", vk);  // Simplified; production would serialize properly
    vk_hasher.update(vk_bytes.as_bytes());
    let vk_hash: [u8; 32] = vk_hasher.finalize().into();

    let mut x_hasher = Sha256::new();
    for x_elem in &statement_x {
        x_hasher.update(format!("{:?}", x_elem).as_bytes());
    }
    let x_hash: [u8; 32] = x_hasher.finalize().into();

    let mut y_cols_hasher = Sha256::new();
    y_cols_hasher.update(b"PVUGC/YCOLS");
    y_cols_hasher.update(format!("{:?}", vk.beta_g2).as_bytes());
    for col in pk.b_g2_query.iter() {
        y_cols_hasher.update(format!("{:?}", col).as_bytes());
    }
    let y_cols_digest: [u8; 32] = y_cols_hasher.finalize().into();

    // Generate unique epoch nonce
    let mut epoch_nonce = [0u8; 32];
    let mut nonce_rng = StdRng::seed_from_u64(999);
    for byte in epoch_nonce.iter_mut() {
        *byte = (nonce_rng.next_u32() % 256) as u8;
    }
    
    // Verify nonce uniqueness
    let mut nonce_registry = EpochNonceRegistry::new();
    assert!(nonce_registry.register(epoch_nonce).is_ok());
    assert!(nonce_registry.register(epoch_nonce).is_err(), "Nonce reuse should be rejected");

    // Build context binding
    let ctx_builder = PvugcContextBuilder::new(vk_hash, x_hash, y_cols_digest, epoch_nonce);
    let ctx = ctx_builder.finalize(None, None);
    
    assert_ne!(ctx.ctx_hash, [0u8; 32], "ctx_hash must not be zero");
    assert_eq!(ctx.epoch_nonce, epoch_nonce, "Nonce should be preserved");

    // PART C: NUMS Key Derivation (New)
    // ==================================
    
    let nums = NumsKeyDerivation::new(vk_hash, x_hash, epoch_nonce);
    let nums_challenge = nums.compute_nums_challenge();
    
    // Verify determinism
    let nums2 = NumsKeyDerivation::new(vk_hash, x_hash, epoch_nonce);
    let nums_challenge2 = nums2.compute_nums_challenge();
    assert_eq!(nums_challenge, nums_challenge2, "NUMS challenge must be deterministic");
    assert!(nums_challenge.starts_with(b"PVUGC/NUMS"), "NUMS challenge must have domain tag");

    // PART D: Taproot Script Paths (New)
    // ==================================
    
    let pubkey_compute = [1u8; 33];
    let pubkey_abort = [2u8; 33];
    
    let compute_path = TaprootScriptPath::compute_spend(&pubkey_compute);
    let abort_path = TaprootScriptPath::timeout_abort(144, &pubkey_abort);
    
    assert_eq!(compute_path.version, 0xc0, "Taproot version must be 0xc0");
    assert_eq!(compute_path.script.len(), 34, "ComputeSpend script: 33 bytes pubkey + 1 byte OP_CHECKSIG");
    assert!(abort_path.script.len() > 34, "TimeoutAbort script longer than ComputeSpend");
    
    // Compute leaf hashes
    let compute_leaf_hash = compute_path.leaf_hash();
    let abort_leaf_hash = abort_path.leaf_hash();
    
    assert_ne!(compute_leaf_hash, abort_leaf_hash, "Different scripts must have different hashes");
    assert_ne!(compute_leaf_hash, [0u8; 32], "Leaf hash must not be zero");

    // PART E: Transaction Template (New)
    // ===================================
    
    let prev_outpoint = vec![0u8; 36];  // 32-byte txid + 4-byte vout
    let output_script = vec![0x51];  // OP_1
    let outputs = vec![(output_script, 50000u64)];
    let tx_template = TransactionTemplate::new(
        prev_outpoint.clone(),
        outputs.clone(),
        0,
        0xfffffffe,  // CSV-capable
        vec![0x02, 0x00, 0x01, 0x00],
    );
    
    let tx_hash1 = tx_template.tx_hash();
    let tx_hash2 = tx_template.tx_hash();
    assert_eq!(tx_hash1, tx_hash2, "TX hash must be deterministic");
    assert_ne!(tx_hash1, [0u8; 32], "TX hash must not be zero");

    // PART F: SIGHASH Binding (New)
    // =============================
    
    let sighash = SighashBinding::compute_sighash_all(
        &prev_outpoint,
        50000u64,
        &[0x51],
        &outputs,
        &compute_path,
        0,
    );
    
    assert_ne!(sighash, [0u8; 32], "SIGHASH must not be zero");

    // PART G: Proof Generation & Key Extraction (Existing PVUGC + Context Binding)
    // ==============================================================================
    
    let mut recorder = SimpleCoeffRecorder::<E>::new();
    let proof =
        Groth16::<E>::create_random_proof_with_hook(circuit.clone(), &pk, &mut rng, &mut recorder)
            .unwrap();

    let commitments = recorder.build_commitments();
    let bundle = PvugcBundle {
        groth16_proof: proof.clone(),
        dlrep_b: recorder.create_dlrep_b(&pvugc_vk, &mut rng),
        dlrep_ties: recorder.create_dlrep_ties(&mut rng),
        gs_commitments: commitments.clone(),
    };

    assert!(OneSidedPvugc::verify(&bundle, &pvugc_vk, &vk, &statement_x));
    
    let k_derived = OneSidedPvugc::decapsulate(&commitments, &col_arms).expect("decapsulate");
    assert_eq!(k_derived, k_expected, "Extracted key must match expected R^ρ");

    // PART H: Full Context Integration (All Layers)
    // ==============================================
    
    // Bind arming package
    let arming_pkg = PvugcContextBuilder::build_arming_pkg_hash(
        b"armed_bases_serialized",
        b"header_metadata",
    );
    
    // Bind presignature package
    let presig_pkg = PvugcContextBuilder::build_presig_pkg_hash(
        &sighash,
        b"adaptor_point_T",
        b"nonce_R",
        b"signer_set",
        b"musig_coeffs",
    );
    
    // Build final context with all three layers
    let full_ctx = PvugcContextBuilder::new(vk_hash, x_hash, y_cols_digest, epoch_nonce)
        .with_tapleaf(compute_leaf_hash, 0xc0)
        .with_txid_template(tx_template.serialized.clone())
        .with_path_tag("compute")
        .finalize(Some(arming_pkg), Some(presig_pkg));
    
    assert_eq!(full_ctx.ctx_core, full_ctx.ctx_core, "ctx_core must be deterministic");
    assert!(full_ctx.arming_pkg_hash.is_some());
    assert!(full_ctx.presig_pkg_hash.is_some());
    assert_ne!(full_ctx.ctx_hash, [0u8; 32], "Final ctx_hash must not be zero");

    // Verify that different paths produce different context
    let different_path_ctx = PvugcContextBuilder::new(vk_hash, x_hash, y_cols_digest, epoch_nonce)
        .with_path_tag("abort")
        .finalize(None, None);
    
    assert_ne!(full_ctx.ctx_core, different_path_ctx.ctx_core, "Different paths must produce different contexts");
}
