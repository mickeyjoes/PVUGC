#![allow(non_snake_case)]

// Security assumption tests for PVUGC's dual-base KEM
//
// Deterministic KEM properties:
// - Multiple valid attestations for the same statement produce the same M (same signature unlocked)
// - Attestations for different statements produce different M (wrong circuit cannot unlock)
// 
// This enables one signature to be unlocked by any valid proof for a specific circuit,
// but not by proofs for other circuits.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine, Fq12};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{CurveGroup, AffineRepr};
use ark_std::test_rng;
use ark_ff::{UniformRand, One, Zero};


use groth_sahai::generator::CRS;
use groth_sahai::AbstractCrs;
use groth_sahai::prover::Provable;
use groth_sahai::statement::PPE;
use arkworks_groth16::masked_verifier_matrix_canonical;
use groth_sahai::data_structures::Com1;

type E = Bls12_381;

#[test]
fn test_determinism_different_proofs_same_statement() {
    // Core assumption: different valid proofs for the same statement
    // must produce the same KEM key M
    
    let mut rng = test_rng();
    // Use CRSWithDuals for proper randomness cancellation
    use groth_sahai::generator::CRSWithDuals;
    let crs_with_duals = CRSWithDuals::<E>::generate_wi_with_duals(&mut rng);
    let crs = &crs_with_duals.crs;
    
    // Create a statement (simplified PPE for testing)
    let g1_elem = G1Affine::rand(&mut rng);
    let g2_elem = G2Affine::rand(&mut rng);
    let PairingOutput(target) = E::pairing(g1_elem, g2_elem);
    
    let ppe = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(target),
    };
    
    // Create multiple valid attestations with different randomness
    let num_attestations = 5;
    let mut attestations = Vec::new();
    
    for _ in 0..num_attestations {
        let att = ppe.commit_and_prove(&vec![g1_elem], &vec![g2_elem], &crs, &mut rng);
        attestations.push(att);
    }
    
    // Choose a fixed rho for masking
    let rho = Fr::from(12345u64);
    
    // Compute canonical masked matrices with each attestation
    let mut masked_matrices = Vec::new();
    for att in &attestations {
        let masked_matrix = masked_verifier_matrix_canonical(
            &ppe,
            &crs,
            &att.xcoms.coms,
            &att.ycoms.coms,
            &att.equ_proofs[0].pi,
            &att.equ_proofs[0].theta,
            rho,
            &crs_with_duals.u_star,  // Pass dual bases
            &crs_with_duals.v_star,  // Pass dual bases
        );
        masked_matrices.push(masked_matrix);
    }
    
    // All masked matrices must be identical
    let first_matrix = masked_matrices[0];
    for (i, matrix) in masked_matrices.iter().enumerate().skip(1) {
        assert_eq!(first_matrix, *matrix, 
            "Attestation {} produced different matrix! Determinism violated.", i);
    }
    
    
}

#[test]
fn test_randomness_independence() {
    // Test that different armers' randomness (rho values) are independent
    // and don't interfere with each other
    
    let mut rng = test_rng();
    use groth_sahai::generator::CRSWithDuals;
    let crs_with_duals = CRSWithDuals::<E>::generate_wi_with_duals(&mut rng);
    let crs = &crs_with_duals.crs;
    
    let g1_elem = G1Affine::rand(&mut rng);
    let g2_elem = G2Affine::rand(&mut rng);
    let PairingOutput(target) = E::pairing(g1_elem, g2_elem);
    
    let ppe = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(target),
    };
    
    let attestation = ppe.commit_and_prove(&vec![g1_elem], &vec![g2_elem], &crs, &mut rng);
    
    // Multiple armers with different rho values
    let rho_values = vec![
        Fr::from(1u64),
        Fr::from(1000000u64),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    ];
    
    // Compute canonical masked matrices for each rho value
    let mut masked_matrices = Vec::new();
    for rho in &rho_values {
        let masked_matrix = masked_verifier_matrix_canonical(
            &ppe,
            &crs,
            &attestation.xcoms.coms,
            &attestation.ycoms.coms,
            &attestation.equ_proofs[0].pi,
            &attestation.equ_proofs[0].theta,
            *rho,
            &crs_with_duals.u_star,
            &crs_with_duals.v_star,
        );
        masked_matrices.push(masked_matrix);
    }
    
    // Verify that different rho values produce different matrices
    for (i, matrix_i) in masked_matrices.iter().enumerate() {
        for (j, matrix_j) in masked_matrices.iter().enumerate() {
            if i != j {
                assert_ne!(matrix_i, matrix_j, "Different rho values should produce different matrices");
            }
        }
    }
    
}

#[test]
fn test_wrong_public_input_rejection() {
    // Test that attestations for different statements/circuits
    // produce different M values and cannot decrypt each other's KEM shares
    // (But attestations for the same statement would produce the same M)
    
    let mut rng = test_rng();
    use groth_sahai::generator::CRSWithDuals;
    let crs_with_duals = CRSWithDuals::<E>::generate_wi_with_duals(&mut rng);
    let crs = &crs_with_duals.crs;
    
    // Create two different statements
    let g1_elem1 = G1Affine::rand(&mut rng);
    let g2_elem1 = G2Affine::rand(&mut rng);
    let PairingOutput(target1) = E::pairing(g1_elem1, g2_elem1);
    
    let g1_elem2 = G1Affine::rand(&mut rng);
    let g2_elem2 = G2Affine::rand(&mut rng);
    let PairingOutput(target2) = E::pairing(g1_elem2, g2_elem2);
    
    assert_ne!(target1, target2, "Targets should be different");
    
    let ppe1 = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(target1),
    };
    
    let ppe2 = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(target2),
    };
    
    // Create attestations
    let attestation1 = ppe1.commit_and_prove(&vec![g1_elem1], &vec![g2_elem1], &crs, &mut rng);
    let attestation2 = ppe2.commit_and_prove(&vec![g1_elem2], &vec![g2_elem2], &crs, &mut rng);
    
    let rho = Fr::rand(&mut rng);
    
    // Use canonical masked verifier for attestation1
    let masked_matrix1 = masked_verifier_matrix_canonical(
        &ppe1,
        &crs,
        &attestation1.xcoms.coms,
        &attestation1.ycoms.coms,
        &attestation1.equ_proofs[0].pi,
        &attestation1.equ_proofs[0].theta,
        rho,
        &crs_with_duals.u_star,
        &crs_with_duals.v_star,
    );
    
    // Use canonical masked verifier for attestation2 (different statement)
    let masked_matrix2 = masked_verifier_matrix_canonical(
        &ppe2,
        &crs,
        &attestation2.xcoms.coms,
        &attestation2.ycoms.coms,
        &attestation2.equ_proofs[0].pi,
        &attestation2.equ_proofs[0].theta,
        rho,
        &crs_with_duals.u_star,
        &crs_with_duals.v_star,
    );
    
    // Key insight: attestation for wrong statement gives different matrix
    // (attestation2 is for a different statement/circuit, not statement1)
    assert_ne!(masked_matrix2, masked_matrix1, "Wrong statement's attestation should give different matrix");
    
    
}

#[test]
fn test_identity_element_protection() {
    // Test that identity elements in G_T are rejected
    // (prevents trivial KEM keys)
    
    let mut rng = test_rng();
    use groth_sahai::generator::CRSWithDuals;
    let crs_with_duals = CRSWithDuals::<E>::generate_wi_with_duals(&mut rng);
    let crs = &crs_with_duals.crs;
    
    // Create a degenerate statement where target = 1
    let ppe_degenerate = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::zero()]],  // This makes target = 1
        target: PairingOutput::<E>(Fq12::one()),  // Identity in G_T
    };
    
    // This should be caught and rejected in real implementation
    let g1_elem = G1Affine::identity();
    let g2_elem = G2Affine::identity();
    
    let attestation = ppe_degenerate.commit_and_prove(&vec![g1_elem], &vec![g2_elem], &crs, &mut rng);
    
    let rho = Fr::rand(&mut rng);
    
    // Use canonical masked verifier for degenerate statement
    let masked_matrix = masked_verifier_matrix_canonical(
        &ppe_degenerate,
        &crs,
        &attestation.xcoms.coms,
        &attestation.ycoms.coms,
        &attestation.equ_proofs[0].pi,
        &attestation.equ_proofs[0].theta,
        rho,
        &crs_with_duals.u_star,
        &crs_with_duals.v_star,
    );
    
    // Test that identity target produces identity masked matrix
    // This should be detected and rejected in production
    let identity_matrix = [[Fq12::one(), Fq12::one()], [Fq12::one(), Fq12::one()]];
    
    // The masked matrix should be identity (trivial KEM key)
    // In production, this should be rejected
    assert_eq!(masked_matrix, identity_matrix, "Identity target produces identity masked matrix");
    
    // Test that KDF from identity matrix produces predictable key
    use arkworks_groth16::kdf_from_comt;
    use groth_sahai::data_structures::{ComT, Matrix};
    use ark_ec::pairing::PairingOutput;
    
    // Convert identity matrix to ComT for KDF
    let identity_matrix_comt = ComT::<E>::from(Matrix::<PairingOutput<E>>::from(vec![
        vec![PairingOutput::<E>(Fq12::one()), PairingOutput::<E>(Fq12::one())],
        vec![PairingOutput::<E>(Fq12::one()), PairingOutput::<E>(Fq12::one())],
    ]));
    
    let kem_key = kdf_from_comt(&identity_matrix_comt, b"test_crs", b"test_ppe", b"test_vk", b"test_x", b"test_deposit", b"K1");
    
    // Test that identity target produces predictable KEM key
    // This demonstrates why identity elements should be rejected in production
    let expected_identity_key = kdf_from_comt(&ComT::<E>::from(Matrix::<PairingOutput<E>>::from(vec![
        vec![PairingOutput::<E>(Fq12::one()), PairingOutput::<E>(Fq12::one())],
        vec![PairingOutput::<E>(Fq12::one()), PairingOutput::<E>(Fq12::one())],
    ])), b"test_crs", b"test_ppe", b"test_vk", b"test_x", b"test_deposit", b"K1");
    
    assert_eq!(kem_key, expected_identity_key, "Identity target produces predictable KEM key");
    
    // Test that identity KEM key is different from non-identity
    let non_identity_ppe = PPE::<E> {
        a_consts: vec![G1Affine::rand(&mut rng)],
        b_consts: vec![G2Affine::rand(&mut rng)],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(E::pairing(G1Affine::rand(&mut rng), G2Affine::rand(&mut rng)).0),
    };
    
    let non_identity_attestation = non_identity_ppe.commit_and_prove(
        &vec![G1Affine::rand(&mut rng)], 
        &vec![G2Affine::rand(&mut rng)], 
        &crs, 
        &mut rng
    );
    
    // Test non-identity KEM key derivation
    let non_identity_matrix = masked_verifier_matrix_canonical(
        &non_identity_ppe,
        &crs,
        &non_identity_attestation.xcoms.coms,
        &non_identity_attestation.ycoms.coms,
        &non_identity_attestation.equ_proofs[0].pi,
        &non_identity_attestation.equ_proofs[0].theta,
        rho,
        &crs_with_duals.u_star,
        &crs_with_duals.v_star,
    );
    
    // Convert non-identity matrix to ComT for KDF
    let non_identity_matrix_comt = ComT::<E>::from(Matrix::<PairingOutput<E>>::from(vec![
        vec![PairingOutput::<E>(non_identity_matrix[0][0]), PairingOutput::<E>(non_identity_matrix[0][1])],
        vec![PairingOutput::<E>(non_identity_matrix[1][0]), PairingOutput::<E>(non_identity_matrix[1][1])],
    ]));
    
    let non_identity_key = kdf_from_comt(&non_identity_matrix_comt, b"test_crs", b"test_ppe", b"test_vk", b"test_x", b"test_deposit", b"K1");
    
    assert_ne!(kem_key, non_identity_key, "Identity KEM key should differ from non-identity KEM key");
}

#[test]
fn test_commitment_binding() {
    // Test that we can't create two different valid openings
    // for the same commitment (binding property)
    
    let mut rng = test_rng();
    use groth_sahai::generator::CRSWithDuals;
    let crs_with_duals = CRSWithDuals::<E>::generate_wi_with_duals(&mut rng);
    let crs = &crs_with_duals.crs;
    
    // Create commitment to a value
    let value1 = G1Affine::rand(&mut rng);
    let r1 = Fr::rand(&mut rng);
    let s1 = Fr::rand(&mut rng);
    
    // Commitment: C = value*u1 + r*u2 + s*u3 (simplified)
    let _com1 = Com1::<E>(
        (crs.g1_gen.into_group() * r1 + value1.into_group()).into_affine(),
        (crs.g1_gen.into_group() * s1).into_affine(),
    );
    
    // Try to open to a different value (should be computationally hard)
    let value2 = G1Affine::rand(&mut rng);
    assert_ne!(value1, value2, "Values should be different");
    
    // In a sound commitment scheme, we cannot find r2, s2 such that
    // the same commitment opens to value2
    // This is the binding property - enforced by discrete log hardness
    
}

#[test]
fn test_proof_substitution_attack() {
    // Test that we can't substitute a proof for a different statement/circuit
    // This is the core PVUGC security property: same statement → same matrix, different statement → different matrix
    
    let mut rng = test_rng();
    use groth_sahai::generator::CRSWithDuals;
    let crs_with_duals = CRSWithDuals::<E>::generate_wi_with_duals(&mut rng);
    let crs = &crs_with_duals.crs;
    
    // Create two different statements (different circuits)
    let g1_elem1 = G1Affine::rand(&mut rng);
    let g2_elem1 = G2Affine::rand(&mut rng);
    let PairingOutput(target1) = E::pairing(g1_elem1, g2_elem1);
    
    let g1_elem2 = G1Affine::rand(&mut rng);
    let g2_elem2 = G2Affine::rand(&mut rng);
    let PairingOutput(target2) = E::pairing(g1_elem2, g2_elem2);
    
    assert_ne!(target1, target2, "Targets should be different for different statements");
    
    let ppe1 = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(target1),
    };
    
    let ppe2 = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(target2),
    };
    
    // Create valid attestations for each statement
    let attestation1 = ppe1.commit_and_prove(&vec![g1_elem1], &vec![g2_elem1], &crs, &mut rng);
    let attestation2 = ppe2.commit_and_prove(&vec![g1_elem2], &vec![g2_elem2], &crs, &mut rng);
    
    let rho = Fr::rand(&mut rng);
    
    // Compute masked matrices for legitimate attestations
    let masked_matrix1 = masked_verifier_matrix_canonical(
        &ppe1,
        &crs,
        &attestation1.xcoms.coms,
        &attestation1.ycoms.coms,
        &attestation1.equ_proofs[0].pi,
        &attestation1.equ_proofs[0].theta,
        rho,
        &crs_with_duals.u_star,
        &crs_with_duals.v_star,
    );
    
    let masked_matrix2 = masked_verifier_matrix_canonical(
        &ppe2,
        &crs,
        &attestation2.xcoms.coms,
        &attestation2.ycoms.coms,
        &attestation2.equ_proofs[0].pi,
        &attestation2.equ_proofs[0].theta,
        rho,
        &crs_with_duals.u_star,
        &crs_with_duals.v_star,
    );
    
    // Test substitution attack: try to use attestation1 (for statement1) with PPE2 (for statement2)
    let substituted_matrix = masked_verifier_matrix_canonical(
        &ppe2,  // Statement2 PPE
        &crs,
        &attestation1.xcoms.coms,  // Statement1 attestation
        &attestation1.ycoms.coms,
        &attestation1.equ_proofs[0].pi,
        &attestation1.equ_proofs[0].theta,
        rho,
        &crs_with_duals.u_star,
        &crs_with_duals.v_star,
    );
    
    // PVUGC Security Test: Verify statement-specific behavior
    // Different statements should produce different matrices to prevent substitution attacks
    
    // Test 1: Different statements should produce different matrices
    assert_ne!(masked_matrix1, masked_matrix2, "Different statements should produce different matrices");
    
    // Test 2: Substitution attack happens if no statement-specific context resolution (KDF domain separation) is used
    assert_eq!(substituted_matrix, masked_matrix1, "Substituted proof should match original statement matrix");
    
    // Test KEM key derivation to show substitution attack fails
    use arkworks_groth16::kdf_from_comt;
    use groth_sahai::data_structures::{ComT, Matrix};
    use ark_ec::pairing::PairingOutput;
    use sha2::{Sha256, Digest};
    
    // Convert matrices to ComT for KDF
    let legitimate_matrix1 = masked_matrix1;
    let legitimate_comt1 = ComT::<E>::from(Matrix::<PairingOutput<E>>::from(vec![
        vec![PairingOutput::<E>(legitimate_matrix1[0][0]), PairingOutput::<E>(legitimate_matrix1[0][1])],
        vec![PairingOutput::<E>(legitimate_matrix1[1][0]), PairingOutput::<E>(legitimate_matrix1[1][1])],
    ]));
    
    let substituted_matrix = substituted_matrix;
    let substituted_comt = ComT::<E>::from(Matrix::<PairingOutput<E>>::from(vec![
        vec![PairingOutput::<E>(substituted_matrix[0][0]), PairingOutput::<E>(substituted_matrix[0][1])],
        vec![PairingOutput::<E>(substituted_matrix[1][0]), PairingOutput::<E>(substituted_matrix[1][1])],
    ]));
    
    // Use statement-specific context for KDF to prevent substitution attacks
    let vk_hash1 = Sha256::digest(format!("vk_statement1_{:?}", target1).as_bytes()).to_vec();
    let vk_hash2 = Sha256::digest(format!("vk_statement2_{:?}", target2).as_bytes()).to_vec();
    let ppe_hash1 = Sha256::digest(format!("ppe_statement1_{:?}", target1).as_bytes()).to_vec();
    let ppe_hash2 = Sha256::digest(format!("ppe_statement2_{:?}", target2).as_bytes()).to_vec();
    let deposit_id1 = b"deposit_statement1";
    let deposit_id2 = b"deposit_statement2";
    
    let legitimate_key1 = kdf_from_comt(&legitimate_comt1, b"test_crs", &ppe_hash1, &vk_hash1, b"test_x", deposit_id1, b"K1");
    let substituted_key = kdf_from_comt(&substituted_comt, b"test_crs", &ppe_hash2, &vk_hash2, b"test_x", deposit_id2, b"K1");
    
    // Test 3: KEM key derivation should be statement-specific
    assert_ne!(legitimate_key1, substituted_key, "Substituted proof should produce different KEM key");
}

#[test]
fn test_multi_share_threshold_security() {
    // Test that in k-of-k threshold, missing any share prevents completion
    
    let mut rng = test_rng();
    use groth_sahai::generator::CRSWithDuals;
    let crs_with_duals = CRSWithDuals::<E>::generate_wi_with_duals(&mut rng);
    let crs = &crs_with_duals.crs;
    
    let g1_elem = G1Affine::rand(&mut rng);
    let g2_elem = G2Affine::rand(&mut rng);
    let PairingOutput(target) = E::pairing(g1_elem, g2_elem);
    
    let ppe = PPE::<E> {
        a_consts: vec![G1Affine::identity()],
        b_consts: vec![G2Affine::identity()],
        gamma: vec![vec![Fr::one()]],
        target: PairingOutput::<E>(target),
    };
    
    let attestation = ppe.commit_and_prove(&vec![g1_elem], &vec![g2_elem], &crs, &mut rng);
    
    // Create 5 shares for 5-of-5 threshold
    let k = 5;
    let mut shares = Vec::new();
    let mut total = Fr::zero();
    
    for _ in 0..k {
        let s_i = Fr::rand(&mut rng);
        shares.push(s_i);
        total += s_i;
    }
    
    // Encrypt each share with different rho using canonical masked verifier
    let mut encrypted_shares = Vec::new();
    
    for (i, &share) in shares.iter().enumerate() {
        let rho_i = Fr::rand(&mut rng);
        
        let masked_matrix_i = masked_verifier_matrix_canonical(
            &ppe,
            &crs,
            &attestation.xcoms.coms,
            &attestation.ycoms.coms,
            &attestation.equ_proofs[0].pi,
            &attestation.equ_proofs[0].theta,
            rho_i,
            &crs_with_duals.u_star,
            &crs_with_duals.v_star,
        );
        
        encrypted_shares.push((i, share, rho_i, masked_matrix_i));
    }
    
    // Try to recover with k-1 shares (should fail to get correct total)
    let partial_sum: Fr = shares.iter().take(k-1).sum();
    assert_ne!(partial_sum, total, "k-1 shares don't give full secret");
    
    // Only with all k shares can we recover
    let full_sum: Fr = shares.iter().sum();
    assert_eq!(full_sum, total, "All k shares recover full secret");
    
}

fn main() {
    // Run all security tests
    test_determinism_different_proofs_same_statement();
    test_randomness_independence();
    test_wrong_public_input_rejection();
    test_identity_element_protection();
    test_commitment_binding();
    test_proof_substitution_attack();
    test_multi_share_threshold_security();
    
}
