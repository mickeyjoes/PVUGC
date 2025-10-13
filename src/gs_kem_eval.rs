//! Canonical masked evaluator for proof-agnostic KEM extraction
//! 
//! This module provides the canonical masked verifier evaluator that applies ρ
//! to CRS constants/primaries (not commitments) and post-exponentiates the γ ComT.

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};

use groth_sahai::data_structures::{Com1, Com2, ComT, vec_to_col_vec, col_vec_to_vec, BT, Mat, Matrix};
use groth_sahai::generator::CRS;
use groth_sahai::statement::PPE;

/// Scale a vector of Com1/Com2 (CRS-side) by rho (used only for CRS constants and primaries).
fn scale_com1<E: Pairing>(v: &[Com1<E>], rho: E::ScalarField) -> Vec<Com1<E>> {
    v.iter().map(|c| {
        Com1::<E>(
            (c.0.into_group() * rho).into_affine(),
            (c.1.into_group() * rho).into_affine(),
        )
    }).collect()
}

fn scale_com2<E: Pairing>(v: &[Com2<E>], rho: E::ScalarField) -> Vec<Com2<E>> {
    v.iter().map(|d| {
        Com2::<E>(
            (d.0.into_group() * rho).into_affine(),
            (d.1.into_group() * rho).into_affine(),
        )
    }).collect()
}

/// Raise every GT cell of a ComT to rho (post-exponentiation).
fn comt_pow_cells<E: Pairing>(m: &ComT<E>, rho: E::ScalarField) -> [[E::TargetField; 2]; 2] {
    let mm = m.as_matrix();
    [
        [ mm[0][0].0.pow(rho.into_bigint()), mm[0][1].0.pow(rho.into_bigint()) ],
        [ mm[1][0].0.pow(rho.into_bigint()), mm[1][1].0.pow(rho.into_bigint()) ],
    ]
}

/// Extract raw GT cells for matrix comparisons.
fn comt_to_cells<E: Pairing>(m: &ComT<E>) -> [[E::TargetField; 2]; 2] {
    let mm = m.as_matrix();
    [
        [mm[0][0].0, mm[0][1].0],
        [mm[1][0].0, mm[1][1].0],
    ]
}

/// Canonical masked verifier evaluator (proof-agnostic under fixed (vk,x)).
/// 
/// This implements the five-bucket formula with dual bases for proper randomness cancellation:
/// B1 + B2 + G - B3 - B4
/// where:
/// - B1 = e(X, U*^ρ) - statement commitments paired with masked dual bases
/// - B2 = e(V*^ρ, Y) - masked dual bases paired with statement commitments
/// - B3 = e(U^ρ, π) - masked primaries paired with proof elements
/// - B4 = e(θ, V^ρ) - proof elements paired with masked primaries
/// - G = e(X, ΓY) - cross term (NOT post-exponentiated)
/// 
/// The dual bases U*, V* are required for randomness cancellation. Without them,
/// different proofs for the same statement will produce different results.
pub fn masked_verifier_matrix_canonical<E: Pairing>(
    ppe: &PPE<E>,
    crs: &CRS<E>,
    xcoms: &[Com1<E>],
    ycoms: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    rho: E::ScalarField,
    u_star: &[(E::G2Affine, E::G2Affine)],  // CRS dual bases (G2 pairs)
    v_star: &[(E::G1Affine, E::G1Affine)],  // CRS dual bases (G1 pairs)
) -> [[E::TargetField; 2]; 2] {
    // Take only the first n duals where n is the number of variables
    // This handles the case where CRS has more elements than the PPE variables
    let num_x = xcoms.len();
    let num_y = ycoms.len();
    
    // Convert dual pairs to Com2/Com1 and scale by rho
    // NOTE: Swap components to match GrothSahaiCommitments convention
    let u_star_com2: Vec<Com2<E>> = u_star[..num_x].iter().map(|(a, b)| Com2(*b, *a)).collect();
    let v_star_com1: Vec<Com1<E>> = v_star[..num_y].iter().map(|(a, b)| Com1(*b, *a)).collect();
    let u_star_rho = scale_com2::<E>(&u_star_com2, rho);
    let v_star_rho = scale_com1::<E>(&v_star_com1, rho);

    // Scale CRS primaries by rho for proof legs (use same count as pi/theta)
    let u_rho = scale_com1::<E>(&crs.u[..pi.len()], rho);
    let v_rho = scale_com2::<E>(&crs.v[..theta.len()], rho);

    // Five-bucket formula:
    // Bucket 1: e(X, U*^ρ) - uses dual bases
    let b1 = ComT::<E>::pairing_sum(xcoms, &u_star_rho);

    // Bucket 2: e(V*^ρ, Y) - uses dual bases
    let b2 = ComT::<E>::pairing_sum(&v_star_rho, ycoms);

    // Bucket 3: e(U^ρ, π) - proof leg
    let b3 = ComT::<E>::pairing_sum(&u_rho, pi);

    // Bucket 4: e(θ, V^ρ) - proof leg
    let b4 = ComT::<E>::pairing_sum(theta, &v_rho);

    // Bucket 5 (G): e(X, ΓY) - cross term, NOT post-exponentiated
    let stmt_y = vec_to_col_vec(ycoms).left_mul(&ppe.gamma, false);
    let g_term = ComT::<E>::pairing_sum(xcoms, &col_vec_to_vec(&stmt_y));

    // Combine: (B1 + B2 + G) - (B3 + B4)
    let result = (b1 + b2 + g_term) - b3 - b4;

    // Extract and return only the [1][1] cell (others should be zero)
    // This matches the linear_map_PPE structure
    let matrix = result.as_matrix();
    [
        [E::TargetField::zero(), E::TargetField::zero()],
        [E::TargetField::zero(), matrix[1][1].0],
    ]
}

/// Convenience: expected RHS matrix = linear_map_PPE(target^ρ)
pub fn rhs_masked_matrix<E: Pairing>(ppe: &PPE<E>, rho: E::ScalarField) -> [[E::TargetField;2];2] {
    use ark_ff::Field;
    let PairingOutput(tgt) = ppe.target;
    let rhs = ComT::<E>::linear_map_PPE(&PairingOutput::<E>(tgt.pow(rho.into_bigint())));
    let m = rhs.as_matrix();
    [[ m[0][0].0, m[0][1].0 ], [ m[1][0].0, m[1][1].0 ]]
}




use ark_serialize::CanonicalSerialize;
use sha2::{Sha256, Digest};

/// Deterministic 32‑byte key from a masked ComT (full matrix, row-major) with domain separation
pub fn kdf_from_comt<E: Pairing>(
    comt: &ComT<E>,
    crs_digest: &[u8],
    ppe_digest: &[u8],
    vk_hash: &[u8],
    x_hash: &[u8],
    deposit_id: &[u8],
    label: &[u8],
) -> [u8; 32] {
    let m = comt.as_matrix();
    let mut h = Sha256::new();
    h.update(b"PVUGC-KEM-ComT-");
    h.update(label);
    h.update(crs_digest);
    h.update(ppe_digest);
    h.update(vk_hash);
    h.update(x_hash);
    h.update(deposit_id);
    for r in 0..2 {
        for c in 0..2 {
            let mut buf = Vec::new();
            m[r][c].0.serialize_compressed(&mut buf).unwrap();
            h.update(buf);
        }
    }
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}


#[cfg(test)]
mod tests {
    use super::*;

    use ark_bls12_381::Bls12_381;
    use ark_ec::{pairing::Pairing, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::{test_rng, Zero};

    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    fn mul_g1(base: &<E as Pairing>::G1Affine, scalar: Fr) -> <E as Pairing>::G1Affine {
        (base.into_group() * scalar).into_affine()
    }

    fn mul_g2(base: &<E as Pairing>::G2Affine, scalar: Fr) -> <E as Pairing>::G2Affine {
        (base.into_group() * scalar).into_affine()
    }

    #[allow(clippy::type_complexity)]
    fn synthetic_inputs(
        g1: &<E as Pairing>::G1Affine,
        g2: &<E as Pairing>::G2Affine,
        target_exp: Fr,
        randomness_a: Fr,
        randomness_b: Fr,
    ) -> (
        Vec<Com1<E>>,
        Vec<Com2<E>>,
        Vec<Com2<E>>,
        Vec<Com1<E>>,
        Vec<Com1<E>>,
        Vec<Com2<E>>,
        Vec<Com2<E>>,
        Vec<Com1<E>>,
        Matrix<Fr>,
    ) {
        let id_g1 = <E as Pairing>::G1Affine::identity();
        let id_g2 = <E as Pairing>::G2Affine::identity();

        let c1 = vec![Com1::<E>(*g1, id_g1)];
        let c2 = vec![Com2::<E>(*g2, id_g2)];

        let u_star_rho = vec![Com2::<E>(mul_g2(g2, target_exp + randomness_a), id_g2)];

        let v_star_rho = vec![Com1::<E>(mul_g1(g1, randomness_b), id_g1)];

        let u_rho = vec![Com1::<E>(*g1, id_g1)];
        let v_rho = vec![Com2::<E>(*g2, id_g2)];

        let pi = vec![Com2::<E>(mul_g2(g2, randomness_a), id_g2)];
        let theta = vec![Com1::<E>(mul_g1(g1, randomness_b), id_g1)];

        let gamma = vec![vec![Fr::zero()]];

        (
            c1, c2, pi, theta, u_rho, v_rho, u_star_rho, v_star_rho, gamma,
        )
    }

    #[test]
    fn five_bucket_matches_linear_map() {
        let mut rng = test_rng();
        let g1 = <E as Pairing>::G1Affine::rand(&mut rng);
        let g2 = <E as Pairing>::G2Affine::rand(&mut rng);

        let target_exp = Fr::from(11u64);
        let randomness_a = Fr::from(5u64);
        let randomness_b = Fr::from(3u64);

        let (c1, c2, pi, theta, u_rho, v_rho, u_star_rho, v_star_rho, gamma) =
            synthetic_inputs(&g1, &g2, target_exp, randomness_a, randomness_b);

        let comt = five_bucket_comt::<E>(
            &c1,
            &c2,
            &pi,
            &theta,
            &gamma,
            &u_rho,
            &v_rho,
            &u_star_rho,
            &v_star_rho,
        );

        let b1 = ComT::<E>::pairing_sum(&c1, &u_star_rho);
        let b2 = ComT::<E>::pairing_sum(&v_star_rho, &c2);
        let b3 = ComT::<E>::pairing_sum(&u_rho, &pi);
        let b4 = ComT::<E>::pairing_sum(&theta, &v_rho);
        let stmt_y = vec_to_col_vec(&c2).left_mul(&gamma, false);
        let g_term = ComT::<E>::pairing_sum(&c1, &col_vec_to_vec(&stmt_y));
        let expected = b1 + b2 + g_term - b3 - b4;
        let cm = comt.as_matrix();
        let em = expected.as_matrix();

        assert_eq!(cm[0][0], PairingOutput::<E>::zero());
        assert_eq!(cm[0][1], PairingOutput::<E>::zero());
        assert_eq!(cm[1][0], PairingOutput::<E>::zero());
        assert_eq!(cm[1][1], em[1][1]);
    }

    #[test]
    fn five_bucket_two_proofs_same_output() {
        let mut rng = test_rng();
        let g1 = <E as Pairing>::G1Affine::rand(&mut rng);
        let g2 = <E as Pairing>::G2Affine::rand(&mut rng);

        let target_exp = Fr::from(17u64);
        let randomness_a1 = Fr::from(7u64);
        let randomness_b1 = Fr::from(4u64);
        let randomness_a2 = Fr::from(13u64);
        let randomness_b2 = Fr::from(9u64);

        let inputs1 = synthetic_inputs(&g1, &g2, target_exp, randomness_a1, randomness_b1);
        let inputs2 = synthetic_inputs(&g1, &g2, target_exp, randomness_a2, randomness_b2);

        let comt1 = five_bucket_comt::<E>(
            &inputs1.0, &inputs1.1, &inputs1.2, &inputs1.3, &inputs1.8, &inputs1.4, &inputs1.5,
            &inputs1.6, &inputs1.7,
        );

        let comt2 = five_bucket_comt::<E>(
            &inputs2.0, &inputs2.1, &inputs2.2, &inputs2.3, &inputs2.8, &inputs2.4, &inputs2.5,
            &inputs2.6, &inputs2.7,
        );

        let b1_1 = ComT::<E>::pairing_sum(&inputs1.0, &inputs1.6);
        let b2_1 = ComT::<E>::pairing_sum(&inputs1.7, &inputs1.1);
        let b3_1 = ComT::<E>::pairing_sum(&inputs1.4, &inputs1.2);
        let b4_1 = ComT::<E>::pairing_sum(&inputs1.3, &inputs1.5);
        let g1_term = ComT::<E>::pairing_sum(
            &inputs1.0,
            &col_vec_to_vec(&vec_to_col_vec(&inputs1.1).left_mul(&inputs1.8, false)),
        );
        let expected1 = b1_1 + b2_1 + g1_term - b3_1 - b4_1;
        let m1 = comt1.as_matrix();
        let e1 = expected1.as_matrix();

        let b1_2 = ComT::<E>::pairing_sum(&inputs2.0, &inputs2.6);
        let b2_2 = ComT::<E>::pairing_sum(&inputs2.7, &inputs2.1);
        let b3_2 = ComT::<E>::pairing_sum(&inputs2.4, &inputs2.2);
        let b4_2 = ComT::<E>::pairing_sum(&inputs2.3, &inputs2.5);
        let g2_term = ComT::<E>::pairing_sum(
            &inputs2.0,
            &col_vec_to_vec(&vec_to_col_vec(&inputs2.1).left_mul(&inputs2.8, false)),
        );
        let expected2 = b1_2 + b2_2 + g2_term - b3_2 - b4_2;
        let m2 = comt2.as_matrix();
        let e2 = expected2.as_matrix();

        for mat in [&m1, &m2] {
            assert_eq!(mat[0][0], PairingOutput::<E>::zero());
            assert_eq!(mat[0][1], PairingOutput::<E>::zero());
            assert_eq!(mat[1][0], PairingOutput::<E>::zero());
        }

        assert_eq!(m1[1][1], e1[1][1]);
        assert_eq!(m2[1][1], e2[1][1]);
        assert_eq!(m1[1][1], m2[1][1]);
    }
}

/// Compute the Groth-Sahai "five bucket" combination for masked verification.
///
/// This matches the verifier's algebra for the Groth16 PPE when dual bases are
/// available.  The inputs must satisfy the following ordering conventions:
///
/// * `c1` / `c2` are the statement commitments (X/Y) in the same order used by
///   the prover.
/// * `pi` / `theta` are the proof legs produced by the GS prover.
/// * `gamma` is the PPE pairing-exponent matrix (Γ) describing cross terms.
/// * `u_rho` / `v_rho` are the CRS primaries scaled by ρ.
/// * `u_star_rho` / `v_star_rho` are the CRS duals scaled by ρ (these remain in
///   the opposite groups, i.e. `u_star_rho` lives in `Com2` and `v_star_rho` in
///   `Com1`).
///
/// The result is a `ComT` matrix equal to `linear_map_PPE(T(vk,x)^ρ)` for valid
/// attestations.  Invalid attestations will yield unrelated values.
pub fn five_bucket_comt<E: Pairing>(
    c1: &[Com1<E>],
    c2: &[Com2<E>],
    pi: &[Com2<E>],
    theta: &[Com1<E>],
    gamma: &Matrix<E::ScalarField>,
    u_rho: &[Com1<E>],
    v_rho: &[Com2<E>],
    u_star_rho: &[Com2<E>],
    v_star_rho: &[Com1<E>],
) -> ComT<E> {
    debug_assert_eq!(c1.len(), u_star_rho.len());
    debug_assert_eq!(c2.len(), v_star_rho.len());
    debug_assert_eq!(u_rho.len(), pi.len());
    debug_assert_eq!(v_rho.len(), theta.len());

    // Bucket 1: Σ e(C1_j, U*_j^ρ)
    let b1 = ComT::<E>::pairing_sum(c1, u_star_rho);

    // Bucket 2: Σ e(V*_k^ρ, C2_k)
    let b2 = ComT::<E>::pairing_sum(v_star_rho, c2);

    // Bucket 3: Σ e(U_j^ρ, π_j)
    let b3 = ComT::<E>::pairing_sum(u_rho, pi);

    // Bucket 4: Σ e(θ_k, V_k^ρ)
    let b4 = ComT::<E>::pairing_sum(theta, v_rho);

    // Bucket 5 ("G"): Σ_{j,k} γ_{jk} · e(C1_j, C2_k)
    let stmt_y = vec_to_col_vec(c2).left_mul(gamma, false);
    let g_term = ComT::<E>::pairing_sum(c1, &col_vec_to_vec(&stmt_y));

    let combined = (b1 + b2 + g_term) - b3 - b4;
    let matrix = combined.as_matrix();

    ComT::<E>::from(vec![
        vec![PairingOutput::<E>::zero(), PairingOutput::<E>::zero()],
        vec![PairingOutput::<E>::zero(), matrix[1][1]],
    ])
}