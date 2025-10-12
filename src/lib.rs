mod bls12381_ops;
pub mod groth16_wrapper;
pub mod gs_commitments;
pub mod gs_kem_eval;
pub mod gs_kem_helpers;
pub mod kem;
pub mod kem_duo;
pub mod schnorr;

// Re-export for external use
pub use groth16_wrapper::{ArkworksGroth16, ArkworksProof, ArkworksVK};
pub use gs_commitments::{GSAttestation, GrothSahaiCommitments};
pub use gs_kem_eval::{kdf_from_comt, masked_verifier_matrix_canonical, rhs_masked_matrix};
pub use gs_kem_helpers::{serialize_attestation_for_kem, serialize_crs_for_kem, masked_verifier_from_masked};
pub use kem::{KEMShare, ProductKeyKEM};
pub use kem_duo::KEMShareDuo;
pub use schnorr::{AdaptorSignature, SchnorrAdaptor};
