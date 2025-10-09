**Title:** PVUGC — **Publicly Verifiable Universal General Computation** gated by witness‑encrypted adaptor signatures on Bitcoin.
**License:** CC‑BY 4.0

### Abstract

PVUGC turns **proof existence** for a fixed verification key $\mathsf{vk}$ and public input $x$ into the **ability to complete a Taproot signature** for a pre‑templated transaction. We pre‑arm a Schnorr adaptor signature whose missing scalar $\alpha$ is **witness‑encrypted** under the statement "Groth16 verifies $(\mathsf{vk},x)$" via a **Groth–Sahai (GS)** attestation. Any valid proof yields the same KEM key, enabling decryption of $\alpha$ and completion of the spend. Without a valid proof, the transaction cannot be signed. The approach requires **no new opcodes** and keeps on‑chain script minimal (`OP_CHECKSIG`, optional `OP_CHECKSEQUENCEVERIFY`). It is **use case-agnostic** and applies to any computation compiled to Groth16.

---

### 0) Intuition

* **Goal.** Keep Bitcoin on‑chain tiny (Taproot OP_CHECKSIG ± OP_CHECKSEQUENCEVERIFY) and enforce *off‑chain truth* for a relation $R_{\mathcal{L}}$.
* **How.** Pre‑arm a Schnorr adaptor signature for an exact `SIGHASH_ALL` digest; the finishing scalar $\alpha$ is witness‑encrypted. If and only if a valid proof exists for $(\mathsf{vk},x)$, any party can derive the same KEM key from the GS attestation, decrypt $\alpha$, and finish the signature.
* **Why not "just a SNARK."** Bitcoin still requires a valid Schnorr signature; we transform **proof existence** into the **secret that completes** that Schnorr signature.
* **Why practical.** The **Product‑Key KEM** encrypts to the *verification product* of the GS check, yielding a **proof‑agnostic, instance-deterministic** key: *every* valid attestation for fixed $(\mathsf{vk},x)$ induces the same product in $\mathbb{G}_T$, avoiding pairing inversion and timing paradoxes.
**Key Innovation:** A Product‑Key KEM that maps proof *existence* (not specific witness values) to a deterministic decryption key. This is the first practical WE-backed Taproot adaptor (prove-to-sign) on Bitcoin.

---

### 1) Model & Language

* **Language $\mathcal{L}$.** Fix an NP relation $R_{\mathcal{L}}(x,w)=1$. Examples: VM execution traces, hash‑preimage statements, "state transition" checks, zk‑rollup validity, etc.
* **Gating predicate.** "There exists a Groth16 proof $\pi$ that verifies for $(\mathsf{vk},x)$."
* **Spend semantics.** The Taproot spend **succeeds iff** the gating predicate is true (i.e., the $\alpha$ needed for the adaptor is recoverable).
* **Optimistic flavor.** You can add an **optional Timeout/Abort** path (timelock) or an **optional Opposite‑Predicate path** (gate a *different* computation) depending on your application. None of this is *required* by the core innovation.

---

### 2) Bitcoin script (generic template)

Two Taproot script leaves (key‑path disabled by NUMS‑style internal key):

```
ComputeSpend : <P_compute> OP_CHECKSIG

Timeout/Abort (optional) :
    <Δ> OP_CHECKSEQUENCEVERIFY OP_DROP
    <P_abort> OP_CHECKSIG
```

* **ComputeSpend** is the path whose adaptor signature is witness‑encrypted under $(\mathsf{vk},x)$.
* **Timeout/Abort** is optional: a plain timelock or a different WE‑gated policy.
* **Key‑path**: internal key is a public point with unknown discrete log (NUMS) so only script‑path is usable (a social burn of the key path). Derive deterministically (cycle‑free), using IETF hash‑to‑curve (simplified‑SWU) for secp256k1 with domain tag `"PVUGC/NUMS"` and canonical encodings:

```
Q_nums <- hash_to_curve("PVUGC/NUMS" || vk_hash || H(x) || tapleaf_hash || tapleaf_version || epoch)
internal_key = xonly_even_y(Q_nums)
```
* **Transaction binding**: all signatures use `SIGHASH_ALL`, bind tapleaf hash **and version**, **annex absent** (BIP‑341 `annex_present = 0`), and include a **small P2TR CPFP hook** output.
* **CPFP hook.** A small P2TR output in a fixed position to allow fee bumping via child‑pays‑for‑parent; changing its value or position invalidates $m$.

---

### 3) Context binding (layered `ctx_hash`)

Use layered hashes to bind the environment without cycles. Transcripts bind to `ctx_hash`, but are not included in these package hashes:

```
ctx_core        = H_bytes("PVUGC/CTX_CORE" || vk_hash || H_bytes(x) || tapleaf_hash || tapleaf_version || txid_template || path_tag)
arming_pkg_hash = H_bytes("PVUGC/ARM"      || {D1} || {D2} || header_meta)
presig_pkg_hash = H_bytes("PVUGC/PRESIG"   || m || T || R || signer_set || musig_coeffs)
ctx_hash        = H_bytes("PVUGC/CTX"      || ctx_core || arming_pkg_hash || presig_pkg_hash)
```

- `path_tag ∈ {compute, abort}` (or others if you add more paths).
- Include exact output ordering, CPFP hook position, and any deployment/epoch identifiers you need.
- Bind PoK/PoCE and `AdaptorVerify(m,T,R,s′)` to `ctx_hash`. Do not include those transcripts inside the package hashes above.

**Message (m).** $m$ is the 32‑byte BIP‑341 script‑path `sighash` for the pre‑templated transaction, computed with `SIGHASH_ALL`, `annex_present=0`, and binding the exact tapleaf hash and leaf version for this path.

**`txid_template`.** A fully specified transaction template (inputs/outputs/locktime/sequence/fees) used only to define $m$. It does not include any signatures or annex. Any change to `txid_template` changes $m$ and hence `presig_pkg_hash` and `ctx_hash`. `txid_template` MUST NOT reference unknown txids (no forward/self‑references). The CPFP child is outside `ctx_hash`; only the CPFP output (scriptPubKey, index, value) is fixed in `ctx_core`.

**`header_meta`.** A deterministic serialization hash of the public KEM header: share index $i$, $\{D_{1,j}\}$, $\{D_{2,k}\}$, $T_i$, $h_i$, $\texttt{ct}_i$, $\tau_i$, $\rho\_\text{link}$, `DEM_PROFILE`, and `GS_instance_digest`. Use strict encodings and reject duplicates.

**Hash functions (normative).**

Let `H_bytes = SHA-256` for byte-level context hashes (`ctx_*`) and tags like `H(x)`. Let `H_p2 = Poseidon2` for KDF/DEM/tag and in-circuit PoCE. Define `H_tag = Poseidon2` domain-tagged as "PVUGC/RHO_LINK"; set `ρ_link = H_tag(ser(ρ_i))`. All hashes MUST be domain‑separated with ASCII tags.

**Context/domain tags (normative).**

* `"PVUGC/CTX_CORE"`, `"PVUGC/ARM"`, `"PVUGC/PRESIG"`, `"PVUGC/CTX"` (inputs to H_bytes)
* `"PVUGC/KEM/v1"` (profile tag)
* `"PVUGC/AEAD-NONCE"` (reserved; not used in Poseidon2 profile)
* `"BIP0340/challenge"` (BIP‑340 tagged hash)

**MUST (Span independence in $\mathbb{G}_T$).** The target $G_{\text{G16}}(\mathsf{vk},x) \in \mathbb{G}_T$ MUST be derived deterministically from (CRS,$\mathsf{vk}$,$x$) alone and domain‑separated from the derivations of $\{U_j(x)\}$ and $\{V_k(x)\}$. Implementations MUST freeze (CRS,$\mathsf{vk}$,$x$) before arming and pin their digests in `GS_instance_digest`. Arming participants MUST have no influence over these derivations. Intuitively, $G_{\text{G16}}(\mathsf{vk},x)$ MUST NOT be algebraically correlated with the pairing span $\langle e(V_k(x), U_j(x))\rangle$ beyond the GS verification equation.

**Production Profile (MUST/SHOULD).**

* **MUST:** BLS12‑381 as the pairing curve family.
* **MUST:** DEM_PROFILE = "PVUGC/DEM-P2-v1" (SNARK‑friendly). KDF(M) = Poseidon2( ser_GT(M) || H_bytes(ctx_hash) || GS_instance_digest ); DEM keystream = Poseidon2(K_i, AD_core); ct = pt ⊕ keystream; τ = Poseidon2(K_i, AD_core, ct). Mixing profiles within a `ctx_hash` is forbidden.
* **MUST:** Multi‑CRS AND‑ing: use at least two independently generated binding GS‑CRS transcripts; publish and pin both digests in `GS_instance_digest` and `header_meta`; derive $(U,V)$ separately per CRS; publish both mask sets; verify both PPEs (logical AND). For AND‑of‑2, define $M_i^{\text{AND}} := \mathrm{ser}_{\mathbb{G}_T}(M_i^{(1)}) || \mathrm{ser}_{\mathbb{G}_T}(M_i^{(2)})$ and derive $K_i = \text{Poseidon2}( M_i^{\text{AND}} || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest} )$.
* **SHOULD:** Enable Timeout/Abort with $\Delta$ chosen to cover proving+network latency.

---

### 4) Keys & one‑time pre‑sign per path (MuSig2)

For each path that will be WE‑gated (at minimum **ComputeSpend**):

* Run MuSig2 (BIP‑327) once to produce a pre‑signature $s'$ with **unique** session nonce $R$ and **unique** adaptor point $T$.
* **Compartmentalization (MUST):** one adaptor ⇒ one unique $T$ and one unique $R$. Never reuse across paths/epochs or templates.
* Publish an `AdaptorVerify(m,T,R,s′)` transcript **bound to** `ctx_hash`, the signer set, their MuSig coefficients, and the exact `txid_template`.

---

### 5) Distributed setting of (T = $\alpha$·G) (k‑of‑k, public PoK + PoCE)

Each of the $k$ arming participants picks an **adaptor share** $s_i \in \mathbb{Z}_n$, publishes $T_i=s_i G$ with a **Schnorr PoK** of knowledge of $s_i$, and a **PoCE** tying their WE ciphertext to the same randomness used for their mask vector (see §6 and §8). Set:

$$
T = \sum_{i=1}^k T_i \quad\text{and}\quad \alpha = \sum_{i=1}^k s_i
$$

**Arm‑time rule:** verify **all** PoK and PoCE before any pre‑signing; abort on any failure. Never reuse any $s_i$ (or $\alpha$) across contexts.

It publicly proves that the published masks $\{D_{1,j}\}$ were made with the same $\rho_i$, and that $T_i$ matches $s_i$. The ciphertext $\texttt{ct}_i$ is key‑committed at decapsulation time via PoCE‑B. Without PoCE an armer could publish structurally valid but semantically wrong artifacts, undermining decrypt‑on‑proof soundness.

---

### 6) WE via Product‑Key KEM (GS‑attested Groth16‑verify)

**The Challenge:** Standard Groth16 verification has proof elements on both sides of pairings:
$$
e(\pi_A,\pi_B) \cdot e(\pi_C,[\delta]_2) = e([\alpha]_1,[\beta]_2) \cdot e\left(\sum_i x_i [l_i]_1,[\gamma]_2\right) \tag{G16}
$$
where $(\pi_A, \pi_C) \in \mathbb{G}_1$ and $\pi_B \in \mathbb{G}_2$. Direct witness encryption would require pairing inversion (computationally infeasible).

**Solution: GS Attestation Layer.** We prove (with Groth–Sahai) that (G16) holds for committed $(\pi_A,\pi_B,\pi_C)$. The GS proof system transforms this into:
- **Commitments**: $C^1_j(\mathsf{Att}) \in \mathbb{G}_1$ (for $\pi_A, \pi_C$) and $C^2_k(\mathsf{Att}) \in \mathbb{G}_2$ (for $\pi_B$)
- **CRS bases**: $U_j(\text{CRS},x) \in \mathbb{G}_2$ and $V_k(\text{CRS},x) \in \mathbb{G}_1$ that depend only on the GS CRS and public input $x$

The GS verifier reduces to a **two-sided product‑of‑pairings equation**:
$$
\underbrace{\prod_{j=1}^{m_1} e(C^1_j, U_j(x))}_{\text{G1-commit × G2-base}} \cdot \underbrace{\prod_{k=1}^{m_2} e(V_k(x), C^2_k)}_{\text{G1-base × G2-commit}} = G_{\text{G16}}(\mathsf{vk},x) \in \mathbb{G}_T \tag{GS-PPE}
$$
where $G_{\text{G16}}(\mathsf{vk},x) = e([\alpha]_1, [\beta]_2) \cdot e(\sum_i x_i [l_i]_1, [\gamma]_2)$ is the right-hand side of (G16).

**Critical property**: The $U_j, V_k$ are **instance‑only** (depend on CRS and $x$ but not on the proof). For *every* valid attestation and fixed $(\mathsf{vk},x)$, the product equals the **same** $G_{\text{G16}}$.

**Target bound (non-normative)**: In common encodings of Groth16-verify, $m_1 + m_2$ is small. The exact count depends on the GS layout.

**MUST (GS size bounds):** Reject GS attestations requiring > 96 pairings 
total (m₁ + m₂ ≤ 96). Typical Groth16→GS encodings require 20-40 pairings.

**Implementation note:** For BLS12-381, 96 pairings is ~50-100ms on modern hardware - 
acceptable for one-time decapsulation.

**Independence (MUST).** The CRS‑ and input‑dependent bases $\{U_j(x), V_k(x)\}$ and the target $G_{\text{G16}}(\mathsf{vk},x)$ are fixed by (CRS, $\mathsf{vk}$, $x$) before any armer chooses randomness; armers cannot choose or influence these bases. (Single‑sided layouts are supported; publish only the corresponding mask set(s).)
**Implementation MUST NOT** allow armers to influence CRS selection, $\mathsf{vk}$, or $x$ once arming begins; these are fixed before any $\rho_i$ is chosen.

**Encapsulation (arm‑time, per share $i$).** Choose $\rho_i \in \mathbb{Z}_r^*$ (where $r = \#\mathbb{G}_1 = \#\mathbb{G}_2 = \#\mathbb{G}_T$, non-zero). Compute:
$$
D_{1,j}=U_j^{\rho_i}\in \mathbb{G}_2, \quad D_{2,k}=V_k^{\rho_i}\in \mathbb{G}_1, \quad M_i=G_{\text{G16}}^{\rho_i}\in \mathbb{G}_T \text{ (do NOT publish)}
$$
$$
K_i=\mathrm{Poseidon2}(\mathrm{ser}_{\mathbb{G}_T}(M_i) || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest})
$$
Encrypt $\texttt{enc}_i=(s_i \| h_i)$ with a **key‑committing DEM** (see §7) to get $(\texttt{ct}_i,\tau_i)$.

**Publish only:** $\{D_{1,j}\}$, $\{D_{2,k}\}$, $\texttt{ct}_i$, $\tau_i$, $T_i$, $h_i$, plus PoK and **PoCE-A** (algebraic proof).
**Keep secret:** $M_i$ (derivable only with valid attestation).

**Degenerate & subgroup guards:** Abort arming if $G_{\text{G16}}(\mathsf{vk}, x) = 1$ (identity in $\mathbb{G}_T$) or if it lies in any proper subgroup of $\mathbb{G}_T$. While negligible for honest setups, these checks prevent trivial keys. PoCE MUST also assert $G_{\text{G16}} \neq 1$ via a public input bit tied to `GS_instance_digest`.
**Serialization (MUST):** Use a canonical, subgroup‑checked encoding $\mathrm{ser}_{\mathbb{G}_T}(\cdot)$ for KDF input; reject non‑canonical encodings.
**Group model.** $\mathbb{G}_1,\mathbb{G}_2,\mathbb{G}_T$ are prime‑order groups of order $r$. Implementations MUST perform subgroup checks using library‑provided tests (and cofactor clearing where applicable) and reject non‑canonical encodings.

**Decapsulation (anyone with a valid attestation).**
Verify GS attestation, then compute
$$
\tilde{M}_i = \left(\prod_{j=1}^{m_1} e(C^1_j,D_{1,j})\right) \cdot \left(\prod_{k=1}^{m_2} e(D_{2,k},C^2_k)\right) = G_{\text{G16}}^{\rho_i} = M_i
$$
derive $K_i'=\mathrm{Poseidon2}(\mathrm{ser}_{\mathbb{G}_T}(\tilde{M}_i) || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest})$, decrypt $\texttt{ct}_i\to(s_i \| h_i)$, check $T_i=s_iG$, $H_\text{bytes}(s_i \| T_i \| i)=h_i$, and verify PoCE-B. Sum $\alpha=\sum_i s_i$ and finish the adaptor $s=s'+\alpha \bmod n$.

**Proof‑agnostic key (the critical insight).** For any two valid GS attestations $\mathsf{Att}_1, \mathsf{Att}_2$ for the same $(\mathsf{vk},x)$, the two-sided product equals the same fixed value:
$$
\left(\prod_{j} e(C^1_j(\mathsf{Att}_1), U_j)\right) \cdot \left(\prod_{k} e(V_k, C^2_k(\mathsf{Att}_1))\right) = G_{\text{G16}}
$$
Therefore, for any valid attestation:
$$
\tilde{M}_i = \left(\prod_j e(C^1_j, D_{1,j})\right) \cdot \left(\prod_k e(D_{2,k}, C^2_k)\right) = G_{\text{G16}}^{\rho_i}
$$

This means *every* valid attestation yields the **same** KEM key $K_i$, regardless of which proof was used.

---

### 7) Correctness & Determinism (Key Lemmas)

**Lemma 1 (GS product determinism).** Let CRS be **binding** under SXDH/DLIN. For fixed $(\mathsf{vk},x)$, any accepting GS attestation $\mathsf{Att}$ for the statement "Groth16 verifies $(\mathsf{vk},x)$" yields
$$
\left(\prod_{j=1}^{m_1} e(C^1_j(\mathsf{Att}),U_j(\text{CRS},x))\right) \cdot \left(\prod_{k=1}^{m_2} e(V_k(\text{CRS},x),C^2_k(\mathsf{Att}))\right) = G_{\text{G16}}(\mathsf{vk},x) \in \mathbb{G}_T
$$
where $U_j, V_k$ are **instance-only** bases and $G_{\text{G16}}(\mathsf{vk},x) = e([\alpha]_1,[\beta]_2) \cdot e(\sum_i x_i[l_i]_1,[\gamma]_2)$. The value is **independent of prover re-randomization** because commitments are binding and randomizers cancel in the verifier's bilinear equations.

**Lemma 2 (KEM correctness).** For share $i$ with randomness $\rho_i$, the published masks $D_{1,j} = U_j^{\rho_i}$, $D_{2,k} = V_k^{\rho_i}$ and any accepting attestation give
$$
\tilde{M}_i = \left(\prod_j e(C^1_j,D_{1,j})\right) \cdot \left(\prod_k e(D_{2,k},C^2_k)\right) = G_{\text{G16}}(\mathsf{vk},x)^{\rho_i} = M_i
$$
Hence $K_i' = \mathrm{Poseidon2}(\mathrm{ser}_{\mathbb{G}_T}(\tilde{M}_i) || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest}) = K_i$, and the DEM decrypts $(s_i \| h_i)$.

**Lemma 3 (No‑Proof‑Spend).** Under the following assumption, given only $\{D_{1,j} = U_j^{\rho_i}\}$ (where $U_j \in \mathbb{G}_2$) and $\{D_{2,k} = V_k^{\rho_i}\}$ (where $V_k \in \mathbb{G}_1$) and public parameters, computing $M_i = G_{\text{G16}}^{\rho_i} \in \mathbb{G}_T$ without an accepting attestation is infeasible. Thus $\alpha = \sum_i s_i$ remains hidden and the adaptor cannot be finalized.

> Assumption (GT‑XPDH: External Power in $\mathbb{G}_T$). Let $e:\mathbb{G}_1\times\mathbb{G}_2\to\mathbb{G}_T$ be a non‑degenerate bilinear map over prime‑order groups of order $r$. Sample random base sets $\{U_j\}\subset\mathbb{G}_2$, $\{V_k\}\subset\mathbb{G}_1$, an unknown exponent $r^*\leftarrow\mathbb{Z}_r^*$, and an independent target $T\leftarrow\mathbb{G}_T$. Given $(\{U_j\},\{V_k\},\{U_j^{r^*}\},\{V_k^{r^*}\},T)$, it is hard for any PPT adversary to compute $T^{r^*}$. In our instantiation, $T=G_{\text{G16}}(\mathsf{vk},x)$ is fixed by (CRS,$\mathsf{vk}$,$x$) and independent of $\{U_j,V_k\}$; GS soundness prevents producing commitments that smuggle a related target.

Generic‑group note. In the bilinear generic/algebraic group model, an adversary with $q$ group/pairing operations has advantage at most $\tilde{O}(q^2/r)$ to compute $T^{r^*}$ when $T$ is independent, since available handles are confined to pairing images of $\{U_j^{r^*}\},\{V_k^{r^*}\}$ and do not link to $T$. Multi‑instance ($q_\text{inst}$ contexts) is captured by the standard union bound (aka $q$‑GT‑XPDH).

*Proof sketches:* (i) follows from GS soundness + binding commitments; (ii) is algebraic as written; (iii) from KEM hardness and Schnorr UF-CMA.

**CRS Requirement:** GS must use a **binding** CRS (SXDH/DLIN). If not binding (e.g., WI/hiding), Lemma 1 may fail. Runtime MUST reject non-binding CRS via a tag embedded in `GS_instance_digest`. A single‑sided PPE layout (only $C^1_j\in\mathbb{G}_1$ with $U_j\in\mathbb{G}_2$) is also possible; the KEM generalizes by publishing the corresponding mask set(s). To mitigate trapdoors, the CRS SHOULD be generated via a publicly auditable ceremony; deployments MAY require two or more independently generated CRS transcripts and pin their digests.

**Knowledge‑soundness (SHOULD).** The GS attestation SHOULD be knowledge‑sound for the relation “there exists a Groth16 proof $\pi$ such that $\textsf{Verify}_{\text{G16}}(\mathsf{vk},x,\pi)=1$.” That is, there exists an extractor that, given any accepting GS attestation, outputs a valid Groth16 proof $\pi$ for $(\mathsf{vk},x)$. Plain soundness suffices for correctness/no‑proof‑spend; knowledge‑soundness is a stronger deployment profile.

---

### 8) PoCE and DEM details (normative)

**PoCE (Two-stage verification):**

**PoCE-A (Arm-time verifiable encryption & mask-link, SNARK-friendly).** A NIZK proving, for share $i$:
* Knowledge of $(\rho_i,s_i,h_i)$ s.t. (i) $D_{1,j}=U_j^{\rho_i}$ for all $j$, $D_{2,k}=V_k^{\rho_i}$ for all $k$; (ii) $T_i=s_iG$; (iii) $\rho\_\text{link}=H_\text{tag}(\rho_i)$.
* Key derivation (in-circuit): $K_i = \mathrm{Poseidon2}(\mathrm{ser}_{\mathbb{G}_T}(G_{\text{G16}}^{\rho_i}) || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest})$.
* DEM correctness (SNARK-friendly): $\texttt{ct}_i = (s_i\|h_i) \oplus \mathrm{Poseidon2}(K_i, \text{AD\_core})$ and $\tau_i = \mathrm{Poseidon2}(K_i, \text{AD\_core}, \texttt{ct}_i)$.
* $\rho_i\neq 0$ (via auxiliary $\rho_i\cdot u_i=1$)

**Public arming checks (performed by coordinator/auditors):**
* Compute $T = \sum T_i$ and reject if $T = \mathcal{O}$ (point at infinity)
* Enforce unique `share_index`; reject duplicates and maintain a replay set keyed by $(\texttt{ctx\_core}, \texttt{presig\_pkg\_hash}, \texttt{header\_meta})$. If the same `header_meta` appears under a different `presig_pkg_hash` for the same `ctx_core`, reject as a replay/misbind.
* Verify $G_{\text{G16}}(\mathsf{vk},x) \neq 1$ (computable from $(\mathsf{vk},x)$ without proof)

**PoCE-B (Decap-time key-commitment check - decapper-local).** After deriving $\tilde{M}_i$ from valid attestation (key-commits the ciphertext to the derived key):
* Recompute $K_i' = \mathrm{Poseidon2}(\mathrm{ser}_{\mathbb{G}_T}(\tilde{M}_i) || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest})$
* (P2) No AEAD nonce is used by the DEM; omit nonce.
* Decrypt $\texttt{ct}_i$ with $K_i'$ and verify $T_i = s_iG$ and $H(s_i \| T_i \| i) = h_i$
* Verify key-commit tag: $\tau_i = \mathrm{Poseidon2}(K_i', \text{AD\_core}, \texttt{ct}_i)$
* **Note:** This is a decapper-local check (not publicly verifiable unless plaintext revealed)
* **Shape check (MUST):** Before decryption, verify the lengths and ordering of $\{D_{1,j}\}$ and $\{D_{2,k}\}$ match `header_meta` exactly; mismatch ⇒ reject.

Ceremony rule (MUST): do not pre-sign unless all PoCE-A proofs and PoK verify for all shares.
* **Publication (SHOULD):** Implementations SHOULD publish a minimal PoCE‑B verification transcript (hashes of inputs/outputs) alongside the broadcasted spend to aid auditing, without revealing plaintext values.

**AD_core** binds: `PVUGC/WE/v1 || vk_hash || H_bytes(x) || ctx_hash || tapleaf_hash || tapleaf_version || txid_template || path_tag || share_index || T_i || T || {D_{1,j}} || {D_{2,k}} || GS_instance_digest`.

**Decapper requirement:** Upon decapsulation, reject if the tuple $(K_i, \text{AD\_core})$ repeats for the same published header/`ctx_core` (indicates encapsulation reuse).

**DEM (key‑committing):**

* **Hash‑only DEM (P2)**: $\texttt{ct}_i=(s_i \| h_i)\oplus \mathrm{Poseidon2}(K_i,\text{AD\_core})$, $\tau_i=\mathrm{Poseidon2}(K_i,\text{AD\_core},\texttt{ct}_i)$.
**Mandatory hygiene:** subgroup checks ($\mathbb{G}_1$, $\mathbb{G}_2$, $\mathbb{G}_T$), cofactor clearing, constant‑time pairings, constant‑time DEM decryption, strict encodings (reject non‑canonical), strict BIP‑340 canonical encodings for $R$ and $s$ (reject non‑canonical signatures), rejection sampling for derived scalars, fresh $\rho_i$, fresh $T$, fresh MuSig2 $R$.
**Why PoCE is needed:** Without PoCE-A, a malicious armer could publish masks/ciphertexts not derived from the same $\rho_i$, breaking decrypt-on-proof soundness.

---

### 9) Activation patterns (optimistic options, orthogonal to the core)

* **N‑of‑N arming.** All armers must publish valid $(T_i,\text{PoK},\text{PoCE},\texttt{ct}_i,\{D_{1,j}\})$ before pre‑signing. No one learns $\alpha$.
* **1‑of‑N trigger.** After arming, **any** prover who can produce a valid Groth16+GS attestation can finish the spend by decapsulating $\alpha$ (permissionless).
* **Timeout/Abort path.** `CSV=Δ` path sending funds to a neutral sink or alternate policy. **RECOMMENDED** to mitigate griefing if malformed arming data passes PoK but breaks decryption. This is a liveness/UX mitigation.
* **Challenge path (optional).** If your application benefits from a *negative* predicate (e.g., "there exists a valid proof that $\neg R_{\mathcal{L}}$"), you may WE‑gate a separate script leaf under a different $(\mathsf{vk}',x')$. Not required by PVUGC‑G itself.
**Takeaway:** The **only requirement** to understand the main innovation is the WE‑gated **ComputeSpend** path. Timeout/Abort/Challenge are **patterns**, not prerequisites.

---

### 10) Adaptor verification (normative)

Define the adaptor pre-signature check and binding:

$$
\text{AdaptorVerify}(m,T,R,s'): \quad s'G + T \stackrel{?}{=} R + cP
$$

Where:
- $c = \text{tagged\_hash}(\text{"BIP0340/challenge"}, R_x || P_x || m)$
- $R$ is normalized to even-$y$
- $R \neq \mathcal{O}$ (reject point at infinity)

Bind `AdaptorVerify` to `ctx_hash`, including the signer set and MuSig2 coefficients via `presig_pkg_hash` (see §3). One adaptor implies one unique $T$ and one unique $R$.

Use x‑only encodings for $R_x$ and $P_x$; $R$ MUST be normalized to even‑$y$ at pre‑sign time per BIP‑340. Witnesses with `annex_present=1` MUST be rejected.
**Key aggregation binding.** `presig_pkg_hash` MUST include the key list $L=(X_1,\dots,X_k)$ and the per‑key coefficients $a_i=\textsf{KeyAggCoeff}(L,X_i)$ as actually used by MuSig2 for $P=\sum a_i X_i$.

---

### 11) Security Analysis

**Security Games (Formal Properties):**

| **Game** | **Definition** | **Holds By** |
|----------|---------------|--------------|
| **Completeness** | Valid proof $\pi$ for $(\mathsf{vk},x)$ ⇒ spend finalizes correctly | GS soundness + KEM correctness (Lemma 2) |
| **No-Proof-Spend** | No valid attestation ⇒ negligible probability to finalize | GT‑XPDH + Schnorr UF-CMA (Lemma 3) |
| **Context-Binding** | Valid attestation for $(\mathsf{vk},x)$ cannot finalize different template/leaf/path | AD binding in `ctx_hash` |
| **Witness Privacy** | Decapsulation reveals only $\alpha = \sum s_i$, not witness $w$ | SNARK zero-knowledge |

**Security Sketch:**

* **No proof ⇒ no spend.** Without a valid attestation, an attacker knows $D_{1,j} = U_j^{\rho_i}$ (where $U_j \in \mathbb{G}_2$) and $D_{2,k} = V_k^{\rho_i}$ (where $V_k \in \mathbb{G}_1$) but cannot compute $M_i = G_{\text{G16}}^{\rho_i} \in \mathbb{G}_T$ without either:
  - A valid GS attestation (which requires a valid Groth16 proof)
  - Breaking GT‑XPDH: given $\{U_j^{r}\},\{V_k^{r}\}$ and independent $T\in\mathbb{G}_T$, compute $T^r$.
  Since $M_i$ is required to derive $K_i$ and decrypt $\alpha$, the adaptor cannot be finished.
**Independence.** $G_{\text{G16}}(\mathsf{vk},x)$ is fixed by (CRS,$\mathsf{vk}$,$x$) and independent of the published bases $\{U_j,V_k\}$ and their $\rho_i$‑powers. GS soundness prevents crafting commitments that correlate $G_{\text{G16}}$ with the published masks.
* **Proof ⇒ spend (right context).** GS soundness + binding CRS ⇒ any verifying attestation enforces the *same* product $G_{\text{G16}}$; AD/`ctx_hash` bind $(\mathsf{vk},x)$, tapleaf(+version), tx template, path tag, $T_i$, $T$, and the mask vector.
* **Arming integrity.** Schnorr PoK ties $T_i$ to $s_i$; **PoCE‑A** proves one $\rho_i$ for both mask vectors and that $T_i$ corresponds to $s_i$; **PoCE‑B** key‑commits the ciphertext to the derived key and AD.
* **Compartmentalization.** Unique $T$ and MuSig2 $R$ per adaptor eliminate cross‑protocol nonce reuse and Wagner‑style collisions.
* **On‑chain minimalism.** Bitcoin validates a standard Taproot Schnorr signature; any break implies forging Schnorr or breaking pairings/GS/Groth16/DEM assumptions.

**Post‑spend learnability.** Given on‑chain $s$ and published $s'$, $\alpha=s-s' \pmod n$ becomes public (by design). This does not harm prior confidentiality.

---

### 12) Engineering checklist

* **Script:** script‑path only; NUMS internal key; leaves for ComputeSpend (and optional Timeout/Abort).
* **SIGHASH:** `SIGHASH_ALL`; annex absent (BIP‑341 `annex_present = 0`); bind tapleaf hash **and version**; pin exact output order and CPFP anchor.
* **MuSig2:** BIP‑327 two‑point nonces; normalize $R$ to even y; erase secnonces; publish `AdaptorVerify(m,T,R,s′)` bound to `ctx_hash`.
* **Adaptor compartmentalization:** one adaptor ⇒ one $T$, one $R$; fresh per path/template/epoch.
* **KEM/DEM:** GS binding CRS; constant‑time pairings; subgroup checks; $\rho_i\neq 0$; nonce‑free, key‑committing DEM (Poseidon2); reject non‑small‑order encodings.
* **k‑of‑k arming:** verify all PoK + PoCE + ciphertexts before pre‑sign; abort on any mismatch.
* **Artifacts to publish:** $\{D_{1,j}\}$, $\{D_{2,k}\}$, $(\texttt{ct}_i,\tau_i)$, $(T_i,h_i)$, PoK, PoCE-A, `AdaptorVerify`, and the hashes composing `ctx_hash`.
* **Side-channel protection:** Pairings, scalars, and DEM MUST be constant-time; avoid cache-tunable table leakage across different `ctx_hash` values.

---

### 13) Minimal example

**Language**: $R_{\mathcal{L}}$ = "SHA‑256(preimage) = $h$" expressed via a tiny Groth16 circuit.

* Fix $\mathsf{vk}$ for that circuit; set $x := h$.
* Build `ctx_hash` from $(\mathsf{vk\_hash}, H(x))$, your exact tapleaf(+version), and `txid_template`.
* Arm k‑of‑k: publish $\{D_{1,j}\}$, $\{D_{2,k}\}$, $(\texttt{ct}_i,\tau_i)$, $(T_i,h_i)$, PoK, PoCE-A; verify; pre‑sign $(m,T,R)\Rightarrow s'$.
* A holder of a valid $\pi$ + GS attestation computes $\tilde{M}_i$, derives $K_i$, decrypts each $\texttt{ct}_i\to s_i$, sums $\alpha$, and outputs the final signature $s=s'+\alpha \pmod n$. Broadcast the ComputeSpend transaction.

**Curve note.** For concreteness, implementers may target an asymmetric Type‑3 pairing (e.g., a BLS12 family). The spec is agnostic; choose libraries with constant‑time pairings and explicit subgroup checks.

---

### 14) Limitations & scope

* **Trusted setup for Groth16** ($\mathsf{vk}$ pinned to a public ceremony transcript).
* **Fixed circuit**: Changing $\mathsf{vk}$ or $x$ changes `ctx_hash` and requires re‑arming.
* **Proving cost**: Proof generation time dominates; WE/KEM work is milliseconds.
* **Security assumptions**: GS soundness under SXDH/DLIN; Groth16 soundness; **GT‑XPDH (External Power in $\mathbb{G}_T$) as in §7, Lemma 3**; Schnorr unforgeability; DEM key‑commitment. Deployments MAY prefer GS knowledge‑soundness for stronger auditability.

---

### 15) Related work

* Witness Encryption: GGSW13; BL20; algebraic‑language WE (CVW18); KZG WE (BCGJM23).
* Adaptor signatures / Scriptless scripts: Poe18; DHLST19; MuSig2 (BIP‑327, NRS21).
* Computation on Bitcoin: BitVM (Linus23) discusses general compute; our construction removes on‑chain predicates by gating signature completion with WE.

---

### 16) Minimal equations

**GS‑PPE & KEM:**

$$
\left(\prod_{j} e(C^1_j, U_j(x))\right) \cdot \left(\prod_{k} e(V_k(x), C^2_k)\right) = G_{\text{G16}}(\mathsf{vk},x)
$$

**Encap (share $i$):**
$$
D_{1,j} = U_j^{\rho_i} \in \mathbb{G}_2, \quad D_{2,k} = V_k^{\rho_i} \in \mathbb{G}_1, \quad M_i = G_{\text{G16}}^{\rho_i} \in \mathbb{G}_T
$$
$$
K_i = \text{Poseidon2}(\text{ser}_{\mathbb{G}_T}(M_i) || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest})
$$

**Decap:**
$$
\tilde{M}_i = \left(\prod_{j} e(C^1_j, D_{1,j})\right) \cdot \left(\prod_{k} e(D_{2,k}, C^2_k)\right) = G_{\text{G16}}^{\rho_i} = M_i
$$
$$
K_i' = \text{Poseidon2}(\text{ser}_{\mathbb{G}_T}(\tilde{M}_i) || H_\text{bytes}(\texttt{ctx\_hash}) || \texttt{GS\_instance\_digest})
$$

**Adaptor finalize:**
$$
\alpha = \sum_i s_i, \quad s = s' + \alpha \pmod{n}
$$

We turn validity into a key, and on Bitcoin that key is exactly the missing scalar that completes a Taproot signature.