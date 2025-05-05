package evoting;

import java.math.BigInteger;

/**
 * Aggregated Chaum–Pedersen Shuffle Proof.
 * This proof demonstrates that the output ciphertexts are a valid re-encryption
 * and permutation of the input ciphertexts.
 * Fields:
 *   A1: Product of input ciphertexts' c1 components (∏ input.c1).
 *   B1: Product of output ciphertexts' c1 components (∏ output.c1).
 *   diff1: Ratio B1 × A1⁻¹ mod p, which should equal g^(Σr_i).
 *   T1:   Ephemeral value T1 = g^(w1) mod p.
 *   c1:   Challenge for the c1 component.
 *   s1:   Response for the c1 component, s1 = w1 + c1·(Σr_i) mod q.
 *   A2: Product of input ciphertexts' c2 components (∏ input.c2).
 *   B2: Product of output ciphertexts' c2 components (∏ output.c2).
 *   diff2: Ratio B2 × A2⁻¹ mod p, which should equal pk^(Σr_i).
 *   T2:   Ephemeral value T2 = pk^(w2) mod p.
 *   c2:   Challenge for the c2 component.
 *   s2:   Response for the c2 component, s2 = w2 + c2·(Σr_i) mod q.
 */
public record ShuffleProof(
        BigInteger A1,
        BigInteger B1,
        BigInteger diff1,
        BigInteger T1,
        BigInteger c1,
        BigInteger s1,
        BigInteger A2,
        BigInteger B2,
        BigInteger diff2,
        BigInteger T2,
        BigInteger c2,
        BigInteger s2
) {
    public ShuffleProof {
        if (A1 == null || B1 == null || diff1 == null || T1 == null || c1 == null || s1 == null ||
                A2 == null || B2 == null || diff2 == null || T2 == null || c2 == null || s2 == null) {
            throw new IllegalArgumentException("All proof components must be non-null");
        }
    }
}
