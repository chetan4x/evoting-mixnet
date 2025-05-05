package evoting;

import java.math.BigInteger;

/**
 * Represents an encrypted message in the ElGamal crypto system
 */
public record EncryptedMessage(BigInteger c1, BigInteger c2) {
    public EncryptedMessage {
        if (c1 == null || c2 == null) {
            throw new IllegalArgumentException("Ciphertext components must be non-null");
        }
    }
}