package evoting;

import java.util.List;

/**
 * Represents a verifiable shuffle output including the shuffled messages,
 * proof of correct shuffling, and the permutation used
 */
public record VerifiableShuffle(
        List<EncryptedMessage> shuffledMessages,
        ShuffleProof proof,
        int[] permutation
) {
    public VerifiableShuffle {
        if (shuffledMessages == null || proof == null || permutation == null) {
            throw new IllegalArgumentException("All parameters must be non-null");
        }
        if (shuffledMessages.size() != permutation.length) {
            throw new IllegalArgumentException("Permutation length must match number of messages");
        }
    }
}
