package evoting;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Demonstrates the full mix net:
 * - Initializes the mix net (generates safe prime, group parameters, and key pair).
 * - Encrypts a list of messages using ElGamal-style encryption.
 * - Performs a verifiable shuffle (with re-encryption).
 * - Displays the shuffle proof and verifies it.
 */
public class TestMixNet {
    public static void main(String[] args) {
        System.out.println("Starting mix net demo...\n");

        // Initialize the mix net.
        System.out.println("Initializing mix net (generating safe prime and parameters)...");
        MixNet mixnet = new MixNet();
        System.out.println("Mix net initialized successfully!\n");

        // Create test messages.
        List<String> messages = Arrays.asList(
                "Vote for Candidate A",
                "Vote for Candidate B",
                "Vote for Candidate A",
                "Vote for Candidate C"
        );

        System.out.println("Original messages:");
        for (int i = 0; i < messages.size(); i++) {
            System.out.println((i + 1) + ". " + messages.get(i));
        }

        // Encrypt messages using the full ElGamal-style encryption.
        BigInteger p = mixnet.getP();
        List<EncryptedMessage> encryptedMessages = messages.stream()
                .map(msg -> {
                    BigInteger m = new BigInteger(1, msg.getBytes()).mod(p);
                    return mixnet.encrypt(m);
                })
                .toList();

        System.out.println("\nEncrypted messages:");
        for (int i = 0; i < encryptedMessages.size(); i++) {
            EncryptedMessage em = encryptedMessages.get(i);
            System.out.println("Message " + (i + 1) + ":");
            System.out.println("  c1: " + em.c1());
            System.out.println("  c2: " + em.c2());
        }

        // Perform the verifiable shuffle (with re-encryption).
        System.out.println("\nPerforming verifiable shuffle...");
        VerifiableShuffle shuffle = mixnet.shuffle(encryptedMessages);
        System.out.println("Shuffle completed!");
        System.out.println("Number of shuffled messages: " + shuffle.shuffledMessages().size());

        System.out.println("\nShuffled and re-encrypted messages:");
        for (int i = 0; i < shuffle.shuffledMessages().size(); i++) {
            EncryptedMessage em = shuffle.shuffledMessages().get(i);
            System.out.println("Message " + (i + 1) + ":");
            System.out.println("  c1: " + em.c1());
            System.out.println("  c2: " + em.c2());
        }

        // Display aggregated shuffle proof details.
        System.out.println("\nProof details:");
        ShuffleProof proof = shuffle.proof();
        System.out.println("A1:    " + proof.A1());
        System.out.println("B1:    " + proof.B1());
        System.out.println("diff1: " + proof.diff1());
        System.out.println("T1:    " + proof.T1());
        System.out.println("c1:    " + proof.c1());
        System.out.println("s1:    " + proof.s1());
        System.out.println("A2:    " + proof.A2());
        System.out.println("B2:    " + proof.B2());
        System.out.println("diff2: " + proof.diff2());
        System.out.println("T2:    " + proof.T2());
        System.out.println("c2:    " + proof.c2());
        System.out.println("s2:    " + proof.s2());

        // Verify the shuffle proof.
        System.out.println("\nVerifying shuffle...");
        boolean isValid = mixnet.verify(encryptedMessages, shuffle.shuffledMessages(), proof);
        System.out.println("Shuffle verification result: " + (isValid ? "VALID" : "INVALID"));
    }
}
