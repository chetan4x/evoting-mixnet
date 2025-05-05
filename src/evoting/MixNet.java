package evoting;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

/**
 * This class demonstrates a mix net that:
 *  - Generates a safe prime and sets up group parameters.
 *  - Creates an ElGamal-style key pair.
 *  - Performs ElGamal encryption with an ephemeral exponent.
 *  - Re-encrypts and shuffles ciphertexts with an aggregated Chaum–Pedersen proof.
 */
public class MixNet {
    // A "safe prime" p = 2q + 1, meaning both p and q are prime.
    // We perform group arithmetic in Z_p^*.
    private final BigInteger p;      // Prime modulus.
    private final BigInteger q;      // Order of the subgroup (p = 2q + 1).
    private final BigInteger g;      // Generator (of a subgroup of Z_p^*).
    private final BigInteger privateKey;
    private final BigInteger publicKey;  // publicKey = g^privateKey mod p.
    private final SecureRandom random;

    /**
     * Constructor: Generates a safe prime, computes the group parameters,
     * and generates an ElGamal key pair.
     */
    public MixNet() {
        this.random = new SecureRandom();

        System.out.println("Generating safe prime...");
        // For demonstration, a 128-bit safe prime is generated.
        this.p = generateSafePrime(128);
        System.out.println("Safe prime generated: " + p);

        // The subgroup order q = (p - 1)/2.
        this.q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        System.out.println("Group order q = " + q);

        System.out.println("Finding generator...");
        // Find a generator of the subgroup of order q.
        this.g = findGenerator(p, q);
        System.out.println("Generator found: g = " + g);

        // Generate a random private key and compute the corresponding public key.
        this.privateKey = new BigInteger(q.bitLength() - 1, random);
        this.publicKey = g.modPow(privateKey, p);
        System.out.println("Key pair generated. Public key = " + publicKey);
    }

    /**
     * Returns the prime modulus p.
     */
    public BigInteger getP() {
        return this.p;
    }

    /**
     * ElGamal-style encryption.
     * Encrypts a message m (as a BigInteger in Z_p) using a random ephemeral exponent k.
     * Ciphertext: c1 = g^k mod p; c2 = m * publicKey^k mod p.
     *
     * @param m The message as a BigInteger.
     * @return The resulting ciphertext.
     */
    public EncryptedMessage encrypt(BigInteger m) {
        // Choose a random ephemeral exponent k (0 < k < q).
        BigInteger k = new BigInteger(q.bitLength() - 1, random);
        BigInteger c1 = g.modPow(k, p);
        BigInteger c2 = m.multiply(publicKey.modPow(k, p)).mod(p);
        return new EncryptedMessage(c1, c2);
    }

    /**
     * Shuffle:
     *   1) Generates a random permutation of the ciphertext list.
     *   2) Re-encrypts each ciphertext with a random exponent r:
     *       newC1 = c1 * g^r mod p,
     *       newC2 = c2 * publicKey^r mod p.
     *   3) Generates an aggregated shuffle proof.
     *
     * @param messages The original list of ciphertexts.
     * @return A VerifiableShuffle containing the shuffled messages and proof.
     */
    public VerifiableShuffle shuffle(List<EncryptedMessage> messages) {
        if (messages == null || messages.size() < 2) {
            throw new IllegalArgumentException("Need at least 2 messages to shuffle");
        }
        int n = messages.size();

        // Generate a random permutation.
        int[] permutation = generatePermutation(n);

        // Generate random exponents r for re-encryption.
        List<BigInteger> randomness = IntStream.range(0, n)
                .mapToObj(i -> new BigInteger(q.bitLength() - 1, random))
                .toList();

        // Apply the permutation and re-encrypt each ciphertext.
        List<EncryptedMessage> shuffled = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            int idx = permutation[i];
            EncryptedMessage msg = messages.get(idx);
            BigInteger r = randomness.get(i);

            BigInteger newC1 = msg.c1().multiply(g.modPow(r, p)).mod(p);
            BigInteger newC2 = msg.c2().multiply(publicKey.modPow(r, p)).mod(p);

            shuffled.add(new EncryptedMessage(newC1, newC2));
        }

        // Generate an aggregated shuffle proof.
        ShuffleProof proof = generateShuffleProof(messages, shuffled, permutation, randomness);
        return new VerifiableShuffle(shuffled, proof, permutation);
    }

    /**
     * Verifies the aggregated Chaum–Pedersen proof over the re-encryption shuffle.
     * Checks that the aggregated values and proofs for c1 and c2 components hold true.
     *
     * @param input  The original ciphertexts.
     * @param output The shuffled (and re-encrypted) ciphertexts.
     * @param proof  The aggregated shuffle proof.
     * @return true if the verification is successful; false otherwise.
     */
    public boolean verify(List<EncryptedMessage> input, List<EncryptedMessage> output, ShuffleProof proof) {
        if (input.size() != output.size()) return false;

        // Recompute aggregated products for c1.
        BigInteger A1 = BigInteger.ONE;
        BigInteger B1 = BigInteger.ONE;
        for (EncryptedMessage em : input) {
            A1 = A1.multiply(em.c1()).mod(p);
        }
        for (EncryptedMessage em : output) {
            B1 = B1.multiply(em.c1()).mod(p);
        }
        BigInteger diff1 = B1.multiply(A1.modInverse(p)).mod(p);

        // Recompute aggregated products for c2.
        BigInteger A2 = BigInteger.ONE;
        BigInteger B2 = BigInteger.ONE;
        for (EncryptedMessage em : input) {
            A2 = A2.multiply(em.c2()).mod(p);
        }
        for (EncryptedMessage em : output) {
            B2 = B2.multiply(em.c2()).mod(p);
        }
        BigInteger diff2 = B2.multiply(A2.modInverse(p)).mod(p);

        // Rebuild the challenge using the same context.
        byte[] context = concatForHashAggregated(A1, B1, proof.T1(), A2, B2, proof.T2());
        BigInteger expectedC = generateChallenge(context);

        if (!proof.c1().equals(expectedC) || !proof.c2().equals(expectedC)) {
            System.out.println("Challenge mismatch.");
            return false;
        }

        // Verify the first component: g^(s1) ?= T1 * (diff1)^(c1)
        BigInteger lhs1 = g.modPow(proof.s1(), p);
        BigInteger rhs1 = proof.T1().multiply(diff1.modPow(proof.c1(), p)).mod(p);
        if (!lhs1.equals(rhs1)) {
            System.out.println("c1 exponent check failed.");
            return false;
        }

        // Verify the second component: publicKey^(s2) ?= T2 * (diff2)^(c2)
        BigInteger lhs2 = publicKey.modPow(proof.s2(), p);
        BigInteger rhs2 = proof.T2().multiply(diff2.modPow(proof.c2(), p)).mod(p);
        if (!lhs2.equals(rhs2)) {
            System.out.println("c2 exponent check failed.");
            return false;
        }

        return true;
    }

    /**
     * Builds an aggregated shuffle proof over input and output ciphertext lists.
     */
    private ShuffleProof generateShuffleProof(
            List<EncryptedMessage> input,
            List<EncryptedMessage> output,
            int[] permutation,
            List<BigInteger> randomness
    ) {
        int n = input.size();
        // Sum the re-encryption exponents modulo q.
        BigInteger rSum = BigInteger.ZERO;
        for (BigInteger r : randomness) {
            rSum = rSum.add(r).mod(q);
        }

        // For c1: compute aggregated products.
        BigInteger A1 = BigInteger.ONE;
        BigInteger B1 = BigInteger.ONE;
        for (EncryptedMessage em : input) {
            A1 = A1.multiply(em.c1()).mod(p);
        }
        for (EncryptedMessage em : output) {
            B1 = B1.multiply(em.c1()).mod(p);
        }
        BigInteger diff1 = B1.multiply(A1.modInverse(p)).mod(p);

        // For c2: compute aggregated products.
        BigInteger A2 = BigInteger.ONE;
        BigInteger B2 = BigInteger.ONE;
        for (EncryptedMessage em : input) {
            A2 = A2.multiply(em.c2()).mod(p);
        }
        for (EncryptedMessage em : output) {
            B2 = B2.multiply(em.c2()).mod(p);
        }
        BigInteger diff2 = B2.multiply(A2.modInverse(p)).mod(p);

        // Ephemeral exponents used for the proof.
        BigInteger w1 = new BigInteger(q.bitLength() - 1, random);
        BigInteger w2 = new BigInteger(q.bitLength() - 1, random);

        BigInteger T1 = g.modPow(w1, p);
        BigInteger T2 = publicKey.modPow(w2, p);

        // Build context and compute challenge.
        byte[] context = concatForHashAggregated(A1, B1, T1, A2, B2, T2);
        BigInteger cChallenge = generateChallenge(context);

        // Compute responses.
        BigInteger s1 = w1.add(cChallenge.multiply(rSum)).mod(q);
        BigInteger s2 = w2.add(cChallenge.multiply(rSum)).mod(q);

        return new ShuffleProof(
                A1, B1, diff1, T1, cChallenge, s1,
                A2, B2, diff2, T2, cChallenge, s2
        );
    }

    /**
     * Concatenates aggregated values into a byte array for hashing.
     */
    private byte[] concatForHashAggregated(BigInteger A1, BigInteger B1, BigInteger T1,
                                           BigInteger A2, BigInteger B2, BigInteger T2) {
        String concat = A1.toString() + B1.toString() + T1.toString() +
                A2.toString() + B2.toString() + T2.toString();
        return concat.getBytes();
    }

    /**
     * Generates a simple challenge hash from the given data.
     *
     */
    private BigInteger generateChallenge(byte[] data) {
        int hash = 0;
        for (byte b : data) {
            hash = 31 * hash + b;
        }
        return BigInteger.valueOf(hash >= 0 ? hash : -hash).mod(q);
    }

    /**
     * Generates a random permutation of indices [0, n-1] using Fisher–Yates shuffle.
     */
    private int[] generatePermutation(int n) {
        int[] perm = IntStream.range(0, n).toArray();
        for (int i = n - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            int tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
        return perm;
    }

    /**
     * Generates a safe prime p (where p and (p-1)/2 are prime).
     */
    private BigInteger generateSafePrime(int bits) {
        BigInteger candidate;
        int attempts = 0;
        do {
            attempts++;
            if (attempts % 10 == 0) {
                System.out.println("Finding safe prime... (attempt " + attempts + ")");
            }
            candidate = BigInteger.probablePrime(bits, random);
        } while (!candidate.subtract(BigInteger.ONE).divide(BigInteger.TWO).isProbablePrime(20));
        return candidate;
    }

    /**
     * Finds a generator for the subgroup of order q in Z_p^*.
     */
    private BigInteger findGenerator(BigInteger p, BigInteger q) {
        // Try small fixed integers first.
        for (int i = 2; i < 40; i++) {
            BigInteger candidate = BigInteger.valueOf(i);
            if (isGenerator(candidate, p, q)) {
                return candidate;
            }
        }
        // Otherwise, try random candidates.
        BigInteger candidate;
        do {
            candidate = new BigInteger(p.bitLength() - 1, random);
        } while (!isGenerator(candidate, p, q));
        return candidate;
    }

    /**
     * Checks whether candidate is a generator of the subgroup of order q.
     */
    private boolean isGenerator(BigInteger candidate, BigInteger p, BigInteger q) {
        return candidate.modPow(q, p).equals(BigInteger.ONE)
                && !candidate.modPow(q.divide(BigInteger.TWO), p).equals(BigInteger.ONE);
    }
}
