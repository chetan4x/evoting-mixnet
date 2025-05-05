# E-Voting
Implementation of Mix-net described in Java. It incorporates prime group setup, ElGamal-style en-
cryption, secure shuffling, and a non-interactive zero-knowledge proof to ensure
that the shuffle was performed honestly, without revealing the permutation or the
randomness used. At the system’s core lies a proof mechanism derived from the
Chaum–Pedersen approach, adapted into an aggregated protocol that verifies the
correctness of the entire shuffle in a single check.

# Instructions for Running
1. Extract as Zip File or Clone as necessary
2. Recompile and Build Project in Java (SDK 21)
3. Run TestMixnet to generate and verify encrypted ballots with proof information.
