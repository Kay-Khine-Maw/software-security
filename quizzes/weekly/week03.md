# Weekly Quiz — Week 3 (Cryptography)

**~10 min · 6 questions · low-stakes** (lowest scores dropped). Individual.

**Name:** ____________  **Student ID:** ________

## MCQ (5 × 1)
1. Hashing is:
   a) reversible with a key  b) reversible without a key  c) one-way (not reversible)  d) the same as Base64
2. The correct way to store passwords is:
   a) MD5  b) SHA-256  c) Base64  d) a salted, slow KDF (argon2id/bcrypt)
3. AES-**ECB** is weak because:
   a) it is too slow  b) identical plaintext blocks produce identical ciphertext  c) it needs no key  d) it cannot decrypt
4. For security tokens you should use:
   a) `random`  b) a CSPRNG such as `secrets`  c) the current time  d) an incrementing counter
5. Base64 provides:
   a) encryption  b) hashing  c) encoding only (no protection)  d) a digital signature

## Short answer (1 × 3)
6. Why does a per-user **salt** defeat precomputed rainbow-table attacks?
