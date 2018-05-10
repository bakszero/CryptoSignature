# CryptoSignature

## Description of Problem
Assume that two participants, say A and B agree on the following digital signature scheme. The participant
A signs a binary message m of any arbitrary length. The participant B can verify that signature by using the
public key of A. The following phases related to this scheme are given below.

### Key Generation Phase
Participant A (client) executes the following steps:
```
1. Select two primes p and q such that q | (p − 1) using the Miller-Robin primality test algorithm.
2. Select a random integer g with 1 < g < p − 1, such that α = g^[(p−1)/q](modp) and α > 1.
3. Select a private key a, 1 ≤ a ≤ q − 1.
4. Compute y = α^[a](modp) using the repeated square-and-multiply algorithm.
5. The public key of A is (p, q, α, y). A sends P UBKEY (p, q, α, y, H(·)) to the server (B), where
H(·) is a secure hash function (for example, secure hash standard (SHA-1) algorithm).
```

### Signature Generation Phase
A signs the message m as follows:
```
1. Select a random secret integer k, 1 ≤ k ≤ q − 1.
2. Compute r = α^[k](mod p), e = H(m||r), and s = (ae + k) mod q, where H(·) is a one-way cryptographic hash function.
3. Select two random secret integers u and v, 0 < u < q and 0 < v < q, and compute r' =rα^[−u]y^[v] mod p.
4. Compute e' = H(m||r') such that e' = e − v and s' = s − u.
5. A then sends the signed message SIGNEDMSG(m,(e', s')) to the verifier B.
```

### Signature Verification Phase
After receiving the signed message from A, B verifies the signature using the following signature
verification algorithm. If signature is valid set status as true (1); otherwise set status as false (0).
```
1. Compute r* = α^[s'].y^[−e'](mod p).
2. Check if H(m||r*) = e'? If so, the signature is valid and set status as true (1); otherwise, the the
signature is invalid and set status as false (0).
3. B sends the message V ERST AT US(status) with signature verification result to A.
```

## Usage

Run the server as:
```python 
python server.py
```

Open another terminal and initialise the client as:
```python
python client.py
```
