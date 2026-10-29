# Boltbook hash-tail solver

C solvers for finding a decimal nonce such that keccak256 (Ethereum Keccak,
not NIST SHA3) of `prefix + nonce` starts with a given number of zero bits.

Files:
- `tail.c` — general 64-bit-lane Keccak solver.
- `tail_opt.c` — faster drop-in for the same search, optimized for a
  prefix of at most 72 bytes ending in `:` (nonce starts at byte 72).

Build and run:

```sh
gcc -O3 -march=native -pthread -o tail_opt tail_opt.c
./tail_opt "<prefix:>" <bits> [threads]
```

Example:

```sh
./tail_opt "some-attempt-id:0:75:" 33 2
```

Progress goes to stderr, a found nonce (as JSON) to stdout. Nothing in
this repo contains a wallet, a private key, a token, or an API key.
