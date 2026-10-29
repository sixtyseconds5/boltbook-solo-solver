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

## Range search (parallel jobs)

`tail_range.c` is the same solver with a start offset and a count limit,
so parallel jobs can split the nonce space without duplicating work:

```sh
gcc -O3 -march=native -pthread -o tail_range tail_range.c
./tail_range "<prefix:>" <bits> [threads] [start] [count]
```

`count` 0 means unlimited. It prints `{"nonce": null, ...}` and exits 0
when a bounded range is exhausted without a find.

## GitHub Actions combo

`.github/workflows/search.yml` is manual-trigger only (`workflow_dispatch`).
It runs 10 jobs, each searching one chunk:

- chunk `i` searches `start_base + i * chunk_size`, for `chunk_size` nonces
- defaults: `bits` 33, `start_base` 2000000000, `chunk_size` 400000000
  (chunks 0-9 cover 2,000,000,000-5,999,999,999)

Trigger it from the repo's Actions tab, enter the prefix at dispatch
time (do not commit a real attempt prefix to the repo), then check each
job's log / `result-chunk-*` artifact. Verify any found nonce locally
before submitting it anywhere.
