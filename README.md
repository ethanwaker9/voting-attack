# Practical Ballot Privacy Attacks on Helios and Belenios

This repository contains our proof of concept attacks against the ballot privacy (BPRIV) of the
Helios and Belenios electronic voting systems, together with clean end-to-end
reference elections for both. The primitives are precise reimplementations of the two vulnerable releases:
* Helios: `benadida/helios-server` at commit `c7d5e60`
  (real 2048-bit ElGamal parameters from `helios/views.py`).
* Belenios: `glondu/belenios` v3.2.0 at commit `45fe837`
  (real `BELENIOS-2048` group from `src/lib/v1/group.ml`).
Every attack is a distinguisher (or a key recovery routine feeding a
distinguisher) in the BPRIV game, run against the reference election that the
same code builds. Our work targets two specific, superseded releases for the purpose of
security research and disclosure and current Helios and Belenios releases fix
these issues.

## Files and Contents

```
helios/
  helios_core.py                 ElGamal, biased sampler, disjunctive CDS proof, verifier
  election.py                    end-to-end Helios election (setup, cast, tally)
  common_subgroup.py             Pohlig-Hellman, BSGS, CRT, small order elements
  attack_A1_malleable_copy.py    A1: weak Fiat-Shamir replay            (H-V1)
  attack_A2_branch_leak.py       A2: simulation-branch leakage          (H-V2)
  attack_A3_subgroup.py          A3: small-subgroup key recovery        (H-V4)
  amplifier_V3_sha1.py           SHA-1 challenge weakness               (H-V3)
belenios/
  belenios_core.py               weak-FS Schnorr, ElGamal-KEM (AES-GCM), password hash
  dkg.py                         Pedersen DKG, share channel, Lagrange, reference election
  mixnet.py                      re-encryption shuffle + membership gate
  attack_B1_setup_channel.py     B1: setup channel key recovery         (B-V3, B-V5)
  attack_B2_mixnet_subgroup.py   B2: mixnet torsion injection           (B-V9, B-V4)
  amplifiers.py                  exclusive ownership / rushing DKG / bias (B-V1, B-V2, B-V11)
experiments.py                   collects all numbers into results/results.json
run_all.py                       runs every reference election and attack
results/                         results.json, plotdata.json
```

## Requirements
Python 3.9+, and:
```
pip install pycryptodome cryptography sympy gmpy2 matplotlib numpy
```
`gmpy2` is optional (a pure-Python fallback is used if it is absent);
`matplotlib` and `epstopdf` are needed only for `make_figures.py`.

## Running
Run a single attack (each prints its intermediate computations):
```
cd helios && python3 attack_A1_malleable_copy.py
cd belenios && python3 attack_B1_setup_channel.py
```
Run everything (both reference elections, all attacks, all amplifiers):
```
python3 run_all.py
```
Regenerate the measured numbers and the result figures:
```
python3 experiments.py       # writes results/results.json
python3 make_figures.py       # writes ../final_paper/figures/*.pdf
```

## Attacks and Implications

| Attack | Flaws | Effect | Measured result |
|--------|-------|--------|-----------------|
| A1 | H-V1 | rerandomize + maul proof, replay into tally | advantage 1.0, defeats weeding |
| A2 | H-V2 | read the vote off the board passively | advantage ~0.06 |
| A3 | H-V4 | confine to a small subgroup, recover the key | 25 bits (std prime), full key (smooth) |
| B1 | B-V3, B-V5 | crack admin, then recover the master key | master key, opens every ballot |
| B2 | B-V9, B-V4 | torsion past the shuffle verifier | key leak mod d, tally denial |

Amplifiers (`amplifier_V3_sha1.py`, `amplifiers.py`) quantify H-V3 (SHA-1),
B-V1 (exclusive ownership), B-V2 (rushing DKG key control), and B-V11 (scalar
bias).

All randomness is seeded, so the runs are deterministic and reproducible.
Total runtime for `run_all.py` is well under a minute on a laptop.

