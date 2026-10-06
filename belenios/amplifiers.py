import hashlib
import time
import random
import belenios_core as B
import dkg
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helios"))
from common_subgroup import element_of_order


def amp_V1_exclusive_ownership(G):
    print("-" * 74)
    print("Amplifier B-V1 : weak Fiat-Shamir Schnorr excludes the verification key")
    print("-" * 74)
    rng = random.Random(3)
    sk = G.random_scalar(rng)
    vk = G.pow(G.g, sk)
    sig = B.sign(G, sk, "channel-message", rng)
    print("  honest signature verifies under vk:", B.verify(G, vk, sig))
    c = sig["challenge"]
    d = None
    for cand in (2, 3, 5, 7, 11, 13):
        if c % cand == 0:
            d = cand
            break
    if d is None:
        print("  (this challenge is not divisible by a tiny prime; retrying messages)")
        for k in range(5000):
            sig = B.sign(G, sk, "channel-message-%d" % k, rng)
            for cand in (2, 3, 5, 7, 11, 13):
                if sig["challenge"] % cand == 0:
                    d, c = cand, sig["challenge"]
                    break
            if d:
                break
    zeta = element_of_order(G.p, G.q, (G.p - 1) // G.q, d, 1)
    vk_prime = G.mul(vk, zeta)
    print("  found challenge c with %d | c; torsion zeta of order %d gives a SECOND key" % (d, d))
    print("  vk' = vk * zeta (vk' != vk):", vk_prime != vk)
    print("  the SAME signature also verifies under vk':", B.verify(G, vk_prime, sig))
    print("  -> exclusive ownership fails: a signature is claimed by two distinct keys.")


def amp_V2_rushing_dkg(G):
    print("-" * 74)
    print("Amplifier B-V2 : Pedersen DKG without a commitment round (rushing)")
    print("-" * 74)
    rng = random.Random(8)
    n, t = 3, 2
    seeds = [B.Password.b58_token(22, rng) for _ in range(n)]
    trustees = [dkg.Trustee(G, i, s, rng) for i, s in enumerate(seeds)]
    for tr in trustees[:-1]:
        tr.choose_polynomial(t, rng)
    honest_product = 1
    for tr in trustees[:-1]:
        honest_product = G.mul(honest_product, tr.coefexps[0])
    target = G.pow(G.g, 12345)
    last = trustees[-1]
    last.choose_polynomial(t, rng)
    last.coefexps[0] = G.mul(target, G.inv(honest_product))
    Y = dkg.joint_public_key(G, [tr.coefexps for tr in trustees])
    print("  the last trustee publishes after seeing the others (no commit-open round).")
    print("  it sets its exponentiated constant term to steer the joint key.")
    print("  forced joint key equals the chosen target g^12345:", Y == target)
    print("  -> the joint public key is fully adversary-controlled, so the uniform-key")
    print("     premise of the machine-checked privacy proof does not hold.")


def amp_V11_scalar_bias(G):
    print("-" * 74)
    print("Amplifier B-V11 : non-uniform scalars from single-width hash reduction")
    print("-" * 74)
    q = G.q
    tw_256 = 1 << 256
    overflow = tw_256 - q
    print("  reduce_hex maps a 256-bit digest into Z_q with q ~ 1.357*2^255.")
    print("  residues in [0, 2^256 - q) receive two preimages, the rest one.")
    print("  fraction of Z_q that is over-represented: (2^256 - q)/q = %.4f" % (overflow / q))
    rng = random.Random(1)
    N = 200000
    lo = 0
    for _ in range(N):
        digest = rng.getrandbits(256)
        if digest % q < overflow:
            lo += 1
    frac = lo / N
    expected = (2 * overflow) / tw_256
    print("  measured share of samples landing in the doubled region: %.4f (theory %.4f)"
          % (frac, expected))
    print("  -> derived keys sk/dk and all challenges are biased on a known sub-interval,")
    print("     which halves the residue budget of the subgroup recoveries.")


def run():
    print("=" * 74)
    print("Belenios amplifiers : further weaknesses (B-V1, B-V2, B-V11)")
    print("=" * 74)
    G = B.belenios_group()
    amp_V1_exclusive_ownership(G)
    print()
    amp_V2_rushing_dkg(G)
    print()
    amp_V11_scalar_bias(G)


if __name__ == "__main__":
    run()
