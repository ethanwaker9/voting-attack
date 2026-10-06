import time
import helios_core as H
from election import Election

THRESHOLD = 1 << 255


def leak_from_ballot(ballot):
    c0 = ballot.proofs[0]["challenge"]
    c1 = ballot.proofs[1]["challenge"]
    if c1 >= THRESHOLD:
        return 1
    if c0 >= THRESHOLD:
        return 0
    return None


def bpriv_guess(observed_ballot):
    leaked_bit = leak_from_ballot(observed_ballot)
    if leaked_bit is None:
        return None
    return 0 if leaked_bit == 1 else 1


def run_game(beta, e_shared, rng):
    ballot = e_shared.vote(0, 1 if beta == 0 else 0, rng=rng)
    g = bpriv_guess(ballot)
    return g


def demo_rows(pk, rng, rows=6):
    print("  branch challenges of honest 'yes' ballots (real branch = branch 1):")
    print("  %-6s %-8s %-8s %-10s" % ("ballot", "c0<2^255", "c1<2^255", "leak?"))
    shown = 0
    tried = 0
    while shown < rows and tried < 400:
        tried += 1
        b = Election.vote.__get__(_mk_election(pk))(0, 1, rng=rng)
        c0 = b.proofs[0]["challenge"]
        c1 = b.proofs[1]["challenge"]
        leak = leak_from_ballot(b)
        flag = "-" if leak is None else ("LEAK bit=%d" % leak)
        if leak is not None or shown < rows - 2:
            print("  %-6d %-8s %-8s %-10s" % (shown, c0 < THRESHOLD, c1 < THRESHOLD, flag))
            shown += 1


def _mk_election(pk):
    e = Election()
    e.pk = pk
    return e


def measure(n_per_side=1500, seed=0):
    rng = H.StrongRandomStub(seed)
    e = Election()
    pk = e.setup(rng=rng)
    correct = 0
    fired = 0
    total = 0
    t0 = time.perf_counter()
    for i in range(n_per_side):
        for beta in (0, 1):
            total += 1
            g = run_game(beta, e, rng)
            if g is not None:
                fired += 1
                if g == beta:
                    correct += 1
    dt = time.perf_counter() - t0
    p_correct = (correct + 0.5 * (total - fired)) / total
    adv = 2 * p_correct - 1
    return adv, fired, total, dt


if __name__ == "__main__":
    print("=" * 74)
    print("Helios A2 : simulation-branch leakage  (flaw H-V2, biased sampler)")
    print("=" * 74)
    print("\nThe rejection sampler draws sub-challenges from [0, 2^255), but q ~ 1.0593*2^255,")
    print("so a published sub-challenge in [2^255, q) can only be a REAL branch, never a")
    print("simulated one. Reading it off the board reveals the vote, with no interaction.\n")
    rng = H.StrongRandomStub(3)
    e = Election()
    pk = e.setup(rng=rng)
    print("  q / 2^255 = %.6f   P(real branch >= 2^255) = q/2^255 - 1 = %.5f"
          % (pk.q / THRESHOLD, (pk.q - THRESHOLD) / THRESHOLD))
    print()
    demo_rows(pk, rng, rows=8)

    print("\n[measure] Passive BPRIV distinguisher over 3000 games:")
    adv, fired, total, dt = measure(n_per_side=1500, seed=11)
    print("    leak fired on %d / %d ballots  (empirical rate %.4f)" % (fired, total, fired / total))
    print("    measured advantage Adv_bpriv = %.4f   (theory ~ %.4f)"
          % (adv, (pk.q - THRESHOLD) / THRESHOLD))
    print("    wall-clock: %.2f s  (%.3f ms/ballot)" % (dt, dt * 1000 / total))
    print("\nRESULT: H-V2 alone breaks BPRIV passively with a constant advantage ~ 0.059,")
    print("        reading honest votes directly from the public transcript.")
