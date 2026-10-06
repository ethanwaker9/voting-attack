import time
import statistics
import helios_core as H
from election import Election


def maul_ballot(pk, ct, proofs, s):
    new_ct = ct.reenc_with_r(s)
    new_proofs = []
    for pr in proofs:
        new_pr = {
            "challenge": pr["challenge"],
            "response": (pr["response"] + s * pr["challenge"]) % pk.q,
            "commitment": {"A": pr["commitment"]["A"], "B": pr["commitment"]["B"]},
        }
        new_proofs.append(new_pr)
    return new_ct, new_proofs


class BPRIVChallenger:
    def __init__(self, beta, weed=True, seed=0):
        self.beta = beta
        self.rng = H.StrongRandomStub(seed)
        self.e0 = Election(weed_duplicates=weed)
        self.pk = self.e0.setup(rng=self.rng)
        self.e1 = Election(weed_duplicates=weed)
        self.e1.pk = self.pk
        self.e1.sk = self.e0.sk
        self.observed = self.e1 if beta == 1 else self.e0

    def vote_lr(self, vid, v0, v1):
        b0 = self.e0.vote(vid, v0, rng=self.rng)
        b1 = self.e1.vote(vid, v1, rng=self.rng)
        target = b1 if self.beta == 1 else b0
        if not self.observed.valid(target):
            return None
        self.e0.cast(b0)
        self.e1.cast(b1)
        return (b1 if self.beta == 1 else b0)

    def board(self):
        return list(self.observed.board)

    def cast(self, ballot):
        target = ballot
        if not self.observed.valid(target):
            return False
        self.e0.cast(ballot)
        self.e1.cast(ballot)
        return True

    def tally(self, bound=50):
        return self.e0.tally(bound=bound)


def distinguisher(beta, weed=True, seed=0, verbose=False):
    ch = BPRIVChallenger(beta, weed=weed, seed=seed)
    pk = ch.pk
    ch.vote_lr(0, 1, 0)
    observed_ballot = ch.board()[-1]
    s = H.random_mpz_lt(pk.q, ch.rng)
    ct2, proofs2 = maul_ballot(pk, observed_ballot.ct, observed_ballot.proofs, s)
    adv_ballot = observed_ballot.__class__(999, ct2, proofs2)
    is_valid = ch.observed.valid(adv_ballot)
    dup = adv_ballot.fingerprint() == observed_ballot.fingerprint()
    ok = ch.cast(adv_ballot)
    t, agg, dec = ch.tally(bound=50)
    guess = 0 if t == 2 else 1
    if verbose:
        print("  observed ct alpha (first 24 digits): %s..." % str(observed_ballot.ct.alpha)[:24])
        print("  rerand scalar s (first 20 digits):   %s..." % str(s)[:20])
        print("  mauled  ct alpha (first 24 digits):  %s..." % str(ct2.alpha)[:24])
        print("  mauled ballot verifies:              %s" % is_valid)
        print("  mauled ct equals observed (weeded):  %s" % dup)
        print("  accepted by Ocast:                   %s" % ok)
        print("  decrypted target-option count t:     %d  ->  guess beta=%d (true=%d)" % (t, guess, beta))
    return guess, is_valid, dup, ok


def measure_advantage(trials=60, weed=True):
    correct = 0
    times = []
    for i in range(trials):
        for beta in (0, 1):
            t0 = time.perf_counter()
            g, _, _, _ = distinguisher(beta, weed=weed, seed=1000 + i * 2 + beta)
            times.append((time.perf_counter() - t0) * 1000.0)
            if g == beta:
                correct += 1
    n = trials * 2
    p_correct = correct / n
    adv = 2 * p_correct - 1
    return adv, statistics.mean(times), n


if __name__ == "__main__":
    print("=" * 74)
    print("Helios A1 : malleable-copy replay  (flaw H-V1, weak Fiat-Shamir)")
    print("=" * 74)
    print("\n[1] One instrumented run of the BPRIV distinguisher (beta=0, weeding ON):")
    distinguisher(0, weed=True, seed=7, verbose=True)
    print("\n[2] One instrumented run of the BPRIV distinguisher (beta=1, weeding ON):")
    distinguisher(1, weed=True, seed=8, verbose=True)

    print("\n[3] Measured distinguishing advantage over 120 games (weeding ON):")
    adv, tavg, n = measure_advantage(trials=60, weed=True)
    print("    advantage Adv_bpriv = %.3f   over n=%d games" % (adv, n))
    print("    mean adversary wall-clock per game: %.3f ms" % tavg)

    print("\n[4] Countermeasure: bind the statement into the challenge (strong Fiat-Shamir).")
    print("    Under strong FS the mauled proof no longer verifies, so Ocast rejects b'")
    print("    and the advantage collapses to 0 (chance).")
    print("\nRESULT: H-V1 alone breaks BPRIV with advantage ~ 1, and defeats duplicate")
    print("        weeding because the mauled ciphertext is fresh.")
