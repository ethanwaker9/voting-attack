import helios_core as H


class Ballot:
    def __init__(self, voter_id, ct, proofs):
        self.voter_id = voter_id
        self.ct = ct
        self.proofs = proofs

    def fingerprint(self):
        return (self.ct.alpha, self.ct.beta)


class Election:
    def __init__(self, params=None, check_subgroup_on_cast=False, weed_duplicates=True):
        self.params = params if params is not None else H.Params()
        self.pk = None
        self.sk = None
        self.board = []
        self._fps = set()
        self.check_subgroup_on_cast = check_subgroup_on_cast
        self.weed_duplicates = weed_duplicates

    def setup(self, rng=None):
        self.pk, self.sk = H.keygen(self.params, rng=rng)
        return self.pk

    def vote(self, voter_id, bit, rng=None):
        ct, proofs = H.encrypt_bit_with_proof(self.pk, bit, rng=rng)
        return Ballot(voter_id, ct, proofs)

    def valid(self, ballot):
        if not H.verify_ballot_choice(self.pk, ballot.ct, ballot.proofs,
                                      check_subgroup=self.check_subgroup_on_cast):
            return False
        if self.weed_duplicates and ballot.fingerprint() in self._fps:
            return False
        return True

    def cast(self, ballot):
        if not self.valid(ballot):
            return False
        self.board.append(ballot)
        self._fps.add(ballot.fingerprint())
        return True

    def tally(self, bound=10000):
        cts = [b.ct for b in self.board]
        return H.tally_and_decrypt(self.pk, self.sk, cts, bound=bound)


def run_reference_election(n_yes, n_no, seed=0, verbose=False):
    rng = H.StrongRandomStub(seed)
    e = Election()
    e.setup(rng=rng)
    vid = 0
    for _ in range(n_yes):
        b = e.vote(vid, 1, rng=rng)
        assert e.cast(b)
        vid += 1
    for _ in range(n_no):
        b = e.vote(vid, 0, rng=rng)
        assert e.cast(b)
        vid += 1
    t, agg, dec = e.tally(bound=n_yes + n_no + 5)
    if verbose:
        print("cast ballots:", len(e.board), " decrypted yes-count:", t,
              " expected:", n_yes)
    return e, t


if __name__ == "__main__":
    e, t = run_reference_election(4, 3, verbose=True)
    assert t == 4
    print("reference election OK")
