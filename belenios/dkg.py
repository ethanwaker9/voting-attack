import belenios_core as B


class Trustee:
    def __init__(self, G, index, seed, rng):
        self.G = G
        self.index = index
        self.seed = seed
        self.sk = B.derive_sk(seed, G.q)
        self.dk = B.derive_dk(seed, G.q)
        self.vk = G.pow(G.g, self.sk)
        self.ek = G.pow(G.g, self.dk)
        self.rng = rng
        self.polynomial = None
        self.coefexps = None

    def make_cert(self, rng):
        cert_keys = {"cert_verification": self.vk, "cert_encryption": self.ek}
        msg = "cert|%d|%d" % (self.vk, self.ek)
        sig = B.sign(self.G, self.sk, msg, rng)
        return {"keys": cert_keys, "sig": sig, "msg": msg}

    def choose_polynomial(self, threshold, rng):
        self.polynomial = [self.G.random_scalar(rng) for _ in range(threshold)]
        self.coefexps = [self.G.pow(self.G.g, a) for a in self.polynomial]
        return self.coefexps

    def eval_share(self, j):
        res = 0
        cur = 1
        for a in self.polynomial:
            res = (res + cur * a) % self.G.q
            cur = (cur * (j + 1)) % self.G.q
        return res


def joint_public_key(G, coefexps_list):
    Y = 1
    for coefexps in coefexps_list:
        Y = G.mul(Y, coefexps[0])
    return Y


def distribute_shares(G, trustees, rng, override_ek=None):
    n = len(trustees)
    channel = {}
    for i in range(n):
        for j in range(n):
            secret = trustees[i].eval_share(j)
            payload = ("share|%d" % secret).encode()
            ek_j = trustees[j].ek if override_ek is None or override_ek.get(j) is None else override_ek[j]
            channel[(i, j)] = B.encrypt(G, ek_j, payload, rng)
    return channel


def master_share_of(G, trustees, j):
    return sum(trustees[i].eval_share(j) for i in range(len(trustees))) % G.q


def lagrange_reconstruct(G, points):
    q = G.q
    secret = 0
    xs = [x for x, _ in points]
    for xi, yi in points:
        num = 1
        den = 1
        for xj in xs:
            if xj == xi:
                continue
            num = (num * (-xj)) % q
            den = (den * (xi - xj)) % q
        secret = (secret + yi * num * pow(den, -1, q)) % q
    return secret


def run_dkg(G, seeds, threshold, rng):
    trustees = [Trustee(G, i, s, rng) for i, s in enumerate(seeds)]
    for t in trustees:
        t.choose_polynomial(threshold, rng)
    Y = joint_public_key(G, [t.coefexps for t in trustees])
    master_secret = sum(t.polynomial[0] for t in trustees) % G.q
    assert G.pow(G.g, master_secret) == Y
    return trustees, Y, master_secret


class Election:
    def __init__(self, G, n_trustees=1, threshold=1, seed=0):
        import random
        self.G = G
        self.rng = random.Random(seed)
        seeds = [B.Password.b58_token(22, self.rng) for _ in range(n_trustees)]
        self.trustees, self.pk, self.master_secret = run_dkg(G, seeds, threshold, self.rng)
        self.board = []

    def vote(self, m):
        ct, r = B.eg_encrypt(self.G, self.pk, m, self.rng)
        return ct

    def cast(self, ct):
        self.board.append(ct)

    def tally_homomorphic(self):
        G = self.G
        A = 1
        B_ = 1
        for ct in self.board:
            A = G.mul(A, ct["alpha"])
            B_ = G.mul(B_, ct["beta"])
        dec = G.pow(A, self.master_secret)
        T = G.mul(B_, G.inv(dec))
        cur = 1
        for t in range(len(self.board) + 1):
            if cur == T:
                return t
            cur = G.mul(cur, G.g)
        return None


if __name__ == "__main__":
    G = B.belenios_group()
    e = Election(G, n_trustees=3, threshold=2, seed=1)
    for m in [1, 0, 1, 1, 0]:
        e.cast(e.vote(m))
    t = e.tally_homomorphic()
    print("BELENIOS-2048 group, 3 trustees, threshold 2")
    print("cast 5 ballots (three 1s), homomorphic tally =", t)
    assert t == 3
    print("reference election OK")
