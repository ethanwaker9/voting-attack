import math
import hashlib

try:
    import gmpy2

    def pow(b, e, m):
        return int(gmpy2.powmod(int(b), int(e), int(m)))

    def inverse(a, m):
        return int(gmpy2.invert(int(a), int(m)))
except ImportError:
    from Crypto.Util.number import inverse

P_STD = 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071
Q_STD = 61329566248342901292543872769978950870633559608669337131139375508370458778917
G_STD = 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533


class StrongRandomStub:
    def __init__(self, seed=None):
        import random as _r
        self._r = _r.Random(seed)

    def getrandbits(self, k):
        return self._r.getrandbits(k)

    def randint(self, a, b):
        return self._r.randint(a, b)


_RNG = StrongRandomStub()


def random_mpz_lt(maximum, strong_random=None):
    r = strong_random if strong_random is not None else _RNG
    n_bits = int(math.floor(math.log(maximum, 2)))
    res = r.getrandbits(n_bits)
    while res >= maximum:
        res = r.getrandbits(n_bits)
    return res


def random_mpz_lt_fixed(maximum, strong_random=None):
    r = strong_random if strong_random is not None else _RNG
    n_bits = maximum.bit_length()
    res = r.getrandbits(n_bits)
    while res >= maximum:
        res = r.getrandbits(n_bits)
    return res


def sha1_int(s):
    return int(hashlib.sha1(s.encode("utf-8")).hexdigest(), 16)


def disjunctive_challenge_generator(commitments):
    parts = []
    for c in commitments:
        parts.append(str(c["A"]))
        parts.append(str(c["B"]))
    return sha1_int(",".join(parts))


def fiatshamir_challenge_generator(commitment):
    return disjunctive_challenge_generator([commitment])


class Params:
    def __init__(self, p=P_STD, q=Q_STD, g=G_STD):
        self.p = p
        self.q = q
        self.g = g


class PublicKey:
    def __init__(self, params, y):
        self.p = params.p
        self.q = params.q
        self.g = params.g
        self.y = y


class SecretKey:
    def __init__(self, pk, x):
        self.pk = pk
        self.x = x

    def decryption_factor(self, alpha):
        return pow(alpha, self.x, self.pk.p)

    def prove_decryption_factor(self, alpha):
        p, q, g = self.pk.p, self.pk.q, self.pk.g
        dec = pow(alpha, self.x, p)
        w = random_mpz_lt(q)
        a = pow(g, w, p)
        b = pow(alpha, w, p)
        c = sha1_int(str(a) + "," + str(b))
        t = (w + self.x * c) % q
        return dec, {"challenge": c, "response": t, "A": a, "B": b}


class Ciphertext:
    def __init__(self, pk, alpha, beta):
        self.pk = pk
        self.alpha = alpha
        self.beta = beta

    def __mul__(self, other):
        return Ciphertext(self.pk, (self.alpha * other.alpha) % self.pk.p,
                          (self.beta * other.beta) % self.pk.p)

    def reenc_with_r(self, r):
        p, g, y = self.pk.p, self.pk.g, self.pk.y
        return Ciphertext(self.pk, (self.alpha * pow(g, r, p)) % p,
                          (self.beta * pow(y, r, p)) % p)

    def check_group_membership(self):
        p, q = self.pk.p, self.pk.q
        if not (1 < self.alpha < p - 1):
            return False
        if not (1 < self.beta < p - 1):
            return False
        if pow(self.alpha, q, p) != 1:
            return False
        if pow(self.beta, q, p) != 1:
            return False
        return True


def keygen(params, rng=None):
    x = random_mpz_lt(params.q, rng)
    y = pow(params.g, x, params.p)
    pk = PublicKey(params, y)
    return pk, SecretKey(pk, x)


def encrypt(pk, m, r=None, rng=None):
    p, g, y = pk.p, pk.g, pk.y
    if r is None:
        r = random_mpz_lt(pk.q, rng)
    alpha = pow(g, r, p)
    beta = (m * pow(y, r, p)) % p
    return Ciphertext(pk, alpha, beta), r


def plaintext_for_bit(pk, b):
    return pow(pk.g, b, pk.p)


def simulate_encryption_proof(ct, plaintext_m, challenge=None, rng=None):
    pk = ct.pk
    p, q, g, y = pk.p, pk.q, pk.g, pk.y
    if challenge is None:
        challenge = random_mpz_lt(q, rng)
    response = random_mpz_lt(q, rng)
    beta_over_plaintext = (ct.beta * inverse(plaintext_m, p)) % p
    A = (inverse(pow(ct.alpha, challenge, p), p) * pow(g, response, p)) % p
    B = (inverse(pow(beta_over_plaintext, challenge, p), p) * pow(y, response, p)) % p
    return {"challenge": challenge, "response": response, "commitment": {"A": A, "B": B}}


def generate_encryption_proof(ct, randomness, challenge_generator, rng=None):
    pk = ct.pk
    p, q, g, y = pk.p, pk.q, pk.g, pk.y
    w = random_mpz_lt(q, rng)
    commitment = {"A": pow(g, w, p), "B": pow(y, w, p)}
    challenge = challenge_generator(commitment)
    response = (w + randomness * challenge) % q
    return {"challenge": challenge, "response": response, "commitment": commitment}


def generate_disjunctive_encryption_proof(ct, plaintexts, real_index, randomness, challenge_generator, rng=None):
    proofs = [None] * len(plaintexts)
    for i in range(len(plaintexts)):
        if i != real_index:
            proofs[i] = simulate_encryption_proof(ct, plaintexts[i], rng=rng)

    def real_challenge_generator(commitment):
        proofs[real_index] = {"commitment": commitment}
        commitments = [pr["commitment"] for pr in proofs]
        disj = challenge_generator(commitments)
        real = disj
        for i in range(len(proofs)):
            if i != real_index:
                real = real - proofs[i]["challenge"]
        return real % ct.pk.q

    real_proof = generate_encryption_proof(ct, randomness, real_challenge_generator, rng=rng)
    proofs[real_index] = real_proof
    return proofs


def verify_encryption_proof(ct, plaintext_m, proof):
    pk = ct.pk
    p = pk.p
    A = proof["commitment"]["A"]
    B = proof["commitment"]["B"]
    c = proof["challenge"]
    f = proof["response"]
    left1 = pow(pk.g, f, p)
    right1 = (pow(ct.alpha, c, p) * A) % p
    beta_over_m = (ct.beta * inverse(plaintext_m, p)) % p
    left2 = pow(pk.y, f, p)
    right2 = (pow(beta_over_m, c, p) * B) % p
    return left1 == right1 and left2 == right2


def verify_disjunctive_encryption_proof(ct, plaintexts, proofs, challenge_generator):
    if len(plaintexts) != len(proofs):
        return False
    for i in range(len(plaintexts)):
        if not verify_encryption_proof(ct, plaintexts[i], proofs[i]):
            return False
    total = sum(pr["challenge"] for pr in proofs) % ct.pk.q
    recomputed = challenge_generator([pr["commitment"] for pr in proofs]) % ct.pk.q
    return recomputed == total


def encrypt_bit_with_proof(pk, bit, rng=None):
    m = plaintext_for_bit(pk, bit)
    ct, r = encrypt(pk, m, rng=rng)
    plaintexts = [plaintext_for_bit(pk, 0), plaintext_for_bit(pk, 1)]
    proofs = generate_disjunctive_encryption_proof(ct, plaintexts, bit, r,
                                                   disjunctive_challenge_generator, rng=rng)
    return ct, proofs


def verify_ballot_choice(pk, ct, proofs, check_subgroup=False):
    if check_subgroup and not ct.check_group_membership():
        return False
    plaintexts = [plaintext_for_bit(pk, 0), plaintext_for_bit(pk, 1)]
    return verify_disjunctive_encryption_proof(ct, plaintexts, proofs,
                                               disjunctive_challenge_generator)


def dlog_bounded(pk, T, bound):
    p, g = pk.p, pk.g
    cur = 1
    for t in range(bound + 1):
        if cur == T:
            return t
        cur = (cur * g) % p
    return None


def tally_and_decrypt(pk, sk, ciphertexts, bound=10000):
    p = pk.p
    A = 1
    B = 1
    for ct in ciphertexts:
        A = (A * ct.alpha) % p
        B = (B * ct.beta) % p
    agg = Ciphertext(pk, A, B)
    dec = sk.decryption_factor(A)
    T = (B * inverse(dec, p)) % p
    t = dlog_bounded(pk, T, bound)
    return t, agg, dec
