import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import gmpy2

    def _pow(b, e, m):
        return int(gmpy2.powmod(int(b), int(e), int(m)))

    def _inv(a, m):
        return int(gmpy2.invert(int(a), int(m)))
except ImportError:
    def _pow(b, e, m):
        return pow(int(b), int(e), int(m))

    def _inv(a, m):
        return pow(int(a), -1, int(m))

BELENIOS_2048 = {
    "p": int("20694785691422546401013643657505008064922989295751104097100884787057374219242717401922237254497684338129066633138078958404960054389636289796393038773905722803605973749427671376777618898589872735865049081167099310535867780980030790491654063777173764198678527273474476341835600035698305193144284561701911000786737307333564123971732897913240474578834468260652327974647951137672658693582180046317922073668860052627186363386088796882120769432366149491002923444346373222145884100586421050242120365433561201320481118852408731077014151666200162313177169372189248078507711827842317498073276598828825169183103125680162072880719"),
    "q": int("78571733251071885079927659812671450121821421258408794611510081919805623223441"),
    "g": int("2402352677501852209227687703532399932712287657378364916510075318787663274146353219320285676155269678799694668298749389095083896573425601900601068477164491735474137283104610458681314511781646755400527402889846139864532661215055797097162016168270312886432456663834863635782106154918419982534315189740658186868651151358576410138882215396016043228843603930989333662772848406593138406010231675095763777982665103606822406635076697764025346253773085133173495194248967754052573659049492477631475991575198775177711481490920456600205478127054728238140972518639858334115700568353695553423781475582491896050296680037745308460627"),
}


class Group:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g

    def pow(self, b, e):
        return _pow(b, e, self.p)

    def mul(self, a, b):
        return (a * b) % self.p

    def inv(self, a):
        return _inv(a, self.p)

    def check(self, x):
        return (0 < x < self.p) and _pow(x, self.q, self.p) == 1

    def hash(self, prefix, elts):
        s = prefix + ",".join(str(e) for e in elts)
        return int(hashlib.sha256(s.encode()).hexdigest(), 16) % self.q

    def random_scalar(self, rng):
        return rng.randrange(1, self.q)


def belenios_group():
    P = BELENIOS_2048
    return Group(P["p"], P["q"], P["g"])


def reduce_hex(hexstr, q):
    return int(hexstr, 16) % q


def derive_sk(seed, q):
    return reduce_hex(hashlib.sha256(("sk|" + seed).encode()).hexdigest(), q)


def derive_dk(seed, q):
    return reduce_hex(hashlib.sha256(("dk|" + seed).encode()).hexdigest(), q)


def sign(G, sk, s_message, rng):
    w = G.random_scalar(rng)
    commitment = G.pow(G.g, w)
    prefix = "sigmsg|" + s_message + "|"
    challenge = G.hash(prefix, [commitment])
    response = (w - sk * challenge) % G.q
    return {"s_message": s_message, "challenge": challenge, "response": response}


def verify(G, vk, sig):
    commitment = G.mul(G.pow(G.g, sig["response"]), G.pow(vk, sig["challenge"]))
    prefix = "sigmsg|" + sig["s_message"] + "|"
    return sig["challenge"] == G.hash(prefix, [commitment])


def _aes_key(hexdigest):
    return hashlib.sha256(("key|" + hexdigest).encode()).digest()


def _aes_nonce(alpha_str):
    return hashlib.sha256(("iv|" + alpha_str).encode()).digest()[:12]


def encrypt(G, y, plaintext, rng):
    r = G.random_scalar(rng)
    key_scalar = G.random_scalar(rng)
    key_elt = G.pow(G.g, key_scalar)
    y_alpha = G.pow(G.g, r)
    y_beta = G.mul(G.pow(y, r), key_elt)
    aeskey = _aes_key(str(key_elt))
    nonce = _aes_nonce(str(y_alpha))
    y_data = AESGCM(aeskey).encrypt(nonce, plaintext, None)
    return {"y_alpha": y_alpha, "y_beta": y_beta, "y_data": y_data}


def decrypt(G, x, ct):
    shared = G.mul(ct["y_beta"], G.inv(G.pow(ct["y_alpha"], x)))
    aeskey = _aes_key(str(shared))
    nonce = _aes_nonce(str(ct["y_alpha"]))
    try:
        return AESGCM(aeskey).decrypt(nonce, ct["y_data"], None)
    except Exception:
        return None


def encrypt_under_shared(G, shared_elt, plaintext, y_alpha):
    aeskey = _aes_key(str(shared_elt))
    nonce = _aes_nonce(str(y_alpha))
    return AESGCM(aeskey).encrypt(nonce, plaintext, None)


class Password:
    @staticmethod
    def b58_token(length, rng):
        digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return "".join(digits[rng.randrange(len(digits))] for _ in range(length))

    @staticmethod
    def make(password, rng):
        salt = Password.b58_token(8, rng)
        hashed = hashlib.sha256((salt + password).encode()).hexdigest()
        return {"salt": salt, "hashed": hashed}

    @staticmethod
    def check(record, password):
        return hashlib.sha256((record["salt"] + password.strip()).encode()).hexdigest() == record["hashed"]


def eg_encrypt(G, pk, m, rng):
    r = G.random_scalar(rng)
    alpha = G.pow(G.g, r)
    beta = G.mul(G.pow(pk, r), G.pow(G.g, m))
    return {"alpha": alpha, "beta": beta}, r


def eg_partial_decrypt(G, x, ct):
    return G.pow(ct["alpha"], x)
