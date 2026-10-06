import random

_rnd = random.Random(20240601)


def element_of_order(p, q, cofactor, ell, e):
    modulus = ell ** e
    exp = (p - 1) // modulus
    for _ in range(200):
        w = _rnd.randrange(2, p - 1)
        h = pow(w, exp, p)
        if h == 1:
            continue
        if pow(h, modulus // ell, p) != 1:
            return h
    return None


def baby_step_giant_step(p, base, target, order):
    import math
    m = int(math.isqrt(order)) + 1
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = (cur * base) % p
    factor = pow(pow(base, order - 1, p), m, p)
    gamma = target
    for i in range(m):
        if gamma in table:
            return (i * m + table[gamma]) % order
        gamma = (gamma * factor) % p
    return None


def pohlig_hellman_prime_power(p, base, target, ell, e):
    order = ell ** e
    base_inv = pow(base, -1, p)
    gamma = pow(base, ell ** (e - 1), p)
    x = 0
    for k in range(e):
        h_k = (target * pow(base_inv, x, p)) % p
        h_k = pow(h_k, ell ** (e - 1 - k), p)
        d_k = baby_step_giant_step(p, gamma, h_k, ell)
        if d_k is None:
            d_k = 0
        x = (x + d_k * (ell ** k)) % order
    return x % order


def crt_combine(residues):
    x = 0
    M = 1
    for (r, m) in residues:
        if m == 1:
            continue
        x = _crt_pair(x, M, r % m, m)
        M *= m
    return x % M if M > 1 else 0, M


def _crt_pair(r1, m1, r2, m2):
    from math import gcd
    g = gcd(m1, m2)
    if m1 == 1:
        return r2 % m2
    lcm = m1 // g * m2
    diff = (r2 - r1) % m2
    inv = pow(m1 // g, -1, m2 // g)
    x = (r1 + (diff // g * inv % (m2 // g)) * m1) % lcm
    return x
