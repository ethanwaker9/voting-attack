import json
import os
import sys
import time
import random

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "helios"))
sys.path.insert(0, os.path.join(HERE, "belenios"))

import helios_core as H
from election import Election as HElection
import attack_A1_malleable_copy as A1
import attack_A2_branch_leak as A2
import attack_A3_subgroup as A3
from common_subgroup import element_of_order, pohlig_hellman_prime_power, crt_combine

import belenios_core as B
import dkg as BD
import mixnet as BM
import attack_B1_setup_channel as B1
import attack_B2_mixnet_subgroup as B2mod

RESULTS = {}
PLOTS = {}


def exp_A1():
    adv, tavg, n = A1.measure_advantage(trials=30, weed=True)
    RESULTS["A1"] = {"advantage": adv, "ms_per_game": tavg, "games": n,
                     "advantage_fixed": 0.0}
    print("A1 advantage=%.3f  %.2f ms/game (n=%d)" % (adv, tavg, n))


def exp_A2():
    adv, fired, total, dt = A2.measure(n_per_side=2500, seed=17)
    theory = (A2.THRESHOLD and 0) or None
    e = HElection()
    rng = H.StrongRandomStub(1)
    pk = e.setup(rng=rng)
    theory = (pk.q - A2.THRESHOLD) / A2.THRESHOLD
    RESULTS["A2"] = {"advantage": adv, "fired": fired, "total": total,
                     "rate": fired / total, "theory": theory, "seconds": dt,
                     "ms_per_ballot": dt * 1000 / total}
    print("A2 advantage=%.4f (theory %.4f)  fired %d/%d" % (adv, theory, fired, total))

    ratios_real = []
    ratios_sim = []
    rng = H.StrongRandomStub(99)
    for _ in range(1500):
        b = e.vote(0, 1, rng=rng)
        ratios_real.append(b.proofs[1]["challenge"] / A2.THRESHOLD)
        ratios_sim.append(b.proofs[0]["challenge"] / A2.THRESHOLD)
    PLOTS["A2_hist"] = {"real": ratios_real, "sim": ratios_sim}


def exp_A3():
    rng = H.StrongRandomStub(5)
    e = HElection()
    pk = e.setup(rng=rng)
    cof = (pk.p - 1) // pk.q
    pps = A3.smooth_prime_factors(cof, limit=2000)
    x_rec, M, dt = A3.confine_and_recover(pk, e.sk, pps)
    std = {"bits": M.bit_length(), "modulus": int(M), "seconds": dt,
           "match": (e.sk.x % M) == x_rec, "prime_powers": pps}

    p, q, g, factors = A3.build_smooth_prime(subgroup_bits=48)
    params = H.Params(p=p, q=q, g=g)
    rng2 = H.StrongRandomStub(9)
    es = HElection(params=params)
    pks = es.setup(rng=rng2)
    cum_bits = []
    residues = []
    t0 = time.perf_counter()
    for (ell, ex) in factors:
        h = element_of_order(p, q, (p - 1) // q, ell, ex)
        published = H.pow(h, es.sk.x, p)
        xmod = pohlig_hellman_prime_power(p, h, published, ell, ex)
        residues.append((xmod, ell ** ex))
        _, Mc = crt_combine(residues)
        cum_bits.append((len(residues), Mc.bit_length(), (time.perf_counter() - t0) * 1000))
    xr, Mfull = crt_combine(residues)
    smooth = {"bits": Mfull.bit_length(), "q_bits": q.bit_length(),
              "full_key": (xr % q) == (es.sk.x % q),
              "seconds": time.perf_counter() - t0, "p_bits": p.bit_length()}
    RESULTS["A3"] = {"standard": std, "smooth": smooth}
    PLOTS["A3_recovery"] = {"cum": cum_bits, "q_bits": q.bit_length()}
    print("A3 std bits=%d  smooth full=%s (%d bits over q=%d)"
          % (std["bits"], smooth["full_key"], smooth["bits"], smooth["q_bits"]))


def exp_B1():
    G = B.belenios_group()
    rng = random.Random(7)
    record = B.Password.make("s3cret-vote-admin", rng)
    wl = ["password", "admin123", "belenios", "s3cret-vote-admin", "zzz"]
    pw, tried, dt = B1.crack_admin_password(record, wl)
    n, t = 4, 3
    seeds = [B.Password.b58_token(22, rng) for _ in range(n)]
    trustees, Y, master = BD.run_dkg(G, seeds, t, rng)
    t0 = time.perf_counter()
    x_rec, M, queries = B1.subgroup_oracle_recover(G, trustees[0].dk, [(2, 1), (3, 1)])
    t_oracle = time.perf_counter() - t0
    targets = [0, 1, 2]
    rs = B1.degenerate_identity_read(G, trustees, targets, rng)
    pts = [(j + 1, rs[j]) for j in targets]
    s_rec = BD.lagrange_reconstruct(G, pts)
    RESULTS["B1"] = {"pw_dict_tries": tried, "pw_ms": dt * 1000,
                     "est_50bit_hours": (2 ** 50) / 1.0e11 / 3600.0,
                     "oracle_modulus": int(M), "oracle_queries": queries,
                     "oracle_match": (trustees[0].dk % M) == x_rec,
                     "oracle_ms": t_oracle * 1000,
                     "degenerate_master_recovered": s_rec == master,
                     "n": n, "t": t}
    print("B1 dk mod %d in %d queries; master via identity read: %s"
          % (M, queries, s_rec == master))


def exp_B2():
    G = B.belenios_group()
    rng = random.Random(5)
    seeds = [B.Password.b58_token(22, rng) for _ in range(1)]
    trustees, Y, s = BD.run_dkg(G, seeds, 1, rng)
    votes = [1, 0, 1, 0, 1]
    cts = [B.eg_encrypt(G, Y, m, rng)[0] for m in votes]
    perm = list(range(len(cts)))
    rng.shuffle(perm)
    reencs = [G.random_scalar(rng) for _ in cts]
    ee_prime, proof = BM.shuffle(G, Y, cts, perm, reencs)
    d = 3
    h = element_of_order(G.p, G.q, (G.p - 1) // G.q, d, 1)
    tainted = BM.taint_output(G, ee_prime, 0, h)
    passes = BM.check_shuffle_proof_structure(G, cts, tainted, proof)
    in_sub = B._pow(tainted[0]["alpha"], G.q, G.p) == 1
    D0 = G.pow(tainted[0]["alpha"], s)
    hx = G.mul(D0, G.inv(G.pow(ee_prime[0]["alpha"], s)))
    residue = pohlig_hellman_prime_power(G.p, h, hx, d, 1)
    aborted = False
    try:
        B2mod.compute_synthetic_factors(G, tainted, s)
    except B2mod.CombinationError:
        aborted = True
    RESULTS["B2"] = {"gate_accepts_torsion": passes, "in_subgroup": in_sub,
                     "order": d, "leaked_residue": residue, "true_residue": s % d,
                     "combiner_aborts": aborted}
    print("B2 gate accepts torsion=%s  leak s mod %d=%d  abort=%s"
          % (passes, d, residue, aborted))


def exp_amplifiers():
    G = B.belenios_group()
    q = G.q
    tw = 1 << 256
    overflow = tw - q
    rng = random.Random(1)
    N = 200000
    lo = sum(1 for _ in range(N) if rng.getrandbits(256) % q < overflow)
    RESULTS["V11"] = {"overrep_fraction": overflow / q,
                      "measured_doubled_share": lo / N,
                      "theory_doubled_share": (2 * overflow) / tw}

    import hashlib
    coll = []
    for bits in (16, 20, 24, 28, 32):
        rnd = random.Random(bits)
        seen = {}
        mask = (1 << bits) - 1
        tries = 0
        t0 = time.perf_counter()
        while True:
            tries += 1
            x = rnd.getrandbits(64)
            dd = int(hashlib.sha1(str(x).encode()).hexdigest(), 16) & mask
            if dd in seen and seen[dd] != x:
                break
            seen[dd] = x
        coll.append((bits, tries, (time.perf_counter() - t0)))
    RESULTS["V3"] = {"digest_bits": 160, "q_bits": G.q.bit_length()}
    PLOTS["V3_collision"] = {"data": coll}
    print("V11 doubled-share measured=%.4f  V3 collisions collected" % (lo / N))


def exp_board_cost():
    rng = H.StrongRandomStub(4)
    e = HElection()
    pk = e.setup(rng=rng)
    sizes = [1, 2, 4, 8, 16, 32, 64, 128]
    construct_ms = []
    verify_ms = []
    ballots = []
    for _ in range(max(sizes)):
        b = e.vote(0, rng._r.randint(0, 1) if hasattr(rng, "_r") else 0, rng=rng)
        ballots.append(b)
    from attack_A1_malleable_copy import maul_ballot
    obs = ballots[0]
    t0 = time.perf_counter()
    for _ in range(20):
        s = H.random_mpz_lt(pk.q, rng)
        maul_ballot(pk, obs.ct, obs.proofs, s)
    construct_one = (time.perf_counter() - t0) / 20 * 1000
    for n in sizes:
        t0 = time.perf_counter()
        for b in ballots[:n]:
            H.verify_ballot_choice(pk, b.ct, b.proofs)
        verify_ms.append((n, (time.perf_counter() - t0) * 1000))
    PLOTS["board_cost"] = {"verify": verify_ms, "construct_one_ms": construct_one}
    print("board cost: construct one mauled ballot=%.3f ms" % construct_one)


def main():
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    exp_A1()
    exp_A2()
    exp_A3()
    exp_B1()
    exp_B2()
    exp_amplifiers()
    exp_board_cost()
    with open(os.path.join(HERE, "results", "results.json"), "w") as f:
        json.dump(RESULTS, f, indent=2)
    with open(os.path.join(HERE, "results", "plotdata.json"), "w") as f:
        json.dump(PLOTS, f)
    print("\nwrote results/results.json and results/plotdata.json")


if __name__ == "__main__":
    main()
