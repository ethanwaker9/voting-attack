import belenios_core as B


def reencrypt(G, pk, ct, s):
    return {"alpha": G.mul(ct["alpha"], G.pow(G.g, s)),
            "beta": G.mul(ct["beta"], G.pow(pk, s))}


def shuffle(G, pk, cts, permutation, reenc_exponents):
    out = [None] * len(cts)
    commitments = []
    for src, dst in enumerate(permutation):
        out[dst] = reencrypt(G, pk, cts[src], reenc_exponents[src])
        commitments.append(G.pow(G.g, reenc_exponents[src]))
    proof = {"cc": commitments, "cc_hat": [G.pow(G.g, e) for e in reenc_exponents],
             "tt_hat": commitments, "t": [G.pow(G.g, 1)]}
    return out, proof


def membership_gate(G, ee, ee_prime, proof):
    for name in ("cc", "cc_hat", "tt_hat", "t"):
        for elt in proof[name]:
            if not G.check(elt):
                return False
    return True


def check_shuffle_proof_structure(G, ee, ee_prime, proof):
    return membership_gate(G, ee, ee_prime, proof)


def taint_output(G, ee_prime, index, torsion):
    tainted = [dict(c) for c in ee_prime]
    tainted[index] = {"alpha": G.mul(tainted[index]["alpha"], torsion),
                      "beta": tainted[index]["beta"]}
    return tainted
