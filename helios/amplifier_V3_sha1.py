import hashlib
import time
import helios_core as H
from election import Election


def truncated_collision(bits, seed=0):
    import random
    rnd = random.Random(seed)
    seen = {}
    mask = (1 << bits) - 1
    tries = 0
    while True:
        tries += 1
        x = rnd.getrandbits(64)
        d = int(hashlib.sha1(str(x).encode()).hexdigest(), 16) & mask
        if d in seen and seen[d] != x:
            return seen[d], x, tries
        seen[d] = x


def run():
    print("=" * 74)
    print("Helios amplifier : SHA-1 Fiat-Shamir challenges  (flaw H-V3)")
    print("=" * 74)
    rng = H.StrongRandomStub(1)
    e = Election()
    pk = e.setup(rng=rng)
    print("\nAll challenges are int(SHA1(commitments)), a 160-bit value, then used mod q.")
    print("  digest width      : 160 bits")
    print("  subgroup order q  : %d bits" % pk.q.bit_length())
    print("  soundness margin  : the challenge space is 2^160, far below q ~ 2^%d,"
          % pk.q.bit_length())
    print("                      so the random-oracle bound is 2^-160, not 2^-256.")

    print("\nCollision resistance of SHA-1 is broken: identical-prefix ~2^63, chosen-prefix ~2^63.4.")
    print("Demonstrating the birthday mechanism on a truncated digest (real cost cited in paper):")
    for bits in (24, 32, 40):
        t0 = time.perf_counter()
        a, b, tries = truncated_collision(bits, seed=bits)
        dt = time.perf_counter() - t0
        da = int(hashlib.sha1(str(a).encode()).hexdigest(), 16) & ((1 << bits) - 1)
        print("  %2d-bit SHA-1 collision: H(%d)=H(%d)=0x%x found in %d trials (~2^%.1f), %.3fs"
              % (bits, a, b, da, tries, (tries).bit_length() - 1, dt))
    print("\n  A colliding pair of commitment strings yields two ballots the verifier cannot")
    print("  tell apart, which combined with the weak binding of H-V1 widens ballot replay.")
    print("\nRESULT: the 160-bit broken hash removes the random-oracle soundness margin that")
    print("        the Fiat-Shamir proofs assume, amplifying the malleability breaks.")


if __name__ == "__main__":
    run()
