import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

STEPS = [
    ("Helios reference election (end-to-end)", ["helios", "election.py"]),
    ("Helios A1 : malleable-copy replay (H-V1)", ["helios", "attack_A1_malleable_copy.py"]),
    ("Helios A2 : simulation-branch leakage (H-V2)", ["helios", "attack_A2_branch_leak.py"]),
    ("Helios A3 : small-subgroup key recovery (H-V4)", ["helios", "attack_A3_subgroup.py"]),
    ("Helios amplifier : SHA-1 challenges (H-V3)", ["helios", "amplifier_V3_sha1.py"]),
    ("Belenios reference election (end-to-end)", ["belenios", "dkg.py"]),
    ("Belenios B1 : setup-channel compromise (B-V3,B-V5)", ["belenios", "attack_B1_setup_channel.py"]),
    ("Belenios B2 : mixnet torsion injection (B-V9,B-V4)", ["belenios", "attack_B2_mixnet_subgroup.py"]),
    ("Belenios amplifiers : B-V1, B-V2, B-V11", ["belenios", "amplifiers.py"]),
]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for title, (folder, script) in STEPS:
        if only and only.lower() not in (folder + "/" + script).lower() and only.lower() not in title.lower():
            continue
        print("\n" + "#" * 74)
        print("# " + title)
        print("#" * 74)
        sys.stdout.flush()
        cwd = os.path.join(HERE, folder)
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(HERE, "helios") + os.pathsep + env.get("PYTHONPATH", "")
        subprocess.run([sys.executable, script], cwd=cwd, env=env)


if __name__ == "__main__":
    main()
