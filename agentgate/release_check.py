import argparse
from pathlib import Path

REQUIRED = ["legal_cra_classification.md","export_classification.md","psirt_contract.md","vuln_disclosure_contact.md","release_key_ceremony.md","design_partner_terms.md","privacy_review.md"]

def check(directory):
    directory = Path(directory); missing = []
    for name in REQUIRED:
        path = directory / name
        if not path.is_file() or "Signed-off-by:" not in path.read_text(errors="replace"):
            missing.append(name)
    return missing

def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument("--evidence-dir", default="evidence")
    args = parser.parse_args(argv); missing = check(args.evidence_dir)
    if missing:
        print("NO RELEASE: missing signed human evidence:")
        for name in missing: print("- " + name)
        return 1
    print("Release evidence gate passed."); return 0
if __name__ == "__main__": raise SystemExit(main())
