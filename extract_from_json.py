import json
import re
from pathlib import Path

SRC = Path(
    r"C:\Users\Mirror\.cursor\projects\c-Users-Mirror-Desktop-Working"
    r"\agent-tools\3118b2b9-a0c9-4625-b443-b557edb45202.txt"
)
OUT = Path(__file__).resolve().parent

def main() -> None:
    data = json.loads(SRC.read_text(encoding="utf-8"))
    seen: dict[str, str] = {}
    for item in data:
        if item.get("issuer_operator") != "eMudhra":
            continue
        name = item["name"]
        if name in seen:
            continue
        pem = item["pem"].replace("\\n", "\n")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
        (OUT / f"{safe}.pem").write_text(pem, newline="\n")
        seen[name] = item["spki_sha256"]

    lines = [f"{n}\tspki_sha256={s}" for n, s in sorted(seen.items())]
    (OUT / "README.txt").write_text(
        "8 affected ECDSA intermediate CAs (eMudhra-issued chain only).\n"
        "Source: galadran/we-have-a-problem.com impacted-intermediates.json\n"
        "Status: revoked 2026-10-18 (ca_compromise)\n\n"
        + "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(seen)} PEM files to {OUT}")
    for p in sorted(OUT.glob("*.pem")):
        print(p.name)

if __name__ == "__main__":
    main()