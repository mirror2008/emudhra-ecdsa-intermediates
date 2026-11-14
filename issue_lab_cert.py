#!/usr/bin/env python3
"""
实验室用：用已恢复的中间 CA 为指定域名签发 TLS 叶子证书并导出多种服务器格式。
仅限授权测试环境使用。
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

BASE = Path(__file__).resolve().parent
KEYS = BASE / "recovered-private-keys"
ISSUE_OUT = BASE / "issued"
ROOT_PEM = BASE / "ca-bundle" / "emSign_Root_TLS_CA_G3.pem"
ROOT_SHA256 = "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d"

@dataclass(frozen=True)
class TLSIntermediateCA:
    name: str
    cert_file: str
    key_file: str
    validation: str  # DV / OV / EV
    series: str  # G3B / G3C
    org: str
    country: str
    emsign_policy_oid: str
    cabf_policy_oid: str
    weak_scalar: int
    use_for: str


TLS_INTERMEDIATES: list[TLSIntermediateCA] = [
    TLSIntermediateCA(
        name="EM DV TLS CA - G3B",
        cert_file="EM_DV_TLS_CA_-_G3B.pem",
        key_file="EM_DV_TLS_CA_-_G3B_d156.pem",
        validation="DV",
        series="G3B",
        org="eMudhra BV",
        country="NL",
        emsign_policy_oid="1.3.6.1.4.1.50977.1.2.100",
        cabf_policy_oid="2.23.140.1.2.1",
        weak_scalar=156,
        use_for="签 HTTPS 普通域名证 (DV)，荷兰主体",
    ),
    TLSIntermediateCA(
        name="EM DV TLS CA - G3C",
        cert_file="EM_DV_TLS_CA_-_G3C.pem",
        key_file="EM_DV_TLS_CA_-_G3C_d230.pem",
        validation="DV",
        series="G3C",
        org="eMudhra Inc",
        country="US",
        emsign_policy_oid="1.3.6.1.4.1.50977.1.2.100",
        cabf_policy_oid="2.23.140.1.2.1",
        weak_scalar=230,
        use_for="签 HTTPS 普通域名证 (DV)，美国主体",
    ),
    TLSIntermediateCA(
        name="EM OV TLS CA - G3B",
        cert_file="EM_OV_TLS_CA_-_G3B.pem",
        key_file="EM_OV_TLS_CA_-_G3B_d155.pem",
        validation="OV",
        series="G3B",
        org="eMudhra BV",
        country="NL",
        emsign_policy_oid="1.3.6.1.4.1.50977.1.2.110",
        cabf_policy_oid="2.23.140.1.2.2",
        weak_scalar=155,
        use_for="签带公司名称的 HTTPS 证 (OV)，荷兰主体",
    ),
    TLSIntermediateCA(
        name="EM OV TLS CA - G3C",
        cert_file="EM_OV_TLS_CA_-_G3C.pem",
        key_file="EM_OV_TLS_CA_-_G3C_d4.pem",
        validation="OV",
        series="G3C",
        org="eMudhra Inc",
        country="US",
        emsign_policy_oid="1.3.6.1.4.1.50977.1.2.110",
        cabf_policy_oid="2.23.140.1.2.2",
        weak_scalar=4,
        use_for="签带公司名称的 HTTPS 证 (OV)，美国主体",
    ),
    TLSIntermediateCA(
        name="EM EV TLS CA - G3B",
        cert_file="EM_EV_TLS_CA_-_G3B.pem",
        key_file="EM_EV_TLS_CA_-_G3B_d115.pem",
        validation="EV",
        series="G3B",
        org="eMudhra BV",
        country="NL",
        emsign_policy_oid="1.3.6.1.4.1.50977.1.2.120",
        cabf_policy_oid="2.23.140.1.1",
        weak_scalar=115,
        use_for="签高端 EV 网站证（实验模拟），荷兰主体",
    ),
    TLSIntermediateCA(
        name="EM EV TLS CA - G3C",
        cert_file="EM_EV_TLS_CA_-_G3C.pem",
        key_file="EM_EV_TLS_CA_-_G3C_d56.pem",
        validation="EV",
        series="G3C",
        org="eMudhra Inc",
        country="US",
        emsign_policy_oid="1.3.6.1.4.1.50977.1.2.120",
        cabf_policy_oid="2.23.140.1.1",
        weak_scalar=56,
        use_for="签高端 EV 网站证（实验模拟），美国主体",
    ),
]


def print_tls_ca_comparison() -> None:
    print("\n=== 能用来干啥（六张都是签网站 HTTPS，不能签代码/下级 CA）===\n")
    print("  DV → 普通域名证书")
    print("  OV → 带公司信息的证书")
    print("  EV → 曾经是“绿条”那种 EV 网站证（做实验用）")
    print("  G3B / G3C → 荷兰 vs 美国分公司，功能相同、密钥不同\n")
    for i, ca in enumerate(TLS_INTERMEDIATES, 1):
        print(f"  {i}. {ca.name}")
        print(f"     → {ca.use_for}")
    print()

OUTPUT_FORMATS = {
    "1": ("nginx", "Nginx（仅 fullchain.pem + privkey.pem）"),
    "2": ("apache", "Apache httpd（与 Nginx 相同 PEM 布局 + 说明）"),
    "3": ("iis", "IIS（certificate.pfx，PKCS#12）"),
    "4": ("pem", "通用 PEM（leaf / key / chain / fullchain 分开）"),
    "5": ("haproxy", "HAProxy（单文件 cert+key+chain 合并）"),
    "6": ("caddy", "Caddy（与 Nginx 相同，附带 Caddyfile 片段）"),
}

KEY_ALG_CHOICES = {
    "1": ("ec_p384", "EC P-384（与中间 CA 同曲线）"),
    "2": ("rsa2048", "RSA 2048（更广泛兼容）"),
}


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower().rstrip(".")
    if not d or " " in d or "@" in d:
        raise ValueError("域名格式无效")
    if not re.fullmatch(r"\*?(\*|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.(\*|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?))*", d):
        raise ValueError("域名包含非法字符")
    return d


def load_root_cert() -> x509.Certificate:
    if not ROOT_PEM.is_file():
        ROOT_PEM.parent.mkdir(parents=True, exist_ok=True)
        print(f"正在下载根证书到 {ROOT_PEM} …")
        raw = urllib.request.urlopen(
            f"https://crt.sh/?d={ROOT_SHA256}", timeout=120
        ).read()
        ROOT_PEM.write_bytes(raw if raw.endswith(b"\n") else raw + b"\n")
    cert = x509.load_pem_x509_certificate(ROOT_PEM.read_bytes())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != "emSign Root TLS CA - G3":
        raise ValueError(f"根证书 CN 异常: {cn}")
    return cert


def load_issuer(name: str) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    match = next((t for t in TLS_INTERMEDIATES if t.name == name), None)
    if not match:
        raise KeyError(name)
    cert = x509.load_pem_x509_certificate((BASE / match.cert_file).read_bytes())
    key = serialization.load_pem_private_key(
        (KEYS / match.key_file).read_bytes(), password=None
    )
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("中间 CA 私钥应为 EC")
    return cert, key


def build_san_list(domain: str, add_www: bool) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = [x509.DNSName(domain)]
    if domain.startswith("*."):
        return names
    if add_www and not domain.startswith("www."):
        names.append(x509.DNSName(f"www.{domain}"))
    return names


def generate_leaf_key(choice: str) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    if choice == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP384R1())


def ski_from_key(public_key) -> x509.SubjectKeyIdentifier:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return x509.SubjectKeyIdentifier(digest.finalize())


def issue_leaf(
    domain: str,
    issuer_cert: x509.Certificate,
    issuer_key: ec.EllipticCurvePrivateKey,
    leaf_key,
    days: int,
    add_www: bool,
) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    issuer_ski = issuer_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value

    pub = leaf_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=isinstance(pub, ec.EllipticCurvePublicKey),
                content_commitment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(build_san_list(domain, add_www)), critical=False)
        .add_extension(ski_from_key(pub), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
            critical=False,
        )
    )
    return builder.sign(issuer_key, hashes.SHA384())


def pem(cert_or_key) -> bytes:
    if isinstance(cert_or_key, x509.Certificate):
        return cert_or_key.public_bytes(serialization.Encoding.PEM)
    return cert_or_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def write_nginx_minimal(
    out_dir: Path,
    leaf_cert: x509.Certificate,
    leaf_key,
    issuer_cert: x509.Certificate,
) -> None:
    """Nginx: ssl_certificate + ssl_certificate_key（站点证 + 中间 CA，不含根）。"""
    (out_dir / "fullchain.pem").write_bytes(pem(leaf_cert) + pem(issuer_cert))
    (out_dir / "privkey.pem").write_bytes(pem(leaf_key))


def write_panel_bundle(
    out_dir: Path,
    leaf_cert: x509.Certificate,
    leaf_key,
    issuer_cert: x509.Certificate,
    root_cert: x509.Certificate,
) -> None:
    leaf = pem(leaf_cert)
    key = pem(leaf_key)
    intermediate = pem(issuer_cert)
    root = pem(root_cert)
    issuer_chain = intermediate + root
    (out_dir / "privkey.pem").write_bytes(key)
    (out_dir / "cert.pem").write_bytes(leaf)
    (out_dir / "intermediate.pem").write_bytes(intermediate)
    (out_dir / "root.pem").write_bytes(root)
    (out_dir / "chain.pem").write_bytes(issuer_chain)
    (out_dir / "fullchain.pem").write_bytes(leaf + issuer_chain)
    (out_dir / "panel-import.txt").write_text(
        "面板拆分上传：\n"
        f"  证书/站点证书 → cert.pem\n"
        f"  证书链/中间证书/CA证书 → chain.pem（中间CA+根，勿只上传 leaf）\n"
        f"  私钥 → privkey.pem\n"
        "单文件上传：\n"
        f"  fullchain.pem + privkey.pem\n",
        encoding="utf-8",
    )


def write_apache_layout(
    out_dir: Path, leaf_cert, leaf_key, issuer_cert, root_cert, domain: str
) -> None:
    write_panel_bundle(out_dir, leaf_cert, leaf_key, issuer_cert, root_cert)
    snippet = f"""# Apache 2.4+ 实验室配置片段
SSLCertificateFile "{out_dir / "cert.pem"}"
SSLCertificateKeyFile "{out_dir / "privkey.pem"}"
SSLCertificateChainFile "{out_dir / "chain.pem"}"
"""
    (out_dir / "apache-snippet.conf").write_text(snippet, encoding="utf-8")


def write_iis_pfx(
    out_dir: Path,
    leaf_cert: x509.Certificate,
    leaf_key,
    issuer_cert: x509.Certificate,
    root_cert: x509.Certificate,
    password: str | None,
) -> None:
    enc = (
        serialization.NoEncryption()
        if not password
        else serialization.BestAvailableEncryption(password.encode())
    )
    pfx = pkcs12.serialize_key_and_certificates(
        name=b"lab-leaf",
        key=leaf_key,
        cert=leaf_cert,
        cas=[issuer_cert, root_cert],
        encryption_algorithm=enc,
    )
    (out_dir / "certificate.pfx").write_bytes(pfx)
    (out_dir / "iis-import.txt").write_text(
        "IIS：服务器证书 → 导入 → 选择 certificate.pfx\n"
        + ("密码：已设置（导入时输入）\n" if password else "密码：无\n"),
        encoding="utf-8",
    )


def write_haproxy(out_dir: Path, leaf_cert, leaf_key, issuer_cert, root_cert) -> None:
    blob = pem(leaf_cert) + pem(leaf_key) + pem(issuer_cert) + pem(root_cert)
    (out_dir / "haproxy.pem").write_bytes(blob)
    (out_dir / "haproxy.txt").write_text(
        f"bind *:443 ssl crt {out_dir / 'haproxy.pem'}\n", encoding="utf-8"
    )


def write_caddy(out_dir: Path, leaf_cert, leaf_key, issuer_cert, root_cert, domain: str) -> None:
    write_nginx_minimal(out_dir, leaf_cert, leaf_key, issuer_cert)
    block = f"""{domain} {{
    tls {out_dir / "fullchain.pem"} {out_dir / "privkey.pem"}
    respond "lab" 200
}}
"""
    (out_dir / "Caddyfile.snippet").write_text(block, encoding="utf-8")


def write_pem_bundle(out_dir: Path, leaf_cert, leaf_key, issuer_cert, root_cert) -> None:
    (out_dir / "leaf.pem").write_bytes(pem(leaf_cert))
    (out_dir / "leaf-key.pem").write_bytes(pem(leaf_key))
    (out_dir / "intermediate.pem").write_bytes(pem(issuer_cert))
    (out_dir / "root.pem").write_bytes(pem(root_cert))
    (out_dir / "chain.pem").write_bytes(pem(issuer_cert) + pem(root_cert))
    (out_dir / "fullchain.pem").write_bytes(
        pem(leaf_cert) + pem(issuer_cert) + pem(root_cert)
    )


def pick_interactive() -> tuple[str, str, str, str, bool, int, str]:
    print_tls_ca_comparison()
    print("=== 请选择签发所用中间 CA ===\n")
    for i, ca in enumerate(TLS_INTERMEDIATES, 1):
        print(f"  {i}. {ca.name} — {ca.use_for}")
    idx = input("\n选择编号 [1-6]（默认 1）: ").strip() or "1"
    if idx not in {str(i) for i in range(1, 7)}:
        sys.exit("无效的中间 CA 编号")
    ca_name = TLS_INTERMEDIATES[int(idx) - 1].name

    domain = input("\n请输入域名: ").strip()
    domain = normalize_domain(domain)

    print("\n=== 叶子密钥算法 ===\n")
    for k, (_, label) in KEY_ALG_CHOICES.items():
        print(f"  {k}. {label}")
    ka = input("选择 [1-2]（默认 2 rsa2048）: ").strip() or "2"
    if ka not in KEY_ALG_CHOICES:
        sys.exit("无效密钥类型")

    print("\n=== 输出格式 ===\n")
    for k, (_, label) in OUTPUT_FORMATS.items():
        print(f"  {k}. {label}")

    fmt = input("选择 [1-6]（默认 1 nginx）: ").strip() or "1"
    if fmt not in OUTPUT_FORMATS:
        sys.exit("无效输出格式")
    fmt_id = OUTPUT_FORMATS[fmt][0]

    add_www_ans = input("自动加入 www. 前缀到 SAN？[Y/n]: ").strip().lower()
    add_www = add_www_ans != "n"

    days_s = input("有效期天数（默认 90）: ").strip() or "90"
    days = int(days_s)
    return domain, ca_name, KEY_ALG_CHOICES[ka][0], fmt_id, add_www, days, ""


def export_all(
    fmt: str,
    out_dir: Path,
    leaf_cert,
    leaf_key,
    issuer_cert,
    root_cert,
    domain: str,
    pfx_password: str | None,
) -> list[str]:
    written: list[str] = []
    if fmt in ("nginx",):
        write_nginx_minimal(out_dir, leaf_cert, leaf_key, issuer_cert)
        written += ["fullchain.pem", "privkey.pem"]
    elif fmt == "apache":
        write_apache_layout(out_dir, leaf_cert, leaf_key, issuer_cert, root_cert, domain)
        written += [
            "cert.pem",
            "privkey.pem",
            "chain.pem",
            "panel-import.txt",
            "apache-snippet.conf",
        ]
    elif fmt == "iis":
        write_iis_pfx(out_dir, leaf_cert, leaf_key, issuer_cert, root_cert, pfx_password)
        written += ["certificate.pfx", "iis-import.txt"]
    elif fmt == "pem":
        write_pem_bundle(out_dir, leaf_cert, leaf_key, issuer_cert, root_cert)
        written += [
            "leaf.pem",
            "leaf-key.pem",
            "intermediate.pem",
            "root.pem",
            "chain.pem",
            "fullchain.pem",
        ]
    elif fmt == "haproxy":
        write_haproxy(out_dir, leaf_cert, leaf_key, issuer_cert, root_cert)
        written += ["haproxy.pem", "haproxy.txt"]
    elif fmt == "caddy":
        write_caddy(out_dir, leaf_cert, leaf_key, issuer_cert, root_cert, domain)
        written += ["fullchain.pem", "privkey.pem", "Caddyfile.snippet"]
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="实验室 TLS 叶子证书签发")
    parser.add_argument("-d", "--domain", help="域名")
    parser.add_argument("-c", "--ca", help="中间 CA 名称（见 TLS_INTERMEDIATES）")
    parser.add_argument(
        "-f",
        "--format",
        choices=[v[0] for v in OUTPUT_FORMATS.values()],
        help="输出格式",
    )
    parser.add_argument("--key-alg", choices=["ec_p384", "rsa2048"], default="rsa2048")
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--no-www-san", action="store_true")
    parser.add_argument("--pfx-password", help="IIS PFX 密码（空则交互询问）")
    parser.add_argument("-o", "--output", type=Path, help="输出目录")
    parser.add_argument(
        "--list-ca",
        action="store_true",
        help="打印六张中间 CA 用途说明后退出",
    )
    args = parser.parse_args()

    if args.list_ca:
        print_tls_ca_comparison()
        return

    if args.domain and args.ca and args.format:
        domain = normalize_domain(args.domain)
        ca_name = args.ca
        fmt = args.format
        key_alg = args.key_alg
        add_www = not args.no_www_san
        days = args.days
    else:
        domain, ca_name, key_alg, fmt, add_www, days, _ = pick_interactive()

    ca_meta = next((t for t in TLS_INTERMEDIATES if t.name == ca_name), None)
    if ca_meta is None:
        sys.exit(f"未知中间 CA: {ca_name}")

    issuer_cert, issuer_key = load_issuer(ca_name)
    root_cert = load_root_cert()
    if issuer_cert.issuer != root_cert.subject:
        sys.exit("中间 CA 与本地根证书不匹配，请更新 ca-bundle。")
    leaf_key = generate_leaf_key(key_alg)
    leaf_cert = issue_leaf(domain, issuer_cert, issuer_key, leaf_key, days, add_www)

    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", domain)[:120]
    out_dir = args.output or (ISSUE_OUT / safe)
    out_dir.mkdir(parents=True, exist_ok=True)

    pfx_pw: str | None = None
    if fmt == "iis":
        if args.pfx_password is not None:
            pfx_pw = args.pfx_password
        else:
            pfx_pw = getpass.getpass("PFX 密码（直接回车=无密码）: ")
            if not pfx_pw:
                pfx_pw = None

    files = export_all(
        fmt, out_dir, leaf_cert, leaf_key, issuer_cert, root_cert, domain, pfx_pw
    )

    meta = {
        "domain": domain,
        "issuer_cn": issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "issuer_validation": ca_meta.validation,
        "issuer_series": ca_meta.series,
        "issuer_org": ca_meta.org,
        "issuer_emsign_policy_oid": ca_meta.emsign_policy_oid,
        "issuer_cabf_policy_oid": ca_meta.cabf_policy_oid,
        "leaf_serial": hex(leaf_cert.serial_number),
        "not_after": leaf_cert.not_valid_after_utc.isoformat(),
        "san": [n.value for n in leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value],
        "format": fmt,
        "output_dir": str(out_dir),
        "files": files,
        "warning": "仅供授权实验室使用；公开信任链已被吊销/封禁。",
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n完成。输出目录: {out_dir}")
    print(f"中间 CA: {meta['issuer_cn']} — {ca_meta.use_for}")
    print(f"SAN: {', '.join(meta['san'])}")
    for name in files:
        print(f"  - {name}")
    print("\n注意：浏览器/系统默认不信任此链；仅在自建信任库环境中测试。")


if __name__ == "__main__":
    main()