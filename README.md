# emudhra-ecdsa-intermediates

实验室工具链：2026 eMudhra 弱 P-384 中间 CA 相关证书、私钥恢复与测试叶子证签发。

**仅供授权安全研究。** 公开 WebPKI 已吊销/封禁该链，不得用于生产或冒充第三方。

## 目录

| 路径 | 说明 |
|------|------|
| `EM_*TLS*.pem` | 8 张 TLS 中间 CA（公钥证书） |
| `recovered-private-keys/` | 枚举恢复的中间 CA 私钥 |
| `recover_private_keys.py` | 从公钥证书恢复弱标量私钥 |
| `issue_lab_cert.py` | 交互式签发叶子证（Nginx / Apache / IIS 等） |
| `ca-bundle/` | `emSign Root TLS CA - G3` 根证书 |

## 依赖

- Python 3.10+
- `cryptography`

## 用法

```bash
python recover_private_keys.py
python issue_lab_cert.py --list-ca
python issue_lab_cert.py -d example.test -c "EM DV TLS CA - G3C" -f nginx
```

## 免责

事件背景见 Mozilla [Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)。使用者须遵守当地法律与授权范围。