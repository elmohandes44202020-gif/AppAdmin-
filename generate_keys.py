#!/usr/bin/env python3
"""
generate_keys.py — يولد كل مفاتيح BAYAN Licensed مرة واحدة
الاستخدام:
  python generate_keys.py
  python generate_keys.py --pepper --show-env
"""
import base64
import secrets
import argparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

def generate_ed25519():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(priv_der).decode(), base64.b64encode(pub_der).decode()

def generate_pepper(n=48):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%_"
    return ''.join(secrets.choice(alphabet) for _ in range(n))

def generate_secret(n=32):
    return secrets.token_urlsafe(n)

def main():
    ap = argparse.ArgumentParser(description="Generate BAYAN Licensed keys")
    ap.add_argument('--pepper', action='store_true', help='Also generate ACTIVATION_CODE_PEPPER')
    ap.add_argument('--show-env', action='store_true', help='Print as .env lines')
    args = ap.parse_args()

    priv_b64, pub_b64 = generate_ed25519()
    pepper = generate_pepper()
    webhook_secret = generate_secret(32)
    key_id = "2026-01"

    print("\n" + "="*62)
    print("  BAYAN Licensed — مفاتيح السيرفر (احفظها ولا ترفعها على Git)")
    print("="*62 + "\n")

    # Env format for Faable Variables
    env_lines = [
        f"GRANT_PRIVATE_KEY_B64={priv_b64}",
        f"GRANT_PUBLIC_KEY_B64={pub_b64}",
        f"GRANT_KEY_ID={key_id}",
        f"ACTIVATION_CODE_PEPPER={pepper}",
        f"TELEGRAM_WEBHOOK_SECRET={webhook_secret}",
    ]
    for line in env_lines:
        print(line)

    print("\n" + "-"*62)
    print("  للـ Flutter (BAYAN Licensed) — ضع هذا في البناء:")
    print("-"*62)
    print(f"داخل tool/encrypt_config.dart:")
    print(f"  --server https://YOUR-APP.faable.app")
    print(f"  --publicKey {pub_b64}")
    print(f"  --keyId {key_id}")
    print(f"  --product bayan")

    print("\n" + "-"*62)
    print("  ملاحظات:")
    print("-"*62)
    print("• PRIVATE_KEY للسيرفر فقط (Faable Variables) — لا تضعه في APK أبداً")
    print("• PUBLIC_KEY للموبايل (آمن) — يُدمج مشفر داخل APK")
    print("• PEPPER يجب أن يكون 32+ حرف عشوائي — لا تغيره بعد إنشاء تراخيص")
    print("• احفظ الناتج في مكان آمن (password manager)")

    # Save to file for convenience
    out = "generated_keys.env"
    with open(out, "w") as f:
        for line in env_lines:
            f.write(line+"\n")
        f.write(f"\n# For Flutter encrypt_config\n")
        f.write(f"# --publicKey {pub_b64}\n")
    print(f"\n✓ حُفظ أيضاً في {out} (لا ترفعه على GitHub)")

if __name__ == "__main__":
    main()
