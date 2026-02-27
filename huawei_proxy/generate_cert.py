import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_ca_certificate(output_dir="certs"):
    os.makedirs(output_dir, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Mexico"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Megacable"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Huawei ONT Proxy CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Huawei ONT Interceptor Root CA"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    cert_path = os.path.join(output_dir, "mitmproxy-ca-cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    key_path = os.path.join(output_dir, "mitmproxy-ca-cert.key")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    cer_path = os.path.join(output_dir, "mitmproxy-ca-cert.cer")
    with open(cer_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    print(f"CA certificate generated successfully!")
    print(f"Certificate: {cert_path}")
    print(f"Private key: {key_path}")
    print(f"Windows installer: {cer_path}")
    print(f"\nTo install on Windows 11, run:")
    print(f"  powershell -ExecutionPolicy Bypass -File install_cert.ps1")

    return cert_path, key_path, cer_path

if __name__ == "__main__":
    generate_ca_certificate()
