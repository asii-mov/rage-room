"""CA and host certificate generation for TLS interception."""

import datetime
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


CERTS_DIR = Path.home() / ".no-keys"
CA_CERT_PATH = CERTS_DIR / "ca.pem"
CA_KEY_PATH = CERTS_DIR / "ca-key.pem"


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Generate a CA certificate and key. Saves to ~/.no-keys/."""
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    key = _generate_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "no-keys proxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "no-keys"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    CA_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    CA_KEY_PATH.chmod(0o600)

    return cert, key


def load_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Load existing CA or generate a new one."""
    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
        return cert, key
    return generate_ca()


def generate_host_cert(
    hostname: str,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
) -> tuple[bytes, bytes]:
    """Generate a TLS cert for a hostname, signed by the CA.

    Returns (cert_pem, key_pem) as bytes.
    """
    key = _generate_key()
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem
