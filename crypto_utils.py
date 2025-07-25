import os
import hashlib
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

class PKIManager:
    """Handles all PKI operations including key generation, certificate creation, and digital signatures"""
    
    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Serialize keys to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem.decode('utf-8'), public_pem.decode('utf-8')
        except Exception as e:
            logger.error(f"Error generating key pair: {str(e)}")
            raise

    @staticmethod
    def create_certificate(username, email, public_key_pem, ca_private_key_pem=None, ca_cert_pem=None):
        """Create X.509 certificate for user"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI File Sharing"),
                x509.NameAttribute(NameOID.COMMON_NAME, username),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
            ])
            
            # If CA keys provided, use them; otherwise self-sign
            if ca_private_key_pem and ca_cert_pem:
                ca_private_key = serialization.load_pem_private_key(
                    ca_private_key_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                ca_cert = x509.load_pem_x509_certificate(
                    ca_cert_pem.encode('utf-8'),
                    backend=default_backend()
                )
                issuer = ca_cert.subject
                signing_key = ca_private_key
            else:
                # Self-signed certificate (for demo purposes)
                private_key_pem, _ = PKIManager.generate_key_pair()
                signing_key = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.RFC822Name(email),
                ]),
                critical=False,
            ).sign(signing_key, hashes.SHA256(), backend=default_backend())
            
            return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        except Exception as e:
            logger.error(f"Error creating certificate: {str(e)}")
            raise

    @staticmethod
    def sign_data(data, private_key_pem):
        """Sign data using private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Error signing data: {str(e)}")
            raise

    @staticmethod
    def verify_signature(data, signature_b64, public_key_pem):
        """Verify signature using public key"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            signature = base64.b64decode(signature_b64)
            
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Error verifying signature: {str(e)}")
            return False

    @staticmethod
    def verify_certificate(cert_pem, ca_cert_pem=None):
        """Verify certificate against CA"""
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Check if certificate is still valid
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False, "Certificate expired or not yet valid"
            
            # If CA certificate provided, verify signature
            if ca_cert_pem:
                ca_cert = x509.load_pem_x509_certificate(
                    ca_cert_pem.encode('utf-8'),
                    backend=default_backend()
                )
                ca_public_key = ca_cert.public_key()
                
                try:
                    ca_public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm
                    )
                except Exception:
                    return False, "Certificate signature verification failed"
            
            return True, "Certificate is valid"
        except Exception as e:
            logger.error(f"Error verifying certificate: {str(e)}")
            return False, f"Certificate verification error: {str(e)}"

    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA256 hash of file for integrity verification"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {str(e)}")
            raise

    @staticmethod
    def encrypt_data(data, public_key_pem):
        """Encrypt data using public key (for small data only due to RSA limitations)"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            encrypted = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Error encrypting data: {str(e)}")
            raise

    @staticmethod
    def decrypt_data(encrypted_data_b64, private_key_pem):
        """Decrypt data using private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            
            encrypted_data = base64.b64decode(encrypted_data_b64)
            
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            raise
