from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os


SERVER_PUBLIC_KEY_FILE = 'server_public_key.pem'
DH_PRIVATE_KEY_FILE = 'dh_private_key.pem'
RSA_PRIVATE_KEY_FILE = 'rsa_private_key.pem'


class Crypto:
    """
    Cryptography class for the client.
    Using Diffie-Hellman's algorithm for a shared secret,
    Using HKDF to derive a cryptographic key
    Using AESGCM to encrypt and decrypt a message with the cryptographic key that we derived.

    Attributes:
        server_public_key (bytes): The RSA public key of the server
        recipient_dh_key (bytes): The dh public key of the recipient (for the shared secret)
        sender_keys (dict): A dictionary of a different client's public DH and RSA keys.
        dh_private (X25519PrivateKey) The DH private key of the client
        dh_public (X25519PublicKey) The DH public key of the client

    """
    def __init__(self):
        self.server_public_key = None
        self.recipient_dh_key = None
        self.sender_keys = {}

        # Try to load existing keys first
        try:
            self.load_private_keys()
        except FileNotFoundError:
            # Generate new keys if files don't exist
            # Generate static DH key pair
            self.dh_private = x25519.X25519PrivateKey.generate()
            self.dh_public = self.dh_private.public_key()

            # Generate RSA key pair for signatures only
            self.signing_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            self.signing_public = self.signing_key.public_key()
            self.save_private_keys()

    def save_private_keys(self, password: bytes = None):
        """Save private keys to files"""
        # Serialize DH private key
        dh_pem = self.dh_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password
            else serialization.NoEncryption()
        )

        # Serialize RSA private key
        rsa_pem = self.signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password
            else serialization.NoEncryption()
        )

        # Save to files
        with open(DH_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(dh_pem)

        with open(RSA_PRIVATE_KEY_FILE, 'wb') as f:
            f.write(rsa_pem)

    def load_private_keys(self, password: bytes = None):
        """Load private keys from files"""
        try:
            # Load DH private key
            with open(DH_PRIVATE_KEY_FILE, 'rb') as f:
                dh_pem = f.read()
                self.dh_private = serialization.load_pem_private_key(
                    dh_pem,
                    password=password
                )
                self.dh_public = self.dh_private.public_key()

            # Load RSA private key
            with open(RSA_PRIVATE_KEY_FILE, 'rb') as f:
                rsa_pem = f.read()
                self.signing_key = serialization.load_pem_private_key(
                    rsa_pem,
                    password=password
                )
                self.signing_public = self.signing_key.public_key()

        except FileNotFoundError:
            raise FileNotFoundError("Private key files not found")
        except ValueError as e:
            raise ValueError(f"Error loading private keys: {str(e)}")

    def load_server_public_key(self):
        """ Load the server's RSA public key from a file """
        if os.path.exists(SERVER_PUBLIC_KEY_FILE):
            with open(SERVER_PUBLIC_KEY_FILE, 'rb') as f:
                self.server_public_key = serialization.load_pem_public_key(f.read())
        else:
            raise FileNotFoundError('Server public key file not found')

    def get_public_keys(self):
        """Export our DH and RSA public keys for sharing"""
        dh_bytes = self.dh_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        signing_bytes = self.signing_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return dh_bytes, signing_bytes

    def compute_shared_secret(self, other_public_bytes):
        """Compute the shared secret using our private and their public DH key"""
        other_public = x25519.X25519PublicKey.from_public_bytes(other_public_bytes)
        shared_secret = self.dh_private.exchange(other_public)
        return shared_secret

    def derive_keys(self, shared_secret, salt=None):
        """Derive encryption keys from the shared secret"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # for AES-256
            salt=salt,
            info=b"message_encryption"
        )
        return hkdf.derive(shared_secret)

    def encrypt_message(self, message: str):
        """Encrypt a message for a recipient"""
        try:
            # Compute shared secret
            shared_secret = self.compute_shared_secret(self.recipient_dh_key)

            # Generate salt and derive encryption key
            salt = os.urandom(16)
            encryption_key = self.derive_keys(shared_secret, salt)

            # Encrypt the message
            aesgcm = AESGCM(encryption_key)
            nonce = os.urandom(12)
            message_bytes = message.encode('utf-8')
            ciphertext = aesgcm.encrypt(nonce, message_bytes, None)

            # Sign the ciphertext
            signature = self.signing_key.sign(
                ciphertext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return {
                'salt': salt,
                'nonce': nonce,
                'ciphertext': ciphertext,
                'signature': signature
            }

        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt_message(self, encrypted_data: dict, sender_dh_key: bytes,
                        sender_signing_key: bytes):
        """Decrypt a message from a sender"""
        try:
            # Load sender's signing key
            sender_signing_key = serialization.load_pem_public_key(sender_signing_key)

            # Verify signature
            try:
                sender_signing_key.verify(
                    encrypted_data['signature'],
                    encrypted_data['ciphertext'],
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidTag:
                raise Exception("Invalid signature - message may be tampered with")

            # Compute shared secret
            shared_secret = self.compute_shared_secret(sender_dh_key)

            # Derive encryption key
            encryption_key = self.derive_keys(shared_secret, encrypted_data['salt'])

            # Decrypt message
            aesgcm = AESGCM(encryption_key)
            decrypted = aesgcm.decrypt(
                encrypted_data['nonce'],
                encrypted_data['ciphertext'],
                None
            )

            return decrypted.decode('utf-8')

        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def verify_signed_key(self, client_public_key, signature):
        """ Verify the signature of a signed key """
        try:
            self.server_public_key.verify(
                signature,
                client_public_key,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            print("Signature verification failed.")
            return False

    @staticmethod
    def pack_encrypted_message(encrypted_data: dict) -> bytes:
        """
        Pack the encrypted message components into a single bytes object.
        Format: [salt(16)][nonce(12)][signature(N)][ciphertext]
        where N is your RSA key size in bytes (e.g., 256 for RSA-2048)

        Args:
            encrypted_data: Dictionary containing salt, nonce, ciphertext, and signature

        Returns:
            Bytes object containing all components packed together
        """
        salt = encrypted_data['salt']  # Always 16 bytes
        nonce = encrypted_data['nonce']  # Always 12 bytes
        signature = encrypted_data['signature']  # Fixed length based on RSA key size
        ciphertext = encrypted_data['ciphertext']

        return salt + nonce + signature + ciphertext

    @staticmethod
    def unpack_encrypted_message(packed_data: bytes, signature_size: int) -> dict:
        """
        Unpack the message back into its components.

        Args:
            packed_data: Bytes object containing the packed message
            signature_size: Size of the signature in bytes (e.g., 256 for RSA-2048)

        Returns:
            Dictionary containing separated components
        """
        pos = 0
        salt = packed_data[pos:pos + 16]  # First 16 bytes are salt
        pos += 16
        nonce = packed_data[pos:pos + 12]  # Next 12 bytes are nonce
        pos += 12
        signature = packed_data[pos:pos + signature_size]  # Next N bytes are signature
        pos += signature_size
        ciphertext = packed_data[pos:]  # Rest is ciphertext

        return {
            'salt': salt,
            'nonce': nonce,
            'signature': signature,
            'ciphertext': ciphertext
        }
