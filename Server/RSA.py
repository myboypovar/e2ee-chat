from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os


PRIVATE_KEY_FILE = 'server_private_key.pem'


class RSA:
    """
    The RSA class is used to sign the client's public keys using the RSA encryption algorithm.

    Attributes:
        private_key: RSA private key.
        public_key: RSA public key.
    """
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.load_keys()

    def load_keys(self):
        """Loads private and public keys from private key file"""
        # The private key doesn't exist.
        if not os.path.exists(PRIVATE_KEY_FILE):
            # Generate RSA key pair
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

            # Save the private key to a file
            with open("server_private_key.pem", "wb") as private_file:
                private_file.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()  # No password for simplicity
                    )
                )
                # Extract the public key from the private key
                self.public_key = self.private_key.public_key()

                # Save the server's public key in a file for the client
                with open("../Client/server_public_key.pem", "wb") as public_file:
                    public_file.write(
                        self.public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    )
                print("Server keys saved successfully!")

        else:  # The private key already exists.
            with open(PRIVATE_KEY_FILE, "rb") as private_file:
                self.private_key = serialization.load_pem_private_key(private_file.read(), None)
            self.public_key = self.private_key.public_key()
            print("Server keys loaded successfully!")

    def sign_client_key(self, client_public_key):
        """ Signs a client's public key with the server's rsa private key """
        signature = self.private_key.sign(
            client_public_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
