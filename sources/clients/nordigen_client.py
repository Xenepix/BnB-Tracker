import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class NordigenClient:

    @staticmethod
    def _set_secrets(secret_id: str, secret_key: str, password: str, salt: bytes | str, **kwargs) -> None:
        """
        Set the secrets of the Nordigen client

        Args:
            - secret_id (str):
            - secret_key (str):
            - password (str): User password
            - salt (str): User salt

        kwargs:
            - iterations (int): Number of iterations for the key generation (default: 100_000)
            - key_length (int): Length of the key (default: 32)
        """
        # Generate a key
        iterations = kwargs.get('iterations', 100_000)
        key_length = kwargs.get('key_length', 32)
        if isinstance(salt, str):
            salt = salt.encode()

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = key_length,
            salt = salt,
            iterations = iterations
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Encrypt the secrets
        fernet = Fernet(key)
        encrypted_secret_id = fernet.encrypt(secret_id.encode())
        encrypted_secret_key = fernet.encrypt(secret_key.encode())

        # Save the secrets in the vault
        secrets_data = {"secret_id": encrypted_secret_id.decode(),
                        "secret_key": encrypted_secret_key.decode()}

        with open('secrets.json', 'w') as vault:
            json.dump(secrets_data, vault, indent = 4)
        os.chmod('secrets.json', 0o600)
        vault.close()


if __name__ == '__main__':
    NordigenClient._set_secrets('12', '13', 'password', os.urandom(16))
