import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class NordigenClient:

    @staticmethod
    def _generate_key(password: str, salt: bytes | str, **kwargs) -> bytes:
        """
        Generate a key from password and salt

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
            iterations = iterations)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def set_secrets(self, secret_id: str, secret_key: str, password: str, salt: bytes | str) -> None:
        """
        Set the secrets in the vault

        Args:
            - secret_id (str):
            - secret_key (str):
            - password (str): User password
            - salt (str): User salt
        """
        key = self._generate_key(password, salt)
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

    def get_secrets(self, password: str, salt: bytes | str) -> dict[str, str]:
        """
        Get the secrets from the vault

        Args:
            - password (str): User password
            - salt (str): User salt

        Returns:
            - dict: Secrets (secret_id, secret_key)
        """
        key = self._generate_key(password, salt)

        # Get the secrets from the vault
        with open('secrets.json', 'r') as vault:
            secrets_data = json.load(vault)
        vault.close()

        # Decrypt the secrets
        fernet = Fernet(key)
        secret_id = fernet.decrypt(secrets_data.get('secret_id').encode()).decode()
        secret_key = fernet.decrypt(secrets_data.get('secret_key').encode()).decode()
        return {"secret_id": secret_id, "secret_key": secret_key}


if __name__ == '__main__':
    rd_salt = os.urandom(16)
    rd_password = 'password'
    rd_secret_id = 'secret_id'
    rd_secret_key = 'secret_key'

    assert NordigenClient._generate_key('password', rd_salt) == NordigenClient._generate_key('password', rd_salt)
    NordigenClient().set_secrets(rd_secret_id, rd_secret_key, rd_password, rd_salt)
    keys = NordigenClient().get_secrets(rd_password, rd_salt)
    assert keys.get('secret_id') == rd_secret_id
    assert keys.get('secret_key') == rd_secret_key
