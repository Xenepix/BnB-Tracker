import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from tools import get_vault_path


class NordigenSecretManager:
    """ Class for managing Nordigen secrets. """

    def __init__(self, salt) -> None:
        self._vault_path: str = get_vault_path() + 'nordigen_secrets.json'
        self._salt = salt

    def _generate_key(self, password: str, iterations: int = 100_000, key_length: int = 32) -> bytes:
        """
        Generate a key from password and salt

        Args:
            - password (str): User password
            - iterations (int): Number of iterations for the key generation (default: 100_000)
            - key_length (int): Length of the key (default: 32)
        """
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = key_length,
            salt = self._salt.encode(),
            iterations = iterations)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def set_secrets(self, secret_id: str, secret_key: str, password: str) -> None:
        """
        Set the secrets in the vault

        Args:
            - secret_id (str):
            - secret_key (str):
            - password (str): User password
        """
        key = self._generate_key(password)

        # Encrypt the secrets
        fernet = Fernet(key)
        encrypted_secret_id = fernet.encrypt(secret_id.encode())
        encrypted_secret_key = fernet.encrypt(secret_key.encode())

        # Save the secrets in the vault
        secrets_data = {"secret_id": encrypted_secret_id.decode(),
                        "secret_key": encrypted_secret_key.decode()}

        with open(self._vault_path, 'w') as vault:
            json.dump(secrets_data, vault, indent = 4)
        os.chmod(self._vault_path, 0o600)
        vault.close()

    def get_secrets(self, password: str) -> dict[str, str]:
        """
        Get the secrets from the vault

        Args:
            - password (str): User password

        Returns:
            - Secrets (dict[str, str]): (secret_id, secret_key)
        """
        key = self._generate_key(password)

        # Get the secrets from the vault
        with open(self._vault_path, 'r') as vault:
            secrets_data = json.load(vault)
        vault.close()

        # Decrypt the secrets
        fernet = Fernet(key)
        secret_id = fernet.decrypt(secrets_data.get('secret_id').encode()).decode()
        secret_key = fernet.decrypt(secrets_data.get('secret_key').encode()).decode()
        return {"secret_id": secret_id, "secret_key": secret_key}
