import os
import json
import hashlib
import base64

from cryptography.fernet import Fernet, InvalidToken
from passlib.hash import argon2
from tools import get_vault_path


class AccountSecretManager:

    def __init__(self, **kwargs) -> None:
        self._vault_path: str = get_vault_path() + 'account_secrets.json'
        self._salt_length: int = kwargs.get('salt_length', 64)
        self._salt: str | None = None

    def encrypt_salt(self, password: str) -> str:
        """
        Encrypt the salt

        Args:
            - password (str): User password
        """
        key = base64.urlsafe_b64encode((hashlib.sha256(password.encode()).digest()))
        fernet = Fernet(key)
        encrypted_salt = fernet.encrypt(self._salt.encode()).decode()
        return encrypted_salt

    def decrypt_salt(self, password: str, encrypted_salt: str) -> str:
        """
        Decrypt the salt

        Args:
            - password (str): User password
            - encrypted_salt (str): Encrypted salt

        Raises:
            - InvalidToken: If the password is wrong
        """
        key = base64.urlsafe_b64encode((hashlib.sha256(password.encode()).digest()))
        fernet = Fernet(key)
        decrypted_salt = fernet.decrypt(encrypted_salt.encode()).decode()
        self._salt = decrypted_salt
        return decrypted_salt

    def set_password(self, password: str) -> None:
        """
        Set the password of the account
        """
        self._salt = os.urandom(self._salt_length).hex()
        password_hash = argon2.using(salt = self._salt.encode()).hash(password)
        encrypted_salt = self.encrypt_salt(password)

        # Save encrypted salt and password hash in the vault
        hash_data = {
            "salt": encrypted_salt,
            "password": password_hash
        }
        with open(self._vault_path, 'w') as vault:
            json.dump(hash_data, vault, indent = 4)
        os.chmod(self._vault_path, 0o600)
        vault.close()

    def verify_password(self, password: str) -> bool:
        """
        Verify the password of the account
        """
        with open(self._vault_path, 'r') as vault:
            hash_pwd = json.load(vault).get("password")
        vault.close()
        return argon2.using(salt = self._salt.encode()).verify(password, hash_pwd)
