import os

def get_project_path() -> str:
    """
    Get the path of the project
    """
    return os.path.dirname(__file__) + '/'

def get_vault_path()-> str:
    """
    Get the path of the vault
    """
    return get_project_path() + 'vault/'
