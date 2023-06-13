


import secrets
from pathlib import Path

private_key = secrets.token_hex(32)
file_path = Path("testWallet-1.sk")

with file_path.open(mode="w") as file:
    file.write(private_key)
