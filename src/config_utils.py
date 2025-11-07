import os
import yaml
import json

def load_config(config_path: str = "config.yaml"):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Override with environment variables
    config["jwt"]["secret_key"] = os.getenv("SECRET_KEY", config["jwt"]["secret_key"])
    config["jwt"]["algorithm"] = os.getenv("ALGORITHM", config["jwt"]["algorithm"])
    config["jwt"]["access_token_expire_minutes"] = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", config["jwt"]["access_token_expire_minutes"]))
    config["users"]["db_path"] = os.getenv("USERS_DB_PATH", config["users"]["db_path"])

    return config

def load_users(db_path: str):
    with open(db_path, 'r') as f:
        return json.load(f)

# Create a new user (hash password and save to DB)
def create_user(username: str, password: str, db_path: str = None, config_path: str = None):
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    if not username or not password:
        raise ValueError("Username and password are required")

    if db_path is None:
        config = load_config(config_path)
        db_path = config["users"]["db_path"]

    users = load_users(db_path)
    if username in users:
        raise ValueError(f"User '{username}' already exists")

    hashed_password = pwd_context.hash(password)
    users[username] = {
        "username": username,
        "hashed_password": hashed_password
    }

    with open(db_path, 'w') as f:
        json.dump(users, f, indent=4)

    return f"User '{username}' created successfully"