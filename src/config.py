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