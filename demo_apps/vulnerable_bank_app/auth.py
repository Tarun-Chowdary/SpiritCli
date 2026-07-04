import hashlib
import jwt
from pymongo import MongoClient

# MongoDB User Collection
client = MongoClient("mongodb://localhost:27017/")
db = client["bank"]
users_collection = db["users"]

# User schema equivalent
def create_user(username, password):
    return {
        "username": username,
        "password": password
    }

# Vulnerable: MD5 is cryptographically broken — mirrors bcrypt rounds=4
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerable: algorithm none — mirrors jwt.sign(user, "secret", { algorithm: "none" })
def generate_token(user):
    return jwt.encode(user, "secret", algorithm="none")
