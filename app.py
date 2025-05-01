import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# Constants
USER_FILE = "users.json" # Store User Credentials
DATA_FILE = "user_data.json" # File to store encrypted user data
KEY_FILE = ".key"
LOCKOUT_DURATION = 60
MAX_FAILED_ATTEMPTS = 3

# Ensure the encryption key exists and is reused
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return f.read()
    
KEY = load_or_create_key()
cipher = Fernet(KEY)

# Load user credentials
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

# Save user credentials
def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

# Load user data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save user data
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Session State Initialization
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

# Helper Function
def check_lockout():
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time()) 
        st.warning(f"Too many failed attempts. Try again in {remaining} seconds.")
        return True
    return False

# Hash password
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    hashed = pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return hashed.hex(), salt.hex()
    
# Verify password
def verify_password(input_password, stored_hash, stored_salt):
    test_hash, _ = hash_password(input_password, bytes.fromhex(stored_salt))
    return test_hash == stored_hash

# Securely hash passkey using PBKDF2 with a salt
def hash_passkey(passkey, salt=None):
    if not salt:
        salt = os.urandom(16) # Generate a random salt for each passkey
    hashed = pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return hashed.hex(), salt.hex()

# Verifying Passkey
def verify_passkey(passkey, stored_hash, stored_salt):
    computed_hash, _ = hash_passkey(passkey, bytes.fromhex(stored_salt))
    return computed_hash == stored_hash

# Encrypt the text using Fernet encryption
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text 
def decrypt_data(token):
    return cipher.decrypt(token.encode()).decode()

# Load Stored Data
users = load_users()
data = load_data()

# Streamlit Interface
st.set_page_config(page_title="Encrypted Data Vault", layout="wide")
# Navigation
if st.session_state.logged_in_user:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
else:
    menu = ["Home", "Register", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home page
if choice == "Home":
    st.markdown("""
        <style>
        .big-title {
            font-size: 32px !important;
            font-weight: 700;
            color: white
        }
        </style>
    """, unsafe_allow_html=True)
    st.markdown('<p class="big-title">🔐 Secure Multi-User Data Vault</p>', unsafe_allow_html=True)
    if st.session_state.logged_in_user:
        st.success(f"👋 Welcome back, **{st.session_state.logged_in_user}**!")
        st.write("You can now securely store or retrieve your encrypted notes.")
    else:
        st.info("Please login or register to access the encrypted vault.")
    
    st.markdown("### Features")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 🔑 End-to-End Encryption")
        st.write("All notes are encrypted with Fernet and protected with a secure passkey.")

    with col2:
        st.markdown("### 👥 Multi-User Isolation")
        st.write("Each user's data is completely isolated and secured individually.")

# Register Page
elif choice == "Register":
    st.subheader("Create an Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Register"):
        if new_user in users: 
            st.error("Username already exists!")
        elif new_user and new_pass:
            hashed, salt = hash_password(new_pass)
            users[new_user]  = {"password": hashed, "salt": salt}
            save_users(users)
            st.success("Account created. Please log in.")
        else:
            st.error("All fields are required.")

# Login Page
elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in users and verify_password(password, users[username]["password"], users[username]["salt"]):
            st.session_state.logged_in_user = username
            st.success("✅ Login Successful!")
        else:
            st.error("❌ Invalid credentials!")
# Logout
elif choice == "Logout":
    st.session_state.logged_in_user = None
    st.session_state.failed_attempts = 0
    st.session_state.lockout_time = 0
    st.success("Logged out successfully.")

# Store Data Page
elif choice == "Store Data":
    st.subheader("Store Encrypted Data")
    data_input = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Encryption Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if data_input and passkey:
            hashed, salt = hash_passkey(passkey)
            encrypted_text = encrypt_data(data_input)
            data[st.session_state.logged_in_user] = {
                "encrypted": encrypted_text,
                "passkey": hashed,
                "salt": salt
            }
            save_data(data) # Save data
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Please fill in all fields.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("Retrieve Your Encrypted Data")

    if check_lockout():
        st.stop()
    
    passkey = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt"):
        user_entry = data.get(st.session_state.logged_in_user)
        
        if user_entry and verify_password(passkey, user_entry["passkey"], user_entry["salt"]):
          decrypted_text = decrypt_data(user_entry["encrypted"])
          st.success(f"Decrypted Text: {decrypted_text}")
          st.session_state.failed_attempts = 0
        else:
            st.session_state.failed_attempts += 1
            st.error("Incorrect passkey or no data found.")

        if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
            st.session_state.logged_in_user = None
            st.warning("Too many failed attempts. Redirecting to Login page for reauthorization...")
            st.rerun()