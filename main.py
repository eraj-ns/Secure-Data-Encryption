import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Session Management ---
if "cipher" not in st.session_state:
    key = Fernet.generate_key()
    st.session_state["cipher"] = Fernet(key)

cipher = st.session_state["cipher"]

if "stored_data" not in st.session_state:
    st.session_state["stored_data"] = {}  # {encrypted_text: {"encrypted_text": ..., "passkey": ...}}

if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0

if "is_logged_in" not in st.session_state:
    st.session_state["is_logged_in"] = False

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    stored = st.session_state["stored_data"].get(encrypted_text)

    if stored and stored["passkey"] == hashed_passkey:
        st.session_state["failed_attempts"] = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state["failed_attempts"] += 1
    return None

def logout():
    st.session_state["is_logged_in"] = False
    st.success("🔓 Logged out successfully.")
    st.experimental_rerun()

# --- UI ---
st.set_page_config(page_title="Secure Encryption System", layout="centered")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Admin Login"]
choice = st.sidebar.selectbox("🔎 Navigation", menu)

# --- HOME ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This tool allows you to securely **store** and **retrieve** sensitive data using encryption.")
    st.markdown("""
    **Features:**
    - 🧠 AES-like Fernet encryption
    - 🛡️ Hashed passkey protection
    - 🔐 Admin-only access to data retrieval
    """)

# --- STORE DATA ---
elif choice == "Store Data":
    st.subheader("📂 Store Your Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Set a Passkey:", type="password")

    if st.button("🔒 Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state["stored_data"][encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")

            # Optional download
            b64 = encrypted_text.encode("utf-8").hex()
            st.download_button("📥 Download Encrypted Data", encrypted_text, file_name="encrypted.txt")
        else:
            st.error("⚠️ Please enter both data and passkey.")

# --- RETRIEVE DATA ---
elif choice == "Retrieve Data":
    if not st.session_state["is_logged_in"]:
        st.warning("🔐 Admin access required. Please login from the sidebar.")
    else:
        st.subheader("🔍 Retrieve Stored Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("🔓 Decrypt"):
            if encrypted_text and passkey:
                result = decrypt_data(encrypted_text, passkey)
                if result:
                    st.success("✅ Data successfully decrypted:")
                    st.text_area("Decrypted Message:", value=result, height=150)
                else:
                    attempts_left = 3 - st.session_state["failed_attempts"]
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                    if attempts_left <= 0:
                        st.warning("🚫 Too many failed attempts. Logging out...")
                        logout()
            else:
                st.error("⚠️ Please enter all required fields.")
        st.button("🚪 Logout", on_click=logout)

# --- LOGIN ---
elif choice == "Admin Login":
    st.subheader("🔑 Admin Login")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure method in real apps
            st.session_state["is_logged_in"] = True
            st.session_state["failed_attempts"] = 0
            st.success("✅ Login successful! You can now access data retrieval.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect admin password.")

# Footer
st.markdown("---")
st.caption("🔐 Built with Python, Streamlit & Cryptography")
