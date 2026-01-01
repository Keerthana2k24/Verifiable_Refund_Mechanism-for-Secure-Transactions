# secure_refund_demo_tamper.py
# pip install streamlit cryptography pynacl

import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import nacl.signing
import nacl.public
import os
import json
import base64
import time

st.set_page_config(page_title="Secure Refund with Tamper Simulation", layout="wide")
st.title("Verifiable Refund Mechanism 🧐..!")


# -------------------------
# Key Setup
# -------------------------
if "alice_sign_key" not in st.session_state:
    st.session_state.alice_sign_key = nacl.signing.SigningKey.generate()
if "bob_sign_key" not in st.session_state:
    st.session_state.bob_sign_key = nacl.signing.SigningKey.generate()
if "bob_x25519" not in st.session_state:
    st.session_state.bob_x25519 = nacl.public.PrivateKey.generate()
if "transactions" not in st.session_state:
    st.session_state.transactions = {}

# -------------------------
# Helper functions
# -------------------------
def encode_b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def decode_b64(s: str) -> bytes:
    return base64.b64decode(s.encode())

def derive_aes_key(ephemeral_private: nacl.public.PrivateKey, recipient_public: nacl.public.PublicKey) -> bytes:
    box = nacl.public.Box(ephemeral_private, recipient_public)
    shared_secret = box.shared_key()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure refund demo"
    ).derive(shared_secret)

def aes_encrypt(key: bytes, plaintext: bytes) -> (bytes, bytes):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return ct, nonce

def aes_decrypt(key: bytes, ct: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def sign_message(sign_key: nacl.signing.SigningKey, message: bytes) -> bytes:
    return sign_key.sign(message).signature

def verify_signature(verify_key: nacl.signing.VerifyKey, message: bytes, sig: bytes) -> bool:
    try:
        verify_key.verify(message, sig)
        return True
    except:
        return False

def tamper_bytes(data: bytes) -> bytes:
    """Flip one bit in the first byte to simulate tampering"""
    tampered = bytearray(data)
    tampered[0] ^= 1
    return bytes(tampered)

# -------------------------
# UI
# -------------------------
tab1, tab2, tab3 = st.tabs(["Create Transaction", "Request Refund", "Audit"])

with tab1:
    st.header("1️⃣ Create Transaction ")
    amount = st.number_input("Amount (USD)", min_value=1, step=1)
    tx_id = st.text_input("Transaction ID", value=f"TX{int(time.time())}")
    tamper = st.checkbox("Simulate Tampering (Transaction)")

    if st.button("Send Transaction"):
        # Alice generates ephemeral key
        ephemeral_key = nacl.public.PrivateKey.generate()
        bob_pubkey = st.session_state.bob_x25519.public_key
        aes_key = derive_aes_key(ephemeral_key, bob_pubkey)

        # Transaction record
        record = {"tx_id": tx_id, "amount": amount, "timestamp": time.time()}
        record_bytes = json.dumps(record).encode()
        ct, nonce = aes_encrypt(aes_key, record_bytes)

        # Alice signs
        sig = sign_message(st.session_state.alice_sign_key, ephemeral_key.public_key.encode() + ct)

        # Optionally tamper
        if tamper:
            ct = tamper_bytes(ct)  # corrupt ciphertext
            sig = tamper_bytes(sig)  # corrupt signature

        # Bob verifies
        eph_pub_bytes = ephemeral_key.public_key.encode()
        aes_key_recv = derive_aes_key(st.session_state.bob_x25519, nacl.public.PublicKey(eph_pub_bytes))
        verified = verify_signature(st.session_state.alice_sign_key.verify_key, eph_pub_bytes + ct, sig)
        status = "Valid ✅" if verified else "Tampered ❌"

        if verified:
            try:
                plaintext = aes_decrypt(aes_key_recv, ct, nonce)
                record_dec = json.loads(plaintext)
                bob_sig = sign_message(st.session_state.bob_sign_key, plaintext)
                st.session_state.transactions[tx_id] = {
                    "record": record_dec,
                    "status": status,
                    "bob_sig": encode_b64(bob_sig),
                    "alice_sig": encode_b64(sig),
                    "ephemeral_pub": encode_b64(eph_pub_bytes),
                    "nonce": encode_b64(nonce),
                    "ciphertext": encode_b64(ct),
                }
                st.success(f"Transaction {tx_id} stored ✅")
                st.json(record_dec)
            except Exception as e:
                st.error("Decryption failed due to tampering ❌")
        else:
            st.error("Signature verification failed ❌")
            st.session_state.transactions[tx_id] = {
                "record": record,
                "status": status,
                "alice_sig": encode_b64(sig),
                "ephemeral_pub": encode_b64(eph_pub_bytes),
                "nonce": encode_b64(nonce),
                "ciphertext": encode_b64(ct),
            }

with tab2:
    st.header("2️⃣ Request Refund ")
    if st.session_state.transactions:
        sel_tx = st.selectbox("Select Transaction to Refund", list(st.session_state.transactions.keys()))
        reason = st.text_input("Reason for Refund", value="Product issue")
        tamper_refund = st.checkbox("Simulate Tampering (Refund)")

        if st.button("Request Refund"):
            tx_data = st.session_state.transactions[sel_tx]["record"]
            refund_msg = {"tx_id": sel_tx, "reason": reason, "timestamp": time.time()}
            refund_bytes = json.dumps(refund_msg).encode()

            eph_refund = nacl.public.PrivateKey.generate()
            aes_key_r = derive_aes_key(eph_refund, st.session_state.bob_x25519.public_key)
            ct_r, nonce_r = aes_encrypt(aes_key_r, refund_bytes)
            sig_r = sign_message(st.session_state.alice_sign_key, eph_refund.public_key.encode() + ct_r)

            if tamper_refund:
                ct_r = tamper_bytes(ct_r)
                sig_r = tamper_bytes(sig_r)

            verified = verify_signature(st.session_state.alice_sign_key.verify_key, eph_refund.public_key.encode() + ct_r, sig_r)
            status = "Valid ✅" if verified else "Tampered ❌"

            if verified:
                try:
                    refund_plain = aes_decrypt(aes_key_r, ct_r, nonce_r)
                    refund_dec = json.loads(refund_plain)
                    bob_sig_refund = sign_message(st.session_state.bob_sign_key, refund_plain)
                    st.session_state.transactions[sel_tx]["refund"] = {
                        "refund_msg": refund_dec,
                        "status": status,
                        "bob_sig": encode_b64(bob_sig_refund),
                        "alice_sig": encode_b64(sig_r),
                        "ephemeral_pub": encode_b64(eph_refund.public_key.encode()),
                        "nonce": encode_b64(nonce_r),
                        "ciphertext": encode_b64(ct_r),
                    }
                    st.success(f"Refund processed for {sel_tx} ✅")
                    st.json(refund_dec)
                except Exception:
                    st.error("Refund decryption failed ❌")
            else:
                st.error("Refund signature verification failed ❌")
                st.session_state.transactions[sel_tx]["refund"] = {
                    "refund_msg": refund_msg,
                    "status": status,
                    "alice_sig": encode_b64(sig_r),
                    "ephemeral_pub": encode_b64(eph_refund.public_key.encode()),
                    "nonce": encode_b64(nonce_r),
                    "ciphertext": encode_b64(ct_r),
                }
    else:
        st.info("No transactions available. Create one first.")

with tab3:
    st.header("3️⃣ Audit Log")
    for tx_id, data in st.session_state.transactions.items():
        st.subheader(f"Transaction ID: {tx_id} ({data['status']})")
        st.json(data.get("record", {}))
        if "refund" in data:
            st.markdown("**Refund Record:**")
            st.json(data["refund"].get("refund_msg", {}))
            st.markdown(f"Status: {data['refund']['status']}")
