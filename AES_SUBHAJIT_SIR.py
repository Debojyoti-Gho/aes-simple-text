import numpy as np
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import qrcode
from io import BytesIO
from PIL import Image
import cv2

# Function to generate a deterministic image
def generate_deterministic_image(n1, n2):
    img = Image.new("RGB", (100, 100), (int(abs(n1 * 255) % 256), int(abs(n2 * 255) % 256), 128))
    return img

# Function to hash an image
def hash_image(img):
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return hashlib.sha256(buffered.getvalue()).digest()

# Encrypt AES key with a hash
def encrypt_aes_key(aes_key, hash_key):
    cipher = AES.new(hash_key[:len(aes_key)], AES.MODE_ECB)
    return cipher.encrypt(pad(aes_key, AES.block_size))

# Decrypt AES key
def decrypt_aes_key(enc_key, hash_key):
    cipher = AES.new(hash_key[:len(enc_key)], AES.MODE_ECB)
    return unpad(cipher.decrypt(enc_key), AES.block_size)

# Streamlit UI
st.title("Encryption and Decryption with Deterministic Image and QR Code")

# Input section
mode = st.radio("Mode", ["Encrypt", "Decrypt"])
if mode == "Encrypt":
    plain_text = st.text_input("Plain Text")
    aes_type = st.selectbox("AES Type", [128, 192, 256])
    n1 = st.number_input("Real Number N1", value=0.0, format="%.5f")
    n2 = st.number_input("Real Number N2", value=0.0, format="%.5f")
    
    if st.button("Encrypt"):
        # Generate AES key
        aes_key = get_random_bytes(aes_type // 8)
        # Generate deterministic image and hash it
        img = generate_deterministic_image(n1, n2)
        hash_key = hash_image(img)
        # Encrypt the AES key using the hash
        enc_aes_key = encrypt_aes_key(aes_key, hash_key)
        # Generate QR code for the encrypted AES key
        qr = qrcode.make(enc_aes_key)
        # Save QR code to a bytes buffer
        qr_buffer = BytesIO()
        qr.save(qr_buffer, format="PNG")
        qr_buffer.seek(0)
        # Encrypt the plain text using the AES key
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
        
        st.success("Encryption Successful!")
        st.write("Ciphertext (in bytes):", ciphertext)
        st.image(qr_buffer, caption="QR Code with Encrypted AES Key")
        
        # Add a download button for the QR code
        st.download_button(
            label="Download QR Code",
            data=qr_buffer,
            file_name="encrypted_aes_key_qr.png",
            mime="image/png"
        )
        
elif mode == "Decrypt":
    ciphertext_input = st.text_area("Ciphertext (Enter as bytes, e.g., b'\\x...')")
    qr_code_file = st.file_uploader("Upload QR Code (PNG)", type=["png"])
    aes_type = st.selectbox("AES Type", [128, 192, 256])
    n1 = st.number_input("Real Number N1", value=0.0, format="%.5f")
    n2 = st.number_input("Real Number N2", value=0.0, format="%.5f")
    
    if st.button("Decrypt"):
        try:
            if qr_code_file:
                # Load and decode the QR code
                qr_image = np.array(Image.open(qr_code_file).convert("RGB"))
                qr_image = cv2.cvtColor(qr_image, cv2.COLOR_RGB2BGR)
                qr_detector = cv2.QRCodeDetector()
                qr_data, _, _ = qr_detector.detectAndDecode(qr_image)
                if not qr_data:
                    raise ValueError("No data found in QR code.")
                
                st.write("Decoded QR Data (binary):", repr(qr_data))  # Debugging output
                
                # Decode QR data as raw bytes
                enc_aes_key = qr_data.encode('latin1')  # Preserve raw binary data
                
                # Regenerate the deterministic image and hash it
                img = generate_deterministic_image(n1, n2)
                hash_key = hash_image(img)
                
                # Ensure hash key length matches AES key length
                hash_key_segment = hash_key[:aes_type // 8]
                
                # Decrypt the AES key
                aes_key = decrypt_aes_key(enc_aes_key, hash_key_segment)
                
                # Convert ciphertext input to bytes
                ciphertext = eval(ciphertext_input)
                if not isinstance(ciphertext, bytes):
                    raise ValueError("Ciphertext must be in bytes format.")
                
                # Decrypt the ciphertext
                cipher = AES.new(aes_key, AES.MODE_ECB)
                plain_text = unpad(cipher.decrypt(ciphertext), AES.block_size)
                
                st.success("Decryption Successful!")
                st.write("Decrypted Plain Text:", plain_text.decode())
            else:
                st.error("Please upload a valid PNG QR code file.")
        except ValueError as e:
            st.error(f"An error occurred: {e}")
        except Exception as e:
            st.error(f"An error occurred during decryption: {e}")
