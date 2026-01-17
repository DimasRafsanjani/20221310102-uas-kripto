import streamlit as st
import os
import base64
import hashlib
import qrcode
import json
from io import BytesIO
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from PIL import Image

# Fungsi untuk menghasilkan pasangan kunci RSA
def dimas20221310102_generate_rsa_keys():
    """Menghasilkan pasangan kunci RSA (public key dan private key)"""
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        # Load kunci yang sudah ada
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        # Generate kunci baru
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        # Simpan private key
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Simpan public key
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return private_key, public_key

# Fungsi untuk hash pesan menggunakan SHA-256
def dimas20221310102_hash_message(message):
    """Melakukan hash pada pesan menggunakan SHA-256"""
    message_bytes = message.encode('utf-8')
    hash_object = hashlib.sha256(message_bytes)
    hash_hex = hash_object.hexdigest()
    return hash_hex, message_bytes

# Fungsi untuk membuat digital signature
def dimas20221310102_create_digital_signature(message, private_key):
    """Membuat digital signature dengan cara:
    1. Hash pesan menggunakan SHA-256
    2. Enkripsi hash menggunakan private key RSA
    """
    # Hash pesan
    hash_hex, message_bytes = dimas20221310102_hash_message(message)
    
    # Enkripsi hash dengan private key (membuat signature)
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Encode signature ke base64 untuk kemudahan penyimpanan
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    return signature_b64, hash_hex, signature

# Fungsi untuk membuat QRIS dari digital signature
def dimas20221310102_create_qris(signature_b64, message, hash_hex):
    """Membuat QRIS (QR Code) dari digital signature"""
    # Membuat payload untuk QR Code
    qr_payload = {
        "message": message,
        "hash": hash_hex,
        "signature": signature_b64
    }
    
    # Convert ke JSON string
    qr_data = json.dumps(qr_payload, indent=2)
    
    # Generate QR Code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    # Buat gambar QR Code dan konversi ke RGB untuk kompatibilitas
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Konversi ke RGB jika perlu (untuk kompatibilitas)
    if qr_img.mode != 'RGB':
        qr_img = qr_img.convert('RGB')
    
    return qr_img, qr_data

# Fungsi untuk verifikasi digital signature
def dimas20221310102_verify_signature(message, signature_b64, public_key):
    """Memverifikasi digital signature dengan cara:
    1. Dekripsi signature menggunakan public key RSA
    2. Hash pesan yang diterima menggunakan SHA-256
    3. Bandingkan hash hasil dekripsi dengan hash pesan
    """
    try:
        # Decode signature dari base64
        signature = base64.b64decode(signature_b64)
        
        # Hash pesan yang diterima
        message_bytes = message.encode('utf-8')
        
        # Verifikasi signature dengan public key
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Jika tidak ada exception, signature valid
        return True, "Signature valid! Pesan tidak diubah dan berasal dari pemilik private key."
    
    except InvalidSignature:
        return False, "Signature tidak valid! Pesan mungkin diubah atau signature tidak cocok."
    except Exception as e:
        return False, f"Error saat verifikasi: {str(e)}"

# Fungsi untuk parse QRIS
def dimas20221310102_parse_qris(qr_data):
    """Mengurai data dari QRIS"""
    try:
        data = json.loads(qr_data)
        return data.get("message", ""), data.get("hash", ""), data.get("signature", "")
    except:
        return None, None, None

# Fungsi untuk load public key
def dimas20221310102_load_public_key():
    """Memuat public key dari file"""
    try:
        if os.path.exists("public_key.pem"):
            with open("public_key.pem", "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            return public_key
        else:
            return None
    except Exception as e:
        st.error(f"Error loading public key: {str(e)}")
        return None

# Konfigurasi halaman
st.set_page_config(
    page_title="Digital Signature & QRIS System",
    page_icon="🔐",
    layout="wide"
)

# Judul aplikasi
st.title("🔐 Sistem Digital Signature & QRIS")
st.markdown("---")

# Sidebar untuk navigasi
page = st.sidebar.selectbox(
    "Pilih Halaman",
    ["📝 Pengirim Pesan", "✅ Penerima & Verifikasi"]
)

if page == "📝 Pengirim Pesan":
    st.header("📝 Interface Pengirim Pesan")
    st.markdown("**Buat digital signature dan QRIS untuk pesan Anda**")
    
    # Input pesan
    message = st.text_area(
        "Masukkan Pesan yang akan Ditandatangani:",
        height=150,
        placeholder="Ketik pesan Anda di sini..."
    )
    
    if st.button("🔑 Generate Kunci RSA", use_container_width=True):
        with st.spinner("Menghasilkan kunci RSA..."):
            private_key, public_key = dimas20221310102_generate_rsa_keys()
            st.success("✅ Kunci RSA berhasil dihasilkan!")
            st.info("Kunci telah disimpan ke file private_key.pem dan public_key.pem")
    
    if st.button("✍️ Buat Digital Signature & QRIS", use_container_width=True):
        if not message:
            st.error("❌ Silakan masukkan pesan terlebih dahulu!")
        else:
            try:
                # Generate kunci jika belum ada
                if not os.path.exists("private_key.pem"):
                    private_key, public_key = dimas20221310102_generate_rsa_keys()
                else:
                    with open("private_key.pem", "rb") as f:
                        private_key = serialization.load_pem_private_key(f.read(), password=None)
                
                # Buat digital signature
                with st.spinner("Membuat digital signature..."):
                    signature_b64, hash_hex, signature = dimas20221310102_create_digital_signature(message, private_key)
                
                # Buat QRIS
                with st.spinner("Membuat QRIS..."):
                    qr_img, qr_data = dimas20221310102_create_qris(signature_b64, message, hash_hex)
                
                st.success("✅ Digital Signature dan QRIS berhasil dibuat!")
                
                # Tampilkan hasil
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📊 Informasi Signature")
                    st.text_area("Hash SHA-256:", hash_hex, height=100, disabled=True)
                    st.text_area("Digital Signature (Base64):", signature_b64, height=150, disabled=True)
                
                with col2:
                    st.subheader("📱 QRIS Code")
                    # Pastikan gambar dalam format yang benar untuk ditampilkan
                    if qr_img.mode != 'RGB':
                        qr_img_display = qr_img.convert('RGB')
                    else:
                        qr_img_display = qr_img
                    st.image(qr_img_display, caption="QRIS Digital Signature", use_container_width=True)
                    
                    # Download QRIS
                    buf = BytesIO()
                    qr_img_display.save(buf, format="PNG")
                    img_bytes = buf.getvalue()
                    buf.close()
                    
                    st.download_button(
                        label="⬇️ Download QRIS",
                        data=img_bytes,
                        file_name="qris_digital_signature.png",
                        mime="image/png"
                    )
                
                # Simpan data untuk verifikasi (opsional, untuk referensi)
                st.session_state['sender_message'] = message
                st.session_state['sender_signature'] = signature_b64
                st.session_state['sender_hash'] = hash_hex
                
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

elif page == "✅ Penerima & Verifikasi":
    st.header("✅ Interface Penerima & Verifikasi")
    st.markdown("**Verifikasi digital signature dari QRIS**")
    
    st.subheader("📱 Upload dan Scan QRIS")
    uploaded_file = st.file_uploader("Upload gambar QRIS", type=["png", "jpg", "jpeg"])
    
    if uploaded_file is not None:
        # Baca gambar
        img = Image.open(uploaded_file)
        st.image(img, caption="QRIS yang diupload", width=300)
        
        # Coba decode QR Code dengan pyzbar
        pyzbar_available = False
        qr_data = None
        
        try:
            from pyzbar import pyzbar
            # Coba decode
            decoded_objects = pyzbar.decode(img)
            if decoded_objects:
                qr_data = decoded_objects[0].data.decode('utf-8')
                pyzbar_available = True
        except ImportError:
            st.error("❌ Library pyzbar tidak terinstall.")
            st.info("💡 **Instalasi:** Jalankan `pip install pyzbar` di terminal/command prompt")
            st.warning("⚠️ **Catatan Windows:** pyzbar memerlukan Visual C++ Redistributable. Jika error, download dari Microsoft.")
        except Exception as e:
            # Error DLL atau error lainnya
            error_msg = str(e)
            if "libzbar" in error_msg.lower() or "dll" in error_msg.lower():
                st.error("❌ pyzbar memerlukan library tambahan di Windows.")
                st.info("💡 **Solusi:**")
                st.markdown("""
                1. Install Visual C++ Redistributable dari Microsoft
                2. Atau install pyzbar dengan: `pip install pyzbar`
                3. Pastikan semua dependencies terinstall dengan benar
                """)
            else:
                st.error(f"❌ Error membaca QR Code: {str(e)}")
                st.info("💡 Pastikan gambar QRIS jelas dan tidak rusak.")
        
        if pyzbar_available and qr_data:
            st.success("✅ QRIS berhasil dibaca!")
            
            # Parse data
            message, hash_hex, signature_b64 = dimas20221310102_parse_qris(qr_data)
            
            if message and signature_b64:
                st.session_state['qr_message'] = message
                st.session_state['qr_signature'] = signature_b64
                st.session_state['qr_hash'] = hash_hex
                st.success("✅ Data QRIS berhasil di-parse dan siap untuk verifikasi!")
            else:
                st.error("❌ Format QRIS tidak valid! Pastikan QRIS dibuat dari aplikasi ini.")
        elif not pyzbar_available:
            st.warning("⚠️ QRIS tidak dapat dibaca. Pastikan pyzbar terinstall dengan benar.")
    
    # Verifikasi
    st.markdown("---")
    
    # Tampilkan status sebelum tombol verifikasi
    if 'qr_message' in st.session_state and st.session_state.get('qr_message'):
        st.success("✅ Data QRIS sudah tersedia dan siap untuk verifikasi!")
    else:
        st.info("💡 **Cara menggunakan:**")
        st.markdown("""
        1. Buka halaman **'📝 Pengirim Pesan'** di sidebar
        2. Masukkan pesan dan klik **'Buat Digital Signature & QRIS'**
        3. Download gambar QRIS yang dihasilkan
        4. Kembali ke halaman ini dan upload gambar QRIS di atas
        """)
    
    if st.button("🔍 Verifikasi Digital Signature", use_container_width=True, type="primary"):
        # Ambil data dari session state
        message = st.session_state.get('qr_message', '')
        signature_b64 = st.session_state.get('qr_signature', '')
        hash_hex = st.session_state.get('qr_hash', '')
        
        if not message or not signature_b64:
            st.error("❌ Data QRIS belum tersedia!")
            st.info("""
            **Langkah-langkah:**
            1. Upload gambar QRIS di atas
            2. Pastikan QRIS berhasil dibaca (akan muncul pesan sukses)
            3. Klik tombol verifikasi lagi
            """)
        else:
            try:
                # Load public key
                public_key = dimas20221310102_load_public_key()
                
                if public_key is None:
                    st.error("❌ Public key tidak ditemukan! Pastikan file public_key.pem ada.")
                else:
                    # Verifikasi signature
                    with st.spinner("Memverifikasi signature..."):
                        is_valid, message_result = dimas20221310102_verify_signature(message, signature_b64, public_key)
                    
                    # Tampilkan hasil
                    st.markdown("---")
                    st.subheader("📋 Hasil Verifikasi")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("### 📝 Isi Pesan")
                        st.info(message)
                        st.markdown("### 🔑 Hash SHA-256")
                        st.code(hash_hex)
                    
                    with col2:
                        st.markdown("### ✍️ Digital Signature")
                        st.code(signature_b64[:100] + "..." if len(signature_b64) > 100 else signature_b64)
                        st.markdown("### ✅ Status Verifikasi")
                        if is_valid:
                            st.success(f"✅ {message_result}")
                        else:
                            st.error(f"❌ {message_result}")
                    
                    # Tampilkan informasi lengkap
                    st.markdown("---")
                    st.subheader("📊 Detail Verifikasi")
                    
                    # Hash pesan yang diterima
                    received_hash, _ = dimas20221310102_hash_message(message)
                    
                    st.markdown("**Proses Verifikasi:**")
                    st.markdown("1. ✅ Pesan diterima dan di-hash menggunakan SHA-256")
                    st.markdown(f"2. ✅ Hash pesan: `{received_hash}`")
                    st.markdown("3. ✅ Signature di-dekripsi menggunakan public key RSA")
                    st.markdown("4. ✅ Hash hasil dekripsi dibandingkan dengan hash pesan")
                    
                    if is_valid:
                        st.balloons()
                    
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

# Footer
st.markdown("---")
st.markdown(f"**Sistem Digital Signature & QRIS** | NPM: 20221310102 | Dibuat untuk UAS Kriptografi")