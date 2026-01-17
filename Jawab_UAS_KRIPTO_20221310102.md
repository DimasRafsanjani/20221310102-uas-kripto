# LAPORAN UJIAN AKHIR SEMESTER
## MATA KULIAH: KRIPTOGRAFI

---

**Nama:** Dimas Rafsanjani  
**NPM:** 20221310102  
**Program Studi:** Teknik Informatika  
**Dosen:** Deni Suprihadi, S.T, M.KOM, MCE  

---

## DAFTAR ISI

1. [Pendahuluan](#1-pendahuluan)
2. [Deskripsi Sistem](#2-deskripsi-sistem)
3. [Algoritma yang Digunakan](#3-algoritma-yang-digunakan)
4. [Dokumentasi Kode](#4-dokumentasi-kode)
5. [Antarmuka Aplikasi](#5-antarmuka-aplikasi)
6. [Cara Penggunaan](#6-cara-penggunaan)
7. [Kesimpulan](#7-kesimpulan)

---

## 1. PENDAHULUAN

### 1.1 Latar Belakang

Seiring dengan meningkatnya kebutuhan akan keamanan dan keaslian data dalam sistem digital, digital signature dan QRIS menjadi salah satu mekanisme penting untuk menjamin integritas, autentikasi, dan non-repudiation suatu pesan. Algoritma kriptografi kunci publik yang umum digunakan untuk digital signature adalah RSA (Rivest-Shamir-Adleman).

### 1.2 Tujuan

Membuat sistem verifikasi dokumen digital yang dapat digunakan untuk:
- Menandatangani pesan secara digital menggunakan RSA
- Memverifikasi pesan secara digital
- Menghasilkan QRIS (QR Code) dari digital signature
- Menyediakan antarmuka yang mudah digunakan dengan framework Streamlit

---

## 2. DESKRIPSI SISTEM

Sistem ini adalah aplikasi web berbasis Streamlit yang menyediakan dua interface utama:

### 2.1 Interface Pengirim Pesan
- Input pesan yang akan ditandatangani
- Generate pasangan kunci RSA (public key dan private key)
- Membuat digital signature dari pesan
- Menghasilkan QRIS dari digital signature
- Download QRIS dalam format gambar PNG

### 2.2 Interface Penerima & Verifikasi
- Upload gambar QRIS
- Scan dan parse data dari QRIS
- Verifikasi digital signature menggunakan public key
- Menampilkan hasil verifikasi dan detail pesan

### 2.3 Alur Proses

**Proses Pembuatan Digital Signature:**
1. User memasukkan pesan
2. Sistem melakukan hash pesan menggunakan SHA-256
3. Hash dienkripsi menggunakan private key RSA
4. Signature di-encode ke Base64
5. Signature, pesan, dan hash dikemas dalam format JSON
6. JSON diubah menjadi QR Code (QRIS)

**Proses Verifikasi:**
1. User upload gambar QRIS
2. Sistem membaca QR Code dan mengekstrak data JSON
3. Data di-parse untuk mendapatkan pesan, hash, dan signature
4. Signature di-dekripsi menggunakan public key RSA
5. Pesan yang diterima di-hash menggunakan SHA-256
6. Hash hasil dekripsi dibandingkan dengan hash pesan
7. Hasil verifikasi ditampilkan

---

## 3. ALGORITMA YANG DIGUNAKAN

### 3.1 RSA (Rivest-Shamir-Adleman)

RSA adalah algoritma kriptografi asimetris yang menggunakan pasangan kunci:
- **Private Key**: Digunakan untuk menandatangani (mengenkripsi hash)
- **Public Key**: Digunakan untuk verifikasi (mendekripsi signature)

**Spesifikasi:**
- Key size: 2048 bit
- Public exponent: 65537
- Padding: PSS (Probabilistic Signature Scheme)
- Hash function: SHA-256

### 3.2 SHA-256 (Secure Hash Algorithm 256-bit)

SHA-256 digunakan untuk menghasilkan hash dari pesan. Hash ini memastikan:
- **Integritas**: Perubahan sekecil apapun pada pesan akan menghasilkan hash yang berbeda
- **Keamanan**: Tidak mungkin untuk membuat pesan dengan hash yang sama (collision resistance)

### 3.3 QR Code (Quick Response Code)

QR Code digunakan untuk menyimpan data digital signature dalam format visual. Data yang disimpan dalam QRIS:
- Pesan asli
- Hash SHA-256 dari pesan
- Digital signature (Base64 encoded)

---

## 4. DOKUMENTASI KODE

Semua fungsi dalam aplikasi ini menggunakan prefix **dimas20221310102** sesuai ketentuan UAS.

### 4.1 Fungsi: `dimas20221310102_generate_rsa_keys()`

**Deskripsi:** Menghasilkan pasangan kunci RSA (public key dan private key)

**Parameter:** Tidak ada

**Return Value:**
- `private_key`: Private key RSA
- `public_key`: Public key RSA

**Algoritma:**
1. Cek apakah file `private_key.pem` dan `public_key.pem` sudah ada
2. Jika ada, load kunci yang sudah ada
3. Jika tidak ada, generate kunci baru dengan:
   - Key size: 2048 bit
   - Public exponent: 65537
4. Simpan kunci ke file dalam format PEM

**Kode:**
```python
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
```

---

### 4.2 Fungsi: `dimas20221310102_hash_message(message)`

**Deskripsi:** Melakukan hash pada pesan menggunakan algoritma SHA-256

**Parameter:**
- `message` (str): Pesan yang akan di-hash

**Return Value:**
- `hash_hex` (str): Hash dalam format hexadecimal
- `message_bytes` (bytes): Pesan dalam format bytes

**Algoritma:**
1. Encode pesan ke UTF-8 bytes
2. Hitung hash SHA-256
3. Konversi hash ke format hexadecimal

**Kode:**
```python
def dimas20221310102_hash_message(message):
    """Melakukan hash pada pesan menggunakan SHA-256"""
    message_bytes = message.encode('utf-8')
    hash_object = hashlib.sha256(message_bytes)
    hash_hex = hash_object.hexdigest()
    return hash_hex, message_bytes
```

---

### 4.3 Fungsi: `dimas20221310102_create_digital_signature(message, private_key)`

**Deskripsi:** Membuat digital signature dengan cara:
1. Hash pesan menggunakan SHA-256
2. Enkripsi hash menggunakan private key RSA

**Parameter:**
- `message` (str): Pesan yang akan ditandatangani
- `private_key`: Private key RSA

**Return Value:**
- `signature_b64` (str): Digital signature dalam format Base64
- `hash_hex` (str): Hash SHA-256 dari pesan
- `signature` (bytes): Digital signature dalam format bytes

**Algoritma:**
1. Hash pesan menggunakan `dimas20221310102_hash_message()`
2. Enkripsi hash dengan private key menggunakan:
   - Padding: PSS (Probabilistic Signature Scheme)
   - MGF: MGF1 dengan SHA-256
   - Hash: SHA-256
3. Encode signature ke Base64 untuk kemudahan penyimpanan

**Kode:**
```python
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
```

---

### 4.4 Fungsi: `dimas20221310102_create_qris(signature_b64, message, hash_hex)`

**Deskripsi:** Membuat QRIS (QR Code) dari digital signature

**Parameter:**
- `signature_b64` (str): Digital signature dalam format Base64
- `message` (str): Pesan asli
- `hash_hex` (str): Hash SHA-256 dari pesan

**Return Value:**
- `qr_img`: Gambar QR Code (PIL Image)
- `qr_data` (str): Data JSON yang disimpan dalam QR Code

**Algoritma:**
1. Membuat payload JSON yang berisi:
   - message: Pesan asli
   - hash: Hash SHA-256
   - signature: Digital signature (Base64)
2. Convert JSON ke string
3. Generate QR Code dengan:
   - Version: 1
   - Error correction: L (Low)
   - Box size: 10
   - Border: 4
4. Konversi gambar ke format RGB untuk kompatibilitas

**Kode:**
```python
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
```

---

### 4.5 Fungsi: `dimas20221310102_verify_signature(message, signature_b64, public_key)`

**Deskripsi:** Memverifikasi digital signature dengan cara:
1. Dekripsi signature menggunakan public key RSA
2. Hash pesan yang diterima menggunakan SHA-256
3. Bandingkan hash hasil dekripsi dengan hash pesan

**Parameter:**
- `message` (str): Pesan yang akan diverifikasi
- `signature_b64` (str): Digital signature dalam format Base64
- `public_key`: Public key RSA

**Return Value:**
- `is_valid` (bool): True jika signature valid, False jika tidak valid
- `message_result` (str): Pesan hasil verifikasi

**Algoritma:**
1. Decode signature dari Base64 ke bytes
2. Hash pesan yang diterima menggunakan SHA-256
3. Verifikasi signature dengan public key menggunakan:
   - Padding: PSS
   - MGF: MGF1 dengan SHA-256
   - Hash: SHA-256
4. Jika verifikasi berhasil (tidak ada exception), signature valid
5. Jika terjadi InvalidSignature exception, signature tidak valid

**Kode:**
```python
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
```

---

### 4.6 Fungsi: `dimas20221310102_parse_qris(qr_data)`

**Deskripsi:** Mengurai data dari QRIS (JSON string)

**Parameter:**
- `qr_data` (str): Data JSON dari QR Code

**Return Value:**
- `message` (str): Pesan yang diekstrak
- `hash_hex` (str): Hash yang diekstrak
- `signature_b64` (str): Signature yang diekstrak

**Algoritma:**
1. Parse JSON string
2. Ekstrak field: message, hash, signature
3. Return None jika terjadi error

**Kode:**
```python
def dimas20221310102_parse_qris(qr_data):
    """Mengurai data dari QRIS"""
    try:
        data = json.loads(qr_data)
        return data.get("message", ""), data.get("hash", ""), data.get("signature", "")
    except:
        return None, None, None
```

---

### 4.7 Fungsi: `dimas20221310102_load_public_key()`

**Deskripsi:** Memuat public key dari file

**Parameter:** Tidak ada

**Return Value:**
- `public_key`: Public key RSA, atau None jika file tidak ditemukan

**Algoritma:**
1. Cek apakah file `public_key.pem` ada
2. Jika ada, load dan return public key
3. Jika tidak ada, return None

**Kode:**
```python
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
```

---

## 5. ANTARMUKA APLIKASI

### 5.1 Halaman Utama

Aplikasi menggunakan framework Streamlit dengan dua halaman utama yang dapat diakses melalui sidebar:

1. **📝 Pengirim Pesan**
2. **✅ Penerima & Verifikasi**

### 5.2 Interface Pengirim Pesan

**Komponen:**
- Text area untuk input pesan
- Tombol "Generate Kunci RSA" untuk membuat pasangan kunci
- Tombol "Buat Digital Signature & QRIS" untuk membuat signature dan QRIS
- Tampilan informasi signature:
  - Hash SHA-256
  - Digital Signature (Base64)
- Tampilan QRIS Code
- Tombol download QRIS

**Fitur:**
- Validasi input pesan
- Auto-generate kunci jika belum ada
- Tampilan informasi lengkap tentang signature
- Download QRIS dalam format PNG

### 5.3 Interface Penerima & Verifikasi

**Komponen:**
- File uploader untuk upload gambar QRIS
- Preview gambar QRIS yang diupload
- Status pembacaan QRIS
- Tombol "Verifikasi Digital Signature"
- Hasil verifikasi yang menampilkan:
  - Isi pesan
  - Hash SHA-256
  - Digital Signature
  - Status verifikasi (Valid/Tidak Valid)
  - Detail proses verifikasi

**Fitur:**
- Auto-scan QRIS saat diupload
- Parse data dari QRIS
- Verifikasi signature dengan public key
- Tampilan hasil verifikasi yang informatif
- Error handling yang jelas

---

## 6. CARA PENGGUNAAN

### 6.1 Instalasi

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Dependencies yang diperlukan:
   - streamlit>=1.28.0
   - cryptography>=41.0.0
   - qrcode[pil]>=7.4.2
   - Pillow>=10.0.0
   - pyzbar>=0.1.9

### 6.2 Menjalankan Aplikasi

```bash
streamlit run app.py
```

Aplikasi akan terbuka di browser pada `http://localhost:8501`

### 6.3 Membuat Digital Signature dan QRIS

1. Buka halaman **"📝 Pengirim Pesan"**
2. Masukkan pesan yang akan ditandatangani di text area
3. (Opsional) Klik **"🔑 Generate Kunci RSA"** jika kunci belum ada
4. Klik **"✍️ Buat Digital Signature & QRIS"**
5. Sistem akan:
   - Generate kunci RSA (jika belum ada)
   - Hash pesan dengan SHA-256
   - Membuat digital signature
   - Generate QRIS
6. Download QRIS dengan klik tombol **"⬇️ Download QRIS"**

### 6.4 Verifikasi Digital Signature

1. Buka halaman **"✅ Penerima & Verifikasi"**
2. Upload gambar QRIS yang sudah didownload
3. Sistem akan otomatis:
   - Membaca QR Code
   - Parse data JSON
   - Menyiapkan data untuk verifikasi
4. Klik **"🔍 Verifikasi Digital Signature"**
5. Sistem akan:
   - Load public key
   - Verifikasi signature
   - Menampilkan hasil verifikasi

### 6.5 Hasil Verifikasi

Jika signature valid:
- ✅ Status: "Signature valid! Pesan tidak diubah dan berasal dari pemilik private key."
- Menampilkan pesan, hash, dan signature
- Menampilkan detail proses verifikasi

Jika signature tidak valid:
- ❌ Status: "Signature tidak valid! Pesan mungkin diubah atau signature tidak cocok."
- Menampilkan error message

---

## 7. KESIMPULAN

### 7.1 Pencapaian

Sistem berhasil mengimplementasikan:
1. ✅ Generate pasangan kunci RSA (public key dan private key)
2. ✅ Hash pesan menggunakan SHA-256
3. ✅ Enkripsi hash menggunakan private key RSA untuk membuat digital signature
4. ✅ Generate QRIS dari digital signature
5. ✅ Verifikasi signature dengan mendekripsi menggunakan public key RSA
6. ✅ Antarmuka yang user-friendly menggunakan Streamlit
7. ✅ Semua fungsi menggunakan prefix NPM sesuai ketentuan

### 7.2 Keamanan

Sistem ini menjamin:
- **Integritas**: Hash SHA-256 memastikan pesan tidak diubah
- **Autentikasi**: Digital signature memastikan pesan berasal dari pemilik private key
- **Non-repudiation**: Pemilik private key tidak dapat menyangkal telah menandatangani pesan

### 7.3 Kelebihan

1. Antarmuka yang mudah digunakan
2. Proses otomatis untuk generate kunci dan verifikasi
3. QRIS memudahkan distribusi digital signature
4. Error handling yang baik
5. Dokumentasi kode yang jelas

### 7.4 Keterbatasan

1. pyzbar memerlukan Visual C++ Redistributable di Windows
2. QRIS harus dibuat dari aplikasi ini untuk format yang kompatibel
3. Private key disimpan tanpa enkripsi (untuk kemudahan, tidak disarankan untuk produksi)

---

## LAMPIRAN

### A. Struktur File

```
uas-kripto/
├── app.py                    # File utama aplikasi Streamlit
├── requirements.txt          # Dependencies
├── README.md                 # Dokumentasi singkat
├── private_key.pem          # Private key RSA (dihasilkan otomatis)
├── public_key.pem           # Public key RSA (dihasilkan otomatis)
└── qris_digital_signature.png # QRIS yang dihasilkan (contoh)
```

### B. Teknologi yang Digunakan

- **Python 3.x**: Bahasa pemrograman
- **Streamlit**: Framework untuk web application
- **cryptography**: Library untuk kriptografi (RSA, SHA-256)
- **qrcode**: Library untuk generate QR Code
- **pyzbar**: Library untuk membaca QR Code
- **Pillow**: Library untuk image processing

---

**Dibuat dengan ❤️ untuk UAS Kriptografi**

**NPM: 20221310102**  
**Tahun Akademik: 2025-2026**

