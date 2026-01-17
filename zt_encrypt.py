import os
import struct
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type
from tqdm import tqdm

# =====================
# CONSTANTS (STRICT)
# =====================
MAGIC = b'ZTAES256'
VERSION = 1

SALT_SIZE = 32
NONCE_SIZE = 12
KEY_SIZE = 32
CHUNK_SIZE = 1024 * 1024  # 1 MB chunks

# PARANOID ARGON2 CONFIG
ARGON_TIME = 6
ARGON_MEMORY = 1024 * 1024  # 1 GB RAM
ARGON_PARALLELISM = 8


# =====================
# HELPER FUNCTIONS
# =====================
def ensure_zte_extension(filepath: str) -> str:
    """Otomatis menambahkan .zte extension jika belum ada"""
    if not filepath.lower().endswith('.zte'):
        return filepath + '.zte'
    return filepath


# =====================
# CRYPTO CORE
# =====================
def paranoid_kdf(password: str, salt: bytes) -> bytes:
    master = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEMORY,
        parallelism=ARGON_PARALLELISM,
        hash_len=64,
        type=Type.ID
    )

    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=salt,
        info=b'ZERO_TRUST_AES_FILE'
    )

    return hkdf.derive(master)


def encrypt_file(input_path, output_path, password):
    output_path = ensure_zte_extension(output_path)
    filesize = os.path.getsize(input_path)

    salt = os.urandom(SALT_SIZE)
    master_nonce = os.urandom(NONCE_SIZE)
    key = paranoid_kdf(password, salt)
    aesgcm = AESGCM(key)

    aad = MAGIC + struct.pack("B", VERSION) + salt + master_nonce

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack("B", VERSION))
        fout.write(salt)
        fout.write(master_nonce)
        fout.write(struct.pack(">I", CHUNK_SIZE))

        with tqdm(total=filesize, desc="Encrypting", unit="B", unit_scale=True) as bar:
            counter = 0
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break

                nonce = struct.pack(">Q", counter).rjust(NONCE_SIZE, b'\0')
                encrypted = aesgcm.encrypt(nonce, chunk, aad)
                fout.write(struct.pack(">I", len(encrypted)))
                fout.write(encrypted)

                bar.update(len(chunk))
                counter += 1

    secure_wipe(key)
    print("[✓] Encryption completed successfully")


def decrypt_file(input_path, output_path, password):
    # Jika output path punya .zte extension, hapus itu agar dipulihkan dengan format asli
    if output_path.lower().endswith('.zte'):
        output_path = output_path[:-4]
    
    with open(input_path, "rb") as fin:
        if fin.read(len(MAGIC)) != MAGIC:
            raise ValueError("Invalid file format")

        version = struct.unpack("B", fin.read(1))[0]
        if version != VERSION:
            raise ValueError("Unsupported version")

        salt = fin.read(SALT_SIZE)
        master_nonce = fin.read(NONCE_SIZE)
        chunk_size = struct.unpack(">I", fin.read(4))[0]

        key = paranoid_kdf(password, salt)
        aesgcm = AESGCM(key)

        aad = MAGIC + struct.pack("B", VERSION) + salt + master_nonce

        with open(output_path, "wb") as fout, tqdm(desc="Decrypting", unit="chunk") as bar:
            counter = 0
            while True:
                size_bytes = fin.read(4)
                if not size_bytes:
                    break

                enc_size = struct.unpack(">I", size_bytes)[0]
                encrypted = fin.read(enc_size)

                nonce = struct.pack(">Q", counter).rjust(NONCE_SIZE, b'\0')
                try:
                    plaintext = aesgcm.decrypt(nonce, encrypted, aad)
                except Exception:
                    raise ValueError("Decryption failed (wrong password or tampered file)")

                fout.write(plaintext)
                counter += 1
                bar.update(1)

    secure_wipe(key)
    print("[✓] Decryption completed successfully")


def secure_wipe(data: bytes):
    if isinstance(data, bytes):
        mutable = bytearray(data)
        for i in range(len(mutable)):
            mutable[i] = 0


# =====================
# CLI - INTERACTIVE
# =====================
if __name__ == "__main__":
    print("\n" + "="*50)
    print("   ZERO-TRUST AES-256 FILE ENCRYPTOR")
    print("="*50 + "\n")

    # Tanyakan mode
    while True:
        print("Pilih Mode:")
        print("1. Encrypt")
        print("2. Decrypt")
        mode_choice = input("\nMasukkan pilihan (1/2): ").strip()
        
        if mode_choice == "1":
            mode = "encrypt"
            break
        elif mode_choice == "2":
            mode = "decrypt"
            break
        else:
            print("[ERROR] Pilihan tidak valid. Silakan coba lagi.\n")

    # Tanyakan input file
    while True:
        input_file = input(f"\nMasukkan path file input: ").strip()
        if os.path.exists(input_file):
            break
        else:
            print("[ERROR] File tidak ditemukan. Silakan coba lagi.")

    # Tanyakan output file
    output_file = input("Masukkan path file output: ").strip()
    if not output_file:
        print("[ERROR] Path output tidak boleh kosong.")
        sys.exit(1)

    # Tanyakan password
    while True:
        password = input("Masukkan passphrase: ").strip()
        if not password:
            print("[ERROR] Passphrase tidak boleh kosong. Silakan coba lagi.")
            continue
        
        if mode == "encrypt":
            password_confirm = input("Konfirmasi passphrase: ").strip()
            if password == password_confirm:
                break
            else:
                print("[ERROR] Passphrase tidak cocok. Silakan coba lagi.\n")
        else:
            break

    # Jalankan operasi
    print("\n" + "-"*50)
    try:
        if mode == "encrypt":
            encrypt_file(input_file, output_file, password)
        else:
            decrypt_file(input_file, output_file, password)
        print("-"*50)
        print("\n✓ Operasi berhasil!\n")
    except Exception as e:
        print("-"*50)
        print(f"\n✗ [ERROR] {e}\n")
        sys.exit(1)
