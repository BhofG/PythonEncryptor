import os
import struct
import time
import itertools
from typing import Iterable

from tqdm import tqdm

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import helper from existing encryptor (safe because zt_encrypt runs CLI only under __main__)
import zt_encrypt


def read_header(path: str):
    with open(path, "rb") as f:
        magic = f.read(len(zt_encrypt.MAGIC))
        if magic != zt_encrypt.MAGIC:
            raise ValueError("Not a ZT encrypted file")
        version = struct.unpack("B", f.read(1))[0]
        salt = f.read(zt_encrypt.SALT_SIZE)
        master_nonce = f.read(zt_encrypt.NONCE_SIZE)
        chunk_size = struct.unpack(">I", f.read(4))[0]
        # read first chunk size + data (if exists)
        size_bytes = f.read(4)
        if not size_bytes:
            first_encrypted = None
        else:
            enc_size = struct.unpack(">I", size_bytes)[0]
            first_encrypted = f.read(enc_size)

    return {
        "version": version,
        "salt": salt,
        "master_nonce": master_nonce,
        "chunk_size": chunk_size,
        "first_encrypted": first_encrypted,
    }


def test_password_on_header(candidate: str, header: dict) -> bool:
    """Return True if candidate decrypts first chunk successfully."""
    if header["first_encrypted"] is None:
        # nothing to test against; treat as unknown
        return False

    key = zt_encrypt.paranoid_kdf(candidate, header["salt"])
    aesgcm = AESGCM(key)
    aad = zt_encrypt.MAGIC + struct.pack("B", zt_encrypt.VERSION) + header["salt"] + header["master_nonce"]
    nonce = struct.pack(">Q", 0).rjust(zt_encrypt.NONCE_SIZE, b"\0")
    try:
        _ = aesgcm.decrypt(nonce, header["first_encrypted"], aad)
        return True
    except Exception:
        return False


def benchmark_attempts_per_second(header: dict, sample_seconds: float = 3.0) -> float:
    """Measure how many candidate attempts (KDF+decrypt) can be tested per second."""
    # Use a dummy password repeatedly to measure cost
    dummy = "password"
    start = time.perf_counter()
    count = 0
    # run for sample_seconds or at least 1 attempt
    while True:
        _ = test_password_on_header(dummy + str(count), header)
        count += 1
        elapsed = time.perf_counter() - start
        if elapsed >= sample_seconds and count > 1:
            break
    return count / elapsed


def human_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{int(m)}m {int(s)}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h {int(m)}m"


def generate_wordlist(path: str, charset: str, minlen: int, maxlen: int):
    """Generate a simple exhaustive wordlist (warning: can be huge)."""
    total = sum(len(charset) ** l for l in range(minlen, maxlen + 1))
    if total > 50_000_000:
        print(f"[WARN] Wordlist size {total:,} is very large. Continue? (y/n)")
        if input().strip().lower() not in ("y", "yes"):
            print("Aborted generation.")
            return

    with open(path, "w", encoding="utf-8") as fout:
        with tqdm(total=total, desc="Generating wordlist") as pbar:
            for l in range(minlen, maxlen + 1):
                for tup in itertools.product(charset, repeat=l):
                    fout.write("".join(tup) + "\n")
                    pbar.update(1)


def generate_candidates(charset: str, minlen: int, maxlen: int):
    """Yield candidate strings (in-memory) without writing to disk."""
    for l in range(minlen, maxlen + 1):
        for tup in itertools.product(charset, repeat=l):
            yield "".join(tup)


def brute_force_file(enc_path: str, wordlist: Iterable[str], out_path: str = None, attempts_per_sec: float = None, total_count: int = None):
    header = read_header(enc_path)
    if attempts_per_sec is None:
        print("Benchmarking attempts/sec (this will run Argon2 a few times)...")
        attempts_per_sec = benchmark_attempts_per_second(header)
    print(f"Attempts/sec: {attempts_per_sec:.2f}")
    # Prepare iterator and total count (if provided)
    total = total_count
    if isinstance(wordlist, str):
        # wordlist is a file path
        f = open(wordlist, "r", encoding="utf-8", errors="ignore")
        if total is None:
            try:
                with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                    total = sum(1 for _ in fh)
            except Exception:
                total = None
        iterator = (line.rstrip("\n\r") for line in f)
    else:
        f = None
        iterator = (w for w in wordlist)

    checked = 0
    start = time.perf_counter()
    for candidate in iterator:
        checked += 1
        if checked % 100 == 0:
            elapsed = time.perf_counter() - start
            rate = checked / elapsed if elapsed > 0 else 0
            if total:
                remaining = total - checked
                eta = remaining / rate if rate > 0 else float("inf")
                print(f"Checked {checked}/{total}  rate={rate:.1f}/s  ETA={human_time(eta)}", end="\r")
        if test_password_on_header(candidate, header):
            print(f"\n[+] Found passphrase: '{candidate}'")
            # call decrypt_file to restore full file
            out = out_path or (enc_path[:-4] if enc_path.lower().endswith('.zte') else enc_path + '.dec')
            zt_encrypt.decrypt_file(enc_path, out, candidate)
            if f:
                f.close()
            return candidate

    if f:
        f.close()
    print("\n[-] No passphrase found in provided wordlist")
    return None


def main():
    print("Interactive brute-force for ZT encrypted files")

    # Ask for encrypted file
    while True:
        enc_file = input("Enter path to encrypted .zte file: ").strip()
        if not enc_file:
            print("Path cannot be empty.")
            continue
        if not os.path.exists(enc_file):
            print("File not found. Try again.")
            continue
        break

    header = read_header(enc_file)
    print(f"File version: {header['version']}; chunk_size: {header['chunk_size']}")

    # Ask whether to use an in-memory generator (no disk)
    use_generator = input("Use in-memory generator (no disk)? (y/n): ").strip().lower()
    total = None
    if use_generator in ("y", "yes"):
        charset = input("Charset (default: lowercase+digits) [press enter for default]: ").strip()
        if not charset:
            charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        try:
            minlen = int(input("Min length (default 1): ").strip() or "1")
            maxlen = int(input("Max length (default 4): ").strip() or "4")
        except ValueError:
            print("Invalid length input")
            return
        # create generator and compute total combinatorially
        wl = generate_candidates(charset, minlen, maxlen)
        total = sum(len(charset) ** l for l in range(minlen, maxlen + 1))
        print(f"Generator configured: charset='{charset}' min={minlen} max={maxlen} (total {total:,} candidates)")
    else:
        # ask for existing wordlist file
        while True:
            wl = input("Enter path to existing wordlist file: ").strip()
            if not wl:
                print("Path cannot be empty.")
                continue
            if not os.path.exists(wl):
                print("Wordlist not found. Try again.")
                continue
            break
        # count lines for ETA if possible
        try:
            with open(wl, "r", encoding="utf-8", errors="ignore") as fh:
                total = sum(1 for _ in fh)
        except Exception:
            total = None

    # Benchmark seconds
    try:
        bench = float(input("Benchmark seconds (default 3.0): ").strip() or "3.0")
    except ValueError:
        bench = 3.0

    out_path = input("Optional output path for decrypted file (press enter to auto): ").strip() or None

    print("Running benchmark to estimate speed...")
    rate = benchmark_attempts_per_second(header, sample_seconds=bench)
    if total:
        eta = total / rate if rate > 0 else float('inf')
        print(f"Wordlist entries: {total:,}; Attempts/sec: {rate:.2f}; ETA: {human_time(eta)}")
    else:
        print(f"Attempts/sec: {rate:.2f}")

    print("Starting brute-force... (press Ctrl-C to stop)")
    try:
        found = brute_force_file(enc_file, wl, out_path=out_path, attempts_per_sec=rate, total_count=total)
        if found:
            print(f"Success: {found}")
        else:
            print("Password not found")
    except KeyboardInterrupt:
        print("\nInterrupted by user")


if __name__ == "__main__":
    main()
