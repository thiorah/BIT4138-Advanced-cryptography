"""
BIT4138 - Advanced Cryptography
Week 9 Programming Assignment
Title: Develop a Secure RSA Encryption System Using Python

Features:
1. Generate RSA Keys (with Miller-Rabin prime generation)
2. Encrypt Message
3. Decrypt Message
4. Sign Message (SHA-256 + RSA signature)
5. Verify Signature
6. Miller-Rabin Prime Test (demo on 10 random numbers)
7. Exit
"""

import random
import hashlib
import math

# ---------------------------------------------------------------------------
# PART F: MILLER-RABIN PRIMALITY TEST
# ---------------------------------------------------------------------------

def miller_rabin(n, k=20):
    """Return True if n is probably prime, False if it is composite."""
    if n in (2, 3):
        return True
    if n % 2 == 0 or n < 2:
        return False

    # write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits=16):
    """Generate a prime number of the given bit length using Miller-Rabin."""
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(candidate):
            return candidate


# ---------------------------------------------------------------------------
# PART A: RSA KEY GENERATION
# ---------------------------------------------------------------------------

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """Extended Euclidean Algorithm to find modular inverse of e mod phi."""
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s % phi


def generate_rsa_keys(bits=16):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while q == p:
        q = generate_large_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)

    print("\n--- RSA KEY GENERATION ---")
    print(f"Prime P        : {p}")
    print(f"Prime Q        : {q}")
    print(f"Modulus n      : {n}")
    print(f"Euler Totient  : {phi}")
    print(f"Public Key  (e, n): ({e}, {n})")
    print(f"Private Key (d, n): ({d}, {n})")

    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


# ---------------------------------------------------------------------------
# PART B & C: ENCRYPTION / DECRYPTION
# ---------------------------------------------------------------------------

def rsa_encrypt(message, e, n):
    ascii_values = [ord(ch) for ch in message]
    encrypted = [pow(val, e, n) for val in ascii_values]

    print("\n--- ENCRYPTION ---")
    print(f"{'Original':<10}{'ASCII':<10}{'Encrypted'}")
    for ch, a, c in zip(message, ascii_values, encrypted):
        print(f"{ch:<10}{a:<10}{c}")

    return encrypted


def rsa_decrypt(encrypted, d, n):
    decrypted_ascii = [pow(c, d, n) for c in encrypted]
    decrypted_message = "".join(chr(a) for a in decrypted_ascii)

    print("\n--- DECRYPTION ---")
    print(f"{'Encrypted':<12}{'Decrypted ASCII':<18}{'Character'}")
    for c, a in zip(encrypted, decrypted_ascii):
        print(f"{c:<12}{a:<18}{chr(a)}")
    print(f"\nRecovered Original Message: {decrypted_message}")

    return decrypted_message


# ---------------------------------------------------------------------------
# PART D & E: DIGITAL SIGNATURE / VERIFICATION
# ---------------------------------------------------------------------------

def hash_message(message):
    """Return a SHA-256 hash of the message as an integer (reduced mod n)."""
    digest = hashlib.sha256(message.encode()).hexdigest()
    return int(digest, 16)


def sign_message(message, d, n):
    hash_int = hash_message(message) % n
    signature = pow(hash_int, d, n)

    print("\n--- DIGITAL SIGNATURE ---")
    print(f"Original Hash     : {hash_int}")
    print(f"Digital Signature : {signature}")

    return hash_int, signature


def verify_signature(message, signature, e, n):
    original_hash = hash_message(message) % n
    recovered_hash = pow(signature, e, n)

    print("\n--- SIGNATURE VERIFICATION ---")
    print(f"Original Hash  : {original_hash}")
    print(f"Recovered Hash : {recovered_hash}")

    if original_hash == recovered_hash:
        print("Result: Signature Valid")
        return True
    else:
        print("Result: Signature Invalid")
        return False


# ---------------------------------------------------------------------------
# PART F DEMO: RUN MILLER-RABIN ON 10 RANDOM NUMBERS
# ---------------------------------------------------------------------------

def miller_rabin_demo():
    print("\n--- MILLER-RABIN PRIME TEST (10 random numbers) ---")
    print(f"{'Number':<10}{'Result'}")
    for _ in range(10):
        number = random.randint(2, 500)
        result = "Prime" if miller_rabin(number) else "Composite"
        print(f"{number:<10}{result}")


# ---------------------------------------------------------------------------
# MAIN MENU
# ---------------------------------------------------------------------------

def main():
    keys = None
    last_encrypted = None
    last_message = None
    last_signature = None

    while True:
        print("\n=================================")
        print("RSA SECURITY SYSTEM")
        print("=================================")
        print("1. Generate RSA Keys")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("4. Sign Message")
        print("5. Verify Signature")
        print("6. Miller-Rabin Prime Test")
        print("7. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            keys = generate_rsa_keys()

        elif choice == "2":
            if not keys:
                print("Please generate keys first (Option 1).")
                continue
            last_message = input("Enter message to encrypt: ")
            last_encrypted = rsa_encrypt(last_message, keys["e"], keys["n"])

        elif choice == "3":
            if not keys or last_encrypted is None:
                print("Please generate keys and encrypt a message first.")
                continue
            rsa_decrypt(last_encrypted, keys["d"], keys["n"])

        elif choice == "4":
            if not keys:
                print("Please generate keys first (Option 1).")
                continue
            msg_to_sign = input("Enter message to sign: ")
            _, last_signature = sign_message(msg_to_sign, keys["d"], keys["n"])
            last_message = msg_to_sign

        elif choice == "5":
            if not keys or last_signature is None:
                print("Please sign a message first (Option 4).")
                continue
            verify_signature(last_message, last_signature, keys["e"], keys["n"])

        elif choice == "6":
            miller_rabin_demo()

        elif choice == "7":
            print("Exiting RSA Security System. Goodbye!")
            break

        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
