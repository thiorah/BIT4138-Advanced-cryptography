"""
BIT4138 - Advanced Cryptography
Week 10 Programming Assignment
Title: Develop a Secure ElGamal Encryption and ECC Demonstration System

Features:
1. Generate Keys (ElGamal)
2. Encrypt Message
3. Decrypt Message
4. Compare RSA vs ElGamal (key gen / encrypt / decrypt timing)
5. ECC Demo (key generation, signing, verification)
6. Exit
"""

import random
import time
import hashlib

# ---------------------------------------------------------------------------
# BASIC NUMBER THEORY HELPERS (shared with RSA benchmark)
# ---------------------------------------------------------------------------

def miller_rabin(n, k=20):
    if n in (2, 3):
        return True
    if n % 2 == 0 or n < 2:
        return False
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
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(candidate):
            return candidate


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    old_r, r = a, m
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s % m


def is_generator(g, p):
    """Very small primitive-root check used only for the classroom demo."""
    seen = set()
    val = 1
    for _ in range(p - 1):
        val = (val * g) % p
        if val in seen:
            return False
        seen.add(val)
    return len(seen) == p - 1


def find_generator(p):
    for g in range(2, p):
        if is_generator(g, p):
            return g
    return 2


# ---------------------------------------------------------------------------
# PART A: ELGAMAL KEY GENERATION
# ---------------------------------------------------------------------------

def generate_elgamal_keys(bits=12):
    p = generate_large_prime(bits)
    g = find_generator(p)
    x = random.randint(2, p - 2)          # private key
    y = pow(g, x, p)                      # public key

    print("\n--- ELGAMAL KEY GENERATION ---")
    print(f"Prime (p)      : {p}")
    print(f"Generator (g)  : {g}")
    print(f"Private Key (x): {x}")
    print(f"Public Key  (y): {y}")

    return {"p": p, "g": g, "x": x, "y": y}


# ---------------------------------------------------------------------------
# PART B & C: ELGAMAL ENCRYPTION / DECRYPTION
# ---------------------------------------------------------------------------

def elgamal_encrypt_char(m, p, g, y, k=None):
    if k is None:
        k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2, k


def elgamal_encrypt_message(message, keys):
    p, g, y = keys["p"], keys["g"], keys["y"]
    ciphertext = []

    print("\n--- ENCRYPTION ---")
    for ch in message:
        m = ord(ch)
        if m >= p:
            raise ValueError(
                f"Prime p={p} is too small for character '{ch}' (ASCII {m}). "
                "Increase 'bits' in generate_elgamal_keys()."
            )
        c1, c2, k = elgamal_encrypt_char(m, p, g, y)
        ciphertext.append((c1, c2))
        print(f"Char: {ch!r:<5} Random k: {k:<8} C1: {c1:<8} C2: {c2}")

    return ciphertext


def elgamal_decrypt_message(ciphertext, keys):
    p, x = keys["p"], keys["x"]
    decrypted_chars = []

    print("\n--- DECRYPTION ---")
    for c1, c2 in ciphertext:
        s = pow(c1, x, p)
        s_inv = mod_inverse(s, p)
        m = (c2 * s_inv) % p
        decrypted_chars.append(chr(m))
        print(f"C1: {c1:<8} C2: {c2:<8} -> Recovered: {chr(m)!r}")

    message = "".join(decrypted_chars)
    print(f"\nRecovered Original Message: {message}")
    return message


# ---------------------------------------------------------------------------
# PART D: RANDOMNESS DEMONSTRATION
# ---------------------------------------------------------------------------

def randomness_demo(message, keys):
    print("\n--- RANDOMNESS DEMONSTRATION (same message, 5 encryptions) ---")
    p, g, y, x = keys["p"], keys["g"], keys["y"], keys["x"]
    m = ord(message[0])  # demonstrate with the first character

    for i in range(1, 6):
        c1, c2, k = elgamal_encrypt_char(m, p, g, y)
        s_inv = mod_inverse(pow(c1, x, p), p)
        recovered = (c2 * s_inv) % p
        print(f"Attempt {i}: k={k:<6} C1={c1:<6} C2={c2:<8} "
              f"Decrypted='{chr(recovered)}'")

    print("\nEach run uses a fresh random k, so C1 and C2 change every time, "
          "but decryption always recovers the same original character. "
          "This is because k only affects the ciphertext values, not the "
          "underlying mathematical relationship that the private key x "
          "reverses.")


# ---------------------------------------------------------------------------
# PART E: RSA vs ELGAMAL BENCHMARK
# ---------------------------------------------------------------------------

def rsa_keygen(bits=16):
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
    return {"n": n, "e": e, "d": d}


def benchmark(message="HELLO"):
    print("\n--- RSA vs ELGAMAL BENCHMARK ---")

    # RSA timings
    t0 = time.perf_counter()
    rsa_keys = rsa_keygen(bits=16)
    t1 = time.perf_counter()
    rsa_cipher = [pow(ord(c), rsa_keys["e"], rsa_keys["n"]) for c in message]
    t2 = time.perf_counter()
    _ = [pow(c, rsa_keys["d"], rsa_keys["n"]) for c in rsa_cipher]
    t3 = time.perf_counter()

    rsa_keygen_time = t1 - t0
    rsa_encrypt_time = t2 - t1
    rsa_decrypt_time = t3 - t2

    # ElGamal timings
    t0 = time.perf_counter()
    eg_keys = generate_elgamal_keys(bits=12)
    t1 = time.perf_counter()
    eg_cipher = [elgamal_encrypt_char(ord(c), eg_keys["p"], eg_keys["g"],
                                       eg_keys["y"]) for c in message]
    t2 = time.perf_counter()
    for c1, c2, _k in eg_cipher:
        s_inv = mod_inverse(pow(c1, eg_keys["x"], eg_keys["p"]), eg_keys["p"])
        _ = (c2 * s_inv) % eg_keys["p"]
    t3 = time.perf_counter()

    eg_keygen_time = t1 - t0
    eg_encrypt_time = t2 - t1
    eg_decrypt_time = t3 - t2

    print(f"\n{'Algorithm':<12}{'Key Gen (s)':<15}{'Encrypt (s)':<15}{'Decrypt (s)'}")
    print(f"{'RSA':<12}{rsa_keygen_time:<15.6f}{rsa_encrypt_time:<15.6f}{rsa_decrypt_time:.6f}")
    print(f"{'ElGamal':<12}{eg_keygen_time:<15.6f}{eg_encrypt_time:<15.6f}{eg_decrypt_time:.6f}")

    print("\nExplanation: RSA key generation tends to be relatively fast for "
          "small demonstration key sizes, while ElGamal encryption produces "
          "two ciphertext values per character (C1, C2), roughly doubling "
          "ciphertext size and typically increasing encryption workload "
          "compared to RSA for the same message.")


# ---------------------------------------------------------------------------
# PART F: ECC DEMONSTRATION (BONUS)
# ---------------------------------------------------------------------------

def ecc_demo():
    """
    Simple educational ECC demo implementing point addition, doubling and
    scalar multiplication on a small curve y^2 = x^3 + ax + b (mod p),
    then a toy Schnorr-style signature to demonstrate sign/verify.
    """
    print("\n--- ELLIPTIC CURVE CRYPTOGRAPHY (ECC) DEMO ---")

    # A small demonstration curve: y^2 = x^3 + 2x + 2 (mod 17)
    p = 17
    a = 2
    b = 2
    G = (5, 1)  # a known point on this curve, used as the generator

    def inverse_mod(k, p):
        return pow(k, -1, p)

    def point_add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None  # point at infinity
        if P == Q:
            m = (3 * x1 * x1 + a) * inverse_mod(2 * y1, p) % p
        else:
            m = (y2 - y1) * inverse_mod(x2 - x1, p) % p
        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)

    def scalar_mult(k, P):
        result = None
        addend = P
        while k:
            if k & 1:
                result = point_add(result, addend)
            addend = point_add(addend, addend)
            k >>= 1
        return result

    def point_order(P):
        """Brute-force the order of point P (fine for this tiny demo curve)."""
        n = 1
        current = P
        while current is not None:
            current = point_add(current, P)
            n += 1
        return n

    order_n = point_order(G)  # scalar arithmetic must be done mod this order

    # Key generation
    private_key = random.randint(2, order_n - 1)
    public_key = scalar_mult(private_key, G)

    print(f"Curve          : y^2 = x^3 + {a}x + {b} (mod {p})")
    print(f"Generator (G)  : {G}")
    print(f"Private Key    : {private_key}")
    print(f"Public Key     : {public_key}")

    # Toy signing: sign the hash of a message using a Schnorr-like scheme
    message = "SECURE MESSAGE"
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % order_n

    k = random.randint(2, order_n - 1)
    R = scalar_mult(k, G)
    s = (k + private_key * h) % order_n

    print(f"\nMessage to sign: {message}")
    print(f"Hash (mod p)   : {h}")
    print(f"Signature      : (R={R}, s={s})")

    # Verification: check s*G == R + h*PublicKey
    lhs = scalar_mult(s, G)
    rhs = point_add(R, scalar_mult(h, public_key))

    print(f"\nVerification check: s*G = {lhs}  |  R + h*PublicKey = {rhs}")
    if lhs == rhs:
        print("Result: Signature Valid")
    else:
        print("Result: Signature Invalid")

    print("\nNote: This is a simplified educational demonstration of ECC "
          "point arithmetic and signing, using a small curve for clarity. "
          "Production systems use standard curves (e.g. secp256k1, P-256) "
          "and libraries such as 'ecdsa' or 'cryptography'.")


# ---------------------------------------------------------------------------
# MAIN MENU
# ---------------------------------------------------------------------------

def main():
    keys = None
    last_ciphertext = None
    last_message = None

    while True:
        print("\n===================================")
        print("ELGAMAL SECURITY SYSTEM")
        print("===================================")
        print("1 Generate Keys")
        print("2 Encrypt Message")
        print("3 Decrypt Message")
        print("4 Compare RSA vs ElGamal")
        print("5 ECC Demo")
        print("6 Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            keys = generate_elgamal_keys(bits=12)

        elif choice == "2":
            if not keys:
                print("Please generate keys first (Option 1).")
                continue
            last_message = input("Enter message to encrypt: ")
            try:
                last_ciphertext = elgamal_encrypt_message(last_message, keys)
            except ValueError as err:
                print(f"Error: {err}")

        elif choice == "3":
            if not keys or last_ciphertext is None:
                print("Please generate keys and encrypt a message first.")
                continue
            elgamal_decrypt_message(last_ciphertext, keys)
            if last_message:
                randomness_demo(last_message, keys)

        elif choice == "4":
            benchmark()

        elif choice == "5":
            ecc_demo()

        elif choice == "6":
            print("Exiting ElGamal Security System. Goodbye!")
            break

        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
