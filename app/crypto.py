import json
import math
import hashlib
import base64
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.ui import ConsoleWindow


class Crypto:
    def _is_prime_miller_rabin(self, n, num_rounds=40) -> bool:
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False

        #n-1 = 2^k * q
        q = n - 1
        k = 0
        while q % 2 == 0:
            q //= 2
            k += 1

        # Perform num_rounds rounds of testing
        for _ in range(num_rounds):
            a = random.randrange(2, n - 1)

            # 1. Check if a^q = 1 (mod n)
            x = pow(a, q, n)
            if x == 1 or x == n - 1:
                continue

            # 2. Check if a^(2^j * q) = -1 (mod n) for 0 <= j < k
            is_composite = True
            for _ in range(k - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    is_composite = False
                    break

            if is_composite:
                return False

        # If all rounds pass, n is probably prime
        return True

    def generate_prime(self, bit_length=1024) -> int:
        while True:
            p = random.getrandbits(bit_length)
            
            p |= (1 << bit_length - 1) | 1

            if self._is_prime_miller_rabin(p):
                return p


class RSAKey(Crypto):
    def __init__(self, bit_length=2048, message_window=None, public_key_file="rsa_public.key", private_key_file="rsa_private.key"):
        self.message_window = message_window or ConsoleWindow()
        self.public_key = None
        self.private_key = None
        self.public_key_file = public_key_file
        self.private_key_file = private_key_file

        if not self._load_keys():
            if bit_length:
                self._generate_keys(bit_length)
                self.save_public_key(self.public_key_file)
                self.save_private_key(self.private_key_file)

    def _load_keys(self):
        try:
            with open(self.private_key_file, "r") as f:
                private_key_data = json.load(f)
            with open(self.public_key_file, "r") as f:
                public_key_data = json.load(f)

            self.private_key = (
                private_key_data["p"],
                private_key_data["q"],
                private_key_data["d"],
            )
            n = private_key_data["p"] * private_key_data["q"]
            
            if n != public_key_data["n"]:
                raise ValueError("Mismatch between public and private key files.")

            self.public_key = (
                public_key_data["n"],
                public_key_data["e"],
            )
            self.message_window.display_message("RSA keys loaded from files.")
            return True

        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            self.message_window.display_message(
                f"Could not load keys, generating new ones..."
            )
            return False

    def _generate_keys(self, bit_length):
        p = self.generate_prime(bit_length // 2)
        q = self.generate_prime(bit_length // 2)
        while p == q:
            q = self.generate_prime(bit_length // 2)

        n = p * q
        g = math.gcd(p - 1, q - 1)

        lambda_n = (p - 1) * (q - 1) // g

        e = 65537

        # if p eller q is not prime
        while math.gcd(e, lambda_n) != 1:
            p = self.generate_prime(bit_length // 2)
            q = self.generate_prime(bit_length // 2)
            while p == q:
                q = self.generate_prime(bit_length // 2)
            n = p * q
            g = math.gcd(p - 1, q - 1)
            lambda_n = (p - 1) * (q - 1) // g

        d = pow(e, -1, lambda_n)


        self.public_key = (n, e)
        self.private_key = (p, q, d)

    def save_public_key(self, filename="rsa_public.key"):
        if self.public_key:
            # Public key is (n, e)
            key_data = {"n": self.public_key[0], "e": self.public_key[1]}
            with open(filename, "w") as f:
                json.dump(key_data, f, indent=4)
            self.message_window.display_message(f"Public key saved to {filename}")

    def save_private_key(self, filename="rsa_private.key"):
        if self.private_key:
            # Private key is (p, q, d)
            key_data = {
                "p": self.private_key[0],
                "q": self.private_key[1],
                "d": self.private_key[2],
            }
            with open(filename, "w") as f:
                json.dump(key_data, f, indent=4)
            self.message_window.display_message(f"Private key saved to {filename}")

    def sign(self, message) -> int:
        p, q, d = self.private_key
        n = p * q

        h = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
        signature = pow(h, d, n)
        return signature

    def verify(self, message, signature, peer_public_key) -> bool:
        n, e = peer_public_key
        # Hash the original message
        h = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
        # "Decrypt" the signature with the public key
        h_from_signature = pow(signature, e, n)
        # The signature is valid if the decrypted hash matches the original hash
        return h == h_from_signature

class AESCipher:

    def __init__(self, key, message_window=None):
        self.key = hashlib.sha256(str(key).encode()).digest()
        self.message_window = message_window or ConsoleWindow()

    def encrypt(self, plaintext: str) -> dict:
        """Encrypts a plaintext string using AES-GCM."""
        try:
            plaintext_bytes = plaintext.encode("utf-8")
            cipher = AES.new(self.key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
            return {
                "nonce": base64.b64encode(cipher.nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "tag": base64.b64encode(tag).decode("utf-8"),
            }
        except Exception as e:
            self.message_window.display_message(f"Encryption error: {e}")
            return None

    def decrypt(self, encrypted_data: dict) -> str:
        """Decrypts an AES-GCM encrypted payload."""
        try:
            nonce = base64.b64decode(encrypted_data["nonce"])
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            tag = base64.b64decode(encrypted_data["tag"])

            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext_bytes.decode("utf-8")
        except (ValueError, KeyError) as e:
            self.message_window.display_message(f"Decryption failed: {e}")
            return None


class DiffieHellman:

    def __init__(self):
        # 2048-bit MODP Group from RFC 3526 (Group 14)
        self.p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16,
        )
        self.g = 2
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self._generate_private_key()
        self._generate_public_key()

    def _generate_private_key(self, bit_length=256):
        self.private_key = random.getrandbits(bit_length)

    def _generate_public_key(self):
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, peer_public_key):
        self.shared_secret = pow(peer_public_key, self.private_key, self.p)
        return self.shared_secret

