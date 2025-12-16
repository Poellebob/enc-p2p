import json
import math
import hashlib
import base64
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.ui import ConsoleWindow


class Crypto:
    """
    A class for cryptographic-related functions, such as generating large primes.
    """

    def _gcd(self, a, b):
        """Helper function to compute the greatest common divisor."""
        return math.gcd(a, b)

    def _is_prime_miller_rabin(self, n, num_rounds=40):
        """
        Test if a number is prime using the Miller-Rabin primality test.
        This implementation is structured to match the theory in the SOP.
        """
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False

        # Write n-1 as 2^k * q where q is odd
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

    def generate_prime(self, bit_length=1024):
        """
        Generate a large prime number of a specified bit length.
        """
        while True:
            p = random.getrandbits(bit_length)
            # Ensure MSB is 1 for correct bit length, and LSB is 1 for odd number
            p |= (1 << bit_length - 1) | 1

            if self._is_prime_miller_rabin(p):
                return p


class CryptoKey(Crypto):
    """
    A base class for cryptographic keys, inheriting prime generation from Crypto.
    """

    def __init__(self):
        super().__init__()
        self.public_key = None
        self.private_key = None

    def save_public_key(self, filename="public_key.pem"):
        """Saves the public key to a file."""
        raise NotImplementedError("This method should be implemented by subclasses.")

    def save_private_key(self, filename="private_key.pem"):
        """Saves the private key to a file."""
        raise NotImplementedError("This method should be implemented by subclasses.")


class RSAKey(CryptoKey):
    """
    Represents an RSA key pair, with generation and saving capabilities,
    matching the theory from the SOP.
    """

    def __init__(self, bit_length=2048, message_window=None):
        super().__init__()
        self.message_window = message_window or ConsoleWindow()
        if bit_length:
            self._generate_keys(bit_length)

    def _generate_keys(self, bit_length):
        """Generates the RSA public and private keys based on SOP theory."""
        p = self.generate_prime(bit_length // 2)
        q = self.generate_prime(bit_length // 2)
        while p == q:
            q = self.generate_prime(bit_length // 2)

        n = p * q
        g = self._gcd(p - 1, q - 1)

        # As per the paper: d is the inverse of e mod (p-1)(q-1)/g
        # This is also known as Carmichael's totient function, lambda(n)
        lambda_n = (p - 1) * (q - 1) // g

        e = 65537

        # It's good practice to ensure gcd(e, lambda_n) == 1
        while self._gcd(e, lambda_n) != 1:
            # In the astronomically unlikely event e is not coprime, we could pick another
            # but for 65537 and large primes, this won't happen.
            # This is more of a theoretical correctness check.
            p = self.generate_prime(bit_length // 2)
            q = self.generate_prime(bit_length // 2)
            while p == q:
                q = self.generate_prime(bit_length // 2)
            g = self._gcd(p - 1, q - 1)
            lambda_n = (p - 1) * (q - 1) // g

        d = pow(e, -1, lambda_n)

        # Public key is (N, e)
        self.public_key = (n, e)
        # Private key is (p, q, d) as per the paper
        self.private_key = (p, q, d)

    def save_public_key(self, filename="rsa_public.key"):
        """Saves the public key to a file in JSON format."""
        if self.public_key:
            # Public key is (n, e)
            key_data = {"n": self.public_key[0], "e": self.public_key[1]}
            with open(filename, "w") as f:
                json.dump(key_data, f, indent=4)
            self.message_window.display_message(f"Public key saved to {filename}")

    def save_private_key(self, filename="rsa_private.key"):
        """Saves the private key to a file in JSON format."""
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

    def sign(self, message):
        """
        Signs a message with the private key.
        :param message: The message to sign (as bytes).
        :return: The signature as an integer.
        """
        p, q, d = self.private_key
        n = p * q
        # Hash the message with SHA-256 and convert the digest to an integer
        h = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
        # "Encrypt" the hash with the private key
        signature = pow(h, d, n)
        return signature

    def verify(self, message, signature, peer_public_key):
        """
        Verifies a signature with a peer's public key.
        :param message: The original message (as bytes).
        :param signature: The signature to verify (as an integer).
        :param peer_public_key: The public key (n, e) of the signer.
        :return: True if the signature is valid, False otherwise.
        """
        n, e = peer_public_key
        # Hash the original message
        h = int.from_bytes(hashlib.sha256(message).digest(), byteorder="big")
        # "Decrypt" the signature with the public key
        h_from_signature = pow(signature, e, n)
        # The signature is valid if the decrypted hash matches the original hash
        return h == h_from_signature


class KeyManager:
    """Handles loading and generating RSA keys."""

    def __init__(
        self,
        public_key_file="rsa_public.key",
        private_key_file="rsa_private.key",
        message_window=None,
    ):
        self.public_key_file = public_key_file
        self.private_key_file = private_key_file
        self.rsa_key = None
        self.message_window = message_window or ConsoleWindow()

    def load_or_generate_keys(self, bit_length=2048):
        """Loads RSA keys from files if they exist, otherwise generates new ones."""
        try:
            with open(self.private_key_file, "r") as f:
                private_key_data = json.load(f)
            with open(self.public_key_file, "r") as f:
                public_key_data = json.load(f)

            self.rsa_key = RSAKey(bit_length=None, message_window=self.message_window)
            self.rsa_key.private_key = (
                private_key_data["p"],
                private_key_data["q"],
                private_key_data["d"],
            )
            n = private_key_data["p"] * private_key_data["q"]
            # Basic validation
            if n != public_key_data["n"]:
                raise ValueError("Mismatch between public and private key files.")

            self.rsa_key.public_key = (
                public_key_data["n"],
                public_key_data["e"],
            )
            self.message_window.display_message("RSA keys loaded from files.")
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            self.message_window.display_message(
                f"Could not load keys ({e}), generating new ones..."
            )
            self.rsa_key = RSAKey(bit_length=bit_length, message_window=self.message_window)
            self.rsa_key.save_public_key(self.public_key_file)
            self.rsa_key.save_private_key(self.private_key_file)
        return self.rsa_key


class AESCipher:
    """Handles AES-GCM encryption and decryption for secure communication."""

    def __init__(self, key, message_window=None):
        # Use SHA-256 to derive a 256-bit key from the shared secret
        self.key = hashlib.sha256(str(key).encode()).digest()
        self.message_window = message_window or ConsoleWindow()

    def encrypt(self, plaintext: str) -> dict:
        """Encrypts a plaintext string using AES-GCM."""
        try:
            plaintext_bytes = plaintext.encode("utf-8")
            cipher = AES.new(self.key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
            # Return a dictionary of base64 encoded strings for JSON serialization
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
    """
    Manages the Diffie-Hellman key exchange.
    Uses pre-defined, safe prime (p) and generator (g) from RFC 3526 (Group 14).
    """

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
        """Generates a private key."""
        self.private_key = random.getrandbits(bit_length)

    def _generate_public_key(self):
        """Generates a public key from the private key."""
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, peer_public_key):
        """
        Computes the shared secret using the peer's public key.
        :param peer_public_key: The public key from the other party.
        """
        self.shared_secret = pow(peer_public_key, self.private_key, self.p)
        return self.shared_secret
