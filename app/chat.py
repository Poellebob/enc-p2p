import socket
import json
import threading

from app.ui import ConsoleWindow
from app.crypto import KeyManager, AESCipher, DiffieHellman


class P2PChat:
    """
    An object-oriented Peer-to-Peer chat application.
    It can either listen for a connection or connect to a peer.
    """

    def __init__(self, port: int = 59420):
        """
        Initializes the chat application.
        Args:
            port: The port number to use for the connection.
        """
        self.port = port
        self.sock = None
        self.message_window = ConsoleWindow()
        # Pass the message_window instance to the KeyManager
        self.key_manager = KeyManager(message_window=self.message_window)
        self.rsa_key = self.key_manager.load_or_generate_keys()
        self.cipher = None

    def _send_json(self, data: dict):
        """Serializes and sends a JSON payload."""
        self.sock.sendall(json.dumps(data).encode("utf-8"))

    def _receive_json(self) -> dict:
        """Receives and deserializes a JSON payload."""
        data = self.sock.recv(8192)  # Increased buffer size for keys
        if not data:
            return None
        return json.loads(data.decode("utf-8"))

    def _perform_handshake(self, mode: str) -> bool:
        """Performs the signed Diffie-Hellman key exchange."""
        try:
            self.message_window.display_message("Starting secure handshake...")
            dh = DiffieHellman()
            my_dh_pub = dh.public_key
            # The message to sign is the DH public key, converted to a string
            message_to_sign = str(my_dh_pub).encode("utf-8")
            signature = self.rsa_key.sign(message_to_sign)

            # Our own payload
            my_payload = {
                "rsa_pub_n": self.rsa_key.public_key[0],
                "rsa_pub_e": self.rsa_key.public_key[1],
                "dh_pub": my_dh_pub,
                "signature": signature,
            }

            if mode == "1":  # Listener
                # 1. Send our payload
                self._send_json(my_payload)
                # 2. Receive peer's payload
                peer_payload = self._receive_json()
                if not peer_payload:
                    raise ConnectionError("Handshake failed: Peer disconnected.")
            else:  # Connector
                # 1. Receive peer's payload
                peer_payload = self._receive_json()
                if not peer_payload:
                    raise ConnectionError("Handshake failed: Peer disconnected.")
                # 2. Send our payload
                self._send_json(my_payload)

            # 3. Verify peer's payload
            peer_rsa_pub_n = peer_payload["rsa_pub_n"]
            peer_rsa_pub_e = peer_payload["rsa_pub_e"]
            peer_dh_pub = peer_payload["dh_pub"]
            peer_signature = peer_payload["signature"]
            peer_public_key = (peer_rsa_pub_n, peer_rsa_pub_e)

            # The message to verify is the peer's DH public key
            message_to_verify = str(peer_dh_pub).encode("utf-8")

            if not self.rsa_key.verify(message_to_verify, peer_signature, peer_public_key):
                self.message_window.display_message("Handshake failed: Invalid signature from peer.")
                return False
            
            self.message_window.display_message("Peer signature verified.")

            # 4. Compute shared secret and initialize cipher
            shared_secret = dh.compute_shared_secret(peer_dh_pub)
            self.cipher = AESCipher(shared_secret, message_window=self.message_window)
            self.message_window.display_message("Secure session established.")
            return True

        except Exception as e:
            self.message_window.display_message(f"Handshake failed: {e}")
            if self.sock:
                self.sock.close()
            return False

    def establish_secure_connection(self, mode: str) -> bool:
        """Establishes the base connection and then performs the handshake."""
        connected = False
        if mode == "1":
            connected = self._start_listen_mode()
        elif mode == "2":
            connected = self._start_connect_mode()

        if connected:
            return self._perform_handshake(mode)
        return False

    def run(self):
        """Starts the main application loop."""
        while True:
            mode = self.message_window.get_input(
                "Choose mode: (1) Listen or (2) Connect? "
            )
            if mode in ["1", "2"]:
                break
            self.message_window.display_message("Invalid choice. Please enter 1 or 2.")

        if self.establish_secure_connection(mode):
            try:
                receiver_thread = threading.Thread(
                    target=self._receive_messages, daemon=True
                )
                receiver_thread.start()
                self._send_messages()
            finally:
                if self.sock:
                    self.sock.close()
                self.message_window.display_message("Connection closed.")
        else:
            self.message_window.display_message("Could not establish a secure connection.")

    def _receive_messages(self):
        """Handles receiving messages from the socket in a loop."""
        while True:
            try:
                # In a real implementation, you'd have a way to read a full message frame
                encrypted_payload = self._receive_json()
                if not encrypted_payload:
                    self.message_window.display_message("\nConnection closed by peer.")
                    break

                decrypted_message_str = self.cipher.decrypt(encrypted_payload)
                if decrypted_message_str:
                    message = json.loads(decrypted_message_str)
                    if "text" in message and message["text"]:
                        self.message_window.display_received_message(message["text"])
                else:
                    self.message_window.display_message("\nFailed to decrypt message.")
                    # Optionally, close connection on decryption failure
                    break

            except (json.JSONDecodeError, ConnectionResetError):
                self.message_window.display_message("\nConnection lost.")
                break
            except Exception as e:
                self.message_window.display_message(
                    f"\nAn error occurred while receiving: {e}"
                )
                break
        if self.sock:
            self.sock.close()

    def _send_messages(self):
        """Handles sending messages to the socket in a loop."""
        while True:
            try:
                message_text = self.message_window.get_input("Enter message to send: ")
                if message_text.lower() == "exit":
                    break
                
                # Original message structure
                message = {"text": message_text, "objs": []}
                message_str = json.dumps(message)
                
                # Encrypt the message string
                encrypted_payload = self.cipher.encrypt(message_str)
                
                if encrypted_payload:
                    self._send_json(encrypted_payload)
                else:
                    self.message_window.display_message("Failed to encrypt message. Not sent.")

            except (EOFError, KeyboardInterrupt):
                self.message_window.display_message("\nClosing connection.")
                break
            except Exception as e:
                self.message_window.display_message(
                    f"\nAn error occurred while sending: {e}"
                )
                break
        if self.sock:
            self.sock.close()

    def _start_listen_mode(self) -> bool:
        """Sets up the server to listen for an incoming connection."""
        # This socket is temporary for accepting the connection
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind(("", self.port))
            server_socket.listen(1)
            self.message_window.display_message(
                f"Listening for connections on port {self.port}..."
            )
            conn, addr = server_socket.accept()
            self.message_window.display_message(f"Connection from {addr}")
            self.sock = conn
            return True
        except Exception as e:
            self.message_window.display_message(f"Error in listen mode: {e}")
            return False
        finally:
            server_socket.close()

    def _start_connect_mode(self) -> bool:
        """Connects to a listening server."""
        host_ip = self.message_window.get_input(
            "Enter the IPv4 address of the host: "
        )
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host_ip, self.port))
            self.message_window.display_message(f"Connected to {host_ip}")
            self.sock = client_socket
            return True
        except ConnectionRefusedError:
            self.message_window.display_message(
                "Connection refused. Make sure the host is listening."
            )
            return False
        except Exception as e:
            self.message_window.display_message(f"Failed to connect: {e}")
            return False
