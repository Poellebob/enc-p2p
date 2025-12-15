import socket
import json
import threading


class ConsoleWindow:
    """Handles console input and output for the chat application."""

    def display_message(self, message: str):
        """Displays a generic message to the console."""
        print(message)

    def display_received_message(self, message: str):
        """Formats and displays a received message."""
        print(f"\nReceived: {message}\nEnter message to send: ", end="")

    def get_input(self, prompt: str) -> str:
        """Gets input from the user with a given prompt."""
        return input(prompt)


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

    def _receive_messages(self):
        """Handles receiving messages from the socket in a loop."""
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    self.message_window.display_message("\nConnection closed by peer.")
                    break

                message = json.loads(data.decode("utf-8"))
                if "text" in message and message["text"]:
                    full_message = " ".join(message["text"])
                    self.message_window.display_received_message(full_message)

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
                message = {"text": message_text.split(), "objs": []}
                self.sock.sendall(json.dumps(message).encode("utf-8"))
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
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind(("", self.port))
            server_socket.listen(1)
            self.message_window.display_message(
                f"Listening for connections on port {self.port}..."
            )
            conn, addr = server_socket.accept()
            self.message_window.display_message(f"Connected to {addr}")
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

    def run(self):
        """Starts the main application loop."""
        while True:
            mode = self.message_window.get_input(
                "Choose mode: (1) Listen or (2) Connect? "
            )
            if mode in ["1", "2"]:
                break
            self.message_window.display_message("Invalid choice. Please enter 1 or 2.")

        is_connected = False
        if mode == "1":
            is_connected = self._start_listen_mode()
        elif mode == "2":
            is_connected = self._start_connect_mode()

        if is_connected and self.sock:
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


def main():
    """Main function to run the P2P chat."""
    chat_app = P2PChat()
    chat_app.run()


if __name__ == "__main__":
    main()
