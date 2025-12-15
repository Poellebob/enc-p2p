import socket
import json
import threading
import crypto
import network
import protocol
import session
import utils

PORT = 59420

def receive_messages(sock):
  """Handles receiving messages from the socket."""
  while True:
    try:
      data = sock.recv(4096)
      if not data:
        print("\nConnection closed by peer.")
        break
      message = json.loads(data.decode('utf-8'))
      if 'text' in message and message['text']:
        # The server joins the array of strings and prints it
        print(f"\nReceived: {' '.join(message['text'])}\nEnter message to send: ", end="")
    except (json.JSONDecodeError, ConnectionResetError):
      print("\nConnection lost.")
      break
    except Exception as e:
      print(f"\nAn error occurred while receiving: {e}")
      break
  sock.close()

def send_messages(sock):
  """Handles sending messages to the socket."""
  while True:
    try:
      message_text = input("Enter message to send: ")
      if message_text.lower() == 'exit':
        break
      
      # The message is split into a list of strings
      message = {
        "text": message_text.split(),
        "objs": []
      }
      sock.sendall(json.dumps(message).encode('utf-8'))
    except (EOFError, KeyboardInterrupt):
      print("\nClosing connection.")
      break
    except Exception as e:
      print(f"\nAn error occurred while sending: {e}")
      break
  sock.close()

def listen_mode():
  """Sets up the server to listen for incoming connections."""
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  try:
    server_socket.bind(('', PORT))
    server_socket.listen(1)
    print(f"Listening for connections on port {PORT}...")
    conn, addr = server_socket.accept()
    print(f"Connected to {addr}")
    return conn
  except Exception as e:
    print(f"Error in listen mode: {e}")
    return None
  finally:
    server_socket.close

def connect_mode():
  """Connects to a listening server."""
  host_ip = input("Enter the IPv4 address of the host: ")
  client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    client_socket.connect((host_ip, PORT))
    print(f"Connected to {host_ip}")
    return client_socket
  except ConnectionRefusedError:
    print("Connection refused. Make sure the host is listening.")
    return None
  except Exception as e:
    print(f"Failed to connect: {e}")
    return None

def main():
  """Main function to run the P2P chat."""
  while True:
    mode = input("Choose mode: (1) Listen or (2) Connect? ")
    if mode in ['1', '2']:
      break
    print("Invalid choice. Please enter 1 or 2.")

  sock = None
  if mode == '1':
    sock = listen_mode()
  elif mode == '2':
    sock = connect_mode()

  if sock:
    try:
      # Start a thread for receiving messages so that sending is not blocked
      receiver_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
      receiver_thread.start()
      send_messages(sock)
    finally:
      sock.close()
      print("Connection closed.")

if __name__ == "__main__":
  main()
