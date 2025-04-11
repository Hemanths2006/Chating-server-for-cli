import socket
import threading
import json
import base64
import sys
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init()

class SecureChatServer:
    def __init__(self):
        self.display_banner()
        self.port = self.get_valid_port()
        self.room_password = self.get_valid_password()
        self.admin_password = self.get_admin_password()
        self.clients = {}
        self.server_socket = None
        self.salt = get_random_bytes(16)
        self.key = self.derive_key(self.room_password, self.salt)
        self.running = True
        self.message_history = []

    def display_banner(self):
        print(Fore.CYAN + "═"*70 + Style.RESET_ALL)
        print(Fore.MAGENTA + pyfiglet.figlet_format("SecureChat", font="slant") + Style.RESET_ALL)
        print(Fore.YELLOW + "║" + " "*68 + "║")
        print(Fore.YELLOW + "║" + Fore.CYAN + "           Secure Server v2.0 - Military Grade Encryption".center(68) + Fore.YELLOW + "║")
        print(Fore.YELLOW + "║" + Fore.CYAN + "           All communications are end-to-end encrypted".center(68) + Fore.YELLOW + "║")
        print(Fore.YELLOW + "║" + " "*68 + "║")
        print(Fore.YELLOW + "═"*70 + Style.RESET_ALL)
        print("\n")

    def get_valid_port(self):
        while True:
            try:
                port = int(input(f"{Fore.GREEN}┌─[" + Fore.MAGENTA + "PORT" + Fore.GREEN + "]\n└──╼ {Fore.WHITE}Enter server port (1024-65535): {Style.RESET_ALL} : "))
                if 1024 <= port <= 65535:
                    return port
                print(f"{Fore.RED}┌─[ERROR]\n└──╼ Port must be between 1024 and 65535{Style.RESET_ALL} ")
            except ValueError:
                print(f"{Fore.RED}┌─[ERROR]\n└──╼ Invalid port number{Style.RESET_ALL} ")

    def get_valid_password(self):
        while True:
            pw = input(f"{Fore.GREEN}┌─[" + Fore.MAGENTA + "ROOM KEY" + Fore.GREEN + "]\n└──╼ {Fore.WHITE}Enter room password (min 8 chars): {Style.RESET_ALL} : ")
            if len(pw) >= 8:
                return pw
            print(f"{Fore.RED}┌─[ERROR]\n└──╼ Password must be at least 8 characters{Style.RESET_ALL} : ")

    def get_admin_password(self):
        return input(f"{Fore.GREEN}┌─[" + Fore.MAGENTA + "ADMIN KEY" + Fore.GREEN + "]\n└──╼ {Fore.WHITE}Set admin password (for server commands): {Style.RESET_ALL} : ")

    def derive_key(self, password, salt):
        return PBKDF2(password.encode(), salt, dkLen=32, count=100000)

    def encrypt_message(self, message):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return json.dumps({
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'timestamp': time.time()
        })

    def decrypt_message(self, encrypted_data):
        try:
            data = json.loads(encrypted_data)
            cipher = AES.new(self.key, AES.MODE_GCM, 
                           nonce=base64.b64decode(data['nonce']))
            plaintext = cipher.decrypt_and_verify(
                base64.b64decode(data['ciphertext']),
                base64.b64decode(data['tag']))
            return plaintext.decode(), data.get('timestamp', time.time())
        except Exception as e:
            print(f"{Fore.RED}┌─[DECRYPTION ERROR]\n└──╼ {e}{Style.RESET_ALL}")
            return None, None

    def broadcast(self, message, sender_socket=None):
        encrypted = self.encrypt_message(message)
        self.message_history.append((time.time(), message))
        
        for username, client_data in self.clients.items():
            client_socket = client_data['socket']
            if client_socket != sender_socket:
                try:
                    client_socket.send(encrypted.encode())
                except:
                    self.remove_client(username)

    def remove_client(self, username):
        if username in self.clients:
            try:
                self.clients[username]['socket'].close()
            except:
                pass
            del self.clients[username]
            self.broadcast(f"{username} has left the chat")

    def handle_client(self, client_socket, addr):
        try:
            # Send salt for key derivation
            client_socket.send(json.dumps({
                'salt': base64.b64encode(self.salt).decode(),
                'message': "Welcome to secure chat"
            }).encode())

            # Get username
            username_data = client_socket.recv(4096).decode()
            username = json.loads(username_data).get('username', 'Unknown')
            
            if username in self.clients:
                username = f"{username}_{len(self.clients)}"
            
            self.clients[username] = {
                'socket': client_socket,
                'address': addr
            }
            
            self.broadcast(f"{username} has joined the chat")
            print(f"{Fore.GREEN}┌─[NEW CONNECTION]\n└──╼ {username} connected from {addr[0]}{Style.RESET_ALL}")

            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break

                decrypted, timestamp = self.decrypt_message(data.decode())
                if decrypted:
                    formatted_time = time.strftime('%H:%M:%S', time.localtime(timestamp))
                    print(f"{Fore.BLUE}┌─[{formatted_time}] {username}\n└──╼ {decrypted}{Style.RESET_ALL}")
                    self.broadcast(f"[{formatted_time}] {username}: {decrypted}", client_socket)

        except Exception as e:
            print(f"{Fore.RED}┌─[CLIENT ERROR]\n└──╼ Error with {addr[0]}: {e}{Style.RESET_ALL}")
        finally:
            if username in self.clients:
                self.remove_client(username)
            print(f"{Fore.YELLOW}┌─[DISCONNECTION]\n└──╼ Client {addr[0]} disconnected{Style.RESET_ALL}")

    def admin_console(self):
        while self.running:
            try:
                cmd = input(f"{Fore.MAGENTA}┌─[ADMIN CONSOLE]\n└──╼ {Style.RESET_ALL}").strip().lower()
                
                if cmd == "help":
                    print(f"{Fore.CYAN}┌─[ADMIN HELP]{"═"*50}")
                    print("║ users - List connected users")
                    print("║ history - Show message history")
                    print("║ kick <username> - Disconnect a user")
                    print("║ shutdown - Stop the server")
                    print("║ clear - Clear screen")
                    print("║ help - Show this help")
                    print("╚" + "═"*60 + Style.RESET_ALL)
                
                elif cmd == "users":
                    print(f"{Fore.CYAN}┌─[CONNECTED USERS]{"═"*50}")
                    for i, username in enumerate(self.clients.keys(), 1):
                        print(f"║ {i}. {username}")
                    print("╚" + "═"*60 + Style.RESET_ALL)
                
                elif cmd.startswith("kick "):
                    username = cmd[5:]
                    if username in self.clients:
                        self.remove_client(username)
                        print(f"{Fore.GREEN}┌─[USER KICKED]\n└──╼ Successfully kicked {username}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}┌─[KICK FAILED]\n└──╼ User not found{Style.RESET_ALL}")
                
                elif cmd == "history":
                    print(f"{Fore.CYAN}┌─[MESSAGE HISTORY]{"═"*50}")
                    for timestamp, msg in self.message_history[-10:]:
                        print(f"║ [{time.strftime('%H:%M:%S', time.localtime(timestamp))}] {msg}")
                    print("╚" + "═"*60 + Style.RESET_ALL)
                
                elif cmd == "shutdown":
                    self.running = False
                    print(f"{Fore.YELLOW}┌─[SERVER SHUTDOWN]\n└──╼ Shutting down server...{Style.RESET_ALL}")
                    break
                
                elif cmd == "clear":
                    print("\033c", end="")
                    self.display_banner()
                
                elif cmd:
                    print(f"{Fore.RED}┌─[UNKNOWN COMMAND]\n└──╼ Type 'help' for available commands.{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}┌─[ADMIN ERROR]\n└──╼ Console error: {e}{Style.RESET_ALL}")

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        print(f"{Fore.GREEN}┌─[SERVER STARTED]\n└──╼ Server running on port {self.port}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}┌─[STATUS]\n└──╼ Waiting for connections...{Style.RESET_ALL}")

        admin_thread = threading.Thread(target=self.admin_console, daemon=True)
        admin_thread.start()

        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, addr))
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}┌─[SHUTDOWN INITIATED]\n└──╼ Server shutting down...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}┌─[SERVER ERROR]\n└──╼ Fatal error: {e}{Style.RESET_ALL}")
        finally:
            self.running = False
            for username in list(self.clients.keys()):
                self.remove_client(username)
            if self.server_socket:
                self.server_socket.close()
            print(f"{Fore.GREEN}┌─[SERVER STOPPED]\n└──╼ Server successfully terminated{Style.RESET_ALL}")

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()
