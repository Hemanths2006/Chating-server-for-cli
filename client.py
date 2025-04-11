import socket
import threading
import json
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from colorama import Fore, Style, init
import pyfiglet
import re

init()

class SecureChatClient:
    def __init__(self):
        self.display_banner()
        self.username = self.get_username()
        self.server_ip, self.server_port = self.get_server_info()
        self.room_password = self.get_password()
        self.socket = None
        self.key = None
        self.running = True
        self.connected = False

    def display_banner(self):
        banner_width = 70
        print(Fore.CYAN + "╔" + "═" * (banner_width-2) + "╗")
        
        ascii_art = pyfiglet.figlet_format("SecureChat", font="slant")
        for line in ascii_art.split('\n'):
            if line.strip():
                print("║" + Fore.MAGENTA + line.center(banner_width-2) + Fore.CYAN + "║")
        
        print("╠" + "═" * (banner_width-2) + "╣")
        print("║" + Fore.YELLOW + " Secure Client v2.0 - Military Grade Encryption ".center(banner_width-2, '•') + Fore.CYAN + "║")
        print("╚" + "═" * (banner_width-2) + "╝" + Style.RESET_ALL)
        print()

    def get_username(self):
        while True:
            username = input(f"{Fore.GREEN}┌─[{Fore.CYAN}USERNAME{Fore.GREEN}]\n└──╼ {Fore.WHITE}").strip()
            if username:
                return username
            print(f"{Fore.RED}┌─[{Fore.YELLOW}ERROR{Fore.RED}]\n└──╼ Username cannot be empty{Style.RESET_ALL}")

    def get_server_info(self):
        while True:
            try:
                ip = input(f"{Fore.GREEN}┌─[{Fore.CYAN}SERVER IP{Fore.GREEN}]\n└──╼ {Fore.WHITE}(127.0.0.1): ").strip() or "127.0.0.1"
                port = int(input(f"{Fore.GREEN}┌─[{Fore.CYAN}SERVER PORT{Fore.GREEN}]\n└──╼ {Fore.WHITE}"))
                return ip, port
            except ValueError:
                print(f"{Fore.RED}┌─[{Fore.YELLOW}ERROR{Fore.RED}]\n└──╼ Invalid port number{Style.RESET_ALL}")

    def get_password(self):
        while True:
            pw = input(f"{Fore.GREEN}┌─[{Fore.CYAN}ROOM PASSWORD{Fore.GREEN}]\n└──╼ {Fore.WHITE}").strip()
            if pw:
                return pw
            print(f"{Fore.RED}┌─[{Fore.YELLOW}ERROR{Fore.RED}]\n└──╼ Password cannot be empty{Style.RESET_ALL}")

    def derive_key(self, password, salt):
        return PBKDF2(password.encode(), salt, dkLen=32, count=100000)

    def encrypt_message(self, message):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return json.dumps({
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'tag': base64.b64encode(tag).decode()
        })

    def decrypt_message(self, encrypted_data):
        try:
            data = json.loads(encrypted_data)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=base64.b64decode(data['nonce']))
            plaintext = cipher.decrypt_and_verify(
                base64.b64decode(data['ciphertext']),
                base64.b64decode(data['tag']))
            return plaintext.decode()
        except Exception as e:
            print(f"{Fore.RED}┌─[{Fore.YELLOW}DECRYPTION ERROR{Fore.RED}]\n└──╼ {e}{Style.RESET_ALL}")
            return None

    def clean_message(self, message):
        """Remove timestamp patterns like [20:04:56] from messages"""
        return re.sub(r'\[\d{2}:\d{2}:\d{2}\]\s*', '', message)

    def display_message(self, message, is_me=False):
        # Clear the current input line if there's one
        print("\033[2K\r", end="")
        
        # Clean the message by removing timestamps
        cleaned_message = self.clean_message(message)
        
        if ':' in cleaned_message:
            username, content = cleaned_message.split(':', 1)
            username = username.strip()
            content = content.strip()
            
            if is_me:
                print(f"{Fore.GREEN}{username}: {Fore.WHITE}{content}{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}{username}: {Fore.WHITE}{content}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}{cleaned_message}{Style.RESET_ALL}")
        
        # Show input prompt again
        print(f"{Fore.GREEN}>> {Style.RESET_ALL}", end="", flush=True)

    def receive_messages(self):
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break

                if not self.key:
                    salt_data = json.loads(data.decode())
                    salt = base64.b64decode(salt_data['salt'])
                    self.key = self.derive_key(self.room_password, salt)
                    self.socket.send(json.dumps({'username': self.username}).encode())
                    self.connected = True
                    print("\033c", end="")  # Clear screen
                    self.display_message(f"Connected to secure chat room at {self.server_ip}:{self.server_port}")
                    print(f"{Fore.GREEN}>> {Style.RESET_ALL}", end="", flush=True)
                    continue

                decrypted = self.decrypt_message(data.decode())
                if decrypted:
                    self.display_message(decrypted)

            except Exception as e:
                if self.connected:
                    self.display_message(f"Connection error: {str(e)}")
                break

    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))

            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            while self.running:
                try:
                    if not self.connected:
                        continue

                    message = input(f"{Fore.GREEN}>> {Style.RESET_ALL}").strip()
                    
                    if not message:
                        continue

                    if message.lower() in ('/quit', '/exit'):
                        break

                    if self.key:
                        self.display_message(f"{self.username}: {message}", is_me=True)
                        encrypted = self.encrypt_message(message)
                        self.socket.send(encrypted.encode())

                except KeyboardInterrupt:
                    break

        except ConnectionRefusedError:
            print(f"{Fore.RED}Connection refused - server may be down{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Fatal error: {str(e)}{Style.RESET_ALL}")
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            print(f"{Fore.YELLOW}Session terminated - Goodbye!{Style.RESET_ALL}")
            print(Fore.CYAN + "╔" + "═" * 68 + "╗")
            print("║" + Fore.YELLOW + " Thank you for using SecureChat ".center(68) + Fore.CYAN + "║")
            print("╚" + "═" * 68 + "╝" + Style.RESET_ALL)

if __name__ == "__main__":
    client = SecureChatClient()
    client.start()
