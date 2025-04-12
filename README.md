# SecureChat - End-to-End Encrypted Chat Application

## 📝 Description
SecureChat is a secure, encrypted chat application that provides military-grade encryption for all communications between clients through a central server.

## ✨ Features
- **End-to-End Encryption** using AES-256 in GCM mode
- **Secure Key Derivation** with PBKDF2 (100,000 iterations)
- **Admin Controls** for server management
- **Clean Interface** without timestamps
- **Cross-Platform** (Windows/Linux/macOS)

## 🛠️ Requirements
- Python 3.6+
- Dependencies (automatically installed):
colorama==0.4.6
pyfiglet==0.8.post1
pycryptodome==3.19.0

Copy

## 🚀 Installation
1. Clone the repository:
 ```bash

 git clone https://github.com/Hemanths2006/Chating-server-for-cli.git
 cd Chating-server-for-cli
Install dependencies:

bash
Copy
pip install -r requirements.txt
🖥️ Server Usage
bash
Copy
python server.py
Set port (1024-65535)

Create room password (min 8 characters)

Set admin password

Admin Commands:
Command Description
users   List connected users
history Show message history
kick <user>     Disconnect a user
shutdown        Stop the server
clear   Clear console
💻 Client Usage
bash
Copy
python client.py
Enter username

Specify server IP (127.0.0.1 for local)

Enter room password

Client Commands:
/quit or /exit - Disconnect

Normal messages are sent by just typing

🔒 Security Details
Encryption: AES-256-GCM

Key Derivation: PBKDF2-HMAC-SHA256

Authentication: GCM message tags

Salting: 16-byte random salts per session

🚨 Troubleshooting
Connection Issues: Verify server IP/port and firewall settings

Decryption Errors: Ensure matching room passwords

Port Conflicts: Change server port if "Port in use" appears

🤝 Contributing
Fork the repository

Create your feature branch

Commit your changes

Push to the branch

Open a pull request

📜 License
MIT License

Note: For optimal security, change passwords regularly and never share admin credentials.
