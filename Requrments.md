```
System Requirements
Server
Required Software
Python 3.10 or newer
Required Libraries
websockets
Python Standard Libraries
hashlib
hmac
secrets
os
base64
Client
A modern web browser is required.
Supported browsers:
Google Chrome
Microsoft Edge
Mozilla Firefox
The browser must support:
```

```
WebSocket API
Web Crypto API
crypto.getRandomValues()
Installation
Clone the Repository
git clone https://github.com/your-username/nexus.git
cd nexus
Install Dependencies
pip install websockets
Running the Server
```

```
Start the WebSocket server:
python server.py
```

```
If the server starts successfully, you should see something similar to:
Server started on ws://localhost:8765
Running the Client
```

```
Open the client application in a web browser:
```

```
index.html
```

```
Connect to the running WebSocket server:
ws://localhost:8765
```

```
Open multiple browser windows or use multiple devices to simulate different
users.
```

```
Usage
Registration
Enter a username.
Enter a password.
The server generates a random salt.
The password is hashed using PBKDF2-HMAC-SHA256.
Only the salt and password hash are stored.
Login
Enter username and password.
```

```
The server generates a random challenge.
The client computes an HMAC response.
The server verifies the response.
Authentication succeeds if the values match.
Messaging
Users exchange public keys.
Shared secrets are derived locally.
Messages are encrypted before transmission.
The server forwards ciphertext only.
The recipient decrypts the message locally.
```

