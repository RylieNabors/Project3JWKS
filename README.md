"# Project3JWKS" 

Added:
	1. AES Encryption of Private keys before they are stored in keys table and decryption when the keys need to be accessed.
	2. User registration that registers users after POST request with /register endpoint and places hashed password in users table.
	3. auth_logs table that for each POST request with /auth endpoint, logs user IP address, timestamp of the request, and assigns randomized user ID number to the user.


Installation Commands Required to Run:
pip install python-dotenv cryptography pyjwt argon2-cffi


To run:

python jwkserver3.py
