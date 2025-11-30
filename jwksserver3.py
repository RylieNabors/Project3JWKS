from dotenv import load_dotenv
import sqlite3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import uuid
import argon2
from urllib.request import urlopen
import re as r
import random
import time

hostName = "localhost"
serverPort = 8080

#load encryption key from .env variable
load_dotenv()
encryption_key = os.environ.get("NOT_MY_KEY", None)

if not encryption_key:
    raise ValueError("Environment variable NOT_MY_KEY is not set!")

# Ensure the key is 32 bytes for AES-256
# If key is too long, truncate to only 32 bytes
# If key is too short, add padding to make it 32 bytes
encryption_key = encryption_key.encode()[:32].ljust(32, b'\0')

request_times = []
WINDOW_SECONDS = 120
LIMIT = 10

def create_key(expiration_time):
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

	# functions to serialize the key to PKCS#1 (TraditionalOpenSSL)
	privatekey_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)

	# Encrypt with AES before storing in sqlite database
	iv = os.urandom(16)  # Initialization vector
	cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(privatekey_pem) + encryptor.finalize()

	# Combine IV and ciphertext, then Base64 encode it
	encrypted_data = base64.b64encode(iv + ciphertext).decode()

	# Create PEM-like format
	pem = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{encrypted_data}\n-----END ENCRYPTED PRIVATE KEY-----"

	# save key into keys
	# kid is filled automatically with an integer since its set to an INTEGER PRIMARY KEY
	# "with conn" eliminates need for commit
	with conn:
		t.execute("INSERT INTO keys (key, exp) VALUES (?,?)", (pem, expiration_time))

def int_to_base64(value):
	"""Convert an integer to a Base64URL-encoded string"""
	value_hex = format(value, 'x')
	# Ensure even length
	if len(value_hex) % 2 == 1:
		value_hex = '0' + value_hex
	value_bytes = bytes.fromhex(value_hex)
	encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
	return encoded.decode('utf-8')

def getIP():
	bit = str(urlopen('http://checkip.dyndns.com/').read())
	return r.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(bit).group(1)

class MyServer(BaseHTTPRequestHandler):
	def do_PUT(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_PATCH(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_DELETE(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_HEAD(self):
		self.send_response(405)
		self.end_headers()
		return

	def do_POST(self):
		parsed_path = urlparse(self.path)
		params = parse_qs(parsed_path.query)

		global request_times
		now = time.time()

		if parsed_path.path == "/auth":
			# drop timestamps older than window
			request_times = [t for t in request_times if now - t < WINDOW_SECONDS]
			print("request time len", len(request_times))

			if len(request_times) > LIMIT:
				print("LIMIT EXCEEDED")
				# Proper rate limit response
				self.send_response(429)
				self.send_header("Content-Type", "text/plain")
				self.end_headers()
				self.wfile.write(b"Too Many Requests")
				return

			request_times.append(now)

			current_time = int(datetime.datetime.now().timestamp())
			if 'expired' in params:
				c = t.execute("SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
			else:
				c = t.execute("SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))

			# get pem from database
			foundKey = c.fetchone()

			if foundKey:
				data_pem = foundKey[0]

				# Begin process of decrypting key
				# Extract the Base64-encoded encrypted data
				encrypted_data = "".join(data_pem.strip().split("\n")[1:-1])  # Remove PEM headers
				decoded_data = base64.b64decode(encrypted_data)

				# Split the IV and ciphertext
				iv, ciphertext = decoded_data[:16], decoded_data[16:]

				# Decrypt with AES
				cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
				decryptor = cipher.decryptor()
				padded_data = decryptor.update(ciphertext) + decryptor.finalize()

				serialized_private_key = serialization.load_pem_private_key(padded_data, password=None) 

			headers = {
				"kid": "goodKID"
			}
			token_payload = {
				"user": "username",
				"exp": datetime.datetime.now() + datetime.timedelta(hours=1)
			}
			if 'expired' in params:
				headers["kid"] = "expiredKID"
				token_payload["exp"] = datetime.datetime.now() - datetime.timedelta(hours=1)
			encoded_jwt = jwt.encode(token_payload, serialized_private_key, algorithm="RS256", headers=headers)

			# auth_logs information
			# request user IP address
			user_ip = getIP()

			# Timestamp for request
			req_timestamp = datetime.datetime.now()

			# user_id foreign key
			with conn:
				t.execute("SELECT * FROM users")
			user_id = t.lastrowid or 0
			print(user_id)

			# Insert into auth_logs
			with conn:
					t.execute("""INSERT INTO auth_logs (request_ip, request_timestamp, user_id) 
			  				VALUES (?,?,?)""", (user_ip, req_timestamp, user_id))

			"""print("Test for auth logs: ")
			t.execute("SELECT * FROM auth_logs")
			auth_log_items = t.fetchall()
			for item in auth_log_items:
				print(item)
			conn.commit()"""

			self.send_response(200)
			self.end_headers()
			self.wfile.write(bytes(encoded_jwt, "utf-8"))
			return

		elif parsed_path.path == "/register":
			self.handle_register()
		else:
			self.send_response(405)
			self.end_headers()
			self.wfile.write(b"Endpoint not found")
			return

	def handle_register(self):
		request_body_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(request_body_length).decode('utf-8')

		try:
			#json.loads must process data in JSON format
			response_data = json.loads(post_data)
			username = response_data.get("username")
			email = response_data.get("email")	

			if not username or not email:
				self.send_response(400)
				self.end_headers()
				self.wfile.write(b"Missing username or email")
				return

			# Generate secure password for user using uuid4
			secure_password = uuid.uuid4()

			# Convert it to string and put it in dictionary since uuid can't be converted to JSON.
			# Then convert dictionary to JSON
			uuid_string = str(secure_password)
			password_data = {"password": uuid_string}

			password_return = json.dumps(password_data)

			# password being hashed is uuid_string
			# create a password hasher object
			ph = argon2.PasswordHasher()

			# hash password using Argon2
			hashed_password = ph.hash(uuid_string)

			# Get date registered (today's date)
			login_time = datetime.datetime.now()
			today = login_time.date()

			# Add everything to users database
			with conn:
				t.execute("""INSERT INTO users (username, password_hash, email, date_registered, last_login) 
							VALUES (?,?,?,?,?)""", (username, hashed_password, email, today, login_time))
			
			"""print("Test for users: ")
			t.execute("SELECT * FROM users")
			user_items = t.fetchall()
			for item in user_items:
				print(item)
			conn.commit()"""

			self.send_response(200)
			self.end_headers()
			self.wfile.write(bytes(password_return, "utf-8"))
			return
		
		except json.JSONDecodeError:
			self.send_response(400)
			self.end_headers()
			self.wfile.write(b"Invalid JSON")
			return


	def do_GET(self):
		if self.path == "/.well-known/jwks.json":
			current_time = int(datetime.datetime.now().timestamp())
			c = t.execute("SELECT key FROM keys WHERE exp > ?", (current_time,))

			# Construct JWKS response
			keys = {"keys": []}

			for row in c.fetchall():
				pem = row[0]

				# Extract the Base64-encoded encrypted data
				encrypted_data = "".join(pem.strip().split("\n")[1:-1])  # Remove PEM headers
				decoded_data = base64.b64decode(encrypted_data)

				# Split the IV and ciphertext
				iv, ciphertext = decoded_data[:16], decoded_data[16:]

				# Decrypt with AES
				cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
				decryptor = cipher.decryptor()
				padded_data = decryptor.update(ciphertext) + decryptor.finalize()
				
				private_key = serialization.load_pem_private_key(padded_data, password=None)
				public_key = private_key.public_key()
				numbers = public_key.public_numbers()

				keys["keys"].append({
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
					"kid": "goodKID",  # Use a method to set appropriate Key ID
					"n": int_to_base64(numbers.n),
					"e": int_to_base64(numbers.e)
				})

			# Return the JWKS
			self.send_response(200)
			self.send_header("Content-Type", "application/json")
			self.end_headers()
			self.wfile.write(bytes(json.dumps(keys), "utf-8"))
			return

		self.send_response(405)
		self.end_headers()
		return


if __name__ == "__main__":
	webServer = HTTPServer((hostName, serverPort), MyServer)

	# create connection to database
	conn = sqlite3.connect('totally_not_my_privateKeys.db')

	# create cursor so that we can use execute method to make SQL commands
	t = conn.cursor()

	# creates keys table in database if it doesn't already exist
	t.execute("""CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)""")

	# creates users table in database if it doesn't already exist
	t.execute("""CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE,
		date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP      
	)""")

	#create auth_logs table in database if it doesn't already exist
	t.execute("""CREATE TABLE IF NOT EXISTS auth_logs(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_ip TEXT NOT NULL,
		request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER,  
		FOREIGN KEY(user_id) REFERENCES users(id)
	)""")

	# commit command
	conn.commit()

	# save pem to database rather than making it a global variable
	# unexpired key
	unexpired_time = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
	create_key(unexpired_time)
	# expired key
	expired_time = int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp())
	create_key(expired_time)

	try:
		webServer.serve_forever()
	except KeyboardInterrupt:
		pass

	# close connection
	conn.close()
	webServer.server_close()
