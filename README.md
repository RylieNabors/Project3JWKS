# JSON Web Key Set Server - Version 3

modules needed to run server:  
```pip install python-dotenv cryptography pyjwt argon2-cffi```

command to run:  
```python jwksserver3.py```

## Overview:  
A JSON Web Key Set (JWKS) contains a list of public keys that are used by servers to verify the signatures of JSON Web Tokens (JWTs).

The server only verifies the JWT is from the user if it was signed with the correct private key, which is confidential and only known by the specific user.

According to the test performed below, the server embodies all intended functionality.

![Rubric of tests passed](GradebotProject3_Finalized.png)

## Previously implemented Features:
[JWKS Server Version 1](https://github.com/RylieNabors/Project1JWKS)  
[JWKS Server Version 2](https://github.com/RylieNabors/Project2JWKS)  

The features implemented in this project include:  
* Functional HTTP server that runs on port 8080
* RSA key pair generation for both valid and unexpired keys
* A RESTful JWKS endpoint that serves unexpired public keys in JWK format
* A /auth endpoint that returns an unexpired, signed JWT on a POST request
* Stores private keys in PEM format and expiration time for each key in keys table using SQLite
* Retrieves key information from keys table for operations in /auth and RESTful JWKS endpoints

## New Features:
Newly added features include:
* AES Encryption of Private keys before they are stored in keys table and decryption when the keys need to be accessed.
* User registration that registers users after POST request with /register endpoint and places password hashed with Argon2 in users table.
* auth_logs table that for each POST request with /auth endpoint, logs user IP address, timestamp of the request, and user ID from users table.
* Rate limits /auth endpoint to prevent the server from being overwhelmed at peak usage.

## Relevant terms:
* Asymmetric Encryption   
An encryption method that uses two mathematically linked keys to transmit data. It uses the public key for encryption and the private key for decryption.

* JSON Web Tokens (JWTs)  
Access tokens that are used by the server to identify authenticated users without having to store session data.

* JSON Web Key (JWK)  
A standardized format for representing private and public cryptographic keys as JSON objects. Private keys are kept confidential and are thus not included in the publically shared JWK.

* Key ID (KID)  
An optional identifier that helps distinguish keys in a set.

* JWKS endpoint  
A read-only URL that is used to provide applications with the public keys that they need to verify the signatures of JWTs.

## Useful Links:  
[Stytch](https://stytch.com/blog/understanding-jwks/)  
[Workos](https://workos.com/blog/jws-jwe-jwk-jwks-explained)
