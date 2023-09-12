from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend #Binds the openSSL to the program
import base64

def encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )

    return ciphertext

def decrypt(private_key, ciphertext):
    decrypted_message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )

    return decrypted_message

def main():
    identifier = input("Enter identifier name for the key pair: ")

    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )

    public_key = private_key.public_key()

    with open(f"{identifier}_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
            ))

    with open(f"{identifier}_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    plaintext = input("Enter the text you want to encrypt: ")
    ciphertext = encrypt(public_key, plaintext.encode('utf-8'))
    print(f"Encrypted message: {base64.urlsafe_b64encode(ciphertext).decode('utf-8')}")

    # Decrypt the data
    decrypted_message = decrypt(private_key, ciphertext)
    print(f"Decrypted message: {decrypted_message.decode('utf-8')}")


    return

if __name__ == "__main__":
    main()
