from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def decrypt_aes_cbc_pkcs7(key, iv, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def decode_base64_and_decrypt(base64_encoded, key, iv):
    ciphertext = b64decode(base64_encoded)
    decrypted_text = decrypt_aes_cbc_pkcs7(key, iv, ciphertext)
    return decrypted_text.decode('utf-8')  # Assume UTF-8 encoding


# Exemplo de uso:
base64_encoded_text = "OIPPjSK9NVGhWbYFXN8vog=="
key = bytes([1, 4, 8, 15, 16, 23, 42, 108, 1, 4, 8, 15, 16, 23, 42,
            108, 1, 4, 8, 15, 16, 23, 42, 108, 1, 4, 8, 15, 16, 23, 42, 108])
iv = bytes([1, 4, 8, 15, 16, 23, 42, 108, 1, 4, 8, 15, 16, 23, 42, 108])

# Ajuste o tamanho do IV
iv = iv[:16]  # Usar apenas os primeiros 16 bytes

decrypted_text = decode_base64_and_decrypt(base64_encoded_text, key, iv)
print("Texto descriptografado:", decrypted_text)
