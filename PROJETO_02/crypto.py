import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class Crypto:
    def __init__(self, key=None):
        """
        Inicializa a classe com uma chave AES de 256 bits.
        Se nenhuma chave for fornecida, gera uma aleatória.
        """
        self.key = key or os.urandom(32)  # Gera uma chave AES de 256 bits

    def encrypt(self, plaintext: str) -> dict:
        """
        Criptografa um texto plano usando AES no modo CFB.
        Retorna um dicionário com IV e texto criptografado.
        """
        iv = os.urandom(16)  # Vetor de inicialização (16 bytes)
        cipher = Cipher(algorithms.AES(self.key),
                        modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(
            plaintext.encode()) + encryptor.finalize()
        return {"iv": iv.hex(), "ciphertext": ciphertext.hex()}

    def decrypt(self, iv: str, ciphertext: str) -> str:
        """
        Descriptografa um texto criptografado usando AES no modo CFB.
        """
        iv = bytes.fromhex(iv)
        ciphertext = bytes.fromhex(ciphertext)
        cipher = Cipher(algorithms.AES(self.key),
                        modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

    def get_key(self) -> str:
        return self.key.hex()

    def generate_random_string(length=32):
        """
        Gera uma string aleatória com o comprimento especificado.
        Ideal para tokens de sessão ou identificadores únicos.
        """
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))


# Teste da classe Crypto
if __name__ == "__main__":
    crypto = Crypto()

    # Testando criptografia e descriptografia
    print("Testando criptografia...")
    encrypted = crypto.encrypt("Texto secreto")
    print("Criptografado:", encrypted)
    decrypted = crypto.decrypt(encrypted["iv"], encrypted["ciphertext"])
    print("Descriptografado:", decrypted)

    # Testando geração de string aleatória
    print("\nTestando geração de string aleatória...")
    random_string = crypto.generate_random_string()
    print("String aleatória:", random_string)
