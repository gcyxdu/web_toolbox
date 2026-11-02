import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

class AESSuite:
    def __init__(self, my_key: str):
        sha1 = SHA1.new()
        sha1.update(my_key.encode("utf-8"))
        self.secret_key = sha1.digest()[:16]
    
    def encrypt(self, plaintext: str) -> str:
        aes = AES.new(self.secret_key, AES.MODE_ECB)
        ciphertext = aes.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt(self, ciphertext_base64: str) -> str:
        aes = AES.new(self.secret_key, AES.MODE_ECB)
        ciphertext = base64.b64decode(ciphertext_base64)
        plaintext = unpad(aes.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')


# ------------------ 测试 ------------------
if __name__ == "__main__":
    key = "my_secret_key"
    aes = AESSuite(key)

    text = "Hello, AES!"
    encrypted = aes.encrypt(text)
    print("Encrypted:", encrypted)

    decrypted = aes.decrypt(encrypted)
    print("Decrypted:", decrypted)
