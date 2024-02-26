# task1 : Implement Diffie Hellman Key Exchange:
# Ethan Swenke and HanYu Wu
# CSC-321-03
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random


def task1():
    iv = generate_IV()
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    gen = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    bob_p, bob_priv = bob_pub(q, gen)
    alice_p, alice_priv = alice_pub(q,gen)
    alice_msg, alice_cipher = alice_encrypt(bob_p, alice_priv, q, iv)
    bob_msg, bob_cipher = bob_encrypt(alice_p, bob_priv, q, iv)

    print("bob's encrypted message: " + str(bob_msg))
    print("bob's decrypted message: " + str(unpad(alice_cipher.decrypt(bob_msg), 16)))
    print("alice's encrypted message: " + str(alice_msg))
    print("alice's decrypted message: " + str(unpad(bob_cipher.decrypt(alice_msg), 16)))

def bob_pub(q, gen):
    priv_num = random.randint(0, q - 1)
    return ((gen ** priv_num) % q, priv_num)

def bob_encrypt(alice_pub, bob_priv, q, iv):
    s = (alice_pub ** bob_priv) % q
    hasher = SHA256.new()
    hasher.update(str(s).encode())
    cipher_key = hasher.digest()[:16]

    enc_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    dec_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    bob_msg_pad = pad(b"Hi Alice!", AES.block_size)
    bob_msg = enc_cipher.encrypt(bob_msg_pad)

    return bob_msg, dec_cipher

def alice_pub(q, gen):
    priv_num = random.randint(0, q - 1)
    return ((gen ** priv_num) % q, priv_num)

def alice_encrypt(bob_pub, alice_priv, q, iv):
    s = (bob_pub ** alice_priv) % q
    hasher = SHA256.new()
    hasher.update(str(s).encode())
    cipher_key = hasher.digest()[:16]

    enc_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    dec_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    alice_msg_pad = pad(b"Hi Bob!", AES.block_size)
    alice_msg = enc_cipher.encrypt(alice_msg_pad)

    return alice_msg, dec_cipher

def generate_IV():
    return get_random_bytes(16)


if __name__ == "__main__":
    task1()