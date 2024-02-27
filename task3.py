from Crypto.Util.number import getPrime, inverse
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_key(bits):
    e = 65537
    p = getPrime(bits)
    q = getPrime(bits)

    # Ensure p and q are distinct primes
    while p == q:
        q = getPrime(bits)

    n = p * q
    z = (p - 1) * (q - 1)

    d = inverse(e, z)

    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key


def aes_cbc_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def aes_cbc_decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

def main():
    public_key, private_key = generate_key(256)
    message = 'Hi!'
    print('Original message:', message)

    # Mallory sends Alice a new c_prime
    c_prime = 1

    # Mallory needs to use public_key[1] instead of private_key[1] for the malleability attack
    s = pow(c_prime, public_key[1], public_key[0])

    k = SHA256.new()
    k.update(str(s).encode())
    c_0 = aes_cbc_encrypt(k.digest(), message)

    c = aes_cbc_decrypt(k.digest(), c_0)
    print("Mallory modified decrypted:", c)


if __name__ == "__main__":
    main()