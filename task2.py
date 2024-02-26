# task2 : Implement MITM key fixing & negotiated groups:
# Ethan Swenke and HanYu Wu
# CSC-321-03
from task1 import *

def q_tamper():
    iv = generate_IV()
    q = 37
    gen = 5

    bob_p, bob_priv = bob_pub(q, gen)
    alice_p, alice_priv = alice_pub(q,gen)

    # mallory replaces public results with q
    alice_msg, alice_cipher = alice_encrypt(q, alice_priv, q, iv)
    bob_msg, bob_cipher = bob_encrypt(q, bob_priv, q, iv)

    print("bob's encrypted message: " + str(bob_msg))
    print("bob's decrypted message: " + str(alice_cipher.decrypt(bob_msg)))
    print("alice's encrypted message: " + str(alice_msg))
    print("alice's decrypted message: " + str(bob_cipher.decrypt(alice_msg)))

    # mallory can now decrypt any message between alice or bob
    mitm(iv, alice_msg)
    mitm(iv, bob_msg)

def mitm(iv, msg):
    # replacing pub results with q means the s is 0 (rarely it will be 1)
    for s in range(2):
        hasher = SHA256.new()
        hasher.update(str(s).encode())
        cipher_key = hasher.digest()[:16]

        dec_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
        print("mallory decrypted this data: " + str(dec_cipher.decrypt(msg)))

def gen_tamper():
    iv = generate_IV()
    q = 37
    gen = 5

    # mallory sets gen to 1
    bob_p, bob_priv = bob_pub(q, 1)
    alice_p, alice_priv = alice_pub(q, 1)

    alice_msg, alice_cipher = alice_encrypt(bob_p, alice_priv, q, iv)
    bob_msg, bob_cipher = bob_encrypt(alice_p, bob_priv, q, iv)

    print("bob's encrypted message: " + str(bob_msg))
    print("bob's decrypted message: " + str(unpad(alice_cipher.decrypt(bob_msg), 16)))
    print("alice's encrypted message: " + str(alice_msg))
    print("alice's decrypted message: " + str(unpad(bob_cipher.decrypt(alice_msg), 16)))

    # mallory can now decrypt any message between alice or bob
    mitm_2(iv, alice_msg)
    mitm_2(iv, bob_msg)
    
    return

def mitm_2(iv, msg):
    # replacing gen with 1 means s turns into 1
    s = 1
    hasher = SHA256.new()
    hasher.update(str(s).encode())
    cipher_key = hasher.digest()[:16]

    dec_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    print("mallory decrypted this data: " + str(unpad(dec_cipher.decrypt(msg), 16)))

if __name__ == "__main__":
    q_tamper()
    print()
    gen_tamper()