import glob
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def read_message(file_path):
    with open(file_path, "rb") as message:
        return message.read()

def read_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=None)
        return public_key


def read_public_keys(file_paths):
    keys = []
    for file in glob.glob(file_paths + "*.pem"):
        file_number = re.findall(r'\d+', file)[0]
        keys.append((file_number, read_public_key(file_path=file)))
    return keys

def gcd(key_a, key_b):
    if key_a > key_b:
        a = key_a
        b = key_b
    else:
        a = key_b
        b = key_a

    if a == 1 or b == 1:
        return -1
    if a == 0:
        return b
    if b == 0:
        return a

    if b > 1:
        return gcd(a % b, b)

def egcd(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb"""
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    # return a , lx, ly  # Return only positive values
    return lx


def find_keys_with_same_pq(keys):
    same_keys = []
    for i_a, k_a in keys:
        for i_b, k_b in keys:
            gcd_v = gcd(k_a.public_numbers().n, k_b.public_numbers().n)
            if i_a != i_b and gcd_v  != -1:
                print(i_a, i_b)
                same_keys.append(
                    {
                        "key_a": k_a,
                        "key_b": k_b,
                        "file_id_a": i_a,
                        "file_id_b": i_b,
                        "gcd": gcd_v
                    }
                )
    return same_keys

def create_privete_key(public_key, q):
    n = public_key.public_numbers().n
    e = public_key.public_numbers().e
    p = n // q

    phi = (p - 1) * (q - 1)
    d = egcd(e, phi)
    d = d % phi

    if d < 0:
        d += phi

    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(d, p)
    dmq1 = rsa.rsa_crt_dmq1(d, q)

    private_key = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_key.public_numbers()).private_key()
    return private_key


def crack(file_path):
    keys = read_public_keys(file_path)
    keys_with_same_pq = find_keys_with_same_pq(keys)

    private_keys = []
    for k in keys_with_same_pq:
        private_key = create_privete_key(k['key_a'], k['gcd'])
        # print(private_key.private_numbers())
        ciphertext = read_message(file_path + k['file_id_a'] + '.bin')
        # print(ciphertext)

        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        print(plaintext)


if __name__ == "__main__":
    crack('./challenge/')
