import numpy as np

def encrypt_hill_cipher(plaintext, key):
    # Convert plaintext to ASCII decimal
    plaintext_ascii = [ord(char) for char in plaintext]

    # Pad the plaintext with 'X' if its length is not a multiple of 3
    while len(plaintext_ascii) % 3 != 0:
        plaintext_ascii.append(ord('X'))

    # Convert plaintext ASCII to a matrix
    plaintext_matrix = [plaintext_ascii[i:i + 3] for i in range(0, len(plaintext_ascii), 3)]

    # Encrypt each block of plaintext
    ciphertext_matrix = []
    for block in plaintext_matrix:
        encrypted_block = [
            sum(key[i][j] * block[j] for j in range(3)) % 127
            for i in range(3)
        ]
        ciphertext_matrix.append(encrypted_block)

    # Flatten the encrypted matrix and convert back to characters
    ciphertext = ''.join([chr(char) for sublist in ciphertext_matrix for char in sublist])

    return ciphertext

from numpy.linalg import inv

def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def decrypt_hill_cipher(ciphertext, key):
    # Convert ciphertext to ASCII decimal
    ciphertext_ascii = [ord(char) for char in ciphertext]

    # Convert ciphertext ASCII to a matrix
    ciphertext_matrix = [ciphertext_ascii[i:i + 3] for i in range(0, len(ciphertext_ascii), 3)]

    # Find the modular inverse of the determinant of the key matrix
    det = (key[0][0] * key[1][1] * key[2][2] + key[0][1] * key[1][2] * key[2][0] +
           key[0][2] * key[1][0] * key[2][1] - key[0][2] * key[1][1] * key[2][0] -
           key[0][0] * key[1][2] * key[2][1] - key[0][1] * key[1][0] * key[2][2]) % 127
    det_inv = mod_inverse(det, 127)
    # print("det_inv >> ", det_inv)

    if det_inv is None:
        raise ValueError("The key matrix is not invertible.")

    # Find the inverse of the key matrix
    key_inv = [
        [(key[(j + 1) % 3][(k + 1) % 3] * key[(j + 2) % 3][(k + 2) % 3] -
          key[(j + 1) % 3][(k + 2) % 3] * key[(j + 2) % 3][(k + 1) % 3]) * det_inv % 127
         for k in range(3)]
        for j in range(3)
    ]
    # print("key_inv >> ", key_inv)

    # Decrypt each block of ciphertext
    decrypted_matrix = []
    for block in ciphertext_matrix:
        decrypted_block = [0, 0, 0]
        for i in range(3):  # iterate over the range of 3
            for j in range(3):
                decrypted_block[i] = (decrypted_block[i] + key_inv[j][i] * block[j]) % 127
        decrypted_matrix.append(decrypted_block)
    # print("decrypted_matrix >> ", decrypted_matrix)


    
    # Flatten the decrypted matrix and convert back to characters
    decrypted_ascii = [int(char) for sublist in decrypted_matrix for char in sublist]
    
    # Remove padding 'X' characters
    decrypted_ascii = decrypted_ascii[:len(ciphertext)]

    decrypted_text = ''.join([chr(char) for char in decrypted_ascii])

    return decrypted_text
# Example usage
if __name__ == "__main__":
    # Input plaintext and key
    plaintext = input("Masukkan plaintext: ")
    
    # Input key matrix
    key = []
    print("Masukkan kunci matriks 3x3:")
    for i in range(3):
        row = [int(x) for x in input().split()]
        key.append(row)

    key = np.array(key)

    # Encrypt plaintext using Hill Cipher
    ciphertext = encrypt_hill_cipher(plaintext, key)

    print(f"Ciphertext: {ciphertext}")
    textDesimal = ''
    for i in range(0,len(ciphertext)):
        textDesimal += str(ord(ciphertext[i])) + " "
        # print(f"{ord(ciphertext[i])}")
    print(textDesimal)

    # Decrypt ciphertext using Hill Cipher
    decrypted_text = decrypt_hill_cipher(ciphertext, key)

    print(f"Decrypted Text: {decrypted_text}")