plaintext = 12
key = 5

ciphertext = plaintext ^ key

recovered_key = plaintext ^ ciphertext

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Recovered Key:", recovered_key)