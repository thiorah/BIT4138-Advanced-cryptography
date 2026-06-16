# Simple SPN Example

plaintext = input("Enter plaintext: ")

# Substitution
substitution = {
    "A":"D",
    "B":"E",
    "C":"F",
    "D":"G"
}

substituted = ""

for char in plaintext:
    substituted += substitution.get(char, char)

# Permutation
ciphertext = substituted[::-1]

print("Substituted Text:", substituted)
print("Ciphertext:", ciphertext)
sbox = {
0:14,
1:4,
2:13,
3:1
}

print("S-Box Mapping")

for key,value in sbox.items():
    print(key,"->",value)