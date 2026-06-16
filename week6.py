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