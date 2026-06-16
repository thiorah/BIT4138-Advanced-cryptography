text1 = "HELLO"
text2 = "HELLo"

print("Plaintext 1:", text1)
print("Plaintext 2:", text2)

if text1 != text2:
    print("Difference detected")

    for i in range(len(text1)):
        if text1[i] != text2[i]:
            print("Changed position:", i)