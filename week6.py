import hashlib

username = input("Enter username: ")
password = input("Enter password: ")

# Hash password
hashed_password = hashlib.sha256(password.encode()).hexdigest()

print("\nStored Hash:")
print(hashed_password)

print("\nLogin")

login = input("Enter password again: ")

login_hash = hashlib.sha256(login.encode()).hexdigest()

if login_hash == hashed_password:
    print("Login Successful")
else:
    print("Wrong Password")