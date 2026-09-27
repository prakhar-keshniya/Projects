user = input("Enter your user name:-")
password = input("Enter your user password:-")

if user != "Prakhar keshniya":
    print("User name is incorrect!")
    exit()

if password != "Prak@123":
    print("Password is incorrect!")
    exit()

print("==============You are logined==============")

with open("Projects/Password_manager.txt", "a") as f:
    f.write(f"Username: {user}\n")
    f.write(f"Password: {password}\n")

print("Saved successfully!")