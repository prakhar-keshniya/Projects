import string
import random

if __name__ == "__main__":
    chara = string.ascii_letters + string.digits + string.punctuation

    GenPass = int(input("Enter length of pass:- "))
    s = []

    s.extend(list(chara))

    random.shuffle(s)

    print("".join(s[0:GenPass]))