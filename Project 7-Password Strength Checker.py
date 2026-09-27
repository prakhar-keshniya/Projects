import string

def Check_our_string(input_string):
    uppercase_count = 0
    lowercase_count = 0
    number_count = 0
    symbol_count = 0

    for char in input_string:
        if char.isupper():
            uppercase_count += 1
        elif char.islower():
            lowercase_count += 1
        elif char.isdigit():
            number_count += 1
        else:
            symbol_count += 1

    return uppercase_count,lowercase_count,number_count,symbol_count

if __name__ == "__main__":

    GetPass = str(input("Enter your password:- "))

    upper,lower,number,symbol = Check_our_string(GetPass)

    if len(GetPass) >= 8 and upper > 0 and lower > 0 and number > 0 and symbol > 0:
        print("Password is strong.")
    elif len(GetPass) >= 6:
        print("Password is Medium.")
    else:
        print("Passord is weak.")