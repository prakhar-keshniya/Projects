'''
Create a python program to secure an existing password by replacing a set of characters with
the corresponding 'password-secure' character (Provided as tuple). 

Example: 
SECURE = (('s', '$'), ('and', '&'), ('a', '@'), ('o', '0'), ('i', '1'), ('I', '|')) 

Input: 
password = "Indians123" 

Output: 
Your secure password is nd1@n$123 

'''

# Prakhar1234

secure = (
    ('a','!'), ('b','@'), ('c','#'), ('d','$'), ('e','%'),
    ('f','^'), ('g','&'), ('h','*'), ('i','('), ('j',')'),
    ('k','-'), ('l','_'), ('m','='), ('n','+'),
    ('o','['), ('p',']'), ('q','{'), ('r','}'),
    ('s','|'), ('t',';'), ('u',':'), ('v',"'"),
    ('w','"'), ('x','<'), ('y','>'), ('z','?'),

    ('A','~'), ('B','`'), ('C','1'), ('D','2'), ('E','3'),
    ('F','4'), ('G','5'), ('H','6'), ('I','7'), ('J','8'),
    ('K','9'), ('L','0'), ('M','.'), ('N',','),
    ('O','/'), ('P','\\'), ('Q','€'), ('R','£'),
    ('S','¥'), ('T','₹'), ('U','¢'), ('V','©'),
    ('W','®'), ('X','™'), ('Y','§'), ('Z','¶'),

    ('0','a'), ('1','b'), ('2','c'), ('3','d'), ('4','e'),
    ('5','f'), ('6','g'), ('7','h'), ('8','i'), ('9','j'),

    (' ','~'), ('.','^'), (',','='), ('!','?'), ('?','!'),
    ('@','%'), ('#','*'), ('$','+'), ('&','-')
)


def SecurePassword(secpassword):
    for a , b in secure:
        secpassword = secpassword.replace(a,b)
    return secpassword

if __name__ == '__main__':
    password = input("Enter your password:- ")
    secpassword = SecurePassword(password)
    print(f"Your secure password is {secpassword}")