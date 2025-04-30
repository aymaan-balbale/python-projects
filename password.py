import random 
import string 

def password_generator(length: int = 100):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(alphabet) for i in range(length) )
    return password

password = password_generator()
print(f"generated password: {password}")