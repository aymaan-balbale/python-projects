username = input("Enter a username: ")

if len(username) > 12:
    print("Your username must contain less than 12 characters")
elif not username.find(" ") == -1:
    print("Your username can't contain space ") 
elif not username.isalpha():
    print("Your usernmae can't contain numbers")
else:
    print(f"{username}, welcome ")    
