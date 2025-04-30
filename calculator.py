operator = (input("Enter a operator(+,-,*,/): "))
Num1 = float(input("Enter a Number(should be int or float): "))
Num2 = float(input("Enter a Number(should be int or float): "))

if operator =="+":
    result = Num1 + Num2
    print(round(result, 2))

elif operator =="-":
    result = Num1 - Num2
    print(round(result, 2))

elif operator =="*":
    result = Num1 * Num2
    print(round(result, 2))

elif operator =="/":
    result = Num1 / Num2
    print(round(result, 2))  

else:
    print(f"{operator} is not a valid operator ")   