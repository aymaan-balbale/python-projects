principle = 0 
rate = 0 
time = 0 

while True:
    principle = float(input("Enter your principle amount: "))
    if principle < 0:
        print("principle amount can't be negative")
    else:
        break

while True:
    rate = float(input("Enter your interest rate: "))
    if rate < 0:
        print("interest rate can't be negative")  
    else:
        break    
    

while True:
    time = int(input("Enter your time in years: "))
    if time < 0:
        print("time in years can't be negative")
    else:
        break                 

total = principle * pow((1 + rate / 100), time)
print(f"Balance after {time} year/s: ${total:.2f}")

