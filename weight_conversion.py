weight = float(input("Enter your weight: "))
unit = input("Enter a unit (K or L): ")

if unit == "K":
   weight = weight * 2.205 
   unit = "Lbs."
   print(f"your weight is : {round(weight, 1)} {unit}")

elif unit == "L":
   weight = weight / 2.205 
   unit = "Kgs."
   print(f"your weight is : {round(weight, 1)} {unit}")   

else:
   print(f"{unit} is invalid ")   