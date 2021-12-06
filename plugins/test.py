from plugins.errorhandling import *


def main():
    print("AAAA")
    a = int(input("Number: "))
    b = int(input("Number2: "))

    try:
        if a == b:
            raise DoesNotExistError(a)
        else:
            print(a+b)
    except DoesNotExistError as e:
        print("Error:" , e)

    print("Thank you")

main()