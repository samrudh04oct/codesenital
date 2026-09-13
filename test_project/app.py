import os

from login import login


def main():
    username = input("Username: ")
    password = input("Password: ")
    result = login(username, password)
    print(result)


if __name__ == "__main__":
    main()
