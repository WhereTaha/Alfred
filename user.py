import argparse
import bcrypt
import csv
import re

CSV_FILE = 'user_data.csv'

def is_valid_password(password):
    password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    return bool(password_regex.match(password))

def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password.encode(), bcrypt.gensalt())

def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(plain_text_password.encode(), hashed_password.encode())

def username_exists(username_to_check):
    """Check if the username exists in the CSV file."""
    with open(CSV_FILE, mode='r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row and row[1] == username_to_check:
                return True
    return False

def get_next_id():
    try:
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            last_row = list(reader)[-1]  
            return int(last_row[0]) + 1  
    except (FileNotFoundError, IndexError):
        return 1  

def register(username, password):
    if username_exists(username):
        return "Username already exists!!"

    if not is_valid_password(password):
        return "Password is not strong enough. It must contain at least one lowercase, one uppercase, one digit, one special character, and be at least 8 characters long."

    hashed_password = get_hashed_password(password)
    user_id = get_next_id()  

    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([user_id, username, hashed_password.decode()])  
    msg = 'Signed up!'
    return msg

def login(username, password):
    msg = "Username doesn't exist!"
    with open(CSV_FILE, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[1] == username:  
                if check_password(password, row[2]):  
                    msg = 'Welcome, You Logged in!'
                else:
                    msg = 'Incorrect password!'
                    break
    return msg

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='User manager')

    username = input('Please enter your username: ')
    password = input('Please enter your password: ')

    parser.add_argument('action', type=str,
                        help='Action <login|register|list>')

    args = parser.parse_args()

    if args.action == "login":
        result = login(username=username, password=password)
    elif args.action == "register":
        result = register(username=username, password=password)
    else:
        result = "Wrong choice"

    print(result)
