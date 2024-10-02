
import argparse
import bcrypt
import csv

CSV_FILE = 'user_data.csv'

def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password.encode(),bcrypt.gensalt())

def check_password(plain_text_password,hashed_password):
    return bcrypt.checkpw(plain_text_password.encode(),hashed_password.encode())

def register(username, password):
  hashed_password = get_hashed_password(password)

  with open(CSV_FILE,mode='a',newline='')as file:
      writer = csv.writer(file)
      writer.writerow([username,hashed_password.decode()])
  msg = 'Signed up!'
  return msg

def login(username, password):
  msg = "Username dosen't exist!"
  with open(CSV_FILE,mode='r') as file:
      reader = csv.reader(file)
      for row in reader:
          if row[0]==username:
              if check_password(password,row[1]):
                  msg = 'Welcome,You Logged in!'
              else:
                  msg = 'Incorrect password'
                  break
  return msg
              

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='User manager')

  username=input('Please Enter  your login usernanme : ')
  password=input('Please Enter your login password : ')

  parser.add_argument('action', type=str,
                    help='Action <login|register|list>')
  
  args = parser.parse_args()

  if args.action == "login":
    result=login(username=username, password=password)
  elif args.action == "register":
    result=register(username=username, password=password)
  else:
     result = "Wrong choice"
  
  print(result)
