## Password Checker 
## Usages: python3 password_checker.py <Password1> <PasswordN>
## Description: This password checker will hash the password provided and take first 5 characters of hashed password
## and call api of https://haveibeenpwned.com/Passwords site to get list of matching hashes and it's breach count. Based on breach details
## it mark password as safe to use or not.
## Author: Devendra Durgapal 
## Date: 08-07-2020
##


import getpass
import requests
import hashlib
import random
import string
import sys
from termcolor import colored

def api_request(query_char):
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'[-] Error fetching: {res.status_code}, check the api and try again')
  return res

def password_leaks_count(hashes, hash_to_check):
  hashes = (line.split(':') for line in hashes.text.splitlines())
  for h, count in hashes:
    if h == hash_to_check:
      return count
  return 0

def pwned_api_password_check(password):
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = api_request(first5_char)
  return password_leaks_count(response, tail)


def single_password_checker(password):
  count = pwned_api_password_check(password)
  if count:
    return count
  else:
    return count


def safe_random_password(length=10):
    random_source = string.ascii_letters + string.digits + string.punctuation
    password = random.choice(string.ascii_lowercase)
    password += random.choice(string.ascii_uppercase)
    password += random.choice(string.digits)
    password += random.choice(string.punctuation)
    
    length = int(length)
    if length < 10:
      length = 10
    
    for i in range(length):
        password += random.choice(random_source)

    password_list = list(password)
    random.SystemRandom().shuffle(password_list)
    password = ''.join(password_list)
    
    ret = single_password_checker(password)
    if ret > 0:
      safe_random_password()
    else:
      return password

def yes_or_no():
  while True:
    answer =  input("[+] Do you want safe random password? Enter Yes/No?").lower()
    if answer == "yes":
      return 1
    elif answer == "no":
      return 0 



if __name__ == '__main__':
  print("[+] Started Password Breached Checker Program.")
  password = getpass.getpass()
  count = single_password_checker(password)
  
  if int(count) > 0:
    print("[-] Password appeared {count} times in data breach by haveibeenpwned.com. Not safe to use")
    if yes_or_no():
      password = safe_random_password()
      print("[+] Use safe password - {password}")

  print("[+] Completed Password Breached Checker Scan.")
  print("\n\n *** Stay Cyber Safe *** \n") 
