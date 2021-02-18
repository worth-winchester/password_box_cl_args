import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass
import sqlite3
import random
import bcrypt
import sys

#Note: remember this program needs python3 to run.
#   to execute use "python3 password_box_cl_args" in the terminal

class Cryptor:
    def encrypt(self, key):
        fernet = Fernet(key)
        with open("pwd.db", "rb") as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open("pwd.db", "wb") as f:
            f.write(encrypted)

    def decrypt(self, key):
        fernet = Fernet(key)
        with open("pwd.db", "rb") as f:
            data = f.read()
        decrypted = fernet.decrypt(data)
        with open("pwd.db", "wb") as f:
            f.write(decrypted)

class KeyMaker:
    def __init__(self, salt):
        self.salt = salt

    def make_key(self, pwd):
        encoded = pwd.encode()
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=self.salt,
        iterations=100000,
        backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(encoded))
        return key

class SaltMaker:
    def make_salt_file(self):
        salt = os.urandom(16)
        with open("salt", "wb") as f:
            f.write(salt)

    def get_salt(self):
        with open("salt", "rb") as f:
            salt = f.read()
        return salt

class HashMaker:
    def make_hash_file(self, pwd):
        encoded = pwd.encode()
        hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
        with open("hash", "wb") as f:
            f.write(hashed)

    def get_hash(self):
        with open("hash", "rb") as f:
            hashed = f.read()
        return hashed

class Authenticator:
    def __init__(self, hashed):
        self.hashed = hashed

    def authenticate(self, pwd):
        encoded = pwd.encode()
        if bcrypt.checkpw(encoded, self.hashed):
            return True
        else:
            return False

class PWDMaker:
    def __init__(self, length, lowerBool, upperBool, numBool, symBool):
        self.length = length
        self.lowerBool = lowerBool
        self.upperBool = upperBool
        self.numBool = numBool
        self.symBool = symBool
        self.lowercase = "abcdefghijklmnopqrstuvwxyz"
        self.uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.numbers = "0123456789"
        self.symbols = "!@#$%&*"

    def make_pwd(self):
        chars = ""
        if self.lowerBool:
            chars += self.lowercase
        if self.upperBool:
            chars += self.uppercase
        if self.numBool:
            chars += self.numbers
        if self.symBool:
            chars += self.symbols
        pwd = "".join(random.sample(chars, self.length))
        return pwd

class DBManager:
    def __init__(self):
        self.connection = sqlite3.connect("pwd.db")
        self.cursor = self.connection.cursor()

    def commit_close(self):
        self.connection.commit()
        self.connection.close()

    def make_pwd_table(self):
        self.cursor.execute('''CREATE TABLE passwords (service text, pwd text)''')

    def insert_pwd(self, service, pwd):
        temp = (service, pwd)
        self.cursor.execute("INSERT INTO passwords VALUES (?, ?)", temp)

    def search_pwd(self, service):
        try:
            temp = (service,)
            self.cursor.execute("SELECT pwd FROM passwords WHERE service=?", temp)
            pwd_tuple = self.cursor.fetchone()
            pwd, = pwd_tuple
            return pwd
        except:
            print("Search returned no result.")

    def delete_pwd(self, service):
        temp = (service,)
        self.cursor.execute("DELETE FROM passwords WHERE service=?", temp)


class ArgumentHandler:
    def __init__(self):
        self.argLengths = {"unlock": 3, "lock": 3, "add": 5, "delete": 3, "search": 3, "init": 3, "pwgen": 7}


    def doesFileExist(self, argIndex):
        if os.path.isfile(sys.argv[argIndex]) == False:
            print(sys.argv[argIndex] + " does not exist in the current directory.")
            return False
        else:
            return True


    def isArgInt(self, argIndex):
        try:
            length = int(sys.argv[argIndex])
            if type(length) is int:
                return True
            else:
                print("The length must be an integer.")
                return False
        except:
            print("The length must be an integer.")
            return False

    def checkBoolArgs(self):
        if ((sys.argv[3] == "y") or (sys.argv[3] == "n")) and ((sys.argv[4] == "y") or (sys.argv[4] == "n")) and ((sys.argv[5] == "y") or (sys.argv[5] == "n")) and ((sys.argv[6] == "y") or (sys.argv[6] == "n")):
            return True
        else:
            print("The syntax for the requires 'y' or 'n' for yes or no.")
            return False


    def isArgFlag(self, argIndex):
        if (sys.argv[argIndex] == "unlock") or (sys.argv[argIndex] == "lock") or (sys.argv[argIndex] == "add") or (sys.argv[argIndex] == "delete") or (sys.argv[argIndex] == "search") or (sys.argv[argIndex] == "init") or (sys.argv[argIndex] == "pwgen"):
            return True
        else:
            print("The appropriate syntax is as follows:")
            print("python3 password_box_cl_args.py unlock 'password'")
            print("python3 password_box_cl_args.py lock 'password'")
            print("python3 password_box_cl_args.py add 'service' 'password' 'passwordConfirmation'")
            print("python3 password_box_cl_args.py delete 'service'")
            print("python3 password_box_cl_args.py search 'service'")
            print("python3 password_box_cl_args.py init 'password'")
            print("python3 password_box_cl_args.py pwgen 'length' 'lowercase(y/n)' 'uppercase(y/n)' 'numbers(y/n)' 'symbols(y/n)'")
            return False


    def argsLengthCorrect(self, argIndex):
        if sys.argv[argIndex] == "unlock":
            key = "unlock"
        if sys.argv[argIndex] == "lock":
            key = "lock"
        if sys.argv[argIndex] == "add":
            key = "add"
        if sys.argv[argIndex] == "delete":
            key = "delete"
        if sys.argv[argIndex] == "search":
            key = "search"
        if sys.argv[argIndex] == "init":
            key = "init"
        if sys.argv[argIndex] == "pwgen":
            key = "pwgen"
        value = self.argLengths[key]
        if value == len(sys.argv):
            return True
        else:
            return False
        

def main():
    arghandler = ArgumentHandler()
    if arghandler.isArgFlag(1):
        if arghandler.argsLengthCorrect(1):
            if (sys.argv[1] == "unlock") or (sys.argv[1] == "lock") or (sys.argv[1] == "delete") or (sys.argv[1] == "search") or (sys.argv[1] == "init"):
                if sys.argv[1] == "unlock":
                    pwd = sys.argv[2]
                    hashmaker = HashMaker()
                    hashed = hashmaker.get_hash()
                    authenticator = Authenticator(hashed)
                    if authenticator.authenticate(pwd):
                        saltmaker = SaltMaker()
                        salt = saltmaker.get_salt()
                        keymaker = KeyMaker(salt)
                        key = keymaker.make_key(pwd)
                        cryptor = Cryptor()
                        cryptor.decrypt(key)
                        print("Unlock Completed")
                    else:
                        print("Unlock Failed")
                if sys.argv[1] == "lock":
                    pwd = sys.argv[2]
                    hashmaker = HashMaker()
                    hashed = hashmaker.get_hash()
                    authenticator = Authenticator(hashed)
                    if authenticator.authenticate(pwd):
                        saltmaker = SaltMaker()
                        salt = saltmaker.get_salt()
                        keymaker = KeyMaker(salt)
                        key = keymaker.make_key(pwd)
                        cryptor = Cryptor()
                        cryptor.encrypt(key)
                        print("Lock Completed")
                    else:
                        print("Lock Failed")
                if sys.argv[1] == "delete":
                    service = sys.argv[2]
                    dbmanager = DBManager()
                    dbmanager.delete_pwd(service)
                    dbmanager.commit_close()
                    print("Delete Completed")
                if sys.argv[1] == "search":
                    service = sys.argv[2]
                    dbmanager = DBManager()
                    pwd = dbmanager.search_pwd(service)
                    if pwd != None:
                        print(pwd)
                if sys.argv[1] == "init":
                    pwd = sys.argv[2]
                    hashmaker = HashMaker()
                    hashmaker.make_hash_file(pwd)
                    dbmanager = DBManager()
                    dbmanager.make_pwd_table()
                    dbmanager.commit_close()
                    saltmaker = SaltMaker()
                    saltmaker.make_salt_file()
                    salt = saltmaker.get_salt()
                    keymaker = KeyMaker(salt)
                    key = keymaker.make_key(pwd)
                    cryptor = Cryptor()
                    cryptor.encrypt(key)
                    print("Initialization Completed")
            if sys.argv[1] == "add":
                service = sys.argv[2]
                pwd = sys.argv[3]
                confirm = sys.argv[4]
                if pwd == confirm:
                    dbmanager = DBManager()
                    dbmanager.insert_pwd(service, pwd)
                    dbmanager.commit_close()
                    print("Add Completed")
                else:
                    print("Add Failed")
            if sys.argv[1] == "pwgen":
                if arghandler.isArgInt(2):
                    if arghandler.checkBoolArgs():
                        length = int(sys.argv[2])
                        lowerBool = False
                        upperBool = False
                        numBool = False
                        symBool = False
                        if sys.argv[3] == "y":
                            lowerBool = True
                        if sys.argv[4] == "y":
                            upperBool = True
                        if sys.argv[5] == "y":
                            numBool = True
                        if sys.argv[6] == "y":
                            symBool = True
                        pwdmaker = PWDMaker(length, lowerBool, upperBool, numBool, symBool)
                        pwd = pwdmaker.make_pwd()
                        print(pwd)
    

main()
