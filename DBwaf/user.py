import hashlib
import os
import re  # for regular expressions
#from pymongo import MongoClient

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'


def hash_password(password):
    salt = os.urandom(32)  # A new salt for this user
    hash_code = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return {'salt': salt, 'hash_code': hash_code}

def verify_password(password, salt, hash_code):
    new_hash_code = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    if hash_code == new_hash_code:
        print('Matching password')
    else:
        print('Not matching password')


#https://www.vitoshacademy.com/hashing-passwords-in-python/
# def hash_password(password):
#     """Hash a password for storing."""
#     salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
#     pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
#                                   salt, 100000)
#     pwdhash = binascii.hexlify(pwdhash)
#     return (salt + pwdhash).decode('ascii')
# def verify_password(stored_password, provided_password):
#     """Verify a stored password against one provided by user"""
#     salt = stored_password[:64]
#     stored_password = stored_password[64:]
#     pwdhash = hashlib.pbkdf2_hmac('sha512',
#                                   provided_password.encode('utf-8'),
#                                   salt.encode('ascii'),
#                                   100000)
#     pwdhash = binascii.hexlify(pwdhash).decode('ascii')
#     return pwdhash == stored_password


# if __name__ == '__main__':
#     mypass = 'ThisIsAPassWord'
#     stored_password = hash_password(mypass)
#     print('stored pass:' + stored_password)
#     print(verify_password(stored_password, mypass))
#     print(verify_password(stored_password, 'msdsfhisf'))
def save_user_in_db(email, password, collection):
    salt = os.urandom(32)  # A new salt for this user
    hash_code = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    data_user = {'email': email, 'hash_code': hash_code, 'salt': salt}
    #return data_user
    #collection_user.create_index('email', unique=True)  # define a key by creating an index
    collection.insert_one(data_user)


def check_strong_password(password):
    # Primary conditions for password validation :
        # Minimum 8 characters.
        # The alphabets must be between [a-z]
        # At least one alphabet should be of Upper Case [A-Z]
        # At least 1 number or digit between [0-9].
        # At least 1 special character

    if len(password) >= 8:
        if not re.search("[a-z]", password):
            return False
        elif not re.search("[0-9]", password):
            return False
        elif not re.search("[A-Z]", password):
            return False
        elif not re.search("[@_!#$%^&*()<>?/\|}{~:]", password):
            return False
        elif re.search("\s", password):
            return False
        else:
            return True  # Valid Password
    else:
        print("Password must be at least 8 characters long")
        return False


def validation_email(email):
    # pass the regular expression and the string in search() method
    if re.search(regex, email):
        return True
    else:
        return False


if __name__ == '__main__':
    # Creating a client
    #client = MongoClient('localhost', 27017)

    # Creating a database name 'WafDB'
    #database = client['WafDB']

    #collection_logger = database['Logger']  # collection Logger is created


    # threshold = 0.9
    # type_attack = 'xss'
    # email = 'sapir@gmail.com'
    # command = '<script>alert(1)</script>'
    # if_warn = True
    # data = {'date': datetime.datetime.now(), 'threshold': threshold, 'type_attack': type_attack, 'email': email,
    #         'command': command, 'if_warn': if_warn}
    #
    # collection_logger.insert_one(data)

    #collection_user = database['User']  # collection User is created

    # input Registration
    print('***Registration***')
    emailR = str(input('enter your email:'))
    while validation_email(emailR) == False:
        print('Invalid email')
        print('enter your email:')
        emailR = str(input())

    passwordR = str(input('enter your password:'))
    while check_strong_password(passwordR) == False:
        print('The password must contain: '
              'alphabets between [a-z],'
              'At least one alphabet of Upper Case [A-Z],'
              'At least 1 number or digit between [0-9],'
              'At least 1 special character.')
        passwordR = str(input('enter your password:'))

    #save_user_in_db(emailR, passwordR, collection_user)

    # input Login
    print('***Login***')
    email = str(input('enter your email:'))
    while validation_email(email) == False:
        print('Invalid email')
        print('enter your email:')
        email = str(input())

    password = str(input('enter your password:'))
    while check_strong_password(password) == False:
        print('The password must contain: '
              'alphabets between [a-z],'
              'At least one alphabet of Upper Case [A-Z],'
              'At least 1 number or digit between [0-9],'
              'At least 1 special character.')
        password = str(input('enter your password:'))

    #current_user = collection_user.find_one({'email': email})
    # if not current_user == None:
    #     current_salt = current_user['salt']
    #     current_hashcode = current_user['hash_code']
    #     verify_password(password, current_salt, current_hashcode)

    else:
        print('The user does not exist in the system')
