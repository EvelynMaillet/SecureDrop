from getpass import getpass
from argon2 import PasswordHasher
import argon2
from os import urandom
import os
import json
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from pickle import dump, load
import hashlib
import socket


# A class to hold user data.
class user():
    def __init__(self, fullName, email, password):
        self.fullName = fullName
        self.email = email
        self.password = password


# A class to hold contact data.
class contact():
    def __init__(self, fullName, email, tag, nonce):
        self.fullName = fullName
        self.email = email
        self.tag = tag
        self.nonce = nonce


# A class to store encrypted messages in
class EncryptedMessage:
    def __init__(self, enc_key, enc_data, tag, nonce):
        self.enc_key = enc_key
        self.enc_data = enc_data
        self.tag = tag
        self.nonce = nonce


class SecureDrop():
    # This variable holds the current user's login so that we can reference it
    # globally.
    user

    # Global incorrect login attempt checker.
    # So far no functionality for this value has been implemented,
    # but it is tracked so that future iterations may use it.
    incorrectLogin = 0

    # Argon2 password hasher for sensitive data
    hasher = PasswordHasher()

    # Our init function sets the file that will contain user data to
    # 'users.json'. This also handles storing our prompt that will be
    # displayed to the user in our main event loops.
    def __init__(self):
        self.usersFile = 'users.json'
        self.prompt = 'SecureDrop> '

    # This is a helper function to clear variables of user data once this data
    # has been securely stored.
    def washData(self, *args):
        for i in args:
            i = '\0'

    # This function allows us to encrypt data using a password
    # for decryption. It functions using a combination of
    # scrypt and AES. scrypt generates the AES encryption key
    # from our supplied password.
    def encryptWithPass(self, toEncrypt, password):
        key = scrypt(password=password, salt=urandom(
            16), key_len=16, N=2**14, r=8, p=1, num_keys=1)
        aes_enc_obj = AES.new(key, AES.MODE_GCM)
        toEncrypt, tag = aes_enc_obj.encrypt_and_digest(
            bytes(toEncrypt, 'utf-8'))
        nonce = aes_enc_obj.nonce
        return toEncrypt, tag, nonce

    # The matching decryption function for the one above
    def decryptWithPass(self, toDecrypt, password):
        aes_dec_obj = AES.new(password, AES.MODE_GCM, nonce=toDecrypt.nonce)
        return aes_dec_obj.decrypt_and_verify(
            toDecrypt.enc_data, toDecrypt.tag)

    # This function uses checksums generated from our users and Contacts
    # files to check if data has been modified externally.
    # This assumes that there exists sercurity certificates from the creation
    # or modification of both these files that are held in an external, secure
    # location.
    def verifyIntegrity(self):
        if (os.path.exists('contacts.json')):
            with open('securitycertContacts.dat', "r") as f:
                hash = f.read()
                f2 = open('contacts.json', "rb")
                data = f2.read()
                # Verify integrity of our contacts file using the md5 hash
                # we made at the last modification through the program.
                hashOrig = hashlib.md5(data).hexdigest()
                if hash != hashOrig:
                    print("Contacts file has been modified externally")

        if (os.path.exists(self.usersFile)):
            with open('securitycertUsers.dat', "r") as f:
                hash = f.read()
                f2 = open(self.usersFile, "rb")
                data = f2.read()
                # Verify integrity of our users file using the md5 hash
                # we made at the last modification through the program.
                hashOrig = hashlib.md5(data).hexdigest()
                if hash != hashOrig:
                    print("Users file has been modified externally.")
                    print(
                        "Login may not function. We reccomend you re-register")

    # The function for handling sending files
    # Currently, it does not handle sending files over the network
    # Instead, it sends files to another folder running this program
    # on the same machine.
    def send(self):
        cmd = input("Would you like to send or recieve a file? (s/r)").lower()

        # If the user would like to send a file
        # they are set up as the client machine
        if cmd == 's':
            IP = socket.gethostbyname(socket.gethostname())
            print(IP)
            Port = 4455
            Address = (IP, Port)
            Size = 1024
            Format = 'utf-8'

            filename = input(
                "Please type the name of the file you would like to send: ")

            # Establish a socket connection with a server listening on the
            # same machine
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect(Address)

                # Here we send the name of the file to the server
                # in response, we get the public RSA key of the
                # user listening.
                client.send(filename.encode(Format))
                resp = client.recv(Size).decode(Format)
                print("Sent file name. Recieved response from user.")
                publicKey = RSA.importKey(resp)
                # Generate an AES session key for this transfer
                # as we are using PGP for this file transfer.
                sessionKey = urandom(16)
                aes_enc_obj = AES.new(sessionKey, AES.MODE_GCM)
                rsa_enc_obj = PKCS1_OAEP.new(publicKey)

                # Open the file, read its contents, and encrypt them
                file = open(filename, "rb")
                data = file.read()
                ciphertext, tag = aes_enc_obj.encrypt_and_digest(data)
                nonce = aes_enc_obj.nonce
                cryptKey = rsa_enc_obj.encrypt(sessionKey)
                # We now take all the encrypted data from the now
                # encrypted message, create an EncryptedMessage object
                # with it and write it to an in-between file.
                msg = EncryptedMessage(cryptKey, ciphertext, tag, nonce)
                with open('output.enc', 'wb') as fd:
                    dump(msg, fd)
                # Read the contents of our in-between file
                # that should now be safe to deliver
                # and send it.
                file = open('output.enc', "rb")
                data = file.read()
                client.send(data)
                print("Sent file contents.")

            file.close()

        elif cmd == 'r':
            # IP = socket.gethostbyname(socket.gethostname())
            IP = "10.0.2.15"
            Port = 4455
            Address = (IP, Port)
            Size = 1024
            Format = 'utf-8'

            password = getpass('Enter Re-Enter User Password: ')

            print("[STARTING SERVER]")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                # Open the file with our private key
                # so that we can decrypt it
                with open('private.pem', 'r') as f:
                    privateKey = f.read()
                privateKey = RSA.importKey(privateKey, passphrase=password)
                rsa_dec_obj = PKCS1_OAEP.new(privateKey)
                server.bind(Address)
                server.listen()
                conn, addr = server.accept()
                with conn:
                    print(f"Securely connected to {addr}")
                    # First we recieve the name of the file
                    # being transferred
                    filename = conn.recv(Size).decode(Format)
                    # We then open the file containing our public key...
                    with open('public.pem', 'rb') as f:
                        pubKey = f.read()
                    # ...and send it to the person on the other end.
                    conn.send(pubKey)
                    print(f"Filename: {filename}")
                    # Open a file to write the encrypted contents to.
                    file = open('output.enc', "wb")
                    while True:
                        data = conn.recv(Size)
                        if not data:
                            break
                        file.write(data)
                    file.close()

                    # Now load those contents into an EncryptedMessage
                    # object
                    with open('output.enc', 'rb') as fd:
                        msg = load(fd)

                    # Pull the session key from the object and decrypt it
                    # using our rsa_dec_obj we created using our private key
                    encryptKey = msg.enc_key
                    sessionKey = rsa_dec_obj.decrypt(encryptKey)

                    # Finally, decrypt the rest of the message using the
                    # session key...
                    aes_dec_obj = AES.new(
                        sessionKey, AES.MODE_GCM, nonce=msg.nonce)

                    decryptedMessage = aes_dec_obj.decrypt_and_verify(
                        msg.enc_data, msg.tag)
                    # ...and write it to a new file.
                    with open(filename, 'wb') as f:
                        f.write(decryptedMessage)

    # This is the function that handles a user adding another user to their
    # contacts. We use the user's password to generate an encryption key
    # for sensitive data within these contacts so an attacker cannot view
    # contact emails.
    def add(self):
        with open(self.usersFile) as users:
            data = json.load(users)
            while True:
                try:
                    password = getpass('Enter Re-Enter User Password: ')
                    hashTrue = self.hasher.verify(data['password'], password)
                    if hashTrue:
                        break
                    else:
                        pass
                except argon2.exceptions.VerifyMismatchError:
                    self.incorrectLogin += 1
                    print("I'm sorry, that password is incorrect.")

        nameOfContact = input(
            'Please enter the full name of the contact you\'d like to add: ')
        contactEmail = input(
            'Please enter the email of the contact you\'d like to add: ')
        # All sensitive contact information is encrypted using the user's
        # password.
        contactEmail, tag, nonce = self.encryptWithPass(
            contactEmail, password)
        newContact = contact(nameOfContact,
                             str(contactEmail), str(tag), str(nonce))
        contacts = open('contacts.json', "w")
        contacts.write(json.dumps(newContact.__dict__))
        contacts.close()

        # We save a hash of the new state of the contacts file made using
        # md5 so we can verify it was not modified.
        with open('contacts.json', "rb") as f:
            data = f.read()
            hash = hashlib.md5(data).hexdigest()
            f2 = open('securitycertContacts.dat', "w")
            f2.write(hash)

    # This is the main event listening loop that runs once the user has either
    # registered or logged in.
    def shell(self):
        while True:
            cmd = input(self.prompt)
            if cmd == "add":
                self.add()
            elif cmd == "list":
                print("not done")
            elif cmd == "send":
                self.send()
            elif cmd == "exit":
                sys.exit()
            elif cmd == "help":
                print('"add" -> Add a new contact')
                print('"list" -> List all online contacts')
                print('"send" -> Transfer file to contact')
                print('"exit" -> Exit SecureDrop')

    # The registration process prompts the user to register with the client.
    # It securely handles and stores the users data so that all sensitive
    # information (such as the user's password) are not accessible by
    # an attacker.
    # Password encryption is done using argon2 as it is the current
    # standard for encryption in this usecase.
    def registerUser(self):
        print('No users are registered with this client.')
        cmd = input('Do you want to register a new user? (y/n) ')
        if cmd == 'y' or cmd == 'Y':
            fullName = input('Enter Full Name: ')
            email = input('Enter Email Address: ')
            password = getpass('Enter Password: ')
            passwordTemp = self.hasher.hash(password)
            while not (self.hasher.verify(passwordTemp,
                                          getpass('Enter Password: '))):
                print("I'm sorry. Those passwords do not match.")
                password = getpass('Enter Password: ')
                passwordTemp = self.hasher.hash(password)
            print("Thank you for registering.")
            # At user registration, we generate an RSA private/public key pair
            # and store them in .pem files.
            # The private key is encrypted and protected by the user's password
            privateKey = RSA.generate(2048)
            with open('private.pem', 'wb') as f:
                f.write(privateKey.export_key(passphrase=password))
            with open('public.pem', 'wb') as f:
                f.write(privateKey.publickey().export_key())

            # Convert user's password from plaintext to a hashed password
            # so it can be securely stored.
            password = self.hasher.hash(password)
            newUser = user(fullName, email, password)
            f = open(self.usersFile, "w")
            f.write(json.dumps(newUser.__dict__))
            f.close()

            newUser = user('\0', '\0', '\0')
            self.washData(fullName, email, password)
            print("Your credentials have been securely stored.")
            print("The program will now close.")
            # We save a hash of the new state of the users file made using
            # md5 so we can verify it was not modified.
            with open(self.usersFile, "rb") as f:
                data = f.read()
                hash = hashlib.md5(data).hexdigest()
                f2 = open('securitycertUsers.dat', "w")
                f2.write(hash)
        else:
            sys.exit()

    # The login loop checks to see if the email a user entered exists in the
    # users file. It then prompts the user for their password which is checked
    # against the encrypted value in the users file for entry.
    def login(self):
        with open(self.usersFile) as users:
            data = json.load(users)
            login = input("Enter Email Address: ")
            while login != data['email']:
                print("I'm sorry, that user is not registered on this device.")
                login = input("Enter Email Address: ")

            while True:
                try:
                    hashTrue = self.hasher.verify(data['password'],
                                                  getpass('Enter Password: '))
                    if hashTrue:
                        break
                    else:
                        pass
                except argon2.exceptions.VerifyMismatchError:
                    self.incorrectLogin += 1
                    print("I'm sorry, that password is incorrect.")
        self.user = login
        self.washData(login)
        print("Welcome to SecureDrop.")
        print('Type "help" for commands.')
        self.shell()

    # The main loop for this object checks to see if the user needs to
    # register or if they can simply log in.
    def run(self):
        self.verifyIntegrity()
        if not (os.path.exists(self.usersFile)):
            self.registerUser()
        else:
            self.login()


if __name__ == '__main__':
    run_forrest = SecureDrop()
    # This is a Forrest Gump (1994 film) reference.
    run_forrest.run()
