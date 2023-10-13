import tkinter as tk
import random
import re
#Creates user window
usertk = tk.Tk()
usertk.geometry("300x300")
#Creates server window
servertk = tk.Tk()
servertk.geometry("300x300")
creates encryption window
encryptk = tk.Tk()
encryptk.geometry("300x300")

#dictionary of log ins
ValidLogIns = {"JimB101": ["IlikeFood300", 100], "Alice101": ["Pizza@11", 50]}

def LogIn():
    # create the login window
    LogInWindow = tk.Frame(usertk)
    LogInLabel = tk.Label(LogInWindow, text="Log In", anchor="center").pack()
    UsernameLabel = tk.Label(LogInWindow, text="Username", anchor="center").pack()
    #username entry
    username_entry = tk.Entry(LogInWindow)
    username_entry.pack()
    PasswordLabel = tk.Label(LogInWindow, text="Password", anchor="center").pack()
    #password entry
    password_entry = tk.Entry(LogInWindow, show="*")
    password_entry.pack()
    #submits username and password. Validates log in
    Submit = tk.Button(LogInWindow, text="Submit", command=lambda: validateLogin(LogInWindow, username_entry.get(), password_entry.get()))
    Submit.pack()
    LogInWindow.tkraise()  # show the login window
    LogInWindow.pack()

def validateLogin(logInWindow, username, password):
    # Check if the username exists and the password matches the one in the dictionary
    if username in ValidLogIns and (md5_hash(password) == md5_hash(ValidLogIns[username][0])):
        bankScreen(logInWindow, username)

def md5_hash(pw):
    #salted value
    salt = "cake"
    message = pw + salt
    # Initialize variables
    a = 0x67452301
    b = 0xefcdab89
    c = 0x98badcfe
    d = 0x10325476
    #converts message to bytes
    message = message.encode('utf-8')
    #md5 constants
    constants = [7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21]

    #shifts byte to left
    def left_rotate(x, amount):
        return ((x << amount) & 0xffffffff) | (x >> (32 - amount))

    # Process the message in 64-byte blocks
    for i in range(0, len(message), 64):
        block = message[i:i + 64]
        # Break block into 16 32-bit words
        words = [int.from_bytes(block[j:j + 4], byteorder='little') for j in range(0, 64, 4)]
        # Save previous values of a, b, c, and d
        aa, bb, cc, dd = a, b, c, d
        # Perform the four rounds of hashing
        for j in range(16):
            if j < 4:
                f = (b & c) | (~b & d)
                g = j
            elif j < 8:
                f = (d & b) | (~d & c)
                g = (5 * j + 1) % 16
            elif j < 12:
                f = b ^ c ^ d
                g = (3 * j + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * j) % 16
            #swaps values
            temp = d
            d = c
            c = b
            b = left_rotate(b + left_rotate(a + f + words[g] + constants[j], amount=j % 4 * 5), amount=j % 4 * 5)
            a = temp
            # Update values of a, b, c, and d
            a = (a + aa) & 0xffffffff
            b = (b + bb) & 0xffffffff
            c = (c + cc) & 0xffffffff
            d = (d + dd) & 0xffffffff
    # Combine values of a, b, c, and d to form final hash
    hash_value = (a.to_bytes(4, byteorder='little') +
                  b.to_bytes(4, byteorder='little') +
                  c.to_bytes(4, byteorder='little') +
                  d.to_bytes(4, byteorder='little'))
    return hash_value.hex()

def bankScreen(LogInWindow, username):
    # create the bank window
    LogInWindow.forget()
    BankWindow = tk.Frame(usertk)
    BankWindow.lift()  # show the bank window
    BankLabel = tk.Label(BankWindow, text=f"Welcome {username}", anchor="center").pack()
    WithdrawalButton = tk.Button(BankWindow, text="Withdrawal", command=lambda: WithdrawalScreen(BankWindow, username)).pack()
    DepositButton = tk.Button(BankWindow, text="Deposit", command=lambda: DepositScreen(BankWindow, username)).pack()
    CheckBalanceButton = tk.Button(BankWindow, text="Check Balance", command=lambda: CheckBalanceScreen(BankWindow, username))
    CheckBalanceButton.pack()
    BankWindow.pack()

def DepositScreen(BankWindow, username):
    #leaves bankwindow screen
    BankWindow.forget()
    # create the deposit window
    DepositWindow = tk.Frame(usertk)
    DepositWindow.lift()  # show the deposit window
    tk.Label(DepositWindow, text="Deposit", anchor="center").pack()
    #deposit amount
    DepositEntry = tk.Entry(DepositWindow)
    DepositEntry.pack()
    #submits deposit, sends transaction through encryption
    Submit = tk.Button(DepositWindow, text="Submit", command=lambda: (bankScreen(DepositWindow, username), RC4Encrypt(username, "Deposit " + str(DepositEntry.get()))))
    Submit.pack()
    DepositWindow.pack()

def WithdrawalScreen(BankWindow, username):
    BankWindow.forget()
    # create the deposit window
    WithdrawalWindow = tk.Frame(usertk)
    WithdrawalWindow.lift()  # show the deposit window
    tk.Label(WithdrawalWindow, text="Withdrawal", anchor="center").pack()
    WithdrawalEntry = tk.Entry(WithdrawalWindow)
    WithdrawalEntry.pack()
    #Submits withdrawal, sends transacition through encryption
    Submit = tk.Button(WithdrawalWindow, text="Submit", command=lambda: (bankScreen(WithdrawalWindow, username), (RC4Encrypt(username, "Withdrawal " + str(WithdrawalEntry.get())))))
    Submit.pack()
    WithdrawalWindow.pack()

def CheckBalanceScreen(BankWindow, username):
    BankWindow.forget()
    # create the check balance window
    CheckBalanceWindow = tk.Frame(usertk)
    CheckBalanceWindow.lift()  # show the check balance window
    #Checks balaance, sends message through encryptiion
    Label = tk.Label(CheckBalanceWindow, text="Current Balance: $" + str(RC4Encrypt(username, "Check Balance")))
    Label.pack()
    #goes back to bank screen
    Back = tk.Button(CheckBalanceWindow, text="Back", command=lambda: (bankScreen(CheckBalanceWindow, username)))
    Back.pack()
    CheckBalanceWindow.pack()

def UpdateBalance(username,type):
    if username in ValidLogIns:
        #adds deposit to balance
        if re.search("Deposit",type):
            ValidLogIns[username][1] += int(type[7:])
            return ValidLogIns[username][1]
        #subtracts withdrawal from balance
        elif re.search("Withdrawal",type):
            ValidLogIns[username][1] -= int(type[10:])
            return ValidLogIns[username][1]
        elif re.search("Check Balance",type):
            return ValidLogIns[username][1]  # return current balance if transaction is not a deposit or withdrawal
        return None

def ServerSide(num):
    #shows current transactions
    ServerWindow = tk.Frame(servertk)
    tk.Label(ServerWindow, text=num).pack()
    ServerWindow.pack()

def EncryptionSide(num):
    #shows current encrypted transactions
    EncryptionWindow = tk.Frame(encryptk)
    tk.Label(EncryptionWindow, text=num).pack()
    EncryptionWindow.pack()

def RC4Encrypt(username, plaintext):
    #random key
    key = ''.join((random.choice('abcdefghijklmnopqrstuvwxyz') for i in range(5)))
    key_len = len(key)
    S = list(range(256))
    j = 0
    output = []
    # KSA Phase
    for i in range(256):
        j = (j + S[i] + ord(key[i % key_len])) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA Phase
    i = j = 0
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        output.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
    EncryptionSide(str(''.join(output)))
    return RC4Decrypt(username, key, str(''.join(output)))

def RC4Decrypt(username, k, ciphertext):
    key = k
    S = list(range(256))
    j = 0
    output = []
    # KSA Phase
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA Phase
    i = j = 0
    for char in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        output.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
    ServerSide(str(''.join(output)))
    return UpdateBalance(username, str(''.join(output)))

LogIn()
usertk.mainloop()
encryptk.mainloop()
servertk.mainloop()
