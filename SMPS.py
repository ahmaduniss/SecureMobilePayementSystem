from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import random

class Encryption:
    def __init__(self, key_length=16):
        self.key = os.urandom(key_length)  
        self.backend = default_backend()

    def encrypt(self, data):
        iv = os.urandom(16)  # Secure random IV
        padder = padding.PKCS7(128).padder()  # AES block size is 128 bits
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ct  # Return IV with the ciphertext for proper decryption

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

class User:
    def __init__(self, username, email, phoneNumber):
        self.username = username
        self.email = email
        self.phoneNumber = phoneNumber
        self.accounts = []

    def add_account(self, account):
        self.accounts.append(account)
        print(f"Account {account.account_id} added for user {self.username}.")

    def generate_otp(self):
        otp = random.randint(1000, 9999)
        print(f"OTP for {self.username}: {otp}")
        return otp

class PaymentAccount:
    def __init__(self, account_id, balance, user):
        self.account_id = account_id
        self.balance = balance
        self.transactions = []
        self.user = user
        self.cipher = Encryption()

    def add_transaction(self, transaction):
        encrypted_details = self.cipher.encrypt(transaction.details.encode('utf-8'))
        transaction.details = encrypted_details
        self.transactions.append(transaction)
        print(f"Transaction {transaction.transaction_id} added: {encrypted_details}")

    def transfer_money(self, recipient_account, amount, details):
        otp = self.user.generate_otp()
        entered_otp = int(input(f"Enter OTP for {self.user.username}: "))

        if entered_otp != otp:
            print("Transaction failed: Invalid OTP")
            return

        if self.balance >= amount:
            self.balance -= amount
            recipient_account.balance += amount

            encrypted_details = self.cipher.encrypt(details.encode('utf-8'))
            sender_transaction = Transaction(-amount, details)
            recipient_transaction = Transaction(amount, details)

            self.add_transaction(sender_transaction)
            recipient_account.add_transaction(recipient_transaction)
            print(f"Transaction successful: {amount} transferred from Account {self.account_id} to Account {recipient_account.account_id}")
        else:
            print("Transaction failed: Insufficient funds")

class Transaction:
    def __init__(self, amount, details):
        self.transaction_id = random.randint(100000, 999999)
        self.amount = amount
        self.details = details  # Details will be encrypted after being passed to `add_transaction`

def main():
    user1 = User("Ahmad", "ahmad@example.com", "0791234567")
    user2 = User("Malek", "malek@example.com", "0771234567")
    account1 = PaymentAccount("acc123", 1000, user1)
    account2 = PaymentAccount("acc456", 500, user2)

    user1.add_account(account1)
    user2.add_account(account2)

    print("User 1 balance:", account1.balance)
    print("User 2 balance:", account2.balance)

    account1.transfer_money(account2, 200, "4299785478963210")

    print("User 1 balance after transfer:", account1.balance)
    print("User 2 balance after transfer:", account2.balance)

if __name__ == "__main__":
    main()
