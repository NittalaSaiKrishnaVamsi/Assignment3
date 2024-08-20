import hashlib
import time
import secrets
import string
from twilio.rest import Client
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class Block:
    def __init__(self, index, previous_hash, transaction, timestamp, signature=None):
        self.index = index
        self.previous_hash = previous_hash
        self.transaction = transaction
        self.timestamp = timestamp
        self.signature = signature
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.transaction}{self.timestamp}{self.signature}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def verify_signature(self, public_key):
        try:
            public_key.verify(
                self.signature,
                f"{self.transaction}{self.timestamp}".encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
        self.users = {} 

    def create_genesis_block(self):
        genesis_block = Block(0, "0", "Genesis Block", time.time())
        self.chain.append(genesis_block)

    def generate_random_password(self, length=8):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for _ in range(length))

    def send_sms(self, to_number, message):
        account_sid = 'AC84a39cfadaeccb347a843a8bdd931b5f'
        auth_token = '3ddc108cf844c5540d05707afbb616e4'
        from_number = '+12566188935'
        
        client = Client(account_sid, auth_token)
        client.messages.create(
            body="Vamsi11",
            from_='+12566188935',
            to="+918309920729"
        )

    def register_user(self, username, phone_number, role):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        self.users[username] = {
            'phone_number': phone_number,
            'role': role,
            'private_key': private_key,
            'public_key': public_key
        }

    def add_new_block(self, username, transaction, input_password):
        if username not in self.users:
            print("Error: Unregistered user.")
            return
        
        user = self.users[username]
        if input_password != self.password:
            print("Error: Incorrect password. Transaction denied.")
            return

        # Digital Signature
        signature = user['private_key'].sign(
            f"{transaction}{time.time()}".encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        last_block = self.chain[-1]
        new_block = Block(len(self.chain), last_block.hash, transaction, time.time(), signature)
        
        if self.is_valid_new_block(new_block, last_block, user['public_key']):
            self.chain.append(new_block)
            self.log_transaction(username, transaction, "Success")
            print("Transaction successfully added.")
        else:
            self.log_transaction(username, transaction, "Failed")
            print("Error: Invalid block. Transaction denied.")

    def is_valid_new_block(self, new_block, last_block, public_key):
        if last_block.index + 1 != new_block.index:
            return False
        if last_block.hash != new_block.previous_hash:
            return False
        if new_block.hash != new_block.compute_hash():
            return False
        if not new_block.verify_signature(public_key):
            return False
        return True

    def log_transaction(self, username, transaction, status):
        with open("transaction_log.txt", "a") as f:
            log_entry = f"{time.ctime()} | {username} | {transaction} | {status}\n"
            f.write(log_entry)

    def display_chain(self):
        for block in self.chain:
            print(f"Block {block.index} [{block.hash}]")
            print(f"Previous: {block.previous_hash}")
            print(f"Transaction: {block.transaction}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Signature: {block.signature}")
            print()


mobile_number = '+918309920729'
supply_chain = Blockchain()

supply_chain.register_user("Vamsi", mobile_number, "Manufacturer")

generated_password = supply_chain.generate_random_password()
supply_chain.send_sms(mobile_number, f"Your transaction password is: {generated_password}")

transaction_password = input("Enter the password you received via SMS: ")
supply_chain.password = generated_password

supply_chain.add_new_block("Vamsi", "Manufacturer created 1000 units of Drug A", transaction_password)

transaction_password = input("Enter the password you received via SMS: ")
supply_chain.add_new_block("Vamsi", "Distributor received 1000 units of Drug A", transaction_password)

transaction_password = input("Enter the password you received via SMS: ")
supply_chain.add_new_block("Vamsi", "Pharmacy received 500 units of Drug A", transaction_password)

supply_chain.display_chain()
