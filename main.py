from hashlib import sha256
import datetime
from datetime import datetime
import json
from helpers import s256, h160, reverseBytes, open_file_as_json, int_to_compact

from write_raw import test, get_raw_transaction, Transaction 
import math
import binascii
import time

TARGET_HASH = "0000ffff00000000000000000000000000000000000000000000000000000000"

def mine(target, merkletree):
    # asdfasd
    found = False
    nonce = 0
    date = str.encode(str(datetime.now().timestamp()))
    hash = ""
    block_header = None
    while not found:
        nonce += 1
        # hash = sha256(str.encode(hex(nonce)) + date).digest()
        block_header = create_block(nonce, merkletree)
        hash = s256(s256(block_header))
        found = is_hash_smaller(target, hash)

        
        if nonce % 100000 == 0 and not found:
            print("reset")
            date = str.encode(str(datetime.now().timestamp()))
            nonce = 0
        
    print(hash)
    return hash, block_header
    # return str.encode(hex(nonce)) + date 


def is_hash_smaller(target, hash):
    for i in range(32):
        if target[i] > hash[i]:
            return True
        elif target[i] < hash[i]:
            return False
    return False


def format_target(target):
    new_target = [0] * 32
    for i in range(32):
        new_target[i] = int(target[i*2:i*2+2], 16)
    return new_target


def validate_transaction(filename):
    file = open(filename)
    data = json.load(file)

def create_block(nonce, merkletree):
    FILENAME = "output.txt"
    PREVIOUS_BLOCK = bytes.fromhex("000000000000000000015b32060fb2b834a4f799616500ab2af7277e93d70736")
    version = (32).to_bytes(length=4, byteorder="little")

    timestamp = int(time.time()).to_bytes(length=4, byteorder="little")
    bits = int("1f00ffff", 16).to_bytes(length=4, byteorder="little")

    block_header = version + PREVIOUS_BLOCK + merkletree + timestamp  + bits + bytes(nonce)
    return block_header

def merkle_tree(transactions):
    res = []
    if len(transactions) == 1:
        return transactions[0]
    for i in range(0, len(transactions), 2):
        a = transactions[i]
        if i+1 >= len(transactions):
            b = transactions[i]
        else:
            b = transactions[i+1]
        
        # print(a, b)
        # a, b = bytes.fromhex(a), bytes.fromhex(b)
        res.append(s256(s256(a+b)))
    return merkle_tree(res)


def calculate_block_reward(trans):
    reward = 0
    for i in trans:
        ins, outs = 0, 0
        
        filename = "mempool/" + reverseBytes(i).hex() + ".json"
        for j in open_file_as_json(filename)["vin"]:
            ins += j["prevout"]["value"]

        for j in open_file_as_json(filename)["vout"]:
            outs += j["value"]
        reward += ins-outs
    return reward



# commands: cat mempool/* | grep -o -E -i '((OP_)[a-zA-z_0-9]*\w)*' | sort | uniq

if __name__ == "__main__":

    test()

    trans = open("files.txt", "r").read().split("\n")[:-1]
    trans = list(map(bytes.fromhex, trans))
    trans = list(map(reverseBytes, trans))
    merkletree = binascii.hexlify(merkle_tree(trans))


    print("tree: ", merkle_tree)
    target = format_target(TARGET_HASH) 

    block_hash, block_header = mine(target, merkletree)

    coinbase_transaction_data = open_file_as_json("example.json")
    reward = calculate_block_reward(trans)
    coinbase_transaction_data["vout"][0]["value"] = reward

    coinbase_transaction = Transaction(coinbase_transaction_data)

    coinbase_transaction_bytes = get_raw_transaction(coinbase_transaction)
    f = open("output.txt", "wb")
    f.write(block_header)
    f.write(b'\n')
    f.write(int_to_compact(len(trans)+1))
    f.write(b'\n')
    f.write(coinbase_transaction_bytes)
    f.write(b'\n')
    # trans.insert(0, coinbase_transaction_id)
    for t in trans:
        f.write(get_raw_transaction(Transaction(open_file_as_json("mempool/"+reverseBytes(t).hex()+".json"))))
        f.write(b'\n')
    f.close()



    

