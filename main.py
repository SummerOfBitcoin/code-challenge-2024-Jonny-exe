from hashlib import sha256
import datetime
from datetime import datetime
import json
from helpers import s256, h160, reverseBytes, open_file_as_json, int_to_compact, format_target

from write_raw import test, get_raw_transaction, Transaction 
import math
import binascii
import time

TARGET_HASH = "0000ffff00000000000000000000000000000000000000000000000000000000"
TARGET_HASH_FORMATED = format_target(TARGET_HASH) 
PREVIOUS_BLOCK = bytes.fromhex("000000000000000000015b32060fb2b834a4f799616500ab2af7277e93d70736")
BLOCK_BITS = int("1f00ffff", 16).to_bytes(length=4, byteorder="little")
VERSION = (2).to_bytes(length=4, byteorder="little")

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
            date = str.encode(str(datetime.now().timestamp()))
            nonce = 0
    # print(binascii.hexlify(block_header))

    return hash, block_header
    # return str.encode(hex(nonce)) + date 


def is_hash_smaller(target, hash):
    for i in range(32):
        if target[i] > hash[i]:
            return True
        elif target[i] < hash[i]:
            return False
    return False


def validate_transaction(filename):
    file = open(filename)
    data = json.load(file)

def create_block(nonce, merkletree):
    FILENAME = "output.txt"

    timestamp = int(time.time()).to_bytes(length=4, byteorder="little")


    block_header = VERSION + PREVIOUS_BLOCK + merkletree + timestamp  + BLOCK_BITS + nonce.to_bytes(length=4, byteorder="little")
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
    merkletree = merkle_tree(trans)


    block_hash, block_header = mine(TARGET_HASH_FORMATED, merkletree)

    coinbase_transaction_data = open_file_as_json("example.json")
    reward = calculate_block_reward(trans)
    coinbase_transaction_data["vout"][0]["value"] = reward

    coinbase_transaction = Transaction(coinbase_transaction_data)

    coinbase_transaction_bytes = get_raw_transaction(coinbase_transaction)
    f = open("output.txt", "w")
    print(str(block_header.hex()))
    f.write(str(block_header.hex()))

    # f.write(b'\n')
    f.write('\n')
        # f.write(int_to_compact(len(trans)+1))
        # f.write(b'\n')
    f.write(str(coinbase_transaction_bytes.hex()))
    # trans.insert(0, coinbase_transaction_id)
    for t in trans:
        f.write('\n')
        # f.write(b'\n')
        f.write(get_raw_transaction(Transaction(open_file_as_json("mempool/"+reverseBytes(t).hex()+".json"))).hex())
    f.close()



    

