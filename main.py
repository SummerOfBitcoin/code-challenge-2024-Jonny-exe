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
PREVIOUS_BLOCK = reverseBytes(bytes.fromhex("000000000000000000015b32060fb2b834a4f799616500ab2af7277e93d70736"))
# BLOCK_BITS = int("1f00ffff", 16).to_bytes(length=4, byteorder="big")
BLOCK_BITS = int("1f00ffff", 16).to_bytes(length=4, byteorder="little")
VERSION = (32).to_bytes(length=4, byteorder="little")
WITNESS_RESERVED_VALUE = bytes(32)

def mine(target, merkletree):
    """
    Mine the hash
    """
    found = False
    nonce = 0
    date = str.encode(str(datetime.now().timestamp()))
    hash = ""
    block_header = None
    while not found:
        nonce += 1
        block_header = create_block(nonce, merkletree)
        hash = reverseBytes(s256(s256(block_header)))
        found = is_hash_smaller(target, hash)

        
        if nonce % 100000 == 0 and not found:
            date = str.encode(str(datetime.now().timestamp()))
            nonce = 0

    return hash, block_header


def is_hash_smaller(target, hash):
    """
    Check if mined hash is valid
    """
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
    """
    Create the raw block
    """
    FILENAME = "output.txt"

    timestamp = int(time.time()).to_bytes(length=4, byteorder="little")


    block_header = VERSION + PREVIOUS_BLOCK + merkletree + timestamp  + BLOCK_BITS + nonce.to_bytes(length=4, byteorder="little")
    return block_header

def merkle_tree(transactions):
    """
    Calculate merkle tree
    """
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
    """
    Given all the transactions, calculate the block reward
    """
    reward = 0
    for i in trans:
        ins, outs = 0, 0
        
        # filename = "mempool/" + reverseBytes(i).hex() + ".json"
        filename = "mempool/" + i.hex() + ".json"
        for j in open_file_as_json(filename)["vin"]:
            ins += j["prevout"]["value"]

        for j in open_file_as_json(filename)["vout"]:
            outs += j["value"]
        reward += ins-outs
    return reward



if __name__ == "__main__":
    test()
    trans = open("files.txt", "r").read().split("\n")[:-1]
    trans = list(map(bytes.fromhex, trans))
    hashes = [s256(s256(get_raw_transaction(Transaction(open_file_as_json("mempool/"+i.hex()+".json")), include_witness=True))) for i in trans]
    types = [Transaction(open_file_as_json("mempool/"+i.hex()+".json")).type for i in trans]
    raws = [get_raw_transaction(Transaction(open_file_as_json("mempool/"+i.hex()+".json")), include_witness=True) for i in trans]
    hashes.insert(0, bytes(32))


    witness_root_hash = merkle_tree(hashes)
    witness_commitment = s256(s256(witness_root_hash + WITNESS_RESERVED_VALUE))

    coinbase_transaction_data = open_file_as_json("example.json")
    reward = calculate_block_reward(trans)
    coinbase_transaction_data["vout"][0]["value"] = reward
    coinbase_transaction_data["vout"][1]["scriptpubkey"] = "6a24aa21a9ed" + witness_commitment.hex()

    coinbase_transaction = Transaction(coinbase_transaction_data)

    coinbase_transaction_bytes = get_raw_transaction(coinbase_transaction)

    hashes = [s256(s256(get_raw_transaction(Transaction(open_file_as_json("mempool/"+i.hex()+".json"))))) for i in trans]
    hashes.insert(0, s256(s256(coinbase_transaction_bytes)))

    merkletree = merkle_tree(hashes)


    block_hash, block_header = mine(TARGET_HASH_FORMATED, merkletree)
    print(block_hash.hex())

    f = open("output.txt", "w")
    f.write(str(block_header.hex()))

    f.write('\n')
    f.write(str(coinbase_transaction_bytes.hex()))
    idx = 0
    for t in hashes:
        f.write('\n')
        f.write(reverseBytes(t).hex())
        idx += 1
    f.close()



    

