#mempool/fea944f8806101aa188e2feb4a0b0158b3531da3f15767e32400274bf3454f8c.json
from ecdsa.util import sigdecode_der

import binascii
from hashlib import sha256
import hashlib
import ecdsa
import json
import base58
import os

from helpers import s256, h160, reverseBytes, open_file_as_json, int_to_compact


# def s256(b):
#     return sha256(b).digest()

# def h160(b):
#     scripthash = hashlib.new('ripemd160')
#     scripthash.update(b)
#     return scripthash.digest()



def doublesha256(input):
    return sha256(sha256(input).digest()).digest()

def hex_to_bytes(hex):
    # return bytearray([int(hex[i:i+2], 16) for i in range(len(hex))])
    return bytes.fromhex(hex)

# def reverseBytes(b):
#     a = bytearray()
#     for i in range(len(b)):
#         a.extend(b[len(b)-i-1].to_bytes())
#     return a

class Transaction():
    def __init__(self, data):
        self.coinbase = data["vin"][0]["is_coinbase"]
        self.data = data
        self.version = data["version"].to_bytes(length=4, byteorder="little")
        self.locktime = data["locktime"].to_bytes(length=4, byteorder='little')

        self.sequences = [i["sequence"].to_bytes(length=4, byteorder='little') for i in data["vin"]]
        self.inputs_n = len(data["vin"])
        # self.inputs = bytearray([self.inputs_n])
        self.inputs = int_to_compact(self.inputs_n)
        self.hashes = [reverseBytes(bytes.fromhex(i["txid"])) for i in data["vin"]]
        self.out_idx = [i["vout"].to_bytes(length=4, byteorder="little") for i in data["vin"]]
        self.scriptsigs = [i["scriptsig"] for i in data["vin"]]

        if not self.coinbase:
            self.type = [i["prevout"]["scriptpubkey_type"] for i in data["vin"]]
            self.in_scripts = [bytes.fromhex(i["prevout"]["scriptpubkey"]) for i in data["vin"]]
            self.input_amount = [i["prevout"]["value"].to_bytes(length=8, byteorder='little') for i in data["vin"]]
            self.sig_and_pubkey = [self.get_sig_and_pubkey(i) for i in range(self.inputs_n)]
            self.sig = [t[0] for t in self.sig_and_pubkey]
            self.pubkey = [t[1] for t in self.sig_and_pubkey]

        self.outputs_n = len(data["vout"])
        # self.outputs = bytearray([self.outputs_n])
        self.outputs = int_to_compact(self.outputs_n)

        self.values = [i["value"].to_bytes(8, byteorder='little') for i in data["vout"]]
        self.out_scriptpubkeys = [bytes.fromhex(i["scriptpubkey"]) for i in data["vout"]]

 

    def get_sig_and_pubkey(self, vin):
        # "4730440220200b9a61529151f9f264a04e9aa17bb6e1d53fb345747c44885b1e185a82c17502200e41059f8ab4d3b3709dcb91b050c344b06c5086f05598d62bc06a8b746db4290121025f0ba0cdc8aa97ec1fffd01fac34d3a7f700baf07658048263a2c925825e8d33",
        if self.type[vin] == "p2pkh":
            scriptsig = self.scriptsigs[vin]
            siglen = int(scriptsig[:2], 16)
            sig = bytes.fromhex(scriptsig[2:2+siglen*2])

            pubkeylen = int(scriptsig[2+siglen*2:2+siglen*2+2], 16)
            pubkey = bytes.fromhex(scriptsig[2+siglen*2+2:2+siglen*2+2+pubkeylen*2])
        # elif self.type[vin] == "p2sh":
        else:
            sig = bytes.fromhex(self.data["vin"][vin]["witness"][0])
            pubkey = bytes.fromhex(self.data["vin"][vin]["witness"][1])
        return sig, pubkey
    
    def verify_signature(pubkey, sig, message):
        vk = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)
        try:
            valid = vk.verify(sig, message, sha256, sigdecode=sigdecode_der)
        except ecdsa.keys.BadSignatureError:
            sig = sig[:len(sig)-1]
            # print("Fixed signature")
            # print("sig: ", binascii.hexlify(sig))
            valid = vk.verify(sig, message, sha256, sigdecode=sigdecode_der) # True
        return valid

def get_raw_transaction(tran, include_witness=False):     
    version = tran.version
    preimage = bytearray([])
    preimage.extend(version)
    # if tran.is_coinbase:
    #     preimage.extend(tran.inputs)
    #     preimage.extend(tran.hashes[0])
    #     preimage.extend(tran.out_idx[0])
    #     preimage.extend(len(tran.scriptsigs[0]).to_bytes())
    #     preimage.extend(tran.scriptsigs[0])
    #     preimage.extend(tran.sequences[0])
    #     preimage.extend(tran.outputs)
    #     preimage.extend(tran.values[0])
    #     preimage.extend(len(tran.out_scriptpubkeys[0]).to_bytes())
    #     preimage.extend(tran.out_scriptpubkeys[0])
    # else
    segwit = False
    if not tran.coinbase and include_witness:
        for i in range(tran.inputs_n):
            segwit |= tran.type[i] ==  "v0_p2wpkh"

    if tran.coinbase or (segwit and include_witness):
        # preimage.extend(tran.data["marker"].to_bytes())
        # preimage.extend(tran.data["flag"].to_bytes())
        preimage.extend(b"\x00")
        preimage.extend(b"\x01")
    preimage.extend(tran.inputs)

    for i in range(tran.inputs_n):
        # preimage.extend(reverseBytes(tran.hashes[i]))
        preimage.extend(tran.hashes[i])
        preimage.extend(tran.out_idx[i])
        preimage.extend(int_to_compact(len(bytes.fromhex(tran.scriptsigs[i]))))
        preimage.extend(bytes.fromhex(tran.scriptsigs[i]))
        preimage.extend(tran.sequences[i])

    preimage.extend(tran.outputs)
    for i in range(tran.outputs_n):
        preimage.extend(tran.values[i])
        preimage.extend(int_to_compact(len(tran.out_scriptpubkeys[i])))
        preimage.extend(tran.out_scriptpubkeys[i])
    
    if tran.coinbase or (segwit and include_witness):
        for i in range(len(tran.data["vin"])):
            if "witness" in tran.data["vin"][i]:
                preimage.extend(int_to_compact(len(tran.data["vin"][i]["witness"])))
                for j in range(len(tran.data["vin"][i]["witness"])):
                    preimage.extend(int_to_compact(len(bytes.fromhex(tran.data["vin"][i]["witness"][j]))))
                    preimage.extend(bytes.fromhex(tran.data["vin"][i]["witness"][j]))

    preimage.extend(tran.locktime)
    # print(binascii.hexlify(preimage))
    return preimage


def get_message(tran):
    version = tran.version
    marker = b'\x00'
    flag = b'\x01'

    # inputs_n = len(data["vin"])
    # tran.inputs = bytearray([inputs_n])

    valid = True

    # START INPUT
    for vin in range(tran.inputs_n): 
        preimage = bytearray([])
        preimage.extend(version)
        if tran.type[vin] == "p2wpkh" or tran.type[vin] == "p2wsh" or tran.type[vin] == "v0_p2wpkh":
            txid_and_vouts = bytearray([])
            sequences = bytearray([])
            input_txid_and_vout = bytearray([])
            input_txid_and_vout.extend(tran.hashes[vin])
            input_txid_and_vout.extend(tran.out_idx[vin])

            # scriptcode = 1976a914{publickeyhash}88ac
            scriptcode = bytearray([])
            scriptcode.extend(b'\x19\x76\xa9\x14')
            scriptcode.extend(tran.in_scripts[vin][2:])
            scriptcode.extend(b'\x88\xac')

            amount = tran.input_amount[vin]
            sequence = tran.sequences[vin]
            outputs = bytearray([])
            locktime = b'\x00\x00\x00\x00'
            hashtype = b'\x01\x00\x00\x00'

            for i in range(tran.inputs_n):
                txid_and_vouts.extend(tran.hashes[i])
                txid_and_vouts.extend(tran.out_idx[i])
                # sequences.extend(doublesha256(tran.sequences[i]))
                sequences.extend(tran.sequences[i])
            sequences = doublesha256(sequences)

            for i in range(tran.outputs_n):
                outputs.extend(tran.values[i])
                outputs.extend(bytearray([len(tran.out_scriptpubkeys[i])]))
                outputs.extend(tran.out_scriptpubkeys[i])
            # preimage = version + hash256(inputs)
            #   + hash256(sequences) + input + scriptcode 
            #   + amount + sequence + hash256(outputs) + locktime
            # https://learnmeabitcoin.com/technical/keys/signature/
            
            preimage.extend(doublesha256(txid_and_vouts))
            preimage.extend(sequences)
            preimage.extend(input_txid_and_vout)
            preimage.extend(scriptcode)
            preimage.extend(amount)
            preimage.extend(sequence)
            preimage.extend(doublesha256(outputs))
            preimage.extend(locktime)
            preimage.extend(hashtype)


            # CHECK HASH

            # print("pubkey: ", tran.pubkey.hex())
            pubkeyhash = h160(s256(tran.pubkey[vin]))
            valid_pubkeyhash = tran.in_scripts[vin][2:]
            # valid &= valid_pubkeyhash.hex() == pubkeyhash.hex()

            if not valid:
                print("NOT VALID")

            # print("version: ", binascii.hexlify(version))
            # print("hash(inputs): ", binascii.hexlify(doublesha256(txid_and_vouts)))
            # print("inputs: ", binascii.hexlify(txid_and_vouts))
            # print("hash(sequences): ", binascii.hexlify(sequences))
            # print("input: ", binascii.hexlify(input_txid_and_vout))
            # print("scriptcode: ", binascii.hexlify(scriptcode))
            # print("amount: ", binascii.hexlify(amount))
            # print("sequence: ", binascii.hexlify(sequence))
            # print("outputs: ", binascii.hexlify(outputs))
            # print("hash(outputs): ", binascii.hexlify(doublesha256(outputs)))
            # print("locktime: ", binascii.hexlify(locktime))
            # print("hashtype: ", binascii.hexlify(hashtype))
            # print("preimage: ", binascii.hexlify(preimage))
        else:
            # p2pkh, p2sh
            preimage.extend(tran.inputs)
            # print("version: ", binascii.hexlify(version))
            if tran.type[vin] == "p2wpkh" or tran.type[vin] == "p2wsh":
                # print("marker: ", binascii.hexlify(marker))
                # print("flat: ", binascii.hexlify(flag))
                pass
            # print("inputs: ", binascii.hexlify(tran.inputs))

            for i in range(tran.inputs_n):
                # HASH OUT_TX SCRIPT_SIZE SCRIPT SEQUENCE
                preimage.extend(tran.hashes[i])
                preimage.extend(tran.out_idx[i])

                arr = bytearray([])
                if i == vin:
                    if tran.type[vin] == "p2sh":
                        # print("P2SH")
                        # print(binascii.hexlify(tran.pubkey[vin]), len(tran.pubkey[vin]))
                        arr.extend(int_to_compact(len(tran.pubkey[vin])))
                        arr.extend(tran.pubkey[vin])
                    else:
                        arr.extend(int_to_compact(len(tran.in_scripts[i])))
                        arr.extend(tran.in_scripts[i])
                else:
                    arr.extend(int(0).to_bytes())

                preimage.extend(arr)
                preimage.extend(tran.sequences[i])
                # print("  txid: ", binascii.hexlify(tran.hashes[i]))
                # print("  vout: ", binascii.hexlify(tran.out_idx[i]))
                if i == vin:
                    if tran.type[vin] == "p2sh":
                        # print("  scriptsigsize: ", binascii.hexlify(len(tran.pubkey[vin]).to_bytes()))
                        # print("  scriptsig: ", binascii.hexlify(tran.pubkey[vin]))
                        pass
                    else:
                        # print("  scriptsigsize: ", binascii.hexlify(len(tran.in_scripts[i]).to_bytes()))
                        # print("  scriptsig: ", binascii.hexlify(tran.in_scripts[i]))
                        pass
                else:
                    # print("  scriptsigsize: ", binascii.hexlify(len("").to_bytes()))
                    pass

                # print("  sequence: ", binascii.hexlify(tran.sequences[i]))
            # END INPUT


            preimage.extend(tran.outputs)

            # print("tran.outputs: ", tran.outputs)
            # START OUTPUTS
            for i in range(tran.outputs_n):
                # VALUE SCRIPT SIZE SCRIPT
                preimage.extend(tran.values[i])

                arr = bytearray([])
                arr.extend(tran.out_scriptpubkeys[i])

                preimage.extend(int_to_compact(len(arr)))
                preimage.extend(arr)
                # print("  amount: ", binascii.hexlify(tran.values[i]))
                # print("  scriptpubkeysize: ", binascii.hexlify(len(arr).to_bytes()))
                # print("  scriptpubkeysize: ", binascii.hexlify(tran.out_scriptpubkeys[i]))
            # END OUTPUT


            locktime = b'\x00\x00\x00\x00'
            hashtype = b'\x01\x00\x00\x00'
            witness = b'\x00'
            # print("locktime: ", locktime)
            # print("sighash: ", hashtype)
            preimage.extend(locktime)
            preimage.extend(hashtype)

            pubkeyhash = h160(s256(tran.pubkey[vin]))
            valid_pubkeyhash = tran.in_scripts[vin][3:3+20]

            valid &= valid_pubkeyhash.hex() == pubkeyhash.hex()
            if not valid:
                print("NOT VALID")

        # print("message: ", binascii.hexlify(preimage))
        message = s256(preimage)
        # print("message: ", binascii.hexlify(message))

        # if tran.type[vin] == "p2sh":
        #     if "witness" in tran.data["vin"][vin]:
        #         redeamscript = bytes.fromhex(tran.data["vin"][vin]["witness"][-1])
        #         a = h160(s256(redeamscript))
        #         scripthash = h160(s256(b'\x00\x14' + a))
        #         validscripthash = tran.in_scripts[vin][2:-1]
        #         # print("scripthash: ", binascii.hexlify(scripthash))
        #         # print("validscripthash: ", binascii.hexlify(validscripthash))
        #         if scripthash == validscripthash:
        #             pass
        #         else:
        #             valid = False
        #             continue

        # print("message: ", binascii.hexlify(message))

        # print("sig: ", binascii.hexlify(tran.sig[vin]))
        # print("pubkey: ", binascii.hexlify(tran.pubkey[vin]))
        # a = s256(tran.pubkey[vin])
        # pubkeyh = h160(a)
        # print("pubkeyhash: ", binascii.hexlify(pubkeyh))
        # print("==================  ===================")

        valid &= Transaction.verify_signature(tran.pubkey[vin], tran.sig[vin], message) 
        if not valid:
            return False
        # print(valid)


    # print("Valid all: ", valid)
    return valid
# print(binascii.hexlify(reverseBytes(bytes.fromhex("0d3edad1d8df2140536f0add480c7125b8d0df8f0327724e25a58fbe7a1e5b0dc344f34e11ab4fe6ec009769ba516da6bfc2f086b5"))))
# FILENAME = "mempool/0bca464849c31d4e2cbf4587a3a3163d94f1c3c513f90d8fc9710938214c0488.json"
# FILENAME = "/home/a/Documents/GitHub/code-challenge-2024-Jonny-exe/mempool/00d7c8ddc2e75f6ba97520623390f01a910dc66a9e6a2052ee31f1b99aabdea5.json"
# FILENAME = "mempool/0a5d6ddc87a9246297c1038d873eec419f04301197d67b9854fa2679dbe3bd65.json"
# FILENAME = "mempool/ff0b097b6baf9a4db7b5bfa8503a39613d1b5b5b1c58f5369a0249d9ff01de16.json"
# FILENAME = "mempool/0a3fd98f8b3d89d2080489d75029ebaed0c8c631d061c2e9e90957a40e99eb4c.json" # TWO OUTPUTS P2WPKH
# FILENAME = "mempool/0a4ce1145b6485c086f277aa185ba799234204f6caddb4228ee42b7cc7ad279a.json" # TWO OUTPUTS P2WPKH
FILENAME = "mempool/0aac26114009989817ba396fbfcdb0ab2f2a51a30df5d134d3294aacb27e8f69.json"
# FILENAME = "mempool/0c012ec325aa8af28ce01aef6b39d9e024f5aa6a026fd74fce6045f207758f8c.json"
# FILENAME = "/home/a/Documents/GitHub/code-challenge-2024-Jonny-exe/mempool/0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240.json"
# FILENAME = "test2.json"
FILENAME = "mempool/0c012ec325aa8af28ce01aef6b39d9e024f5aa6a026fd74fce6045f207758f8c.json"
data = open_file_as_json(FILENAME)
tran = Transaction(data)
# print(get_message(data, tran))



def test():
    rootdir = "mempool"
    idx = 0
    validcount = 0
    invalidcount = 0
    res = []
    for subdir, dirs, files in os.walk(rootdir):
        for file in files:
            ## print os.path.join(subdir, file)
            filepath = subdir + os.sep + file

            try:
                data = open_file_as_json(filepath)
                tran = Transaction(data)
                valid = get_message(tran)
            except:
                valid = False
            valdi = False

            if valid:
                
                res.append(file[:-5])      
                validcount += 1
                # print(str(validcount) + "\n", flush=True)
            else:
                invalidcount += 1
            # if validcount + invalidcount > 100:
            #     break
            if validcount > 100:
                # print(filepath)
                break
            if (validcount + invalidcount) % 100 == 0:
                # print((validcount + invalidcount))
                pass
    
    f = open("files.txt", "w")
    for i in res:
        f.write(i+"\n")
    f.close()
    return res


# test()