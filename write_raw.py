from ecdsa.util import sigdecode_der
from ecdsa import VerifyingKey, BadSignatureError, MalformedPointError


import binascii
from hashlib import sha256
import hashlib
import ecdsa
import json
import base58
import os

from helpers import s256, h160, reverseBytes, open_file_as_json, int_to_compact


def doublesha256(input):
    return sha256(sha256(input).digest()).digest()

def hex_to_bytes(hex):
    return bytes.fromhex(hex)


class Transaction():
    def __init__(self, data):
        self.error = False
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
        if self.type[vin] == "p2pkh":
            scriptsig = self.scriptsigs[vin]
            siglen = int(scriptsig[:2], 16)
            sig = bytes.fromhex(scriptsig[2:2+siglen*2])

            pubkeylen = int(scriptsig[2+siglen*2:2+siglen*2+2], 16)
            pubkey = bytes.fromhex(scriptsig[2+siglen*2+2:2+siglen*2+2+pubkeylen*2])
        # elif self.type[vin] == "p2sh":
        else:
            try:
                sig = bytes.fromhex(self.data["vin"][vin]["witness"][0])
                pubkey = bytes.fromhex(self.data["vin"][vin]["witness"][1])
            except (IndexError,KeyError):
                self.error = True
                sig = bytes(0)
                pubkey = bytes(0)
        return sig, pubkey
    
    def verify_signature(pubkey, sig, message):
        try:
            vk = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)
        except MalformedPointError:
            return False


        try:
            valid = vk.verify(sig, message, sha256, sigdecode=sigdecode_der)
        except ecdsa.keys.BadSignatureError:
            sig = sig[:len(sig)-1]
            # print("Fixed signature")
            # print("sig: ", binascii.hexlify(sig))
            valid = vk.verify(sig, message, sha256, sigdecode=sigdecode_der) # True
        return valid

def get_raw_transaction(tran, include_witness=False):     
    """
    Given a transaction return the raw data
    """
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
            else:
                preimage.extend(bytes(1))

    preimage.extend(tran.locktime)
    # print(binascii.hexlify(preimage))
    return preimage


def is_tran_valid(tran):
    """
    Given a transaction check if it's valid
    """
    if tran.error:
        return False
    version = tran.version
    marker = b'\x00'
    flag = b'\x01'

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
            valid &= valid_pubkeyhash.hex() == pubkeyhash.hex()

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
            if tran.type[vin] == "p2wpkh" or tran.type[vin] == "p2wsh":
                pass

            for i in range(tran.inputs_n):
                # HASH OUT_TX SCRIPT_SIZE SCRIPT SEQUENCE
                preimage.extend(tran.hashes[i])
                preimage.extend(tran.out_idx[i])

                arr = bytearray([])
                if i == vin:
                    if tran.type[vin] == "p2sh":
                        arr.extend(int_to_compact(len(tran.pubkey[vin])))
                        arr.extend(tran.pubkey[vin])
                    else:
                        arr.extend(int_to_compact(len(tran.in_scripts[i])))
                        arr.extend(tran.in_scripts[i])
                else:
                    arr.extend(bytes(1))

                preimage.extend(arr)
                preimage.extend(tran.sequences[i])
                if i == vin:
                    if tran.type[vin] == "p2sh":
                        pass
                    else:
                        pass
                else:
                    pass

            # END INPUT


            preimage.extend(tran.outputs)

            for i in range(tran.outputs_n):
                # VALUE SCRIPT SIZE SCRIPT
                preimage.extend(tran.values[i])

                arr = bytearray([])
                arr.extend(tran.out_scriptpubkeys[i])

                preimage.extend(int_to_compact(len(arr)))
                preimage.extend(arr)
            # END OUTPUT


            locktime = b'\x00\x00\x00\x00'
            hashtype = b'\x01\x00\x00\x00'
            witness = b'\x00'
            preimage.extend(locktime)
            preimage.extend(hashtype)

            pubkeyhash = h160(s256(tran.pubkey[vin]))
            valid_pubkeyhash = tran.in_scripts[vin][3:3+20]

            valid &= valid_pubkeyhash.hex() == pubkeyhash.hex()

        message = s256(preimage)

        valid &= Transaction.verify_signature(tran.pubkey[vin], tran.sig[vin], message) 
        if not valid:
            return False


    return valid

FILENAME = "mempool/0aac26114009989817ba396fbfcdb0ab2f2a51a30df5d134d3294aacb27e8f69.json"
FILENAME = "mempool/0c012ec325aa8af28ce01aef6b39d9e024f5aa6a026fd74fce6045f207758f8c.json"
data = open_file_as_json(FILENAME)
tran = Transaction(data)



def test():
    """
    Test the program, take all the transactions and check which ones are valid
    """
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
                # segwit = False
                # for i in range(tran.inputs_n):
                #     segwit |= tran.type[i] ==  "v0_p2wpkh"
                # if not segwit:
                #     continue
                same = True
                past = ""
                for i in tran.type:
                    same &= i == past or past == ""
                    past = i

                # if not same:
                #     continue
                if tran.inputs_n > 10:
                    continue
                valid = is_tran_valid(tran)
            except BadSignatureError:
                valid = False

            if valid:
                res.append(file[:-5])      
                validcount += 1
                # print(str(validcount) + "\n", flush=True)
            else:
                invalidcount += 1
            # if validcount + invalidcount > 100:
            #     break
            if validcount > 10000:
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

