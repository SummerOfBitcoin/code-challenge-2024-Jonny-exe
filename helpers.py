import hashlib
from hashlib import sha256
import json

def s256(b):
    return sha256(b).digest()

def h160(b):
    scripthash = hashlib.new('ripemd160')
    scripthash.update(b)
    return scripthash.digest()

def reverseBytes(b):
    a = bytearray()
    for i in range(len(b)):
        a.extend(b[len(b)-i-1].to_bytes(length=1, byteorder="little"))
    return a

def open_file_as_json(filename):
    f = open(filename, "r")
    txt = f.read()
    return json.loads(txt)

def int_to_compact(i):
    res = None
    l= 1
    while 1:
        try:
            res = i.to_bytes(byteorder="little", length=l)
            if l == 2:
                res = "\xFD" + res
            elif l == 3:
                res = "\xFE" + res
            elif l == 4:
                res = "\xFF" + res
            break
        except:
            pass
        l += 1
    return res
            