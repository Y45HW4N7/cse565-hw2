#!/usr/bin/env python3

import hashlib

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class aesCBC:
    def cbcEnc(self, inputFile, encKeyFile):
        with open(inputFile, "rb") as f:
            data = f.read()

        data = pad(data, AES.block_size)
        key = get_random_bytes(16)

        with open(encKeyFile, "wb") as f:
            f.write(key)

        cipher = AES.new(key, AES.MODE_CBC)
        encData = cipher.encrypt(data)

        with open("dec.txt", "wb") as f:
            f.write(cipher.iv)
            f.write(encData)

    def cbcDec(self, outputFile, encKeyFile):
        with open(outputFile, "rb") as f:
            iv = f.read(16)
            e_data = f.read()

        with open(encKeyFile, "rb") as f:
            key = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(e_data)
        data = unpad(data, AES.block_size)

        with open(outputFile, "wb") as f:
            f.write(data)


class aesCTR:
    def ctrEnc(self, inputFile, encKeyFile):
        print("hello")

    def ctrDec(self, ouputFile, encKeyFile):
        print("from the other side")


class fileHash:
    def calcHash(self, inputfile):
        sha256_hash = hashlib.sha256(inputfile.encode("utf8")).hexdigest()
        sha512_hash = hashlib.sha512(inputfile.encode("utf8")).hexdigest()
        sha3256_hash = hashlib.sha3_256(inputfile.encode("utf8")).hexdigest()

        print("The SHA-256 Hash for the file " + inputfile + " is " + sha256_hash)
        print("The SHA-512 Hash for the file " + inputfile + " is " + sha512_hash)
        print("The SHA3-256 Hash for the file " + inputfile + " is " + sha3256_hash)


aesCBC().cbcEnc("1kb.txt", "key.enc")
aesCBC().cbcDec("dec.txt", "key.enc")
aesCBC().cbcEnc("10MB.txt", "key.enc")
aesCBC().cbcDec("dec.txt", "key.enc")

fileHash().calcHash("1kb.txt")
fileHash().calcHash("10MB.txt")
