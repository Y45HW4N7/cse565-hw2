#!/usr/bin/env python3

import hashlib
import os
import time

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

smallFile = os.path.getsize("1kb.txt")
largeFile = os.path.getsize("10MB.txt")


class aesCBC:
    def cbcEnc(self, inputFile, encKeyFile, outputFile):
        with open(inputFile, "rb") as f:
            data = f.read()

        data = pad(data, AES.block_size)

        keyGenStartTime = time.time()
        key = get_random_bytes(16)
        keyGenEndTime = time.time()
        totalKeyGenTime = keyGenEndTime - keyGenStartTime
        print("Time it takes to generate a 128 bit key is: ", totalKeyGenTime)

        with open(encKeyFile, "wb") as f:
            f.write(key)

        cipher = AES.new(key, AES.MODE_CBC)
        encData = cipher.encrypt(data)

        with open(outputFile, "wb") as f:
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


class fileHash:
    def calcHash(self, inputFile):

        sha256GenStartTime = time.time()
        sha256_hash = hashlib.sha256(inputFile.encode("utf8")).hexdigest()
        sha256GenEndTime = time.time()
        total256GenTime = sha256GenEndTime - sha256GenStartTime
        print(sha256GenStartTime)
        print(sha256GenEndTime)
        print("Time it takes to generate a SHA256 hash is : ", total256GenTime)

        sha512GenStartTime = time.time()
        sha512_hash = hashlib.sha512(inputFile.encode("utf8")).hexdigest()
        sha512GenEndTime = time.time()
        total512GenTime = sha512GenEndTime - sha512GenStartTime
        print("Time it takes to generate a SHA512 hash is : ", total512GenTime)

        sha3256GenStartTime = time.time()
        sha3256_hash = hashlib.sha3_256(inputFile.encode("utf8")).hexdigest()
        sha3256GenEndTime = time.time()
        total3256GenTime = sha3256GenEndTime - sha3256GenStartTime
        print(sha3256GenStartTime)
        print(sha3256GenEndTime)
        print("Time it takes to generate a SHA3-256 hash is : ", total3256GenTime)

        print("The SHA-256 Hash for the file " + inputFile + " is " + sha256_hash)
        print("The SHA-512 Hash for the file " + inputFile + " is " + sha512_hash)
        print("The SHA3-256 Hash for the file " + inputFile + " is " + sha3256_hash)


smallCBCEncStartTime = time.time()
aesCBC().cbcEnc("1kb.txt", "key.enc", "1kbdec.txt")
smallCBCEncEndTime = time.time()
totalSmallCBCEncTime = smallCBCEncEndTime - smallCBCEncStartTime
smallFileEncSpeed = smallFile / totalSmallCBCEncTime
print("Time it takes to encrypt a 1kb file using CBC is ", totalSmallCBCEncTime)
print("Encryption speed is ", smallFileEncSpeed)

smallCBCDecStartTime = time.time()
aesCBC().cbcDec("1kbdec.txt", "key.enc")
smallCBCDecEndTime = time.time()
totalSmallCBCDecTime = smallCBCDecEndTime - smallCBCDecStartTime
print("Time it takes to decrypt a 1kb file using CBC is ", totalSmallCBCDecTime)

bigCBCEncStartTime = time.time()
aesCBC().cbcEnc("10MB.txt", "key.enc", "10MBdec.txt")
bigCBCEncEndTime = time.time()
totalBigCBCEncTime = smallCBCEncEndTime - smallCBCEncStartTime
print("Time it takes to encrypt a 10MB file using CBC is ", totalBigCBCEncTime)

bigCBCDecStartTime = time.time()
aesCBC().cbcDec("10MBdec.txt", "key.enc")
bigCBCDecEndTime = time.time()
totalBigCBCDecTime = bigCBCDecEndTime - bigCBCDecStartTime
print("Time it takes to decrypt a 10MB file using CBC is ", totalBigCBCDecTime)

fileHash().calcHash("1kb.txt")
fileHash().calcHash("10MB.txt")
