#!/usr/bin/env python3

import os
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

smallFile = os.path.getsize("1kb.txt")
largeFile = os.path.getsize("10MB.txt")


def cbcEnc(inputFile, encKeyFile, outputFile):
    with open(inputFile, "rb") as f:
        data = f.read()

    data = pad(data, AES.block_size)

    keyGenStartTime = time.time_ns()

    key = get_random_bytes(16)

    keyGenEndTime = time.time_ns()
    totalKeyGenTime = keyGenEndTime - keyGenStartTime
    print("Time it takes to generate a 128 bit key is: ", totalKeyGenTime)

    with open(encKeyFile, "wb") as f:
        f.write(key)

    cipher = AES.new(key, AES.MODE_CBC)
    encData = cipher.encrypt(data)

    with open(outputFile, "wb") as f:
        f.write(cipher.iv)
        f.write(encData)


def cbcDec(outputFile, encKeyFile):
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


print("\n********** Small file AES-CBC encryption **********")
smallCBCEncStartTime = time.time_ns()
cbcEnc("1kb.txt", "key.enc", "1kbCBCdec.txt")
smallCBCEncEndTime = time.time_ns()
totalSmallCBCEncTime = smallCBCEncEndTime - smallCBCEncStartTime
smallFileEncSpeed = smallFile / totalSmallCBCEncTime
print("Time it takes to encrypt a 1kb file using CBC is", totalSmallCBCEncTime)
print("The encryption speed of small file is", smallFileEncSpeed)

print("\n********** Small file AES-CBC decryption **********")
smallCBCDecStartTime = time.time_ns()
cbcDec("1kbCBCdec.txt", "key.enc")
smallCBCDecEndTime = time.time_ns()
totalSmallCBCDecTime = smallCBCDecEndTime - smallCBCDecStartTime
smallFileDecSpeed = smallFile / totalSmallCBCDecTime
print("Time it takes to decrypt a 1kb file using CBC is", totalSmallCBCDecTime)
print("The decryption speed of small file is", smallFileDecSpeed)

print("\n********** Large file AES-CBC encryption **********")
largeCBCEncStartTime = time.time_ns()
cbcEnc("10MB.txt", "key.enc", "10MBCBCdec.txt")
largeCBCEncEndTime = time.time_ns()
totalLargeCBCEncTime = largeCBCEncEndTime - largeCBCEncStartTime
largeFileEncSpeed = largeFile / totalLargeCBCEncTime
print("Time it takes to encrypt a 10MB file using CBC is", totalLargeCBCEncTime)
print("The encryption speed of large file is", largeFileEncSpeed)

print("\n********** Large file AES-CBC decryption **********")
largeCBCDecStartTime = time.time_ns()
cbcDec("10MBCBCdec.txt", "key.enc")
largeCBCDecEndTime = time.time_ns()
totalLargeCBCDecTime = largeCBCDecEndTime - largeCBCDecStartTime
largeFileDecSpeed = largeFile / totalLargeCBCDecTime
print("Time it takes to decrypt a 10MB file using CBC is", totalLargeCBCDecTime)
print("The decryption speed  of large file is", largeFileDecSpeed)
