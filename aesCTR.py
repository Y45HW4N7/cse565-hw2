#!/usr/bin/env python3

import datetime
import os
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

smallFile = os.path.getsize("1kb.txt")
largeFile = os.path.getsize("10MB.txt")


def ctrEnc(inputFile, keySize, encKeyFile, outputFile):
    with open(inputFile, "rb") as f:
        data = f.read()

    keyGenStartTime = datetime.datetime.now()
    key = get_random_bytes(keySize)
    keyGenEndTime = datetime.datetime.now()
    totalKeyGenTime = keyGenEndTime - keyGenStartTime
    print("Time it takes to generate a 128 bit key is: ", totalKeyGenTime)

    with open(encKeyFile, "wb") as f:
        f.write(key)

    cipher = AES.new(key, AES.MODE_CTR)
    encData = cipher.encrypt(data)

    with open(outputFile, "wb") as f:
        f.write(encData)

    with open("nonceFile", "wb") as f:
        f.write(cipher.nonce)


def ctrDec(outputFile, encKeyFile):
    with open("nonceFile", "rb") as f:
        nonce = f.read()

    with open(outputFile, "rb") as f:
        e_data = f.read()

    with open(encKeyFile, "rb") as f:
        key = f.read()

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    data = cipher.decrypt(e_data)

    with open(outputFile, "wb") as f:
        f.write(data)


print("\n********** Small file AES-CTR encryption w/128-bit key **********")
small128CTREncStartTime = time.time_ns()
ctrEnc("1kb.txt", 16, "key.enc", "1kbCTR128dec.txt")
small128CTREncEndTime = time.time_ns()
totalSmall128CTREncTime = small128CTREncEndTime - small128CTREncStartTime
smallFile128EncSpeed = smallFile / totalSmall128CTREncTime
print("Time it takes to decrypt a 1kb fisle using CTR is", totalSmall128CTREncTime)
print("The encryption speed  of small file is", smallFile128EncSpeed)


print("\n********** Small file AES-CTR decryption w/128-bit key **********")
small128CTRDecStartTime = time.time_ns()
ctrDec("1kbCTR128dec.txt", "key.enc")
small128CTRDecEndTime = time.time_ns()
totalSmall128CTRDecTime = small128CTRDecEndTime - small128CTRDecStartTime
smallFile128DecSpeed = smallFile / totalSmall128CTRDecTime
print("Time it takes to decrypt a 1kb file using CTR is", totalSmall128CTRDecTime)
print("The decryption speed  of small file is", smallFile128DecSpeed)


print("\n********** Large file AES-CTR encryption w/128-bit key **********")
large128CTREncStartTime = time.time_ns()
ctrEnc("10MB.txt", 32, "key.enc", "10MBCTR128dec.txt")
large128CTREncEndTime = time.time_ns()
totalLarge128CTREncTime = large128CTREncEndTime - large128CTREncStartTime
largeFile128EncSpeed = largeFile / totalSmall128CTREncTime
print("Time it takes to decrypt a 1kb file using CTR is", totalLarge128CTREncTime)
print("The encryption speed  of large file is", largeFile128EncSpeed)


print("\n********** Large file AES-CTR decryption w/128-bit key **********")
large128CTRDecStartTime = time.time_ns()
ctrDec("10MBCTR128dec.txt", "key.enc")
large128CTRDecEndTime = time.time_ns()
totalLarge128CTRDecTime = large128CTRDecEndTime - large128CTRDecStartTime
largeFile128DecSpeed = largeFile / totalLarge128CTRDecTime
print("Time it takes to decrypt a 10MB file using CTR is", totalLarge128CTRDecTime)
print("The decryption speed  of large file is", largeFile128DecSpeed)


print("\n********** Small file AES-CTR encryption w/256-bit key **********")
smallCTREncStartTime = time.time_ns()
ctrEnc("1kb.txt", 32, "key.enc", "1kbCTR256dec.txt")
smallCTREncEndTime = time.time_ns()
totalSmallCTREncTime = smallCTREncEndTime - smallCTREncStartTime
smallFileEncSpeed = smallFile / totalSmallCTREncTime
print("Time it takes to decrypt a 1kb file using CTR is", totalSmallCTREncTime)
print("The encryption speed  of small file is", smallFileEncSpeed)


print("\n********** Small file AES-CTR decryption w/256-bit key **********")
smallCTRDecStartTime = time.time_ns()
ctrDec("1kbCTR256dec.txt", "key.enc")
smallCTRDecEndTime = time.time_ns()
totalSmallCTRDecTime = smallCTRDecEndTime - smallCTRDecStartTime
smallFileDecSpeed = smallFile / totalSmallCTRDecTime
print("Time it takes to decrypt a 1kb file using CTR is", totalSmallCTRDecTime)
print("The decryption speed  of large file is", smallFileDecSpeed)


print("\n********** Large file AES-CTR encryption w/256-bit key **********")
largeCTREncStartTime = time.time_ns()
ctrEnc("10MB.txt", 32, "key.enc", "10MBCTR256dec.txt")
largeCTREncEndTime = time.time_ns()
totalLargeCTREncTime = largeCTREncEndTime - largeCTREncStartTime
largeFileEncSpeed = largeFile / totalLargeCTREncTime
print("Time it takes to decrypt a 10MB file using CTR is", totalLargeCTREncTime)
print("The encryption speed  of small file is", largeFileEncSpeed)


print("\n********** Large file AES-CTR decryption w/256-bit key **********")
largeCTRDecStartTime = time.time_ns()
largeCTRDecEndTime = time.time_ns()
totalLargeCTRDecTime = largeCTRDecEndTime - largeCTRDecStartTime
largeFileDecSpeed = largeFile / totalLargeCTRDecTime
print("Time it takes to decrypt a 10MB file using CTR is", totalLargeCTRDecTime)
print("The decryption speed  of large file is", largeFileDecSpeed)
