#!/usr/bin/env python3

import os
import time

from Crypto.Hash import SHA3_256, SHA256, SHA512
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

smallFile = os.path.getsize("1kb.txt")
largeFile = os.path.getsize("10MB.txt")


def calcHash(inputFile):
    with open(inputFile, "rb") as f:
        data256 = f.read()

    sha256GenStartTime = time.time_ns()
    sha256_hash = SHA256.new(data256)
    sha256GenEndTime = time.time_ns()
    total256GenTime = sha256GenEndTime - sha256GenStartTime
    sha256PerByteTime = total256GenTime / smallFile
    print("\n********** SHA-256 Hash **********")
    print(
        "The SHA-256 Hash for the file " + inputFile + " is " + sha256_hash.hexdigest()
    )
    print("Time it takes to generate a SHA256 hash is : ", total256GenTime)
    print("Per-byte time for SHA256 is :", sha256PerByteTime)

    with open(inputFile, "rb") as f:
        data512 = f.read()

    sha512GenStartTime = time.time_ns()
    sha512_hash = SHA512.new(data512)
    sha512GenEndTime = time.time_ns()
    total512GenTime = sha512GenEndTime - sha512GenStartTime
    sha512PerByteTime = total512GenTime / smallFile
    print("\n********** SHA-512 Hash **********")
    print(
        "The SHA-512 Hash for the file " + inputFile + " is " + sha512_hash.hexdigest()
    )
    print("Time it takes to generate a SHA512 hash is : ", total512GenTime)
    print("Per-byte time for SHA512 is :", sha512PerByteTime)

    with open(inputFile, "rb") as f:
        data3256 = f.read()

    sha3256GenStartTime = time.time_ns()
    sha3256_hash = SHA3_256.new(data3256)
    sha3256GenEndTime = time.time_ns()
    total3256GenTime = sha3256GenEndTime - sha3256GenStartTime
    sha3256PerByteTime = total3256GenTime / smallFile
    print("\n********** SHA3-256 Hash **********")
    print(
        "The SHA3-256 Hash for the file "
        + inputFile
        + " is "
        + sha3256_hash.hexdigest()
    )
    print("Time it takes to generate a SHA3-256 hash is : ", total3256GenTime)
    print("Per-byte time for SHA3256 is :", sha3256PerByteTime)

    return sha256_hash


def signFiles(dsaKeyLen, inputFile, sha256_hash):
    privateKey = DSA.generate(dsaKeyLen)
    publicKey = privateKey.public_key()

    signer = DSS.new(privateKey, "fips-186-3")
    signature = signer.sign(sha256_hash)

    return publicKey, signature


def verifySignatures(publicKey, sha256_hash, signature):
    verifier = DSS.new(publicKey, "fips-186-3")
    try:
        verifier.verify(sha256_hash, signature)
        print("verification successful")
    except ValueError:
        print("verificaiton failed")


oneKBhash = calcHash("1kb.txt")
calcHash("10MB.txt")


publicVar, signature = signFiles(2048, "1kb.txt", oneKBhash)

print("\n********** Small file DSA Signature **********")
smallDSASignStartTime = time.time_ns()
signFiles(2048, "1kb.txt", oneKBhash)
smallDSASignEndTime = time.time_ns()
totalSmallDSASignTime = smallDSASignEndTime - smallDSASignStartTime
smallFileSignSpeed = smallFile / totalSmallDSASignTime
print("Time it takes to sign a 1kb file using 2048-DSA is", totalSmallDSASignTime)
print("The encryption speed of signing per byte of small file is", smallFileSignSpeed)

print("\n********** Small file DSA Verification **********")
smallDSAVerifyStartTime = time.time_ns()
verifySignatures(publicVar, oneKBhash, signature)
smallDSAVerifyEndTime = time.time_ns()
totalSmallDSAVerifyTime = smallDSAVerifyEndTime - smallDSAVerifyStartTime
smallFileVerifySpeed = smallFile / totalSmallDSAVerifyTime
print("Time it takes to verify a 1kb file using 2048-DSA is", totalSmallDSAVerifyTime)
print(
    "The encryption speed of verifying per byte of small file is", smallFileVerifySpeed
)

print("\n********** Large file DSA Signature **********")
largeDSASignStartTime = time.time_ns()
signFiles(2048, "10MB.txt", oneKBhash)
largeDSASignEndTime = time.time_ns()
totalLargeDSASignTime = largeDSASignEndTime - largeDSASignStartTime
largeFileSignSpeed = largeFile / totalLargeDSASignTime
print("Time it takes to sign a 10MB file using 2048-DSA is", totalLargeDSASignTime)
print("The encryption speed of signing per byte of large file is", largeFileSignSpeed)

print("\n********** Large file DSA Verification **********")
largeDSAVerifyStartTime = time.time_ns()
verifySignatures(publicVar, oneKBhash, signature)
largeDSAVerifyEndTime = time.time_ns()
totalLargeDSAVerifyTime = largeDSAVerifyEndTime - largeDSAVerifyStartTime
largeFileVerifySpeed = largeFile / totalLargeDSAVerifyTime
print("Time it takes to verify a 10MB file using 2048-DSA is", totalLargeDSAVerifyTime)
print(
    "The encryption speed of verifying per byte of large file is", largeFileVerifySpeed
)
