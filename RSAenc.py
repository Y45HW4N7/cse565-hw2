#!/usr/bin/env python3

import os
import time

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

smallFile = os.path.getsize("1kb.txt")
largeFile = os.path.getsize("1MB.txt")


def genkey(passphrase, rsaKeyLen):
    code = passphrase
    key = RSA.generate(rsaKeyLen)
    privateKey = key.exportKey(
        passphrase=code, pkcs=8, protection="scryptAndAES128-CBC"
    )
    publicKey = key.publickey().exportKey()

    return privateKey, publicKey


def writekeystofile(privateKey, publicKey, priv_fname, pub_fname):
    with open(priv_fname, "wb") as f:
        f.write(privateKey)
    with open(pub_fname, "wb") as f:
        f.write(publicKey)


def encrypt(inputFile, encFile, publicKey):

    with open(encFile, "wb") as out_file:
        recipient_key = RSA.import_key(open(publicKey).read())
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))

        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        with open(inputFile, "rb") as fi:
            data = fi.read()

        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)


def decrypt(passphrase, encFile, privateKey):

    with open(encFile, "rb") as fobj:
        privateKey = RSA.import_key(open(privateKey).read(), passphrase=passphrase)

        enc_session_key, nonce, tag, ciphertext = [
            fobj.read(x) for x in (privateKey.size_in_bytes(), 16, 16, -1)
        ]

        cipher_rsa = PKCS1_OAEP.new(privateKey)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data


def rsa2048key():
    password = "cse565hw2"
    privkey_name = "privateRSAkey.bin"
    pubkey_name = "publicRSAkey.pem"

    print("\n********** RSA-2048 Key Gen **********")
    rsa2048KeyStartTime = time.time_ns()
    priv, pub = genkey(password, 2048)
    rsa2048KeyEndTime = time.time_ns()
    totalRSA2048KeyTime = rsa2048KeyEndTime - rsa2048KeyStartTime
    print("Time it takes to generate RSA-2048 key is", totalRSA2048KeyTime)
    writekeystofile(priv, pub, privkey_name, pubkey_name)

    print("\n********** RSA-2048 Encryption of Small File **********")
    rsa2048EncSmallStartTime = time.time_ns()
    encrypt("1kb.txt", "encryptedData.bin", pubkey_name)
    rsa2048EncSmallEndTime = time.time_ns()
    totalRSA2048EncSmallTime = rsa2048EncSmallEndTime - rsa2048EncSmallStartTime
    rsa2048SmallEncSpeed = smallFile / totalRSA2048EncSmallTime
    print(
        "Time it takes to encrypt small file with RSA-2048 key is",
        totalRSA2048EncSmallTime,
    )
    print(
        "The encryption speed  of small file with RSA-2048 key is ",
        rsa2048SmallEncSpeed,
    )

    print("\n********** RSA-2048 Decryption of Small File **********")
    rsa2048DecSmallStartTime = time.time_ns()
    data = decrypt(password, "encryptedData.bin", privkey_name)
    rsa2048DecSmallEndTime = time.time_ns()
    totalRSA2048DecSmallTime = rsa2048DecSmallEndTime - rsa2048DecSmallStartTime
    rsa2048SmallDecSpeed = smallFile / totalRSA2048DecSmallTime
    print(
        "Time it takes to decrypt small file with RSA-2048 key is",
        totalRSA2048DecSmallTime,
    )
    print(
        "The decryption speed  of small file with RSA-2048 key is ",
        rsa2048SmallDecSpeed,
    )
    with open("1kbRSA2dec.txt", "wb") as f:
        f.write(data)

    print("\n********** RSA-2048 Encryption of Large File **********")
    rsa2048EncLargeStartTime = time.time_ns()
    encrypt("1MB.txt", "encryptedData.bin", pubkey_name)
    rsa2048EncLargeEndTime = time.time_ns()
    totalRSA2048EncLargeTime = rsa2048EncLargeEndTime - rsa2048EncLargeStartTime
    rsa2048LargeEncSpeed = largeFile / totalRSA2048EncLargeTime
    print(
        "Time it takes to encrypt large file with RSA-2048 key is",
        totalRSA2048EncLargeTime,
    )
    print(
        "The encryption speed  of large file with RSA-2048 key is ",
        rsa2048LargeEncSpeed,
    )

    print("\n********** RSA-2048 Decryption of Large File **********")
    rsa2048DecLargeStartTime = time.time_ns()
    data = decrypt(password, "encryptedData.bin", privkey_name)
    rsa2048DecLargeEndTime = time.time_ns()
    totalRSA2048DecLargeTime = rsa2048DecLargeEndTime - rsa2048DecLargeStartTime
    rsa2048LargeDecSpeed = largeFile / totalRSA2048DecLargeTime
    print(
        "Time it takes to decrypt small file with RSA-2048 key is",
        totalRSA2048DecLargeTime,
    )
    print(
        "The decryption speed  of large file with RSA-2048 key is",
        rsa2048LargeDecSpeed,
    )
    with open("1MBRSA2dec.txt", "wb") as f:
        f.write(data)


def rsa3072key():
    password = "cse565hw2"
    privkey_name = "privateRSAkey.bin"
    pubkey_name = "publicRSAkey.pem"

    print("\n********** RSA-3072 Key Gen **********")
    rsa3072KeyStartTime = time.time_ns()
    priv, pub = genkey(password, 3072)
    rsa3072KeyEndTime = time.time_ns()
    totalRSA3072KeyTime = rsa3072KeyEndTime - rsa3072KeyStartTime
    print("Time it takes to generate RSA-3072 key is", totalRSA3072KeyTime)
    writekeystofile(priv, pub, privkey_name, pubkey_name)

    print("\n********** RSA-3072 Encryption of Small File **********")
    rsa3072EncSmallStartTime = time.time_ns()
    encrypt("1kb.txt", "encryptedData.bin", pubkey_name)
    rsa3072EncSmallEndTime = time.time_ns()
    totalRSA3072EncSmallTime = rsa3072EncSmallEndTime - rsa3072EncSmallStartTime
    rsa3072SmallEncSpeed = smallFile / totalRSA3072EncSmallTime
    print(
        "Time it takes to encrypt small file with RSA-3072 key is",
        totalRSA3072EncSmallTime,
    )
    print(
        "The encryption speed  of small file with RSA-3072 key is ",
        rsa3072SmallEncSpeed,
    )

    print("\n********** RSA-3072 Decryption of Small File **********")
    rsa3072DecSmallStartTime = time.time_ns()
    data = decrypt(password, "encryptedData.bin", privkey_name)
    rsa3072DecSmallEndTime = time.time_ns()
    totalRSA3072DecSmallTime = rsa3072DecSmallEndTime - rsa3072DecSmallStartTime
    rsa3072SmallDecSpeed = smallFile / totalRSA3072DecSmallTime
    print(
        "Time it takes to decrypt small file with RSA-3072 key is",
        totalRSA3072DecSmallTime,
    )
    print(
        "The decryption speed  of small file with RSA-3072 key is ",
        rsa3072SmallDecSpeed,
    )
    with open("1kbRSA3dec.txt", "wb") as f:
        f.write(data)

    print("\n********** RSA-3072 Encryption of Large File **********")
    rsa3072EncLargeStartTime = time.time_ns()
    encrypt("1MB.txt", "encryptedData.bin", pubkey_name)
    rsa3072EncLargeEndTime = time.time_ns()
    totalRSA3072EncLargeTime = rsa3072EncLargeEndTime - rsa3072EncLargeStartTime
    rsa3072LargeEncSpeed = largeFile / totalRSA3072EncLargeTime
    print(
        "Time it takes to encrypt small file with RSA-3072 key is",
        totalRSA3072EncLargeTime,
    )
    print(
        "The encryption speed  of large file with RSA-3072 key is ",
        rsa3072LargeEncSpeed,
    )

    print("\n********** RSA-3072 Decryption of Large File **********")
    rsa3072DecLargeStartTime = time.time_ns()
    data = decrypt(password, "encryptedData.bin", privkey_name)
    rsa3072DecLargeEndTime = time.time_ns()
    totalRSA3072DecLargeTime = rsa3072DecLargeEndTime - rsa3072DecLargeStartTime
    rsa3072LargeDecSpeed = largeFile / totalRSA3072DecLargeTime
    print(
        "Time it takes to decrypt small file with RSA-3072 key is",
        totalRSA3072DecLargeTime,
    )
    print(
        "The decryption speed  of large file with RSA-3072 key is",
        rsa3072LargeDecSpeed,
    )
    with open("1MBRSA3dec.txt", "wb") as f:
        f.write(data)


rsa2048key()
rsa3072key()
