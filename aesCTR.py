import datetime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


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


ctrEnc("1kb.txt", 16, "key.enc", "1kbdec.txt")
ctrDec("1kbdec.txt", "key.enc")
ctrEnc("1kb.txt", 32, "key.enc", "1kbdec.txt")
ctrDec("1kbdec.txt", "key.enc")

ctrEnc("10MB.txt", 16, "key.enc", "10MBdec.txt")
ctrDec("10MBdec.txt", "key.enc")
ctrEnc("10MB.txt", 32, "key.enc", "10MBdec.txt")
ctrDec("10MBdec.txt", "key.enc")