from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import socket

RSA_KEY_SIZE = 2048

keypair = None

def randomBytes(n: int):
    return Random.get_random_bytes(n)

def initializeSecurity():
    global keypair
    keypair = RSA.generate(RSA_KEY_SIZE)

def getRSAPublicKey():
    return keypair.publickey().exportKey("PEM").decode("utf-8")

def printRSAPublicKey():
    print(getRSAPublicKey())

def rsaEncrypt(data, key):
    pubkey = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(pubkey)

    return cipher.encrypt(data)

def rsaDecrypt(data):
    cipher = PKCS1_OAEP.new(keypair)

    return cipher.decrypt(data)
