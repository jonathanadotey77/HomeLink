from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import socket
import struct

RSA_KEY_SIZE = 2048

keypair = None


e_Command = 255
e_Ack = 0
e_KeyRequest = 1
e_KeyResponse = 2


class PacketTypeException(Exception):
    pass


class CLIPacket:
    def __init__(self, rsaPublicKey, data):
        self.packetType = e_Command
        self.rsaPublicKey = rsaPublicKey
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "B512s256s",
            packet.packetType,
            packet.rsaPublicKey.encode("utf-8"),
            packet.data,
        )

    @staticmethod
    def deserialize(buffer):
        packetType, rsaPublicKey, data = struct.unpack("B512s256s", buffer)
        if packetType != e_Command:
            raise PacketTypeException()
        return CLIPacket(rsaPublicKey.decode("utf-8"), data.decode("utf-8"))


class AckPacket:
    def __init__(self, value: int):
        self.packetType = e_Ack
        self.value = value

    @staticmethod
    def serialize(packet):
        return struct.pack("!BI", packet.packetType, packet.value)

    @staticmethod
    def deserialize(buffer):
        packetType, value = struct.unpack("!BI", buffer)
        if packetType != e_Ack:
            raise PacketTypeException()
        return KeyResponsePacket(value)


class KeyRequestPacket:
    def __init__(self, connectionId: int, rsaPublicKey: str):
        self.packetType = e_KeyRequest
        self.connectionId = connectionId
        self.rsaPublicKey = rsaPublicKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI512s",
            packet.packetType,
            packet.connectionId,
            packet.rsaPublicKey.encode("utf-8"),
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, rsaPublicKey = struct.unpack("!BI512s", buffer)
        if packetType != e_KeyRequest:
            raise PacketTypeException()
        return KeyRequestPacket(connectionId, rsaPublicKey)


class KeyResponsePacket:
    def __init__(self, success: bool, rsaPublicKey: str, aesKey: bytearray):
        self.packetType = e_KeyResponse
        self.success = success
        self.rsaPublicKey = rsaPublicKey
        self.aesKey = aesKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "BB512s256s",
            packet.packetType,
            1 if packet.success else 0,
            packet.rsaPublicKey.encode("utf8"),
            packet.aesKey,
        )

    @staticmethod
    def deserialize(buffer):
        packetType, success, rsaPublicKey, aesKey = struct.unpack("BB512s256s", buffer)
        if packetType != e_KeyResponse:
            raise PacketTypeException()
        return KeyResponsePacket(success == 1, rsaPublicKey.decode("utf-8"), aesKey)


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

def main():

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass