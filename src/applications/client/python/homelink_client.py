from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import ipaddress
import os
import random
import socket
import struct

RSA_KEY_SIZE = 2048

keypair = None

e_LoginFailed = 0
e_LoginSuccess = 1
e_NoAvailablePort = 2
e_NoSuchUser = 3
e_UserAlreadyExists = 4

e_CLI = 255
e_Ack = 0
e_KeyRequest = 1
e_KeyResponse = 2
e_Handshake = 3
e_Command = 4
e_LoginRequest = 5
e_LoginResponse = 6
e_RegisterRequest = 7
e_RegisterResponse = 8


class PacketTypeException(Exception):
    pass

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

class CommandPacket:
    def __init__(self, sessionToken: bytearray, data: bytearray):
        self.packetType = e_Command
        self.sessionToken = sessionToken
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!B256s256s",
            packet.packetType,
            packet.sessionToken,
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, sessionToken, data = struct.unpack("!B256s256s", buffer)
        if packetType != e_KeyRequest:
            raise PacketTypeException()
        return CommandPacket(sessionToken, data)

class LoginRequestPacket:
    def __init__(self, connectionId: int, username: str, data: bytearray):
        self.packetType = e_LoginRequest
        self.connectionId = connectionId
        self.username = username
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI33s256s",
            packet.packetType,
            packet.connectionId,
            packet.username.encode("UTF-8"),
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, username, data = struct.unpack("!BI33s256s", buffer)
        if packetType != e_LoginRequest:
            raise PacketTypeException()
        return LoginRequestPacket(connectionId, username, data)

class LoginResponsePacket:
    def __init__(self, status: bool, sessionKey: bytearray):
        self.packetType = e_LoginResponse
        self.status = status
        self.sessionKey = sessionKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BB256s",
            packet.packetType,
            packet.status,
            packet.sessionKey
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, status, sessionKey = struct.unpack("!BB256s", buffer)
        if packetType != e_LoginResponse:
            raise PacketTypeException()
        return LoginResponsePacket(status, sessionKey)

class RegisterRequestPacket:
    def __init__(self, connectionId: int, username: str, sessionKey: bytearray):
        self.packetType = e_RegisterRequest
        self.connectionId = connectionId
        self.username = username
        self.sessionKey = sessionKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI33s256s",
            packet.packetType,
            packet.connectionId,
            packet.username.encode("UTF-8"),
            packet.sessionKey
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, username, sessionKey = struct.unpack("!BI33s256s", buffer)
        if packetType != e_RegisterRequest:
            raise PacketTypeException()
        return RegisterRequestPacket(connectionId, username, sessionKey)


class RegisterResponsePacket:
    def __init__(self, status: bool):
        self.packetType = e_RegisterResponse
        self.status = status

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BB",
            packet.packetType,
            packet.status
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, status = struct.unpack("!BB", buffer)
        if packetType != e_RegisterResponse:
            raise PacketTypeException()
        return RegisterResponsePacket(status)

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


def rsaDecrypt(data, key):
    cipher = PKCS1_OAEP.new(keypair if key == None else key)

    return cipher.decrypt(data)

def hashString(string: str):
    hash_object = SHA256.new(data=string.encode())
    sha256_hash = hash_object.hexdigest()
    
    return sha256_hash

class HomeLinkClient:
    def __init__(self):
        self.controlSocket = None
        self.dataSocket = None
        self.serverAddress = [None, None]
        self.controlAddress = [None, None]
        self.dataAddress = [None, None]
        self.serverPort = None
        self.serverPublicKey = None
        self.clientPublicKey = None
        self.hostId = None
        self.serviceId = None
        self.connectionId = None
        
    def initialize(self, serviceId):
        self.serviceId = serviceId
        configFilePath = os.environ["HOMELINK_CONFIG_PATH"]
        with open(configFilePath, "r") as configFile:
            for line in configFile:
                key, value = line.split()
                if key == "host_id":
                    self.host_id = value
                elif key == "server_port":
                    self.serverAddress[1] = int(value)
                elif key == "server_address":
                    self.serverAddress[0] = str(ipaddress.IPv6Address(f"::ffff:{value}"))

        self.serverAddress = tuple(self.serverAddress)
        self.controlSocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.dataSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.controlAddress = ("::0.0.0.0", 13000)
        self.dataAddress = ("::0.0.0.0", 13001)
        self.controlSocket.bind(self.controlAddress)
        self.dataSocket.bind(self.dataAddress)
        self.controlSocket.settimeout(3)
        self.dataSocket.settimeout(3)
        self.controlSocket.connect(tuple(self.serverAddress))
        self.clientPublicKey = getRSAPublicKey()
    
    def shutdown(self):
        self.controlSocket.close()
        self.dataSocket.close()
    
    def login(self, password: str):
        connectionId = 0
        while True:
            connectionId = random.randint(0,4294967295)
            keyRequestPacket = KeyRequestPacket(connectionId, self.clientPublicKey)
            data = KeyRequestPacket.serialize(keyRequestPacket)
            self.controlSocket.sendto(data, self.serverAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue
            
            keyResponsePacket = KeyResponsePacket.deserialize(data)
            self.serverPublicKey = keyResponsePacket.rsaPublicKey.rstrip('\x00')
            if keyResponsePacket.success == 0:
                continue
            else:
                break
        
        while True:
            passwordData = struct.pack("32s65s7s24s", randomBytes(32), hashString(password).encode("UTF-8"), bytes([0] * 8), randomBytes(24))
            registerRequestPacket = RegisterRequestPacket(connectionId, f"{self.host_id}__{self.serviceId}", rsaEncrypt(passwordData, self.serverPublicKey))
            data = RegisterRequestPacket.serialize(registerRequestPacket)
            self.controlSocket.sendto(data, self.serverAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue
            
            registerResponsePacket = RegisterResponsePacket.deserialize(data)
            if registerResponsePacket.status == e_UserAlreadyExists or registerResponsePacket.status == e_LoginSuccess:
                break
            else:
                return None
        
        while True:
            tag = random.randint(0,4294967295)
            passwordData = struct.pack("!I28s65s7s24s", tag, randomBytes(28), hashString(password).encode("UTF-8"), bytes([0] * 8), randomBytes(24))
            loginRequestPacket = LoginRequestPacket(connectionId, f"{self.host_id}__{self.serviceId}", rsaEncrypt(passwordData, self.serverPublicKey))
            data = LoginRequestPacket.serialize(loginRequestPacket)
            self.controlSocket.sendto(data, self.serverAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue
            
            loginResponsePacket = LoginResponsePacket.deserialize(data)
            if loginResponsePacket.status == e_LoginSuccess:
                break
            else:
                return None
        
        self.connectionId = connectionId
        return connectionId

def main():
    initializeSecurity()
    homeLinkClient = HomeLinkClient()
    homeLinkClient.initialize("ERIC")
    homeLinkClient.login("password7")
    homeLinkClient.shutdown()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass