from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import ipaddress
import os
import random
import socket
import struct
import sys

RSA_KEY_SIZE = 2048

FILE_BLOCK_SIZE = 8192

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
e_Logout = 9

e_Empty = 0
e_Available = 1
e_NoPort = 2


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
    def __init__(self, connectionId: int, sessionToken: bytearray, data: bytearray):
        self.packetType = e_Command
        self.connectionId = connectionId
        self.sessionToken = sessionToken
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI256s256s",
            packet.packetType,
            packet.connectionId,
            packet.sessionToken,
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, sessionToken, data = struct.unpack("!BI256s256s", buffer)
        if packetType != e_Command:
            raise PacketTypeException()
        return CommandPacket(connectionId, sessionToken, data)

class LoginRequestPacket:
    def __init__(self, connectionId: int, hostId: str, serviceId: str, data: bytearray):
        self.packetType = e_LoginRequest
        self.connectionId = connectionId
        self.hostId = hostId
        self.serviceId = serviceId
        self.data = data

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI33s33s256s",
            packet.packetType,
            packet.connectionId,
            packet.hostId.encode("UTF-8"),
            packet.serviceId.encode("UTF-8"),
            packet.data
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, hostId, serviceId, data = struct.unpack("!BI33s33s256s", buffer)
        if packetType != e_LoginRequest:
            raise PacketTypeException()
        return LoginRequestPacket(connectionId, hostId, serviceId, data)

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
    def __init__(self, connectionId: int, hostId: str, serviceId: str, sessionKey: bytearray):
        self.packetType = e_RegisterRequest
        self.connectionId = connectionId
        self.hostId = hostId
        self.serviceId = serviceId
        self.sessionKey = sessionKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI33s33s256s",
            packet.packetType,
            packet.connectionId,
            packet.hostId.encode("UTF-8"),
            packet.serviceId.encode("UTF-8"),
            packet.sessionKey
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, hostId, serviceId, sessionKey = struct.unpack("!BI33s33s256s", buffer)
        if packetType != e_RegisterRequest:
            raise PacketTypeException()
        return RegisterRequestPacket(connectionId, hostId, serviceId, sessionKey)


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

class LogoutPacket:
    def __init__(self, connectionId: int, sessionKey: bytearray):
        self.packetType = e_Logout
        self.connectionId = connectionId
        self.sessionKey = sessionKey
    
    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI256s",
            packet.packetType,
            packet.connectionId,
            packet.sessionToken
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, connectionId, sessionToken = struct.unpack("!BI256s", buffer)
        if packetType != e_Logout:
            raise PacketTypeException()
        return LogoutPacket(connectionId, sessionToken)


def randomBytes(n: int):
    return bytearray(Random.get_random_bytes(n))


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

    return bytearray(cipher.encrypt(data))


def rsaDecrypt(data, key):
    cipher = PKCS1_OAEP.new(keypair if key == None else key)
    
    return bytearray(cipher.decrypt(data))

def aesEncrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    temp = cipher.encrypt_and_digest(data)
    temp = (bytearray(temp[0]), bytearray(temp[1]))
    
    return temp

def aesDecrypt(data, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    temp = cipher.decrypt_and_verify(data, tag)

    return bytearray(temp) if temp else None

def hashString(string: str):
    hash_object = SHA256.new(data=string.encode())
    sha256_hash = hash_object.hexdigest()
    
    return sha256_hash

class HomeLinkClient:
    def __init__(self):
        self.controlSocket = None
        self.dataSocket = None
        self.serverUdpAddress = [None, None]
        self.serverTcpAddress = [None, None]
        self.controlAddress = [None, None]
        self.dataAddress = [None, None]
        self.serverPort = None
        self.serverPublicKey = None
        self.clientPublicKey = None
        self.hostId = None
        self.serviceId = None
        self.connectionId = None
        self.aesKey = None
        
    def initialize(self, serviceId):
        self.serviceId = serviceId
        configFilePath = os.environ["HOMELINK_CONFIG_PATH"]
        with open(configFilePath, "r") as configFile:
            for line in configFile:
                key, value = line.split()
                if key == "host_id":
                    self.host_id = value
                elif key == "server_control_port":
                    self.serverUdpAddress[1] = int(value)
                elif key == "server_data_port":
                    self.serverTcpAddress[1] = int(value)
                elif key == "server_address":
                    self.serverUdpAddress[0] = str(ipaddress.IPv6Address(f"::ffff:{value}"))
                    self.serverTcpAddress[0] = str(ipaddress.IPv6Address(f"::ffff:{value}"))

        self.serverTcpAddress = tuple(self.serverTcpAddress)
        self.serverUdpAddress = tuple(self.serverUdpAddress)
        self.controlSocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.dataSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        
        self.dataSocket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self.dataSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dataSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        self.controlAddress = ("::0.0.0.0", random.randint(50000, 59999))
        self.dataAddress = ("::0.0.0.0", random.randint(50000, 59999))
        self.controlSocket.bind(self.controlAddress)
        self.dataSocket.bind(self.dataAddress)
        self.controlSocket.settimeout(3)
        self.dataSocket.settimeout(1)
        self.controlSocket.connect(tuple(self.serverUdpAddress))
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
            self.controlSocket.sendto(data, self.serverUdpAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue
            
            keyResponsePacket = KeyResponsePacket.deserialize(data)
            self.serverPublicKey = keyResponsePacket.rsaPublicKey.rstrip('\x00')
            if keyResponsePacket.success == 0:
                continue
            else:
                self.aesKey = rsaDecrypt(keyResponsePacket.aesKey, None)
                break
        
        while True:
            passwordData = struct.pack("32s65s7s24s", randomBytes(32), hashString(password).encode("UTF-8"), bytes([0] * 8), randomBytes(24))
            registerRequestPacket = RegisterRequestPacket(connectionId, self.host_id, self.serviceId, rsaEncrypt(passwordData, self.serverPublicKey))
            data = RegisterRequestPacket.serialize(registerRequestPacket)
            self.controlSocket.sendto(data, self.serverUdpAddress)
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
            loginRequestPacket = LoginRequestPacket(connectionId, self.host_id, self.serviceId, rsaEncrypt(passwordData, self.serverPublicKey))
            data = LoginRequestPacket.serialize(loginRequestPacket)
            self.controlSocket.sendto(data, self.serverUdpAddress)
            try:
                data, _ = self.controlSocket.recvfrom(1024)
            except socket.timeout:
                continue
            
            loginResponsePacket = LoginResponsePacket.deserialize(data)
            if loginResponsePacket.status == e_LoginSuccess:
                self.sessionToken = rsaDecrypt(loginResponsePacket.sessionKey, None).decode('UTF-8')
                break
            else:
                return None
        
        self.connectionId = connectionId
        return connectionId
    
    def sendBufferTcp(self, buffer: bytearray):
        bytesSent = 0
        
        for _ in range(10):
            if bytesSent >= len(buffer):
                break
            
            rc = self.dataSocket.send(buffer[bytesSent:])
            
            if rc < 0:
                print(f"send() failed [{socket.error}]")
                return False
            
            bytesSent += rc
        return bytesSent == len(buffer)
    
    def receiveBufferTcp(self, n: int):
        bytesReceived = 0
        buffer = bytearray()
        
        for _ in range(10):
            if len(buffer) >= n:
                break
            data = None
            try:
                data = self.dataSocket.recv(n - bytesReceived)
            except socket.timeout:
                print(bytesReceived)
                continue
            
            if data == None:
                print(f"recv() failed [{socket.error}]")
                return None
            buffer.extend(data)
            
            bytesReceived += len(data)
        return buffer

    def sendFile(self, destinationHostId: str, destinationServiceId: str, filepath: str, filename: str):
        self.dataSocket.connect(self.serverTcpAddress)
        fileSize = os.stat(filepath).st_size
        self.sendCommand(f"WRITE_FILE {destinationHostId} {destinationServiceId} {filename} {fileSize}")
        fileInfo = bytearray(f"{filename} {fileSize}".encode("UTF-8"))
        if(len(fileInfo) < 128):
            fileInfo.extend(bytearray(128-len(fileInfo)))
        iv = randomBytes(16)
        sendBuffer, tag = aesEncrypt(fileInfo, self.aesKey, iv)
        sendBuffer = bytearray(sendBuffer)
        if len(sendBuffer) < 128:
            sendBuffer.extend(bytearray(128 - len(sendBuffer)))
        sendBuffer.extend(iv)
        sendBuffer.extend(tag)
        
        self.sendBufferTcp(sendBuffer)
        
        recvBuffer = self.receiveBufferTcp(17)
        if recvBuffer == None:
            return
        
        with open(filepath, "rb") as f:
            bytesSent = 0
            fileData = bytearray(f.read(FILE_BLOCK_SIZE))
            if len(fileData) < FILE_BLOCK_SIZE:
                fileData.extend(bytearray(FILE_BLOCK_SIZE - len(fileData)))
            while bytesSent < fileSize:
                iv = recvBuffer[1:]
                sendBuffer, tag = aesEncrypt(fileData, self.aesKey, iv)
                sendBuffer.extend(tag)
                status = self.sendBufferTcp(sendBuffer)
                if not status:
                    print(f"sendBufferTcp() failed")
                    break
                
                recvBuffer = self.receiveBufferTcp(17)
                if recvBuffer == None:
                    print(f"recvBufferTcp() failed")
                    break
                if recvBuffer[0] == 0:
                    bytesSent += FILE_BLOCK_SIZE
                    fileData = bytearray(f.read(FILE_BLOCK_SIZE))
                    if len(fileData) < FILE_BLOCK_SIZE:
                        fileData.extend(bytearray(FILE_BLOCK_SIZE - len(fileData)))
            
        self.dataSocket.close()
        self.dataSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                
    def recvFile(self, prefix: str, display: bool):
        self.dataSocket.connect(self.serverTcpAddress)
        
        self.sendCommand("READ_FILE")
        
        info = self.receiveBufferTcp(1)
        
        if not info:
            print("recvBufferTcp() failed")
            
        
        if info[0] == 0:
            return ""
        
        fileInfo = self.receiveBufferTcp(160)
        if not fileInfo:
            print("Could not fetch file info")
            return None
        
        fileInfo = aesDecrypt(fileInfo[:128], self.aesKey, fileInfo[128:144], fileInfo[144:])
        if fileInfo == None:
            print("Could not fetch file info")
            return None
        
        fileInfo = fileInfo.decode("UTF-8").rstrip('\x00')
        fileInfo = fileInfo.split()
        if len(fileInfo) != 2 or len(fileInfo[0]) == 0:
            print("Invalid file info")
            return None
        
        filename, fileSize = fileInfo
        fileSize = int(fileSize)
        iv = randomBytes(16)
        status = self.sendBufferTcp(bytearray(1) + iv)
        if not status:
            print("Could not send first ACK")
            return None
        
        
        filePath = prefix + filename
        bytesReceived = 0
        success = True
        with open(filePath, 'wb') as f:
            blockNumber = 0
            
            while bytesReceived < fileSize:
                buffer = self.receiveBufferTcp(FILE_BLOCK_SIZE + 16)
                if not buffer:
                    print("recvBufferTcp() failed")
                    success = False
                    break
                
                data = buffer[:FILE_BLOCK_SIZE]
                tag = buffer[FILE_BLOCK_SIZE:]
                data = aesDecrypt(data, self.aesKey, iv, tag)
                if data:
                    bytesReceived += FILE_BLOCK_SIZE
                    numBytes = FILE_BLOCK_SIZE
                    if bytesReceived >= fileSize:
                        numBytes = fileSize - FILE_BLOCK_SIZE * blockNumber
                    blockNumber += 1
                    
                    f.write(data[:numBytes])
                
                iv = randomBytes(16)
                status = self.sendBufferTcp(bytearray(1) + iv)
        
        
        if not success or bytesReceived < fileSize:
            os.remove(filePath)
            return None
    
    
        if display:
            with open(filePath, "r") as f:
                try:
                    i = 1
                    for line in f:
                        print(f"{i}| {line}")
                except UnicodeDecodeError:
                    print("File is not in UTF-8 format")
        
        self.dataSocket.close()
        self.dataSocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        return filePath
    
    def sendCommand(self, command: str):
        sessionToken = rsaEncrypt(self.sessionToken.encode("UTF-8"), self.serverPublicKey)
        data = randomBytes(32)
        data.extend(command.encode("UTF-8"))
        if len(data) < 200:
            data.extend(bytearray(200-len(data)))
        data = rsaEncrypt(data, self.serverPublicKey)
        commandPacket = CommandPacket(self.connectionId, sessionToken, data)
        buffer = CommandPacket.serialize(commandPacket)
        self.sendBufferTcp(buffer)
        

def main():
    
    args = sys.argv
    
    if len(args) < 2:
        print("Invalid command")
        return
    
    initializeSecurity()
    homeLinkClient = HomeLinkClient()
    homeLinkClient.initialize(sys.argv[1])
    connectionId = homeLinkClient.login("password7")
    if not connectionId:
        print("Login failed")
        
    command = args[2]
    
    
    if command == "get":
        if len(args) < 3:
            print("Invalid command")
            return
        prefix = ""
        display = False
        
        for i in range(3, len(args)):
            arg, data = args[i].split('=')
            if arg == "directory":
                prefix = data
            elif arg == "display":
                display = data == "true"
            else:
                print("Invalid command")
                return
        
        filePath = homeLinkClient.recvFile(prefix, display)
        
        if filePath:
            print(f"Received file: {filePath}")
        elif len(filePath) == 0:
            print("No files in file queue")
        else:
            print("Could not receive file")
        
    
    elif command == "send":
        if len(args) < 7:
            print("Invalid command")
            return
        _, _, _, hostId, serviceId, localPath, remotePath = args
        homeLinkClient.sendFile(hostId, serviceId, localPath, remotePath)
        
    else:
        print("Invalid command")
        return    
    
    homeLinkClient.shutdown()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass