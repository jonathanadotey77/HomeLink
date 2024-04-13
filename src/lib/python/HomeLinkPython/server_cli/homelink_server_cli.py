from HomeLinkPython.common.homelink_packet import *
from HomeLinkPython.common.homelink_security import *

import socket

serverAddress = None
myAddress = None
mySocket = None
serverRSAKey = None


def init():
    global serverAddress, myAddress, mySocket, serverRSAKey
    initializeSecurity()
    serverAddress = ("127.0.0.1", 45000)
    myAddress = ("127.0.0.1", 44000)

    mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mySocket.bind(myAddress)

    keyRequestPacket = KeyRequestPacket(7000, getRSAPublicKey())
    mySocket.sendto(KeyRequestPacket.serialize(keyRequestPacket), serverAddress)

    data, _ = mySocket.recvfrom(1024)

    keyResponsePacket = KeyResponsePacket.deserialize(data)
    if keyResponsePacket.success == False:
        return False

    serverRSAKey = keyResponsePacket.rsaPublicKey
    serverRSAKey = serverRSAKey.rstrip("\x00")

    return True


def handleCommand(command):
    cliPacket = CLIPacket(
        getRSAPublicKey(), rsaEncrypt(command.encode("utf-8"), serverRSAKey)
    )
    data = CLIPacket.serialize(cliPacket)
    mySocket.sendto(data, serverAddress)


def main():
    init()

    while True:
        command = input("> ")

        if command == "quit":
            break

        handleCommand(command)

    mySocket.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
