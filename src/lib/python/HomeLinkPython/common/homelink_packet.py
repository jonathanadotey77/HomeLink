import struct

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
    def __init__(self, keysetId: int, rsaPublicKey: str):
        self.packetType = e_KeyRequest
        self.keysetId = keysetId
        self.rsaPublicKey = rsaPublicKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "!BI512s",
            packet.packetType,
            packet.keysetId,
            packet.rsaPublicKey.encode("utf-8"),
        )

    @staticmethod
    def deserialize(buffer: bytearray):
        packetType, keysetId, rsaPublicKey = struct.unpack("!BI512s", buffer)
        if packetType != e_KeyRequest:
            raise PacketTypeException()
        return KeyRequestPacket(keysetId, rsaPublicKey)


class KeyResponsePacket:
    def __init__(self, success: bool, rsaPublicKey: str, aesKey: bytearray):
        self.packetType = e_KeyResponse
        self.success = success
        self.rsaPublicKey = rsaPublicKey
        self.aesKey = aesKey

    @staticmethod
    def serialize(packet):
        return struct.pack(
            "BB512s32s",
            packet.packetType,
            1 if packet.success else 0,
            packet.rsaPublicKey.encode("utf8"),
            packet.aesKey,
        )

    @staticmethod
    def deserialize(buffer):
        packetType, success, rsaPublicKey, aesKey = struct.unpack("BB512s32s", buffer)
        if packetType != e_KeyResponse:
            raise PacketTypeException()
        return KeyResponsePacket(success == 1, rsaPublicKey.decode("utf-8"), aesKey)
