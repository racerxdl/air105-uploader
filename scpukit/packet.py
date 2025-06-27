import binascii
import hashlib
import struct
from enum import IntEnum

from Crypto.PublicKey import RSA

from .crc import CRC

NULL_KEY = RSA.construct((13, 3),  consistency_check=False)

class PacketType(IntEnum):
    '''
        Reverse engineered from ISP Tool
    '''
    Patch = 0x10
    USBTimeOut = 0x11
    ChipUpdate = 0x12
    WaferComplete = 0x13
    ChipUpdateNoSN = 0x14
    ChipUpdateFix = 0x15
    BackPatch = 0x17
    WriteFlashOption = 0x18
    Unknown = 0x19
    FWHeader = 0x20
    FWData = 0x21
    EraserFlash = 0x22
    FlashID = 0x23
    VCPCompleted = 0x24
    RequestKey = 0x25
    MSDHandshake1 = 0x29
    MSDHandshake2 = 0x30
    BootCheck = 0x40
    ReadBootCheck = 0x41
    CryptoCheck = 0x42
    ReadCryptoCheck = 0x43
    ImportSmKey = 0x60
    EnterSMBranch = 0x61
    Ack = 0x80
    ChipSN = 0x81
    DeviceSN = 0x82
    DiskSN = 0x83
    ResponseKey = 0x84
    BootCheckResult = 0xc0
    ReadBootCheckResult = 0xc1
    CryptoCheckResult = 0xc2
    ReadCryptoCheckResult = 0xc3
    FlashIDResult = 0xa3
    HANDSHAKE1 = 0xf8
    HANDSHAKE2 = 0x7c


class Packet:
    def __init__(self, pkt_type: PacketType, data: bytearray):
        self.pkt_type = pkt_type
        self.data = data

    @staticmethod
    def decode(data):
        if data[0] != 0x02:
            raise ValueError("Invalid start of packet")
        pkt_type = data[1]
        size = struct.unpack("<H", data[2:3])[0]
        if len(data) != (size - 6):
            raise ValueError("Not enough data")

        payload = data[4:len(data)-6]
        c16 = CRC()
        c16.set_config_by_name('CRC-16/CCITT-FALSE')
        crc = struct.pack("<H", c16.compute(data[:len(data)-2]))
        if crc != data[len(data)-2:]:
            raise ValueError("Invalid CRC")
        return Packet(pkt_type, payload)

    @classmethod
    def encode(self):
        if self.pkt_type == PacketType.HANDSHAKE1 or self.pkt_type == PacketType.HANDSHAKE2 or self.pkt_type == PacketType.Ack:
            return chr(self.pkt_type) * 100

        c16 = CRC()
        c16.set_config_by_name('CRC-16/CCITT-FALSE')

        buff = bytearray(len(self.data) + 6)  # Header + Payload + CRC
        buff[0] = 0x02
        buff[1] = self.pkt_type
        buff[2:3] = struct.pack("<H", len(self.data))

        buff[4:len(self.data)+4] = self.data
        crc = struct.pack("<H", c16.compute(buff[:len(buff-2)]))
        buff[len(buff)-2:] = crc

        return buff


class PacketChipSN:

    def __init__(self, data):
        self.rom_version_value = 0
        self.chip_name_index = "unknown"
        self.chip_timeout = 0
        self.chip_key_info = 0
        self.chip_id = "unknown"

        self.stage = data[0]
        self.serial_number_bytes = binascii.hexlify(data[1:][:4]).upper()
        if len(self.serial_number_bytes) != 8:
            self.serial_number_bytes = "0" * \
                (8-len(self.serial_number_bytes)) + self.serial_number_bytes
        self.boot_version_value = struct.unpack("<I", data[5:][:4])[0]
        self.chip_series = data[9:][:4].decode("ascii")[::-1]

        if len(data) == 13:
            if self.chip_series == "D009":
                self.chip_name_index = "MH1902S-D900" if self.chip_serial_number == "00000000" else "MH1902S-D904"
                return
            if self.chip_series == "1902":
                self.chip_name_index = "MH1902S"
                return

        if len(data) == 17:
            self.rom_version_value = struct.unpack("<I", data[13:][:4])[0]
            if self.rom_version == "V1.9.0":
                self.chip_name_index = "MH1902S-SMV"
            else:
                self.chip_name_index = "MH1902S-SMV2"

        self.serial_number_bytes = binascii.hexlify(data[1:][:16]).upper()

        if len(data) == 25:
            self.chip_series = data[21:][:4].decode("ascii")[::-1]
            if self.chip_series == "D009":
                self.chip_name_index = "MH1902S-D916"
                return

            self.chip_series = "S031"
            self.chip_timeout = struct.unpack("<H", data[17:][:2])
            self.boot_version_value = struct.unpack("<H", data[19:][:2])[0]
            self.chip_name_index = "MH1903"
            return

        if len(data) == 29:
            self.boot_version_value = struct.unpack("<I", data[17:][:4])[0]
            self.chip_series = data[21:][:4].decode("ascii")[::-1]
            if self.serial_number_bytes[:10] == binascii.hexlify("2020C"):
                self.chip_name_index = "MH2020C"
            else:
                self.chip_name_index = "MH1902T"
            return

        if len(data) == 33:
            self.chip_timeout = struct.unpack("<H", data[17:][:2])[0]
            self.chip_key_info = struct.unpack("<I", data[21:][:4])[0]
            self.boot_version_value = struct.unpack("<I", data[25:][:4])[0]
            self.chip_series = data[29:][:4].decode("ascii")[::-1]
            if self.chip_series == "1908":
                self.chip_name_index = "MH1908"
            elif self.chip_series == "A019":
                self.chip_name_index = "MH1706-V1"
            return

        if len(data) == 36:
            self.chip_timeout = struct.unpack("<H", data[20][:2])[0]
            self.chip_key_info = struct.unpack("<I", data[24][:2])[0]
            self.boot_version_value = struct.unpack("<I", data[28:][:4])[0]
            self.chip_series = data[32:][:4].decode("ascii")[::-1]
            if self.chip_series == "U060":
                self.chip_name_index = "MH1706-V2"
            return

        if len(data) == 37:
            self.chip_timeout = struct.unpack("<H", data[17:][:2])[0]
            self.chip_key_info = struct.unpack("<I", data[21:][:4])[0]
            self.boot_version_value = struct.unpack("<I", data[25:][:4])[0]
            self.chip_series = data[29:][:4].decode("ascii")[::-1]
            self.chip_id = struct.unpack("<I", data[33:][:4])[0]
            if self.chip_series == "S030":
                self.chip_name_index = "MH1903S"
            elif self.chip_series == "U060":
                self.chip_name_index = "MH1706-V2"
            return

    @property
    def boot_version(self):
        return "V{}.{}.{}".format(int(self.boot_version_value/1024), int((self.boot_version_value % 1024) / 32), self.boot_version_value % 32)

    @property
    def rom_version(self):
        if self.rom_version_value == 0:
            return "Unknown"
        return "V{}.{}.{}".format(((self.rom_version_value & 0xFF0000) >> 16) - 48, ((self.rom_version_value & 0xFF00) >> 8) - 48, (self.rom_version_value & 0xFF)-48)

    @property
    def chip_serial_number(self):
        hex = self.serial_number_bytes.decode("ascii")
        try:
            return binascii.unhexlify(hex).decode("ascii")
        except:
            return hex

class PacketFirmware:
    Start = 0x1001000
    Length = 0
    Version = 0x0
    Option = 0x2
    Hash = bytearray(64)
    Data = bytearray(0)
    rsaKey: RSA.RsaKey = NULL_KEY

    def __init__(self, data=bytearray(0), startAddress=0x1001000, opt=0x02, rsa: RSA.RsaKey = NULL_KEY):
        self.Start = startAddress
        self.Data = data
        self.Length = len(data)
        self.Option = opt
        self.rsaKey = rsa
        self.c32 = CRC()
        self.c32.set_config_by_name('CRC-32')

        self.update()

    def update(self):
        if self.Option == 2:
            hash = hashlib.sha256(self.Data).digest()
        else:
            hash = hashlib.sha512(self.Data).digest()

        self.Hash[:len(hash)] = hash

        self.header = struct.pack(
            "<6I", 0x5555AAAA, 0, self.Start, self.Length, self.Version, self.Option)
        self.header += self.Hash
        crc = self.c32.compute(self.header[4:])
        self.header += struct.pack("<I", crc)

        if self.rsaKey != NULL_KEY:
            signData = self.header[4:]
            signData += b"\x00" * (256 - len(signData))  # Pad to 256 bytes
            signData = int.from_bytes(signData, byteorder='big')
            signed = pow(signData, self.rsaKey.d, self.rsaKey.n)

            self.signed_header = self.header[:4] + signed.to_bytes(
                self.rsaKey.size_in_bytes(), byteorder='big')

    @property
    def is_signed(self):
        return self.rsaKey != NULL_KEY

    @property
    def header_as_bytes(self):
        if self.is_signed:
            return self.signed_header
        return self.header


class PacketEraseFlash:
    address = 0
    sector_size = 4096
    sectors = 0

    def __init__(self, address=0, sectors=0, sector_size=4096):
        self.address = address
        self.sector_size = sector_size
        self.sectors = sectors

    @property
    def as_bytes(self):
        return struct.pack("<III", self.address, self.sectors, self.sector_size)

    def __str__(self) -> str:
        return f"PacketEraseFlash(address={self.address:08X}, sectors={self.sectors}, sector_size={self.sector_size})"