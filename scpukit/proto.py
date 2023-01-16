import struct
import time

import serial
from Crypto.PublicKey import RSA

from .crc import CRC
from .packet import *


class Uploader:
    '''
        Uploader helper for MH190x devices
    '''

    def __init__(self, port="/dev/ttyUSB0", baudrate=115200, offset=0x1001000, signKey=None):
        '''
        Initializes the Uploader class with the given parameters.
        port: serial port to use, defaults to "/dev/ttyUSB0"
        baudrate: baudrate to use, defaults to 115200
        offset: offset to start uploading firmware, defaults to 0x1001000
        signKey: path to key used for signing firmware, defaults to None
        '''
        self.c16 = CRC()
        self.c16.set_config_by_name('CRC-16/CCITT-FALSE')

        self.c32 = CRC()
        self.c32.set_config_by_name('CRC-32')

        self.offset = offset

        if signKey:
            print(">>> Loading signature private key from {}".format(signKey))
            with open(signKey, "rb") as f:
                privateData = f.read()
            self.rsa = RSA.import_key(privateData)
        else:
            print(">>> No signature key. Ignoring firmware signature")
            self.rsa = NULL_KEY

        self.port = serial.Serial(port, baudrate=baudrate, timeout=0.1)
        print(">>> Port: {}".format(self.port.name))

    def close(self):
        '''
        Closes the serial port
        '''
        self.port.close()

    def upload(self, firmwareData: bytearray):
        '''
        Uploads firmware to device
        firmwareData: bytearray containing firmware data
        '''
        firmwarePacket = PacketFirmware(data=firmwareData, startAddress=self.offset, rsa=self.rsa)
        self.reset_device()
        self.start_boot()
        self.boot_stage2()

        pkt = self.make_packet(PacketType.FWHeader, firmwarePacket.header_as_bytes)
        self.port.write(pkt)
        cmd, data = self.receive_packet()
        if cmd != PacketType.Ack:
            raise("Error sending header: {}".format(binascii.hexlify(data)))

        if data[0] == ord(')'):
            raise("Received error from header: {}".format(data))

        print(">>> Erasing flash memory")
        sectorsToErase = (len(firmwareData) >> 12) + 2
        self.erase_flash(0, sectorsToErase)

        print(">>> Sending firmware")
        sentBytes = 0
        while sentBytes != len(firmwareData):
            sectorLen = len(firmwareData) - sentBytes
            if sectorLen > 4096:
                sectorLen = 4096
            chunk = firmwareData[sentBytes:sentBytes+sectorLen]
            offset = firmwarePacket.Start + sentBytes
            self.write_chunk(offset, chunk)
            sentBytes += sectorLen
        print(">>> Upload finished")
        print(">>> Resetting device")

        self.reset_device()
        self.port.rts = 0
        time.sleep(0.1)

    def erase_flash(self, sectorStart: int, sectorEnd: int):
        '''
        Erases flash memory from sectorStart to sectorEnd
        sectorStart: starting sector to erase
        sectorEnd: ending sector to erase
        '''
        print(">>> Erasing flash from {:08X} to {:08X}".format(sectorStart*4096, sectorEnd*4096))
        pkt = PacketEraseFlash(sectorStart, sectorEnd, 4096)
        pkt = self.make_packet(PacketType.EraserFlash, pkt.as_bytes)
        cmd = None
        while cmd == None:
            self.port.write(pkt)
            cmd, _ = self.receive_packet(1) # Flash erase is slow and needs more time
            if cmd != False and cmd != PacketType.Ack:
                raise("error erasing flash")

    def write_chunk(self, offset, data):
        '''
        Writes a chunk of data to a specific offset in memory (absolute offset)
        offset: offset in memory to write to
        data: data to write
        '''
        print(">>> Writing @0x{:04X}".format(offset))
        payload = struct.pack("<I", offset)
        payload += data
        pkt = self.make_packet(PacketType.FWData, payload)
        self.port.write(pkt)
        cmd, data = self.receive_packet()
        if cmd != PacketType.Ack or data[0] == ord(')'):
            raise("Error sending chunk: {}".format(data))

    def reset_device(self):
        '''
            Resets the device by toggling RTS
        '''
        self.port.rts = 1
        time.sleep(0.1)
        self.port.rts = 0
        time.sleep(0.1)
        self.port.rts = 1

    def start_boot(self):
        '''
            Sends the 0xF8 handshake to put the bootloader in stage1 mode
        '''
        print(">>> Starting bootloader")
        self.port.rts = 1
        self.port.read_all()
        time.sleep(0.1)
        self.port.rts = 0

        while True:
            self.port.write(b"\xF8"*64)
            cmd, data = self.receive_packet()
            if cmd:
                if cmd == PacketType.ChipSN:
                    chipsn = PacketChipSN(data)
                    print(">>> Received ChipSN Packet")
                    print(">>>  Boot Version: {}".format(chipsn.boot_version))
                    print(">>>  ChipID: {}".format(chipsn.chip_id))
                    print(">>>  ROM Version: {}".format(chipsn.rom_version))
                    print(">>>  Series: {} ({})".format(chipsn.chip_series, chipsn.chip_name_index))
                    print(">>>  Serial: {}".format(chipsn.serial_number_bytes))
                    break

    def boot_stage2(self):
        '''
        Sends the 0x7C Handshake2 payload to initialize the stage2 from bootrom
        This allows the device to be programmed
        '''
        print(">>> Initializing stage2")
        self.port.write(b"\x7C"*16)
        cmd, _ = self.receive_packet()
        if cmd != PacketType.DeviceSN:
            raise Exception("Cannot connect, received wrong command {:02X}".format(cmd))


    def make_packet(self, cmd: PacketType, payload):
        '''
        Makes a packet to send to the device
        cmd: command for the packet
        payload: payload data for the packet
        '''
        packet = struct.pack("<BBH", 0x02, cmd, len(payload))
        packet += bytearray(payload)
        crc = self.c16.compute(packet)
        packet += struct.pack("<H", crc)
        return packet


    def receive_packet(self, timeout=1):
        '''
        Receives a packet from the device
        timeout: time to wait for packet to arrive, defaults to 1
        '''
        timestart = time.time()
        while self.port.inWaiting() < 6:
            if time.time() - timestart > timeout:
                return False, False
        data = self.port.read(6)
        if len(data) < 6:
            return False, False
        found = False
        while not found:
            for i in range(len(data)):
                if data[i] == 0x02:
                    data = data[i:]
                    found = True
                    break
            if not found:
                b = self.port.read(6)
                if len(b) != 6:
                    return False, False
                data += b
        l = struct.unpack("<H", data[2:4])[0]
        if l > 256:
            print("Received length > 256: {}".format(l))
            exit()

        missingBytes = l - len(data) + 6
        data = data + self.port.read(missingBytes)
        if len(data) != l + 6:
            return False, False
        gotcrc = self.c16.compute(data[:len(data)-2])
        expcrc = struct.unpack("<H", data[len(data)-2:])[0]
        if gotcrc == expcrc:
            return PacketType(data[1]), data[4:len(data)-2]
        print("Invalid packet CRC. Expected {} got {}".format(gotcrc, expcrc))
        return False, False

