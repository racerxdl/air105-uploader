#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
  SySS CRC
  Simple Python CRC implementation for playing around with cyclic redundancy
  checks, for instance when analyzing undocumented protocols or file formats
  by Matthias Deeg <matthias.deeg@syss.de>
  inspired by Online CRC Calculator by Anton Isakov (https://crccalc.com/)
  and Sunshine2k's CRC Calculator by Bastian Molkenthin
  (http://www.sunshine2k.de/coding/javascript/crc/crc_js.html)
  MIT License
  Copyright (c) 2018, 2019 SySS GmbH
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
"""

__version__ = '0.3'
__author__ = 'Matthias Deeg'

# look-up table for faster bit order reversing
REVERSE_BITS_LUT = [
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF,
]

def reverse_bits(n, width=8):
    """Reverse bit order (not the fastest way)"""

    b = '{:0{width}b}'.format(n, width=width)
    return int(b[::-1], 2)


def reverse_bits_byte(n):
    """Reverse bit order of bytes (8 bit values) using a look-up table"""
    return REVERSE_BITS_LUT[n]


def reverse_bits_word(n):
    """Reverse bit order of words (16 bit values) using a look-up table"""
    return (REVERSE_BITS_LUT[(n >> 8) & 0xff] |
            REVERSE_BITS_LUT[n & 0xff] << 8)


def reverse_bits_dword(n):
    """Reverse bit order of dwords (32 bit values) using a look-up table"""
    return (REVERSE_BITS_LUT[(n >> 24) & 0xff] |
            REVERSE_BITS_LUT[(n >> 16) & 0xff] << 8 |
            REVERSE_BITS_LUT[(n >> 8) & 0xff] << 16 |
            REVERSE_BITS_LUT[n & 0xff] << 24)


class CRC():
    """Simple CRC calculator"""

    # input string for CRC check
    CHECK_DATA = b'123456789'

    # some well-known CRC configurations
    CRC_CONFIG = {
            # 8 bit
            'CRC-8': {'width': 8, 'poly': 0x07, 'init': 0x00, 'refin': False, 'refout': False, 'xorout': 0x00, 'check': 0xF4},
            'CRC-8/CDMA2000': {'width': 8, 'poly': 0x9B, 'init': 0xFF, 'refin': False, 'refout': False, 'xorout': 0x00, 'check': 0xDA},
            'CRC-8/DARC': {'width': 8, 'poly': 0x39, 'init': 0x00, 'refin': True, 'refout': True, 'xorout': 0x00, 'check': 0x15},
            'CRC-8/DVB-S2': {'width': 8, 'poly': 0xD5, 'init': 0x00, 'refin': False, 'refout': False, 'xorout': 0x00, 'check': 0xBC},
            'CRC-8/EBU': {'width': 8, 'poly': 0x1D, 'init': 0xFF, 'refin': True, 'refout': True, 'xorout': 0x00, 'check': 0x97},
            'CRC-8/I-CODE': {'width': 8, 'poly': 0x1D, 'init': 0xFD, 'refin': False, 'refout': False, 'xorout': 0x00, 'check': 0x7E},
            'CRC-8/ITU': {'width': 8, 'poly': 0x07, 'init': 0x00, 'refin': False, 'refout': False, 'xorout': 0x55, 'check': 0xA1},
            'CRC-8/MAXIM': {'width': 8, 'poly': 0x31, 'init': 0x00, 'refin': True, 'refout': True, 'xorout': 0x00, 'check': 0xA1},
            'CRC-8/ROHC': {'width': 8, 'poly': 0x07, 'init': 0xFF, 'refin': True, 'refout': True, 'xorout': 0x00, 'check': 0xD0},
            'CRC-8/WCDMA': {'width': 8, 'poly': 0x9B, 'init': 0x00, 'refin': True, 'refout': True, 'xorout': 0x00, 'check': 0x25},
            # 16 bit
            'CRC-16/CCITT-FALSE': {'width': 16, 'poly': 0x1021, 'init': 0xFFFF, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0x29B1},
            'CRC-16/ARC': {'width': 16, 'poly': 0x8005, 'init': 0x0000, 'refin': True, 'refout': True, 'xorout': 0x0000, 'check': 0xBB3D},
            'CRC-16/AUG-CCITT': {'width': 16, 'poly': 0x1021, 'init': 0x1D0F, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0xE5CC},
            'CRC-16/BUYPASS': {'width': 16, 'poly': 0x8005, 'init': 0x0000, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0xFEE8},
            'CRC-16/CDMA2000': {'width': 16, 'poly': 0xC867, 'init': 0xFFFF, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0x4C06},
            'CRC-16/DDS-110': {'width': 16, 'poly': 0x8005, 'init': 0x800D, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0x9ECF},
            'CRC-16/DECT-R': {'width': 16, 'poly': 0x0589, 'init': 0x0000, 'refin': False, 'refout': False, 'xorout': 0x0001, 'check': 0x007E},
            'CRC-16/DECT-X': {'width': 16, 'poly': 0x0589, 'init': 0x0000, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0x007F},
            'CRC-16/DNP': {'width': 16, 'poly': 0x3D65, 'init': 0x0000, 'refin': True, 'refout': True, 'xorout': 0xFFFF, 'check': 0xEA82},
            'CRC-16/EN-13757': {'width': 16, 'poly': 0x3D65, 'init': 0x0000, 'refin': False, 'refout': False, 'xorout': 0xFFFF, 'check': 0xC2B7},
            'CRC-16/GENIBUS': {'width': 16, 'poly': 0x1021, 'init': 0xFFFF, 'refin': False, 'refout': False, 'xorout': 0xFFFF, 'check': 0xD64E},
            'CRC-16/MAXIM': {'width': 16, 'poly': 0x8005, 'init': 0x0000, 'refin': True, 'refout': True, 'xorout': 0xFFFF, 'check': 0x44C2},
            'CRC-16/MCRF4XX': {'width': 16, 'poly': 0x1021, 'init': 0xFFFF, 'refin': True, 'refout': True, 'xorout': 0x0000, 'check': 0x6F91},
            'CRC-16/T10-DIF': {'width': 16, 'poly': 0x8BB7, 'init': 0x0000, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0xD0DB},
            'CRC-16/TELEDISK': {'width': 16, 'poly': 0xA097, 'init': 0x0000, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0x0FB3},
            'CRC-16/TMS37157': {'width': 16, 'poly': 0x1021, 'init': 0x89EC, 'refin': True, 'refout': True, 'xorout': 0x0000, 'check': 0x26B1},
            'CRC-16/USB': {'width': 16, 'poly': 0x8005, 'init': 0xFFFF, 'refin': True, 'refout': True, 'xorout': 0xFFFF, 'check': 0xB4C8},
            'CRC-A': {'width': 16, 'poly': 0x1021, 'init': 0xC6C6, 'refin': True, 'refout': True, 'xorout': 0x0000, 'check': 0xBF05},
            'CRC-16/KERMIT': {'width': 16, 'poly': 0x1021, 'init': 0x0000, 'refin': True, 'refout': True, 'xorout': 0x0000, 'check': 0x2189},
            'CRC-16/MODBUS': {'width': 16, 'poly': 0x8005, 'init': 0xFFFF, 'refin': True, 'refout': True, 'xorout': 0x0000, 'check': 0x4B37},
            'CRC-16/X-25': {'width': 16, 'poly': 0x1021, 'init': 0xFFFF, 'refin': True, 'refout': True, 'xorout': 0xFFFF, 'check': 0x906E},
            'CRC-16/XMODEM': {'width': 16, 'poly': 0x1021, 'init': 0x0000, 'refin': False, 'refout': False, 'xorout': 0x0000, 'check': 0x31C3},
            # 32 bit
            'CRC-32': {'width': 32, 'poly': 0x04C11DB7, 'init': 0xFFFFFFFF, 'refin': True, 'refout': True, 'xorout': 0xFFFFFFFF, 'check': 0xCBF43926},
            'CRC-32/UBI': {'width': 32, 'poly': 0x04C11DB7, 'init': 0xFFFFFFFF, 'refin': True, 'refout': True, 'xorout': 0x00000000, 'check': 0x340BC6D9},
            'CRC-32/BZIP2': {'width': 32, 'poly': 0x04C11DB7, 'init': 0xFFFFFFFF, 'refin': False, 'refout': False, 'xorout': 0xFFFFFFFF, 'check': 0xFC891918},
            'CRC-32/32D': {'width': 32, 'poly': 0xA833982B, 'init': 0xFFFFFFFF, 'refin': True, 'refout': True, 'xorout': 0xFFFFFFFF, 'check': 0x87315576},
            'CRC-32/MPEG-2': {'width': 32, 'poly': 0x04C11DB7, 'init': 0xFFFFFFFF, 'refin': False, 'refout': False, 'xorout': 0x00000000, 'check': 0x0376E6E7},
            'CRC-32/POSIX': {'width': 32, 'poly': 0x04C11DB7, 'init': 0x00000000, 'refin': False, 'refout': False, 'xorout': 0xFFFFFFFF, 'check': 0x765E7680},
            'CRC-32/32Q': {'width': 32, 'poly': 0x814141AB, 'init': 0x00000000, 'refin': False, 'refout': False, 'xorout': 0x00000000, 'check': 0x3010BF7F},
            'CRC-32/JAMCRC': {'width': 32, 'poly': 0x04C11DB7, 'init': 0xFFFFFFFF, 'refin': True, 'refout': True, 'xorout': 0x00000000, 'check': 0x340BC6D9},
            'CRC-32/XFER': {'width': 32, 'poly': 0x000000AF, 'init': 0x00000000, 'refin': False, 'refout': False, 'xorout': 0x00000000, 'check': 0xBD0BE338},
            }


    def __init__(self):
        """CRC constructor"""
        # set default configuration for operating mode
        self.config = self.set_config_by_name('CRC-8')


    def set_config(self, config):
        """Set CRC configuration"""

        try:
            # set CRC parameters
            self.width = config['width']            # width in bits, e.g. 8, 16, 32
            self.poly = config['poly']              # generator polynom
            self.check = config['check']            # check value for check input string ("123456789")
            self.init = config['init']              # initial value
            self.refin = config['refin']            # flag for reflection of input data
            self.refout = config['refout']          # flag for reflection of checksum output
            self.xorout = config['xorout']          # value for final xor (0x00 if not used)

            # set CRC compute method and rebuild look-up table
            if self.width == 8:
                self.crc_method = self.fast_crc8
                self.crc8_table = self.calc_crc8_lut(self.poly)
            elif self.width == 16:
                self.crc_method = self.fast_crc16
                self.crc16_table = self.calc_crc16_lut(self.poly)
            elif self.width == 32:
                self.crc_method = self.fast_crc32
                self.crc32_table = self.calc_crc32_lut(self.poly)
        except KeyError:
            msg = "Invalid CRC configuration '{}'".format(config)
            raise ValueError(msg)

        return True


    def set_config_by_name(self, crc_name):
        """Set CRC configuration by name"""

        try:
            # get parameters of specified configuration
            config = self.CRC_CONFIG[crc_name.upper()]

            # set CRC parameters
            self.width = config['width']            # width in bits, e.g. 8, 16, 32
            self.poly = config['poly']              # generator polynom
            self.check = config['check']            # check value for check input string ("123456789")
            self.init = config['init']              # initial value
            self.refin = config['refin']            # flag for reflection of input data
            self.refout = config['refout']          # flag for reflection of checksum output
            self.xorout = config['xorout']          # value for final xor (0x00 if not used)

            # set CRC compute method and rebuild look-up table
            if self.width == 8:
                self.crc_method = self.fast_crc8
                self.crc8_table = self.calc_crc8_lut(self.poly)
            elif self.width == 16:
                self.crc_method = self.fast_crc16
                self.crc16_table = self.calc_crc16_lut(self.poly)
            elif self.width == 32:
                self.crc_method = self.crc32
                self.crc32_table = self.calc_crc32_lut(self.poly)

        except KeyError:
            msg = "Could not set CRC configuration '{}'".format(crc_name)
            raise ValueError(msg)

        return True


    def compute(self, data):
        """Compute CRC with the current active configuration"""

        result = self.crc_method(data)
        return result

    def self_test(self):
        """Perform a self-test with all CRC configurations"""

        success = True

        print("[*] Starting CRC self-test ({} configurations)".format(len(CRC.CRC_CONFIG)))
        for conf in CRC.CRC_CONFIG.keys():
            self.set_config_by_name(conf)
            crc = self.compute(CRC.CHECK_DATA)
            passed = (crc == self.check)
            print("{}: result = 0x{:0X}, check = 0x{:0X}, passed = {}".format(conf, crc, self.check, passed))

            if not passed:
                success = False

        if success:
            print("[*] CRC self-test completed successfully")
        else:
            print("[*] CRC self-test completed not successfully")

        return success



    def crc8(self, data):
        """Calculate CRC-8
           Bitwise implementation
        """

        # initialize CRC
        crc = self.init

        # process all data bytes
        for b in data:
            if self.refin:
                crc ^= REVERSE_BITS_LUT[b]
            else:
                crc ^= b

            # process bits of data byte
            for i in range(8):
                if (crc & 0x80) != 0:
                    crc = (crc << 1) ^ self.poly
                else:
                    crc <<= 1

        if self.refout:
            crc = REVERSE_BITS_LUT[crc & 0xff]

        # return CRC-8
        return (crc ^ self.xorout) & 0xff


    def calc_crc8_lut(self, generator):
        """Calculate look-up table for CRC-8"""

        # CRC-8 look-up table
        self.crc8_table = [None] * 256

        # calculate all possible 256 byte values
        for divident in range(256):
            b = divident

            # process bits of data byte
            for bit in range(8):
                if (b & 0x80) != 0:
                    b <<= 1
                    b ^= generator
                else:
                    b <<= 1

            # store CRC value in look-up table
            self.crc8_table[divident] = b

        # return generated CRC-8 look-up table
        return self.crc8_table


    def fast_crc8(self, data):
        """Calculate CRC-8
           Look-up table implementation
        """

        # initialize CRC
        crc = self.init

        # process all data bytes
        for b in data:
            if self.refin:
                b = REVERSE_BITS_LUT[b]

            # xor next input byte with CRC
            d = (b ^ crc) & 0xff

            # get CRC value from look-up table
            crc = self.crc8_table[d]

        # CRC reflection
        if self.refout:
            crc = REVERSE_BITS_LUT[crc & 0xff]

        # return CRC-8
        return (crc ^ self.xorout) & 0xff


    def crc16(self, data):
        """Calculate CRC-16
           Bitwise implementation
        """

        # initialize CRC
        crc = self.init

        # process all data bytes
        for b in data:
            # xor data byte with most significant byte of 16 bit CRC
            if self.refin:
                crc ^= REVERSE_BITS_LUT[b] << 8
            else:
                crc ^= (b << 8)

            # process bits of data byte
            for i in range(8):
                # check if most significant bit is set
                if (crc & 0x8000) != 0:
                    crc = (crc << 1) ^ self.poly
                else:
                    crc <<= 1

        # CRC reflection
        if self.refout:
            crc = reverse_bits_word(crc & 0xffff)

        # return CRC-16
        return (crc ^ self.xorout) & 0xffff


    def calc_crc16_lut(self, generator):
        """Calculate look-up table for CRC-16"""

        # CRC-16 look-up table
        self.crc16_table = [None] * 256

        # calculate all possible 256 byte values
        for divident in range(256):
            # move divident byte into most significant byte of 16 bit CRC
            b = (divident << 8)

            # process bits of data byte
            for bit in range(8):
                if (b & 0x8000) != 0:
                    b <<= 1
                    b ^= generator
                else:
                    b <<= 1

            # store CRC value in look-up table
            self.crc16_table[divident] = b

        # return generated CRC-16 look-up table
        return self.crc16_table


    def fast_crc16(self, data):
        """Calculate CRC-16
           Look-up table implementation
        """

        # initialize CRC
        crc = self.init

        # process all data bytes
        for b in data:
            if self.refin:
                b = REVERSE_BITS_LUT[b]

            # xor next input byte with  most significant byte of CRC
            d = (b ^ (crc >> 8)) & 0xff

            # get CRC value from look-up table
            crc = (crc << 8) ^ self.crc16_table[d]

        # CRC reflection
        if self.refout:
            crc = reverse_bits_word(crc & 0xffff)

        # return CRC-16
        return (crc ^ self.xorout) & 0xffff


    def crc32(self, data):
        """Calculate CRC-32
           Bitwise implementation
        """

        # initialize CRC
        crc = self.init

        # process all data bytes
        for b in data:
            # xor data byte with most significant byte of 32 bit CRC
            if self.refin:
                crc ^= REVERSE_BITS_LUT[b] << 24
            else:
                crc ^= (b << 24)

            # process bits of data byte
            for i in range(8):
                # check if most significant bit is set
                if (crc & 0x80000000) != 0:
                    crc = (crc << 1) ^ self.poly
                else:
                    crc <<= 1

        # CRC reflection
        if self.refout:
            crc = reverse_bits_dword(crc & 0xffffffff)

        # return CRC-32
        return (crc ^ self.xorout) & 0xffffffff


    def calc_crc32_lut(self, generator):
        """Calculate look-up table for CRC-32"""

        # CRC-32 look-up table
        self.crc32_table = [None] * 256

        # calculate all possible 256 byte values
        for divident in range(256):
            # move divident byte into most significant byte of 32 bit CRC
            b = (divident << 24)

            # process bits of data byte
            for bit in range(8):
                if (b & 0x80000000) != 0:
                    b <<= 1
                    b ^= generator
                else:
                    b <<= 1

            # store CRC value in look-up table
            self.crc32_table[divident] = b

        # return generated CRC-32 look-up table
        return self.crc32_table


    def fast_crc32(self, data):
        """Calculate CRC-32
           Look-up table implementation
        """

        # initialize CRC
        crc = self.init

        # process all data bytes
        for b in data:
            if self.refin:
                b = REVERSE_BITS[b]

            # xor next input byte with  most significant byte of CRC
            d = (((b << 24) ^ crc) >> 24) & 0xff

            # get CRC value from look-up table
            crc = (crc << 8) ^ self.crc32_table[d]

        # CRC reflection
        if self.refout:
            crc = reverse_bits_dword(crc & 0xffffffff)

        # return CRC-32
        return (crc ^ self.xorout) & 0xffffffff


    def find_config(self, width, target, only_known=False, max_poly=0xff, max_init=0xff, max_xor=0xff):
        """Try to find a suitable CRC config for a given CRC and data
           in the most simple and not efficient way
        """

        # first, test all known CRC configurations with the given width
        for conf in CRC.CRC_CONFIG.keys():
            self.set_config_by_name(conf)

            # test CRC for all given targets and count matches
            match_count = 0
            for t in target:
                c = self.compute(t[0])
                if c == t[1]:
                    match_count += 1
                else:
                    break

            if match_count == len(target):
                return (conf, CRC.CRC_CONFIG[conf])

        # if only known CRC configurations should be searched, return here
        # without result
        if only_known:
            return None

        # create initial config
        config = {'width': width, 'poly': 0, 'init': 0, 'refin': False, 'refout': False, 'xorout': 0x00, 'check': 0x00}

        self.width = width
        self.refin = False
        self.refout = False
        self.xorout = 0x00

        # set CRC compute method and rebuild look-up table
        if self.width == 8:
            self.crc_method = self.fast_crc8
            self.crc8_table = self.calc_crc8_lut(self.poly)
            update_table = self.calc_crc8_lut
        elif self.width == 16:
            self.crc_method = self.fast_crc16
            self.crc16_table = self.calc_crc16_lut(self.poly)
            update_table = self.calc_crc16_lut
        elif self.width == 32:
            self.crc_method = self.crc32
            self.crc32_table = self.calc_crc32_lut(self.poly)
            update_table = self.calc_crc32_lut


        # test all possible xor values
        for xorout in range(max_xor):
            self.xorout = xorout

            # test all possibly generator polynoms
            for poly in range(1, max_poly):
                self.poly = poly

                # update CRC table for new generator polynom
                update_table(self.poly)

                # test all possible init values
                for init in range(max_init):
                    self.init = init

                    # check configuration for all targets with all possible
                    # configurations

                    # refin=False, refout=False
                    self.refin = False
                    self.refout = False

                    # test CRC for all given targets and count matches
                    match_count = 0
                    for t in target:
                        c = self.compute(t[0])
                        if c == t[1]:
                            match_count += 1
                        else:
                            break

                    if match_count == len(target):
                        # set found config parameters in config
                        config['poly'] = self.poly
                        config['init'] = self.init
                        config['xorout'] = self.xorout
                        config['refin'] = self.refin
                        config['refout'] = self.refout
                        config['check'] = self.compute(CRC.CHECK_DATA)
                        return ('unknown', config)

                    # refin=True, refout=False
                    self.refin = True
                    self.reout = False

                    # test CRC for all given targets and count matches
                    match_count = 0
                    for t in target:
                        c = self.compute(t[0])
                        if c == t[1]:
                            match_count += 1
                        else:
                            break

                    if match_count == len(target):
                        # set found config parameters in config
                        config['poly'] = self.poly
                        config['init'] = self.init
                        config['xorout'] = self.xorout
                        config['refin'] = self.refin
                        config['refout'] = self.refout
                        config['check'] = self.compute(CRC.CHECK_DATA)
                        return ('unknown', config)

                    # refin=False, refout=True
                    self.refin = False
                    self.refout = True

                    # test CRC for all given targets and count matches
                    match_count = 0
                    for t in target:
                        c = self.compute(t[0])
                        if c == t[1]:
                            match_count += 1
                        else:
                            break

                    if match_count == len(target):
                        # set found config parameters in config
                        config['poly'] = self.poly
                        config['init'] = self.init
                        config['xorout'] = self.xorout
                        config['refin'] = self.refin
                        config['refout'] = self.refout
                        config['check'] = self.compute(CRC.CHECK_DATA)
                        return ('unknown', config)

                    # refin=True, refout=True
                    self.refin = True
                    self.refout = True

                    # test CRC for all given targets and count matches
                    match_count = 0
                    for t in target:
                        c = self.compute(t[0])
                        if c == t[1]:
                            match_count += 1
                        else:
                            break

                    if match_count == len(target):
                        # set found config parameters in config
                        config['poly'] = self.poly
                        config['init'] = self.init
                        config['xorout'] = self.xorout
                        config['refin'] = self.refin
                        config['refout'] = self.refout
                        config['check'] = self.compute(CRC.CHECK_DATA)
                        return ('unknown', config)
        return None


# main
if __name__ == "__main__":

    # CRC self-test
    crc = CRC()
    data = b"123456789"
    crc.self_test()