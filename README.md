# AIR105 Uploader

AIR105 MCU program uploader, works with basically any SCPU from MH190X family.


# Usage:

```bash
python3 upload.py [PORT] [FIRMWARE FILE] [MEMORY OFFSET] [RSA PRIVATE KEY]
```

* **PORT** => Serial port to communicate with the device
    * Ensure **RTS** signal toggles the **VBAT** to ensure device reset
    * Default baudrate: 115200
* **FIRMWARE FILE** => The binary file of the firmware to write
* **MEMORY OFFSET** => Offset to write in the flash memory. This should be in hexadecimal format without the `0x`
    * By default, the AIR105 has its entrypoint at 0x1001000
* **RSA PRIVATE KEY** => X.509 PEM RSA Private Key used for signing the firmware. Only required if secure-boot is enabled


Example:

```bash
python3 upload.py /dev/ttyUSB0 firmware.bin
```


# Thanks

Special thanks to [wendall](https://github.com/wendal) for providing the basic programming program (used in LuatOS) at https://github.com/openLuat/LuatOS/issues/83. The rest of the work was done by reverse engineering the oficial ISP Tool.

Also thanks to Matthias Deeg for the CRC library at https://github.com/SySS-Research/syss-crc/blob/master/syss_crc.py