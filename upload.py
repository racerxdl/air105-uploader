import sys

from scpukit.proto import Uploader

if len(sys.argv) < 3:
    print("upload.py PORT filename [offset in hex] [rsa private key]")
    print(" offset defaults to 0x1001000")
    print(" rsa private key only needed for secure boot")
    exit(1)

offset = 0x1001000
rsaKeyFile = None

port = sys.argv[1]
filename = sys.argv[2]

if len(sys.argv) >= 4:
    offset = int(sys.argv[3], 16)

if len(sys.argv) >= 5:
    rsaKeyFile = sys.argv[4]

uploader = Uploader(port, 115200, offset, rsaKeyFile)

with open(filename, "rb") as f:
    firm = f.read()

print(">>> Firmware: {} bytes".format(len(firm)))

uploader.upload(firm)
uploader.close()