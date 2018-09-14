import base64
import math
import argparse
from Crypto.Cipher import DES

# REQUIREMENTS:
# Windows: Requires Python Compiler for VC++ 9.0:
# https://www.microsoft.com/en-ca/download/details.aspx?id=44266
#
# Python scripts requires the PyCrypto package to be installed:
# C:\Python27\Scripts\easy_install pycrypto


def pad_pkcs7(text, block_size=8):
    no_of_blocks = math.ceil(len(text)/float(block_size))
    pad_value = int(no_of_blocks * block_size - len(text))
    if pad_value == 0:
        return text + chr(block_size) * block_size
    else:
        return text + chr(pad_value) * pad_value


def strip_pkcs7(text):
    return "".join(i for i in text if 31 < ord(i) < 127) # remove funky characters added by PKCS7


print("DESCrypto - C# .NET Decryptor - V1 - Last Updated: September 15th, 2018")
parser = argparse.ArgumentParser(description='This came up in an engagement where a C# application contained a hard-coded key that was being used to store user credentials for remote access.  As a POC we reverse engineered the application to extract the key and IV used to store the passwords and created a simple Python script to decrypt these.')
parser.add_argument("-decode", type=str, help='Specify a cyphertext password stored in the BatchPath *.BPS file to decrypt using the BatchPath hardcoded key value.')
parser.add_argument("-encode", type=str, help='Specify a cleartext password to be encrypted using the BatchPatch hardcoded key value. ')
parser.add_argument("-key", default="s3cret12",  type=str, help='Specify a key to be used for the DEC Encryption (must have a length that is a multiple of 8). (default: %(default)s)')
parser.add_argument("-iv", default="s3cret12",  type=str, help='Specify initilization vector to be used for the DEC Encryption (must have a length that is a multiple of 8). (default: %(default)s)')
args = parser.parse_args()

cipher = DES.new(args.key, DES.MODE_CBC, args.iv)

if args.encode is not None:
    print "Encoded: " + args.encode
    padded_plaintext = pad_pkcs7(args.encode)
    print base64.b64encode(cipher.encrypt(padded_plaintext))

elif args.decode is not None:
    print "Decoded: " + args.decode
    print strip_pkcs7(cipher.decrypt(base64.b64decode(args.decode)))
