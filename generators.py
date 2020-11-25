#! /usr/bin/env python
import argparse
import hashlib

from binascii import hexlify, unhexlify
from struct import Struct
from utils import g, b58encode, b58decode

PACKER = Struct('>QQQQ')


def count_leading_zeroes(s):
    count = 0
    for c in s:
        if c == '\0':
            count += 1
        else:
            break
    return count


def base58_check_encode(prefix, payload, compressed=False):
    # Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    s = prefix + payload
    if compressed:
        s = prefix + payload + b'\x01'

    # Add the 4 checksum bytes at the end of extended RIPEMD-160 hash. This is the 25-byte binary Bitcoin Address.
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]

    result = s + checksum

    return '1' * count_leading_zeroes(result) + b58encode(result).decode()


def pub_key_to_addr(s):
    ripemd160 = hashlib.new('ripemd160')

    hash_sha256 = hashlib.new('SHA256')

    # Perform SHA-256 hashing on the public key
    hash_sha256.update(bytes.fromhex(s))

    # Perform RIPEMD-160 hashing on the result of SHA-256
    ripemd160.update(hash_sha256.digest())

    return base58_check_encode(b'\0', ripemd160.digest())


def int_to_address(number):
    number0 = number >> 192
    number1 = (number >> 128) & 0xffffffffffffffff
    number2 = (number >> 64) & 0xffffffffffffffff
    number3 = number & 0xffffffffffffffff

    private_key = hexlify(PACKER.pack(number0, number1, number2, number3)).decode("utf-8")

    print('Converting from: ' + str(int(private_key, 16)))

    compressed_key = base58_check_encode(b'\x80', unhexlify(private_key), True)
    print('Private key (base58): ' + compressed_key)

    # address
    x, y = str(g * int(private_key, 16)).split()
    len1 = len(x)
    len2 = len(y)
    if len1 != 64:
        z = 64 - len1
        x = '0'*z + x

    if len2 != 64:
        z = 64 - len2
        y = '0'*z + y
    compressed_public_key_with_out_prefix = x + y

    pk_prefix = '02'
    if not int(compressed_public_key_with_out_prefix[64:], 16) % 2 == 0:
        pk_prefix = '03'
    compressed_public_key = pk_prefix + compressed_public_key_with_out_prefix[:64]

    print('Public key: ' + compressed_public_key)
    print('Bitcoin address: ' + pub_key_to_addr(compressed_public_key))


def wif_to_key(wif):
    slicer = 4
    if wif[0] in ['K', 'L']:
        slicer = 5

    return hexlify(b58decode(wif)[1:-slicer]).decode('utf-8')


#Added just for fun, see main()
def key_to_addr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(bytes.fromhex(s))
    return base58_check_encode(b'\0', ripemd160.digest())

def main():
    import hashlib

    #This is the bitcoin paper sha256 hash
    #btc_paper_key = key_to_addr("b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553")
    #print(btc_paper_key)

    parser = argparse.ArgumentParser(description='Generates private key, public key and wallet address from number')

    parser.add_argument('number', type=str, nargs='?',
            default=0x1,
            #default=0x18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725,
            #Bitcoin paper sha256
            #default=0xb1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553,
                        help='A required string or hexadecimal or integer number argument')
    args = parser.parse_args()
    try:
        secret = int(args.number, 0)
    except:
        hash_sha256 = hashlib.new('SHA256')
        hash_sha256.update(args.number.encode('utf-8'))
        secret = int('0x'+hash_sha256.hexdigest(), 0)
    int_to_address(secret)

if __name__ == "__main__":
    import time
    start_time = time.perf_counter()
    main()
    stop_time = time.perf_counter()
    print(f"BTC Private to Public generated in {stop_time - start_time:0.4f} seconds")

