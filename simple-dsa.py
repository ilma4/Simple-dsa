#!/usr/bin/env python3

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
import sys


def read_private_key_from_file(filename):
    file = open(filename, 'rt')
    key = ECC.import_key(file.read(), curve_name='ed25519')
    file.close()
    return key


def read_public_key_from_file(filename):
    file = open(filename, 'rt')
    key = ECC.import_key(file.read(), curve_name='ed25519')
    file.close()
    return key


def write_to_file(data, filename, mode='wt'):
    file = open(filename, mode)
    file.write(data)
    file.close()


def print_help():
    print("""Usage:
    python3 simple-dsa.py sign file private_key_file signature_file
    python3 simple-dsa.py keygen private_key_file public_key_file
    python3 simple-dsa.py check file signature_file public_key_file
    python3 simple-dsa.py --help          """)


def check(filepath, signature_file_path, public_key_path):
    file_data = open(filepath, 'rb').read()
    public_key = read_public_key_from_file(public_key_path)
    signature = open(signature_file_path, 'rb').read()
    signer = eddsa.new(key=public_key, mode='rfc8032')
    try:
        signer.verify(file_data, signature)
        print("The message is authentic! :)")
    except ValueError:
        print("The message is not authentic! :(")


def sign(filepath, private_key_path, signature_path):
    file_data = open(filepath, 'rb').read()
    private_key = read_private_key_from_file(private_key_path)
    signer = eddsa.new(key=private_key, mode='rfc8032')
    signature = signer.sign(file_data)
    write_to_file(signature, signature_path, 'wb')


def keygen(private_key_path, public_key_path):
    key = ECC.generate(curve='ed25519')
    write_to_file(key.export_key(format='PEM'), private_key_path)
    write_to_file(key.public_key().export_key(format='PEM'), public_key_path)


def main():
    argv = sys.argv
    if len(argv) == 2:
        print_help()

    elif len(argv) == 4:
        if argv[1] == 'keygen':
            keygen(argv[2], argv[3])
        else:
            print("Wrong second argument! Expected: keygen. Got: " + argv[1])

    elif len(argv) == 5:
        if argv[1] != 'sign' and argv[1] != 'check':
            print("Wrong second argument! Expected: sign, check. Got: "
                  + argv[1])

        elif argv[1] == 'sign':
            sign(argv[2], argv[3], argv[4])

        elif argv[1] == 'check':
            check(argv[2], argv[3], argv[4])

    else:
        print("Wrong number of arguments! Expected 5, 4 or 2. Got: " +
              str(len(sys.argv)))
        print_help()


if __name__ == '__main__':
    main()
