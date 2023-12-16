from rsa_key import RSAPrivateKey, RSAPublicKey
from argparse import ArgumentParser
import hashlib


HASHING_ALGORITHM = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
}


def main():
    parser = ArgumentParser()
    parser.add_argument('-m', '--message', help='Input message file path.')
    parser.add_argument('-si', '--signature', help='Input (if verify) signature file path.')
    parser.add_argument('-o', '--output', help='Output file path.')
    parser.add_argument('-k', '--key', help='Input key path (.pem).')
    parser.add_argument('-ha', '--hash', choices=tuple(HASHING_ALGORITHM.keys()), help='Hashing algorithm.')
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument('-s', '--sign', action='store_true', help='To encrypt message.')
    operation.add_argument('-v', '--verify', action='store_true', help='To decrypt ciphertext.')
    opts = parser.parse_args()

    if opts.sign:
        private_key = RSAPrivateKey.from_pem_file(opts.key)
        with open(opts.message, 'rb') as f:
            message = f.read()
            signed = private_key.sign(message=message, hash=HASHING_ALGORITHM.get(opts.hash, None))
        to_write = signed
    elif opts.verify:
        public_key = RSAPublicKey.from_pem_file(opts.key)
        with open(opts.message,'rb') as f:
            message = f.read()
        with open(opts.signature, 'rb') as f:
            signed = f.read()
        if public_key.verify(message=message, signed=signed, hash=HASHING_ALGORITHM.get(opts.hash, None)) == True:
            to_write = 'Verification succeeded.'
        else:
            to_write = 'Verification failed.'

    if opts.output:
        with open(opts.output, 'wb') as f:
            f.write(to_write)
    else:
        print(to_write)


if __name__ == '__main__':
    main()