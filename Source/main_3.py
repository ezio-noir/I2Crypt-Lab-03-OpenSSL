from rsa_key import RSAPrivateKey, RSAPublicKey
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', help='Input plaintext (if encrypt) or ciphertext (if decrypt) file path.')
    parser.add_argument('-o', '--output', help='Output ciphertext (if encrypt) or plaintext (if decrypt) file path.')
    parser.add_argument('-k', '--key', help='Input key path (.pem).')
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument('-e', '--encrypt', action='store_true', help='To encrypt message.')
    operation.add_argument('-d', '--decrypt', action='store_true', help='To decrypt ciphertext.')
    opts = parser.parse_args()

    if opts.encrypt:
        public_key = RSAPublicKey.from_pem_file(opts.key)
        with open(opts.input, 'rb') as f:
            message = f.read()
            ciphertext = public_key.encrypt_pkcs1v15(message=message)
        to_write = ciphertext
    elif opts.decrypt:
        private_key = RSAPrivateKey.from_pem_file(opts.key)
        with open(opts.input, 'rb') as f:
            ciphertext = f.read()
            plaintext, message = private_key.decrypt_pkcs1v15(ciphertext=ciphertext)
        to_write = message

    if opts.output:
        with open(opts.output, 'wb') as f:
            f.write(to_write)
    else:
        print(to_write)


if __name__ == '__main__':
    main()