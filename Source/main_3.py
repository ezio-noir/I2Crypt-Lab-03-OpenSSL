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
            output_bytes = public_key.encrypt_pkcs1v15(data=message)
    elif opts.decrypt:
        private_key = RSAPrivateKey.from_pem_file(opts.key)
        with open(opts.input, 'rb') as f:
            ciphertext = f.read()
            output_bytes = private_key.decrypt_pkcs1v15(data=ciphertext)

    if opts.output:
        with open(opts.output, 'wb') as f:
            f.write(output_bytes)
    else:
        print(output_bytes)


if __name__ == '__main__':
    main()