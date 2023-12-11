from argparse import ArgumentParser
import sys


def load_public_key(path):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    with open(path, 'rb') as f:
        public_key = load_pem_public_key(
            f.read(),
        )
    return public_key


def load_private_key(path):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    with open(path, 'rb') as f:
        private_key = load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key    
    

def rsa_encrypt(message: bytes, public_key):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(ciphertext: bytes, private_key):
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return message


def output(content, path=None):
    if path is None:
        print(content)
    else:
        with open(path, 'wb') as f:
            f.write(content)


def main():
    parser = ArgumentParser()
    parser.add_argument('-m', '--message-path')
    parser.add_argument('-c', '--ciphertext-path')
    parser.add_argument('-k', '--key-path')
    parser.add_argument('-o', '--output-path')
    parser.add_argument('-e', '--encrypt', action='store_true')
    parser.add_argument('-d', '--decrypt', action='store_true')
    opts = parser.parse_args()

    if opts.encrypt:
        public_key = load_public_key(path=opts.key_path)
        with open(opts.message_path, 'rb') as f:
            message = f.read()
            ciphertext = rsa_encrypt(message, public_key)
            output(ciphertext, opts.output_path)
    elif opts.decrypt:
        private_key = load_private_key(path=opts.key_path)
        with open(opts.ciphertext_path, 'rb') as f:
            ciphertext = f.read()
            message = rsa_decrypt(ciphertext, private_key)
            output(message, opts.output_path)

if __name__ == '__main__':
    main()