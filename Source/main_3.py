from rsa_key import RSAPrivateKey, RSAPublicKey
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', help='Input plaintext (if encrypt) or ciphertext (if decrypt) file path.')
    parser.add_argument('-o', '--output', help='Output ciphertext (if encrypt) or plaintext (if decrypt) file path.')
    parser.add_argument('-k', '--key', help='Input key path (.pem).')
    parser.add_argument('-e', '--encrypt', action='store_true', help='To encrypt message.')
    parser.add_argument('-d', '--decrypt', action='store_true', help='To decrypt ciphertext.')
    parser.add_argument('-p', '--padding', choices=('PKCS1v15', 'OAEP'), help='Padding procedure.')
    parser.add_argument('-pA', '--padding-arguments', action='append', type=lambda option: option.split(':'), help='Padding arguments.')
    opts = parser.parse_args()

    print(opts)

    # if opts.padding == 'OAEP':
    #     if opts.padding:
    #         padding_arguments = {}
    #         for key, value in opts.padding_arguments:
    #             padding_arguments[key] = value
    #     padding=OAEP(
    #         mgf=globals()[padding_arguments["mgf"]](
    #             algorithm=globals()[padding_arguments["mgf_hash"]]()
    #         ),
    #         algorithm=globals()[padding_arguments["hash"]](),
    #         label=padding_arguments.get('label', None)
    #     )
    # elif opts.padding == 'PKCS1v15':
    #     padding=PKCS1v15()


    if opts.encrypt:
        # public_key = load_rsa_public_key(opts.key, extract_info=False)
        # with open(opts.input, 'rb') as f:
        #     message = f.read()
        #     output_bytes = rsa_encrypt(message=message, public_key=public_key, padding=padding)

        public_key = RSAPublicKey.from_pem_file(opts.key)
        with open(opts.input, 'rb') as f:
            message = f.read()
            output_bytes = public_key.encrypt_pkcs1v15(block_type=b'\x02', data=message)
    elif opts.decrypt:
        private_key = RSAPrivateKey.from_pem_file(opts.key)
        with open(opts.input, 'rb') as f:
            ciphertext = f.read()
            output_bytes = private_key.decrypt(block_type=b'\x01', data=ciphertext)
    #     private_key = load_rsa_private_key(opts.key, extract_info=False)
    #     with open(opts.input, 'rb') as f:
    #         ciphertext = f.read()
    #         output_bytes = rsa_decrypt(ciphertext=ciphertext, private_key=private_key, padding=padding)

    if opts.output:
        with open(opts.output, 'wb') as f:
            f.write(output_bytes)
    else:
        print(output_bytes)


if __name__ == '__main__':
    main()