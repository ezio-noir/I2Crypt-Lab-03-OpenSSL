from argparse import ArgumentParser
import sys


def load_rsa_private_key(path, password=None, extract_info=True) -> dict:
    from cryptography.hazmat.primitives import serialization as srl

    with open(path, 'rb') as f:
        private_key = srl.load_pem_private_key(data=f.read(), password=password)
    if extract_info == True:
        return {
            'key': private_key.private_bytes(
                encoding=srl.Encoding.PEM,
                format=srl.PrivateFormat.PKCS8,
                encryption_algorithm=srl.NoEncryption()
            ),
            'parameters': {
                'n': private_key.public_key().public_numbers().n,
                'e': private_key.public_key().public_numbers().e,
                'd': private_key.private_numbers().d,
                'p': private_key.private_numbers().p,
                'q': private_key.private_numbers().q,
                # 'x': private_key.private_numbers().dmp1,
                # 'y': private_key.public_key().public_numbers().y,
                # 'q_inv': private_key.private_numbers().iqmp
            }
        }
    return private_key
    

def load_rsa_public_key(path, extract_info=True) -> dict:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    with open(path, 'rb') as f:
        public_key = load_pem_public_key(data=f.read())
    if extract_info == True:
        return {
            # 'key': public_key.public_bytes(),
            'parameters': {
                'n': public_key.public_numbers().n,
                'e': public_key.public_numbers().e,
                # 'x': public_key.public_numbers().x,
                # 'y': public_key.public_numbers().y,
            }
        }
    return public_key


def format_integer(integer: int, base: int = 10, order: str = 'big') -> str:
    if order == 'little':
        byte_string = integer.to_bytes(
            length=(integer.bit_length() + 7) // 8,
            byteorder='big'
        )
        integer = int.from_bytes(byte_string, byteorder='little')
    
    if base == 2:
        base_converter = bin
    elif base == 10:
        base_converter = lambda x: x
    elif base == 16:
        base_converter = hex

    return f'{base_converter(integer)}'


def print_key_info(key_info: dict, opts) -> None:
    output_stream = open(opts.output, 'w') if opts.output else sys.stdout
    base = opts.output_base if opts.output_base else 10
    order = opts.output_order if opts.output_order else 'big'

    output_stream.write('RSA {} key (integer format: base {}, {}-endian):\n'.format(
        'private' if opts.private else 'public',
        base,
        order
    ))
    # output_stream.write('\t- Key: {}'.format(format_integer(key_info['key'], base, order)))
    for parameter, value in key_info['parameters'].items():
        output_stream.write('\t- {}: {}\n'.format(parameter, format_integer(value, base, order)))


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', help='Input file path (.pem)')
    parser.add_argument('-o', '--output', help='Output file path.')
    parser.add_argument('-p', '--password', help='Password for private key.')
    parser.add_argument('--private', action='store_true', help='To read private key file.')
    parser.add_argument('--public', action='store_true', help='To read public key file.')
    parser.add_argument('-oB', '--output-base', type=int, default=10, help='Display integer output in specified base.')
    parser.add_argument('-oO', '--output-order', choices=('little', 'big'), default='big', help='Display interger output as little endian/big endian.')
    opts = parser.parse_args()

    if opts.private:
        key_info = load_rsa_private_key(opts.input, password=opts.password)
    elif opts.public:
        key_info = load_rsa_public_key(opts.input)
    print_key_info(key_info, opts)


if __name__ == '__main__':
    main()