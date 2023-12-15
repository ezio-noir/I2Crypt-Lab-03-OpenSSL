from RSAKey import *
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', help='Input file path (.pem)')
    parser.add_argument('-o', '--output', help='Output file path.')
    # parser.add_argument('-p', '--password', help='Password for private key.')
    parser.add_argument('--private', action='store_true', help='To read private key file.')
    parser.add_argument('--public', action='store_true', help='To read public key file.')
    parser.add_argument('-oB', '--output-base', type=int, default=10, help='Display integer output in specified base.')
    parser.add_argument('-oO', '--output-order', choices=('little', 'big'), default='big', help='Display interger output as little endian/big endian.')
    opts = parser.parse_args()

    if opts.private:
        key = RSAPrivateKey.from_pem_file(path=opts.input)
    elif opts.public:
        key = RSAPublicKey.from_pem_file(path=opts.input)
    
    key.output(base=opts.output_base, order=opts.output_order)


if __name__ == '__main__':
    main()