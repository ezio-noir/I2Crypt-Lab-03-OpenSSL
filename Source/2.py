import asn1
import base64
from argparse import ArgumentParser
import sys


decoder = asn1.Decoder()
RSA_OID = '1.2.840.113549.1.1.1'
RSA_NOTATION = {
    'modulus': 'n',
    'public_exponent': 'e',
    'private_exponent': 'd',
    'prime_1': 'p',
    'prime_2': 'q',
    'exponent_1': 'x',
    'exponent_2': 'y',
    'coefficient': 'q_inv'
}


# Decode BER-encoded ASN.1
def decode(data) -> list:
    assert isinstance(data, bytes), 'Expected input as bytes.'
    decoder.start(data)
    return read_der(decoder)


# Recuresively decode BER-encoded ASN.1
def read_der(decoder: asn1.Decoder) -> list:
    result = []
    while not decoder.eof():
        tag = decoder.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = decoder.read()
            result.append({
                'class': tag.cls,
                'tag': tag.nr,
                'value': value
            })
        elif tag.typ == asn1.Types.Constructed:
            decoder.enter()
            result.append({
                'class': tag.cls,
                'tag': tag.nr,
                'value': read_der(decoder)
            })
            decoder.leave()
    return result


# Extract private key information from decoded ASN.1
def extract_private_key_pkcs8(decoded_der: list) -> dict:
    result = {}
    result['type'] = 'private'

    key_info = decoded_der[0]['value']
    # assert key_info[1]['value'] == RSA_OID, 'Key encryption algorithm is not RSA.'

    result['version'] = key_info[0]['value']
    result['algorithm'] = key_info[1]['value']
    result['parameters'] = {}

    private_key = decode(key_info[2]['value'])
    key_parameters = private_key[0]['value']

    result['parameters']['key_encryption_algorithm_id'] = key_parameters[0]['value']
    result['parameters']['modulus'] = key_parameters[1]['value']
    result['parameters']['public_exponent'] = key_parameters[2]['value']
    result['parameters']['private_exponent'] = key_parameters[3]['value']
    result['parameters']['prime_1'] = key_parameters[4]['value']
    result['parameters']['prime_2'] = key_parameters[5]['value']
    result['parameters']['exponent_1'] = key_parameters[6]['value']
    result['parameters']['exponent_2'] = key_parameters[7]['value']
    result['parameters']['coefficient'] = key_parameters[8]['value']

    return result


# Extract public key information from decoded ASN.1
def extract_public_key_pkcs8(decoded_der: list) -> dict:
    result = {}
    result['type'] = 'public'

    key_info = decoded_der[0]['value']
    result['algorithm'] = key_info[0]['value']
    result['parameters'] = {}

    public_key = decode(key_info[1]['value'])
    key_parameters = public_key[0]['value']

    result['parameters']['modulus'] = key_parameters[0]['value']
    result['parameters']['public_exponent'] = key_parameters[1]['value']

    return result


def print_key(key_info: dict, base: int = 10, output_stream=sys.stdout) -> None:
    assert base == 2 or base == 10 or base == 16, 'Expected integer base is 2, 10, or 16.'

    if base == 2:
        base_converter = bin
    elif base == 10:
        base_converter = lambda x: x
    elif base == 16:
        base_converter = hex

    if key_info['type'] == 'private':
        output_stream.write('RSA private key:\n')
        output_stream.write('\t- Version: {}\n'.format(key_info['version']))
        output_stream.write('\t- Algorithm (OID): {}\n'.format(key_info['algorithm'][0]['value']))
        output_stream.write('\t- Parameters:\n')
        for para, val in key_info['parameters'].items():
            para_notation = RSA_NOTATION.get(para, None)
            if para_notation:
                output_stream.write('\t\t+ {} ({}) = {}\n'.format(para, para_notation, base_converter(val)))
            else:
                output_stream.write('\t\t+ {}: {}\n'.format(para, val))
    elif key_info['type'] == 'public':
        output_stream.write('RSA public key:\n')
        output_stream.write('\t- Algorithm (OID): {}\n'.format(key_info['algorithm'][0]['value']))
        output_stream.write('\t- Parameters:\n')
        for para, val in key_info['parameters'].items():
            para_notation = RSA_NOTATION.get(para, None)
            if para_notation:
                output_stream.write('\t\t+ {} ({}) = {}\n'.format(para, para_notation, base_converter(val)))
            else:
                output_stream.write('\t\t+ {}: {}\n'.format(para, val))


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input')
    parser.add_argument('-o', '--output')
    parser.add_argument('--private', action='store_true')
    parser.add_argument('--public', action='store_true')
    parser.add_argument('-b', '--base', type=int)

    opts = parser.parse_args()

    with open(opts.input, 'r') as f:
        lines = f.readlines()
        der = ''.join(line.strip() for line in lines[1:-1])
        data = base64.b64decode(der)
        decoded = decode(data)

    if opts.private:
        key_info = extract_private_key_pkcs8(decoded)
    elif opts.public:
        key_info = extract_public_key_pkcs8(decoded)

    if opts.output:
        output_stream = open(opts.output, 'w')
    else:
        output_stream = sys.stdout
    print_key(key_info, base=opts.base, output_stream=output_stream)


if __name__ == '__main__':
    main()