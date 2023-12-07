import asn1
import sys
import base64
from argparse import ArgumentParser


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


def decode(data) -> list:
    assert isinstance(data, bytes)
    
    decoder.start(data)
    return read_der(decoder)


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


def extract_private_key_pkcs8(decoded_der: list) -> dict:
    result = {}

    key_info = decoded_der[0]['value']
    result['version'] = key_info[0]['value']
    result['algorithm'] = 'RSA' if key_info[1]['value'] == RSA_OID else key_info[1]['value']
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


def extract_public_key_pkcs8(decoded_der: list) -> dict:
    result = {}

    key_info = decoded_der[0]['value']
    result['version'] = key_info[0]['value']
    result['algorithm'] = 'RSA' if key_info[1]['value'] == RSA_OID else key_info[1]['value']
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


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input')
    parser.add_argument('-o', '--output')
    parser.add_argument('--private', action='store_true')

    opts = parser.parse_args()

    with open(opts.input, 'r') as f:
        lines = f.readlines()
        der = ''.join(line.strip() for line in lines[1:-1])
        data = base64.b64decode(der)
        decoded = decode(data)

    if opts.private:
        private_key_info = extract_private_key_pkcs8(decoded)
        print(private_key_info)


if __name__ == '__main__':
    main()