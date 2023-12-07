import asn1
import sys
import base64


decoder = asn1.Decoder()


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


def extract_private_key_pkcs8(decoded_der: list):
    result = {}

    key_info = decoded_der[0]['value']
    result['version'] = key_info[0]['value']
    result['private_key_algorithm'] = key_info[1]['value']
    result['private_key'] = {}

    private_key = decode(key_info[2]['value'])
    private_key_info = private_key[0]['value']

    result['private_key']['enc_algo_id'] = private_key_info[0]['value']
    result['private_key']['modulus'] = private_key_info[1]['value']
    result['private_key']['public_exponent'] = private_key_info[2]['value']
    result['private_key']['private_exponent'] = private_key_info[3]['value']
    result['private_key']['prime_1'] = private_key_info[4]['value']
    result['private_key']['prime_2'] = private_key_info[5]['value']
    result['private_key']['exponent_1'] = private_key_info[6]['value']
    result['private_key']['exponent_2'] = private_key_info[7]['value']
    result['private_key']['coefficient'] = private_key_info[8]['value']

    return result



def main():
    with open(sys.argv[1], 'r') as f:
        lines = f.readlines()
        der = ''.join(line.strip() for line in lines[1:-1])
        data = base64.b64decode(der)

        decoded = decode(data)
        infos = extract_private_key_pkcs8(decoded)

        print('version: {}'.format(infos['version']))
        print('algorithm: {}'.format(infos['private_key_algorithm']))
        print('private_key:')
        for key, value in infos['private_key'].items():
            print('\t', end='')
            print(f'{key}: {value}')


if __name__ == '__main__':
    main()