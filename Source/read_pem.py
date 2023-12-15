from argparse import ArgumentParser
import base64



# Map tags with tag names
TAGS = {
    0x02: 'INTERGER',
    0x04: 'OCTET STRING',
    0x05: 'NULL',
    0x06: 'OBJECT IDENTIFIER',
    0x10: 'SEQUENCE',
}


# Map classes with class names
CLASSES = {
    0b00: 'UNIVERSAL',
    0b01: 'APPLICATION',
    0b10: 'CONTEXT-SPECIFIED',
    0b11: 'PRIVATE',
}


# Decode a PEM file into raw bytes
def decode_pem_file(path) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
        splitted = data.splitlines()
        key_data = b''.join(splitted[1:-1])
        return base64.b64decode(key_data)
    

# Parse identifier octet
def parse_identifier(octet: int):
    return (CLASSES[octet >> 6], TAGS[octet & 0b11111])


# Convert base-256 integer into base-10 integer
def convert_256_10(b256: bytes):
    x = 0
    for i in range(len(b256)):
        x = (x << 8) + b256[i]
    return x


# Parse length octets. Return (length of header, length of length field)
def parse_length(octets: int):
    if octets[0] < 128:
        return (octets[0], 1)
    else:
        length_length = octets[0] & 0b01111111
        return convert_256_10(octets[1:1+length_length]), 1 + length_length
    

# (Recursively) Parse raw bytes into ASN.1 structure
def parse_asn1(data: bytes):
    result = []
    bytes_read = 0

    while bytes_read < len(data):
        class_, tag = parse_identifier(data[bytes_read])
        bytes_read += 1
        length, l_length = parse_length(data[bytes_read:])
        bytes_read += l_length
        value = data[bytes_read:bytes_read+length]
        bytes_read += length
        
        if tag == 'SEQUENCE':
            result.append({
                'class': class_,
                'tag': tag,
                'length': length,
                'value': parse_asn1(value)
            })
        else:
            result.append({
                'class': class_,
                'tag': tag,
                'length': length,
                'value': value               
            })

    return result


# Read a PEM file and extract RSA private key information
def load_pem_private_key(path):
    assert path.endswith('.pem'), 'Must be a .pem file.'
    
    result = {}

    # Read bytes decoded from .pem file
    raw_bytes = decode_pem_file(path)
    # Convert bytes to ASN.1 structure
    asn1 = parse_asn1(raw_bytes)
    key_info = asn1[0]['value']
    # Key version
    result['version'] = key_info[0]['value']
    # Encryption algorithm
    result['algorithm'] = key_info[1]['value']
    # Private key parameters
    key_parameters = parse_asn1(key_info[2]['value'])[0]['value']
    result['parameters'] = {
        'key_encryption_algorithm_id': key_parameters[0]['value'][0],
        'n': key_parameters[1]['value'],
        'e': key_parameters[2]['value'],
        'd': key_parameters[3]['value'],
        'p': key_parameters[4]['value'],
        'q': key_parameters[5]['value'],
        'dmp1': key_parameters[6]['value'],
        'dmq1': key_parameters[7]['value'],
        'q_inv': key_parameters[8]['value'],
    }

    return result


def load_pem_public_key(path):
    assert path.endswith('.pem'), 'Must be a .pem file'


def main():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input')
    opts = parser.parse_args()

    key_bytes = decode_pem_file(opts.input)
    info = load_pem_private_key(opts.input)
    print(info)


if __name__ == '__main__':
    main()