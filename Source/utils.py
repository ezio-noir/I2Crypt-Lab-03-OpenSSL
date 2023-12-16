import sys


# Convert base-256 (string of octets) into integer
def b256_to_int(octets: bytes, order='big') -> int:
    x = 0
    for i in range(len(octets)):
        x = (x << 8) + octets[i]
    return x


# Convert an integer into base-256 (string of octets)
def int_to_b256(x: int, length=None, order='big') -> bytes:
    result = b''
    while x > 0:
        result += bytes([x & 0b11111111])
        x = x >> 8
    if length is not None and length > len(result):
        result += b'\x00' * (length - len(result))
    return result[::-1] if order =='big' else result


# Format an integer with given base and order
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


# Print a nested dict
def print_dict(data: dict, path=None, indent: int = 0) -> None:
    if path:
        output_stream = open(path, 'w')
    else:
        output_stream = sys.stdout
    print_recursively(data, output_stream, 1)


# Print a dict recursively
def print_recursively(data: dict, output_stream, indent: int = 0) -> None:
    for key, value in data.items():
        if isinstance(value, dict):
            output_stream.write('\t' * indent + '{}: \{\n'.format(key))
            print_recursively(value, output_stream, indent + 1)
            output_stream.write('\t' * indent + '}\n')
        else:
            output_stream.write('\t' * indent + '{}: {}\n'.format(key, value))