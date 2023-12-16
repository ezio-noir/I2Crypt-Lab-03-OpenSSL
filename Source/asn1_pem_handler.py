from utils import b256_to_int, int_to_b256
import base64


class ASN1Decoder:
    # Map tags with tag names
    TAGS = {
        0x00: 'EOC',
        0x02: 'INTEGER',
        0x03: 'BIT STRING',
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


    # Parse object identifier
    @classmethod
    def _parse_oid(cls, octets: bytes) -> str:
        values = []
        # Read first octet
        values.append(octets[0] // 40)
        values.append(octets[0] % 40)
        # Read remaining octets
        value = 0
        for i in range(1, len(octets)):
            value = (value << 7) + (octets[i] & 0b01111111)
            if octets[i] < 0x80:
                values.append(value)
                value = 0
        values_str = [str(value) for value in values]
        return '.'.join(values_str)


    # Parse identifier octet
    @classmethod
    def _parse_identifier(cls, octet: int):
        return (cls.CLASSES[octet >> 6], cls.TAGS[octet & 0b11111])
    

    # Parse length octets. Return (length of header, length of length field)
    @classmethod
    def _parse_length(cls, octets: int):
        if octets[0] < 128:
            return (octets[0], 1)
        else:
            length_length = octets[0] & 0b01111111
            return b256_to_int(octets[1:1+length_length]), 1 + length_length


    # (Recursively) Parse raw bytes into ASN.1 structure
    @classmethod
    def parse_asn1(cls, data: bytes) -> list:
        result = []
        bytes_read = 0
        while bytes_read < len(data):
            class_, tag = cls._parse_identifier(data[bytes_read])
            org_tag = data[bytes_read]
            bytes_read += 1
            length, l_length = cls._parse_length(data[bytes_read:])
            bytes_read += l_length
            value = data[bytes_read:bytes_read+length]
            bytes_read += length
            # If the tag is of a construced type, then decode the inner value
            if tag == 'SEQUENCE':
                result.append({
                    'class': class_,
                    'tag': tag,
                    'length': length,
                    'value': cls.parse_asn1(value)
                })
            # Else (i.e. primitive type), then the value is just raw value
            else:
                if tag == 'INTEGER':
                    value = b256_to_int(value)
                elif tag == 'BIT STRING':
                    value = value[1:]
                elif tag == 'NULL':
                    length = 0
                elif tag == 'OBJECT IDENTIFIER':
                    value = cls._parse_oid(value)
                result.append({
                    'class': class_,
                    'tag': tag,
                    'length': length,
                    'value': value      
                })
        return result
    

    # Open a PEM file, decode and parse the ASN.1
    @classmethod
    def from_pem_file(cls, path: str) -> list:
        with open(path, 'rb') as f:
            data = f.read()
            splitted = data.splitlines()
            key_data = b''.join(splitted[1:-1])
            key_data_bytes = base64.b64decode(key_data)
        return cls.parse_asn1(key_data_bytes)
    

class ASN1Encoder:
    TAGS = {
        'INTEGER': 0x02,
        'BIT STRING': 0x03,
        'OCTET STRING': 0x04,
        'NULL': 0x05,
        'OBJECT IDENTIFIER': 0x06,
        'SEQUENCE': 0x10,
    }
    CLASSES = {
        'UNIVERSAL': 0b00,
        'APPLICATION': 0b01,
        'CONTEXT-SPECIFIED': 0b10,
        'PRIVATE': 0b11,
    }


    @classmethod
    def _encode_oid(cls, oid: str) -> bytes:
        values = [int(value) for value in oid.split('.')]
        result = b''
        result += bytes([values[0] * 40 + values[1]])
        for value in values[2:]:
            to_bytes = b''
            while value > 0:
                if to_bytes == b'':
                    to_bytes += bytes([value & 0b01111111])
                else:
                    to_bytes += bytes([(value & 0b01111111) | 0b10000000])
                value >>= 7
            result += to_bytes[::-1]
        return result


    # Encode identifier
    @classmethod
    def _encode_identifier(cls, class_: str, tag: str) -> bytes:
        return bytes([(cls.CLASSES[class_] << 6) | (cls.TAGS[tag])])
    

    @classmethod
    def _encode_length(cls, length: int) -> bytes:
        if length < 128:
            return length.to_bytes(length=1, byteorder='big')
        else:
            b256 = int_to_b256(length)
            return bytes([0b10000000 | (len(b256))]) + int_to_b256(length)


    @classmethod
    def encode_asn1(cls, data: list) -> bytes:
        result = b''
        for entry in data:
            result += cls._encode_identifier(entry['class'], entry['tag'])
            if entry['tag'] == 'SEQUENCE':
                value = cls.encode_asn1(entry['value'])
            else:
                if entry['tag'] == 'INTEGER':
                    value = int_to_b256(entry['value'], length=entry['length'], order='big')
                elif entry['tag'] == 'BIT STRING':
                    value = b'\x00' + entry['value']
                elif entry['tag'] == 'OBJECT IDENTIFIER':
                    value = cls._encode_oid(entry['value'])
                else:
                    value = entry['value']
            length = cls._encode_length(len(value))
            result += length
            result += value
        return result