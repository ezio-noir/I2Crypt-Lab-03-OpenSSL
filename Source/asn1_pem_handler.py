from utils import b256_to_int
import base64


class ASN1Decoder:
    # Map tags with tag names
    TAGS = {
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