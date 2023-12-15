from abc import ABC, abstractmethod
import base64
import sys


def b256_to_int(octets: bytes) -> int:
    x = 0
    for i in range(len(octets)):
        x = (x << 8) + octets[i]
    return x


def int_to_b256(x: int, length=None) -> bytes:
    result = b''
    while x > 0:
        result += bytes([x & 0b11111111])
        x = x >> 8
    if length is not None and length > len(result):
        result += b'\x00' * (length - len(result))
    return result[::-1]


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


    # Parse identifier octet
    @classmethod
    def _parse_identifier(cls, octet: int):
        return (cls.CLASSES[octet >> 6], cls.TAGS[octet & 0b11111])
    

    # Convert base-256 integer into base-10 integer
    @classmethod
    def _convert_256_10(cls, octets: bytes):
        x = 0
        for i in range(len(octets)):
            x = (x << 8) + octets[i]
        return x
    

    # Parse length octets. Return (length of header, length of length field)
    @classmethod
    def _parse_length(cls, octets: int):
        if octets[0] < 128:
            return (octets[0], 1)
        else:
            length_length = octets[0] & 0b01111111
            return cls._convert_256_10(octets[1:1+length_length]), 1 + length_length


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
                    value = cls._convert_256_10(value)
                elif tag == 'BIT STRING':
                    value = value[1:]
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


# Abstract base class for RSA private and public key
class RSAKey(ABC):
    @abstractmethod
    def key_length(self) -> int:
        pass


    @classmethod
    @abstractmethod
    def load_pem_file(cls):
        pass

    
    @classmethod
    @abstractmethod
    def from_pem_file(cls):
        pass


    def _format_integer(self, integer: int, base: int = 10, order: str = 'big') -> str:
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


    def output(self, path=None, base: int = 10, order='big') -> None:
        output_stream = open(path, 'w') if path else sys.stdout
        for parameter, value in self.__dict__.items():
            output_stream.write('{}: {}\n'.format(parameter, self._format_integer(value, base, order)))
    

# RSA private key class
class RSAPrivateKey(RSAKey):
    def __init__(self, parameters: dict):
        self.n = parameters['n']
        self.e = parameters['e']
        self.d = parameters['d']
        self.p = parameters['p']
        self.q = parameters['q']
        self.dmp1 = parameters['dmp1']
        self.dmq1 = parameters['dmq1']
        self.iqmp = parameters['iqmp']


    def key_length(self) -> int:
        if not hasattr(self, '_key_length'):
            count = 0
            n = self.n
            while n > 0:
                n = n >> 1
                count += 1
            self._key_length = count
        return self._key_length


    @classmethod
    def load_pem_file(cls, path) -> dict:
        assert path.endswith('.pem'), 'Must be a .pem file.'       
        result = {}
        # Convert bytes to ASN.1 structure
        asn1 = ASN1Decoder.from_pem_file(path)
        key_info = asn1[0]['value']
        # Key version
        result['version'] = key_info[0]['value']
        # Encryption algorithm
        result['algorithm'] = key_info[1]['value']
        # Private key parameters
        key_parameters = ASN1Decoder.parse_asn1(key_info[2]['value'])[0]['value']
        result['parameters'] = {
            # 'key_encryption_algorithm_id': key_parameters[0]['value'][0],
            'key_encryption_algorithm_id': key_parameters[0]['value'],
            'n': key_parameters[1]['value'],
            'e': key_parameters[2]['value'],
            'd': key_parameters[3]['value'],
            'p': key_parameters[4]['value'],
            'q': key_parameters[5]['value'],
            'dmp1': key_parameters[6]['value'],
            'dmq1': key_parameters[7]['value'],
            'iqmp': key_parameters[8]['value'],
        }
        return result
    

    @classmethod
    def from_pem_file(cls, path):
        return cls(parameters=cls.load_pem_file(path)['parameters'])
    

    def decrypt(self, block_type, data) -> bytes:
        y = b256_to_int(data)
        x = pow(y, self.d, self.n)
        print(x % self.n)
        plaintext = int_to_b256(x)
        return plaintext

    

# RSA public key class
class RSAPublicKey(RSAKey):
    def __init__(self, parameters: dict):
        self.n = parameters['n']
        self.e = parameters['e']


    def key_length(self) -> int:
        if not hasattr(self, '_key_length'):
            count = 0
            n = self.n
            while n > 0:
                n = n >> 1
                count += 1
            self._key_length = count
        return self._key_length


    @classmethod
    def load_pem_file(cls, path) -> dict:
        assert path.endswith('.pem'), 'Must be a .pem file.'       
        result = {}
        # Convert bytes to ASN.1 structure
        asn1 = ASN1Decoder.from_pem_file(path)
        key_info = asn1[0]['value']
        # Key version
        result['version'] = key_info[0]['value']
        # # Encryption algorithm
        # result['algorithm'] = key_info[1]['value']
        # Private key parameters
        key_parameters = ASN1Decoder.parse_asn1(key_info[1]['value'])[0]['value']
        result['parameters'] = {
            # 'key_encryption_algorithm_id': key_parameters[0]['value'][0],
            # 'key_encryption_algorithm_id': key_parameters[0]['value'],
            'n': key_parameters[0]['value'],
            'e': key_parameters[1]['value'],
        }
        return result
    

    @classmethod
    def from_pem_file(cls, path):
        return cls(parameters=cls.load_pem_file(path)['parameters'])
    

    def encrypt_pkcs1v15(self, block_type: bytes, data: bytes) -> bytes:
        k = self.key_length()
        assert len(data) <= k - 11, 'Message is too long.'

        if block_type == b'\x00':
            padding_string = b'\x00' * (k - 3 - len(data))
        elif block_type == b'\x01':
            padding_string = b'\xFF' * (k - 3 - len(data))
        elif block_type == b'\x02':
            import random
            x = random.getrandbits(8 * (k - 3 - len(data)))
            padding_string = int_to_b256(x, length=k - 3 - len(data))
            # pass    # A pseudorandom octet

        encrypted_block = b'\x00' + block_type + padding_string + b'\x00' + data
        x = b256_to_int(encrypted_block)
        y = pow(x, self.e, self.n)
        print(x % self.n)
        ciphertext = int_to_b256(y)

        return ciphertext