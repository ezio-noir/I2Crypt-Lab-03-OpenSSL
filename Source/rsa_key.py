from utils import b256_to_int, int_to_b256, format_integer
from asn1_pem_handler import ASN1Decoder
from math_operation import rsa_encrypt, rsa_decrypt
import hashlib
from abc import ABC, abstractmethod
import sys


HASHING_ALGORITHM_IDENTIFIER_PREFIXES = {
    hashlib.md5: b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    hashlib.sha1: b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    hashlib.sha224: b'\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c',
    hashlib.sha256: b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    hashlib.sha384: b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    hashlib.sha512: b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}


# Abstract base class for RSA private and public key
class RSAKey(ABC):
    # Return key length in bytes (i.e. number of bytes of `n`)
    def key_length(self) -> int:
        if not hasattr(self, '_key_length'):
            count = 0
            n = self.n
            while n > 0:
                n = n >> 8
                count += 1
            self._key_length = count
        return self._key_length


    @classmethod
    @abstractmethod
    def load_pem_file(cls):
        pass

    
    @classmethod
    @abstractmethod
    def from_pem_file(cls):
        pass


    @abstractmethod
    def encrypt(self):
        pass


    @abstractmethod
    def decrypt(self):
        pass


    @abstractmethod
    def sign(self):
        pass


    @abstractmethod
    def verify(self):
        pass


    def output(self, path=None, base: int = 10, order='big') -> None:
        output_stream = open(path, 'w') if path else sys.stdout
        for parameter, value in self.__dict__.items():
            output_stream.write('{}: {}\n'.format(parameter, format_integer(value, base, order)))


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
    

    def encrypt(self, **kwargs):
        return self.encrypt_pkcs1v15(**kwargs)
    

    def decrypt(self, **kwargs):
        return self.decrypt_pkcs1v15(**kwargs)
    

    def sign(self, **kwargs):
        return self.sign_pcks1v15(**kwargs)
    

    def verify(self):
        raise NotImplementedError('Operation is not supported by private key.')
    

    def encrypt_pkcs1v15(self, data: bytes, padding_block_type: bytes = b'\x01'):
        k = self.key_length()

        assert len(data) <= k - 11, 'Message is too long.'

        if padding_block_type == b'\x00':
            padding_string = b'\x00' * (k - 3 - len(data))
        elif padding_block_type == b'\x01':
            padding_string = b'\xFF' * (k - 3 - len(data))
        elif padding_block_type == b'\x02':
            from secrets import randbelow
            padding_string = bytes(randbelow(255) + 1 for _ in range(k - 3 - len(data)))

        encrypted_block = b'\x00' + padding_block_type + padding_string + b'\x00' + data
        x = b256_to_int(encrypted_block)
        y = rsa_decrypt(x, self.n, self.p, self.q, self.dmp1, self.dmq1, self.iqmp)
        ciphertext = int_to_b256(y, length=k)

        return ciphertext
    

    def decrypt_pkcs1v15(self, ciphertext: bytes) -> tuple:
        y = b256_to_int(ciphertext)
        x = rsa_decrypt(y, self.n, self.p, self.q, self.dmp1, self.dmq1, self.iqmp)
        plaintext = int_to_b256(x, length=self.key_length())
        message = plaintext.split(b'\x00')[-1]
        return (plaintext, message)
    

    def sign_pcks1v15(self, message: bytes, hash=None) -> bytes:
        if hash is not None:
            hashed = hash(message).digest()
            hashed_prefix = HASHING_ALGORITHM_IDENTIFIER_PREFIXES[hash]
            data = hashed_prefix + hashed
        else:
            data = message

        assert len(data) <= self.key_length() - 11, "Total length exceeds limit."

        return self.encrypt(data=data)
    

# RSA public key class
class RSAPublicKey(RSAKey):
    def __init__(self, parameters: dict):
        self.n = parameters['n']
        self.e = parameters['e']


    # Return key length in bytes (i.e. number of bytes of `n`)
    def key_length(self) -> int:
        if not hasattr(self, '_key_length'):
            count = 0
            n = self.n
            while n > 0:
                n = n >> 8
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

        key_parameters = ASN1Decoder.parse_asn1(key_info[1]['value'])[0]['value']
        result['parameters'] = {
            'n': key_parameters[0]['value'],
            'e': key_parameters[1]['value'],
        }
        return result
    

    @classmethod
    def from_pem_file(cls, path):
        return cls(parameters=cls.load_pem_file(path)['parameters'])
    

    def encrypt(self, **kwargs):
        return self.encrypt_pkcs1v15(**kwargs)
    
    
    def decrypt(self, **kwargs):
        return self.decrypt_pkcs1v15(**kwargs)
    

    def sign(self, **kwargs):
        raise NotImplementedError('Operation is not supported by public key.')


    def verify(self, **kwargs):
        return self.verify_pkcs1v15(**kwargs)
    

    def encrypt_pkcs1v15(self, message: bytes, padding_block_type: bytes = b'\x02') -> bytes:
        k = self.key_length()

        assert len(message) <= k - 11, 'Message is too long.'

        if padding_block_type == b'\x00':
            padding_string = b'\x00' * (k - 3 - len(message))
        elif padding_block_type == b'\x01':
            padding_string = b'\xFF' * (k - 3 - len(message))
        elif padding_block_type == b'\x02':
            from secrets import randbelow
            padding_string = bytes(randbelow(255) + 1 for _ in range(k - 3 - len(message)))

        encrypted_block = b'\x00' + padding_block_type + padding_string + b'\x00' + message
        x = b256_to_int(encrypted_block)
        y = rsa_encrypt(x, self.e, self.n)
        ciphertext = int_to_b256(y, length=k)

        return ciphertext
    

    def decrypt_pkcs1v15(self, data: bytes) -> bytes:
        y = b256_to_int(data)
        x = rsa_encrypt(y, self.e, self.n)
        plaintext = int_to_b256(x, length=self.key_length())
        return plaintext
    

    def verify_pkcs1v15(self, message, signed, hash=None) -> bool:
        if hash is not None:
            digested_message = hash(message).digest()
        else:
            digested_message = message

        plaintext = self.decrypt(data=signed)
        hash_prefix = HASHING_ALGORITHM_IDENTIFIER_PREFIXES[hash]
        digest_info = ASN1Decoder.parse_asn1(plaintext[- len(hash_prefix) - len(digested_message):])[0]
        digested_message_ = digest_info['value'][1]['value']

        result = (hash_prefix == plaintext[- len(hash_prefix) - len(digested_message_):- len(digested_message_)]) and (digested_message == digested_message_)

        return result