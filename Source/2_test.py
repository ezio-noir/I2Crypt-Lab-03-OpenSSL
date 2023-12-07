from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def read_rsa_private_key_info_from_pem_file(pem_file_path):
    try:
        with open(pem_file_path, 'rb') as pem_file:
            # Load the private key from the PEM file
            private_key = serialization.load_pem_private_key(
                pem_file.read(),
                password=None,  # No password for unencrypted keys
                backend=default_backend()
            )
            
            # Extract information from the private key
            print(private_key.__dict__)
            key_info = {
                'type': 'RSA',
                'modulus': private_key.public_key().public_numbers().n,
                'public_exponent': private_key.public_key().public_numbers().e,
                'private_exponent': private_key.private_numbers().d,
                'prime1': private_key.private_numbers().p,
                'prime2': private_key.private_numbers().q,
                'exponent1': private_key.private_numbers().dmp1,
                'exponent2': private_key.private_numbers().dmq1,
                'coefficient': private_key.private_numbers().iqmp
            }
            
            return key_info
    except Exception as e:
        print(f"Error reading RSA private key information from PEM file: {e}")
        return None

# Replace 'your_private_key.pem' with the actual path to your PEM file
pem_file_path = 'priv.pem'

# Read and print information from the RSA private key
private_key_info = read_rsa_private_key_info_from_pem_file(pem_file_path)

# if private_key_info:
#     print("RSA Private Key Information:")
#     for key, value in private_key_info.items():
#         print(f"{key}: {value}")
