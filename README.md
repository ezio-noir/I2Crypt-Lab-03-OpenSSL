#



# RSA encryption and decryption
- OpenSSL command for encryption:
    - With specified padding:
    ```openssl pkeyutl -in message.txt -out ciphertext_txt -inkey pub.pem -pubin -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256```
    - With default padding:
    ```openssl pkeyutl -in message.txt -out ciphertext.txt -inkey pub.pem -pubin -encrypt```
- `rsa_encryption.py` encryption:
    - With specified padding:
    - With default padding:
    ```python Source/rsa_encryption.py -i message.txt -o ciphertext.txt -k pub.pem -e -p PKCS1v15```
- OpenSSL command for decryption:
    - With specified padding:
    - With default padding:
    ```openssl pkeyutl -in ciphertext.txt -out decoded.txt -inkey priv.pem -decrypt```
- `rsa_encryption.py` decryption:
    - With specified padding:
    ```python Source/rsa_encryption.py -i ciphertext_test.txt -k priv.pem -d -p OAEP -pA mgf:MGF1 -pA mgf_hash:SHA256 -pA hash:SHA256```
    - With default padding:
    ```python Source/rsa_encryption.py -i ciphertext.txt -k priv.pem -d -p PKCS1v15```