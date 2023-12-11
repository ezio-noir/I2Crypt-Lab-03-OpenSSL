#



# RSA encryption and decryption
- OpenSSL command for encryption:
```openssl pkeyutl -in message.txt -out ciphertext_.txt -inkey pub.pem -pubin -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256```