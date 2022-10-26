# Sign a file with a private key using OpenSSL

# Generate Private Key
openssl genrsa -out privatekey.pem 2048

# Sign
openssl dgst -sha256 -sign privatekey.pem -out data.txt.signature data.txt

# Generate The Public Key
openssl rsa -in privatekey.pem -outform PEM -pubout -out publickey.pem

# Verify
openssl dgst -sha256 -verify publickey.pem -signature data.txt.signature data.txt

