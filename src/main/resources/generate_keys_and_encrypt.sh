# Generate private key with pkcs1 encoding
openssl genrsa -out private_key_rsa_4096_pkcs1.pem 4096

# Convert private key to pkcs8 encoding
openssl pkcs8 -topk8 -in private_key_rsa_4096_pkcs1.pem -inform pem -out private_key_rsa_4096_pkcs8-exported.pem -outform pem -nocrypt

# Export public key in pkcs8 format
openssl rsa -pubout -outform pem -in private_key_rsa_4096_pkcs1.pem -out public_key_rsa_4096_pkcs8-exported.pem

# encrypt a file
openssl rsautl -encrypt -inkey public_key_rsa_4096_pkcs8-exported.pem -pubin -in file_unencrypted.txt | openssl enc -A -base64 > file_encrypted_and_encoded.txt

# encrypts values in a file
sed "s|XXXX|`printf "SECRET" | openssl rsautl -encrypt -inkey public_key_rsa_4096_pkcs8-exported.pem -pubin | openssl enc -A -base64`|g" some_template.properties > some_tmp1.properties

sed "s|YYYY|`printf "123-45-7890" | openssl rsautl -encrypt -inkey public_key_rsa_4096_pkcs8-exported.pem -pubin | openssl enc -A -base64`|g" some_tmp1.properties > some_app.properties
