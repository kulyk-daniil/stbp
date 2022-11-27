import rsa
import hashlib
import hmac
import base64


class RSAKeyGen:

    def __init__(self, path_to_public_key, path_to_private_key):
        self.path_to_public_key = path_to_public_key
        self.path_to_private_key = path_to_private_key

    def generate_license(self, email):
        with open(self.path_to_private_key, 'rb') as file:
            key = rsa.PrivateKey.load_pkcs1(file.read())
        return base64.b64encode(rsa.sign(email.encode(), key, 'SHA-1')).decode()

    def new_rsa(self):
        public, private = rsa.newkeys(512)
        with open(self.path_to_public_key, 'wb') as file:
            file.write(public.save_pkcs1())
        with open(self.path_to_private_key, 'wb') as file:
            file.write(private.save_pkcs1())

    def valid(self, email, license_key):
        with open(self.path_to_public_key, 'rb') as file:
            key = rsa.PublicKey.load_pkcs1(file.read())
        try:
            rsa.verify(email.encode(), base64.b64decode(license_key), key)
        except rsa.VerificationError:
            return False
        else:
            return True


class SHA1KeyGen:

    def __init__(self, secret):
        self.secret = secret.encode()

    def generate_license(self, email):
        hashed = hmac.new(self.secret, email.encode(), hashlib.sha1)
        return base64.encodebytes(hashed.digest()).decode('utf-8').rstrip('\n')

    def valid(self, email, key):
        hashed = hmac.new(self.secret, email.encode(), hashlib.sha1)
        return base64.encodebytes(hashed.digest()).decode('utf-8').rstrip('\n') == key


if __name__ == '__main__':
    email = 'daniil2022kulyk@mail.com'

    PUBLIC_KEY_PATH = './public_key.pem'
    PRIVATE_KEY_PATH = './private_key.pem'
    keygen = RSAKeyGen(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH)
    keygen.new_rsa()
    key = keygen.generate_license(email)
    print(f'RSA: LICENSE KEY   : {key}')
    is_valid = keygen.valid(email, key)
    print(f'RSA: IS VALID      : {is_valid}')

    SECRET = 'fa4db30478c45ef'
    keygen = SHA1KeyGen(SECRET)
    key = keygen.generate_license(email)
    print(f'SHA1: LICENSE KEY   : {key}')
    is_valid = keygen.valid(email, key)
    print(f'SHA1: IS VALID      : {is_valid}')
