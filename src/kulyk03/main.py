from my_rsa import RSA, RSAKey
import rsa


def my_rsa(text, bits):
    key = RSAKey(bits=bits)
    public_key = (key.e, key.N)
    private_key = (key.d, key.N)

    print(f'Розроблений RSA: public_key            : {public_key}')
    print(f'Розроблений RSA: private_key           : {private_key}')
    cipher = RSA(key)

    encrypted = cipher.encrypt_data(text.encode())

    print(f'Розроблений RSA: Заданий текст         : {text}')
    print(f'Розроблений RSA: Зашифрований текст    : {encrypted.hex()}')

    decrypted = cipher.decrypt_data(encrypted)
    print(f'Розроблений RSA: Розшифрований текст   : {decrypted.decode()}')


def rsa_lib(text, bits):
    public_key, private_key = rsa.newkeys(bits)
    print(f'RSA_LIB: public_key                    : {public_key}')
    print(f'RSA_LIB: private_key                   : {private_key}')

    encrypted = rsa.encrypt(text.encode(), public_key)

    print(f'RSA_LIB: Заданий текст                 : {text}')
    print(f'RSA_LIB: Зашифрований текст            : {encrypted.hex()}')

    decrypted = rsa.decrypt(encrypted, private_key)

    print(f'RSA_LIB: Розшифрований текст           : {decrypted.decode()}')


if __name__ == '__main__':
    TEXT = 'Daniil Kulyk'
    BITS = 1024

    my_rsa(TEXT, BITS)
    print('')
    print('')
    rsa_lib(TEXT, BITS)
