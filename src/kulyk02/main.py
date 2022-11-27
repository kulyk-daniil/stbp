import aes

text = b'Daniil Kulyk'

# key = os.urandom(16)
key = b"\x02\xc6\x0c\xde}\xc1\x87S\xae\xb6\x04\xd8'\xa2\xc5z"

# iv = os.urandom(16)
iv = b"*'\xd4\xb0\x85\xa4\x17N\x05\xd9z\xcc\x88^\xda("

encrypted = aes.AES(key).encrypt_ctr(text, iv)


print(f'Заданий текст          :{text}')
print(f'Текст у байтах         :{text.hex()}')
print(f'Зашифрований текст     :{encrypted.hex()}')

decrypted = aes.AES(key).decrypt_ctr(encrypted, iv)
print(f'Розшифрований текст    :{decrypted}')
print(f'Розшифровано в байтах  :{decrypted.hex()}')
