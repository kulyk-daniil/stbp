import hashlib
import unicodedata
from struct import pack
import pandas as pd
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC
from Crypto.PublicKey import RSA


def get_2048_words(lang):
    """
    Функція повертає словник із парами <індекс, слово>
    де індекси приймають значення від 0 до 2047
    """
    if lang == 'en':
        df = pd.read_csv(
            './src/kulyk04/en_words.txt',
            names=['words']
        ).reset_index().set_index('words')

        nums = df.to_dict()['index']
    elif lang == 'ua':
        df = pd.read_csv(
            './src/kulyk04/ua_words.txt',
            names=['words']
        ).reset_index().set_index('words')

        nums = df.to_dict()['index']

    return nums


class PRNG(object):
    """
    Клас, що утримує в собі значення seed
    """
    def __init__(self, seed):
        self.index = 0
        self.seed = seed
        self.buffer = b""

    def __call__(self, n):
        while len(self.buffer) < n:
            self.buffer += HMAC.new(self.seed +
                                    pack("<I", self.index)).digest()
            self.index += 1
        result, self.buffer = self.buffer[:n], self.buffer[n:]
        return result


def encrypt(text, mnemonic):
    """Функція, що зашифровує задане повідолення за допомогою
    заданої мнемонічної фрази"""
    rsa = RSA.generate(1024, randfunc=PRNG(get_seed(mnemonic)))
    public_key = rsa.public_key().export_key('PEM')
    print(f'PUBLIC KEY           : {public_key}')
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_text = cipher.encrypt(text)

    return encrypted_text


def decrypt(encrypted_text, mnemonic):
    """Функція, що дешифрує задане повідолення за допомогою
    заданої мнемонічної фрази"""
    rsa = RSA.generate(1024, randfunc=PRNG(get_seed(mnemonic)))
    private_key = rsa.export_key('PEM')
    print(f'PRIVATE KEY          : {private_key}')
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    decrypted_text = cipher.decrypt(encrypted_text)

    return decrypted_text


class DecodingError(Exception):
    """Виникає, якщо задана BIP39 мнемонічна фраза не може бути
    декодована у послідовність байтів."""


def get_entropy_bits(num_words: int) -> int:
    """Функція, що визначає кількість слів в залежності від ентропії.
    В нашому випадку 128-бітний алгоритм шифрування, тому й ентропія = 128
    Кількість слів num_words = (Entropy + Checksum) / 11 = (128 + 4) / 11 = 12.
    """
    try:
        return {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}[num_words]
    except KeyError:
        raise DecodingError(
            "Invalid number of words provided, "
            "BIP39 mnemonic phrases are only specified for 12, 15, 18, 21, or 24 words."
        )


def decode_phrase(phrase: str) -> bytes:
    """
    Функція, що декодує задані мнемонічні фрази у послідовність байтів
    """
    if not all(c in LETTERS for c in phrase):
        raise DecodingError(
            f"Invalid mnemonic phrase {repr(phrase)} provided, phrase contains an invalid character."
        )

    words = phrase.split()
    num_bits_entropy = get_entropy_bits(len(words))
    num_bits_checksum = num_bits_entropy // 32

    bits = 0
    for word in words:
        bits <<= 11
        try:
            bits |= WORD_TO_INDEX_TABLE[word]
        except KeyError:
            raise DecodingError(
                f"Invalid mnemonic phrase {repr(phrase)} provided, word '{word}' is not in the BIP39 wordlist."
            )

    checksum = bits & (2 ** num_bits_checksum - 1)
    bits >>= num_bits_checksum
    data = bits.to_bytes(num_bits_entropy // 8, byteorder="big")

    checksum_for_verification = hashlib.sha256(data).digest()[0] >> (
            8 - num_bits_checksum
    )

    return data


def normalize_string(txt: str) -> str:
    """Функція, що необхідна для зручного відображення строк"""
    assert type(txt) is str
    return unicodedata.normalize("NFKD", txt)


def get_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Функція, що генерує початкове двійкове число за допомогою функції
    pbkdf2_hmac(). Кількість ітерацій встановлено на 2048, а HMAC-SHA512
    використовується як псевдовипадкова функція.
    Довжина отриманого ключа становить 512 біт (= 64 байти).
    """
    decode_phrase(mnemonic)
    mnemonic = normalize_string(mnemonic)
    passphrase = "mnemonic" + normalize_string(passphrase)
    mnemonic_bytes = mnemonic.encode("utf-8")
    passphrase_bytes = passphrase.encode("utf-8")
    stretched = hashlib.pbkdf2_hmac(
        "sha512", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS
    )
    print(f'GENERATED SEED       : {stretched.hex()}')
    return stretched


LANG = 'en'
LETTERS = {
    'ua': " 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя",
    'en': " abcdefghijklmnopqrstuvwxyz"
}[LANG]

WORD_TO_INDEX_TABLE = get_2048_words(lang=LANG)
PBKDF2_ROUNDS = 2048

if __name__ == '__main__':

    text = b'Daniil Kulyk'
    mnemonic = 'admit achieve appear awesome behind border bullet casino admit clean admit abstract'
    # mnemonic = 'каміння каміння каміння каміння каміння каміння каміння каміння каміння каміння каміння мисливець'

    for c in mnemonic:
        if c not in LETTERS:
            print(c)

    print(f'ORIGINAL TEXT        : {text}')
    print(f'Mnemonic             : {mnemonic}')
    print('----' * 30)
    print('----' * 13 + 'ENCRYPTION' + '----' * 13)
    print('----' * 30)
    encrypted_text = encrypt(text, mnemonic)
    print(f'ENCRYPTED TEXT       : {encrypted_text.hex()}')

    print('----' * 30)
    print('----' * 13 + 'DECRYPTION' + '----' * 13)
    print('----' * 30)
    decrypted_text = decrypt(encrypted_text, mnemonic)
    print(f'DECRYPTED TEXT       : {decrypted_text}')
    print('-----' * 30)
