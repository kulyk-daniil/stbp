import hmac
import base64
import struct
import hashlib
import time

from config import INTERVAL


def get_hotp_token(secret, intervals_no):
    """Фукнція визначає алгоритм створення одноразового пароля
    із секретного ключа та лічильника на основі HMAC"""
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = o = h[19] & 15
    h = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
    return h


def get_totp_token(secret):
    """Функція, що генерує одноразовий пароль із шести символів
    за допомогою алгоритма HOTP"""
    x = str(get_hotp_token(secret, intervals_no=int(time.time()) // INTERVAL))
    while len(x) != 6:
        x += '0'
    return x


def write_to_file(msg, filename):
    """Функція, що записує згенерований пароль у файл"""
    with open(filename, "w") as f:
        f.write(msg)


def read_from_file(filename):
    """Функція, що зчитує згенерований пароль у файл"""
    result = None
    with open(filename, "r") as f:
        result = f.read()
    return result
