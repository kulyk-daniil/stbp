__all__ = [
    'pyversion',
    'egcd', 'modinv',
    'Str', 'Bytes', 'IntTypes',
    'bytes2int', 'int2bytes',
    'ensure_bytes', 'ensure_str'
]

import sys

pyversion = 3
Str, Bytes, IntTypes = str, bytes, (int,)


def bytes2int(b):
    return int.from_bytes(ensure_bytes(b), 'little')


def int2bytes(b, sz):
    return b.to_bytes(sz, 'little')


if sys.version_info.minor < 3:
    print('python3.3+ or python2.7+ required')
    exit()

assert sys.version_info.major == pyversion


def ensure_bytes(s):
    if type(s) is Str:
        return s.encode('utf-8')
    elif type(s) in (Bytes, bytearray):
        return Bytes(s)
    else:
        raise TypeError


def ensure_str(s):
    if type(s) is Str:
        return s
    elif type(s) in (Bytes, bytearray):
        return Bytes(s).decode('utf-8')
    else:
        raise TypeError


def egcd(a, b):
    l, r = abs(a), abs(b)
    x, lx, y, ly = 0, 1, 1, 0
    while r:
        l, (q, r) = r, divmod(l, r)
        x, lx = lx - q * x, x
        y, ly = ly - q * y, y

    return l, -lx if a < 0 else lx, -ly if b < 0 else ly


def modinv(a, m):
    g, x, y = egcd(a, m)  # solving g = a * x + m * y
    assert g == a * x + m * y
    if g != 1:
        raise ValueError
    return x % m
