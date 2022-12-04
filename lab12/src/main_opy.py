import hashlib
"""Таблиця констант (перші 32 біти дробових частин
кубічних коренів перших 64 простих чисел"""
l1l1l1_opy_ = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
def l11_opy_(message: bytearray) -> bytearray:
    """Повертає хеш SHA-256 із переданого повідомлення.
    Аргумент має бути об’єктом bytes, bytearray або string."""
    if isinstance(message, str):
        message = bytearray(message, 'ascii')
    elif isinstance(message, bytes):
        message = bytearray(message)
    elif not isinstance(message, bytearray):
        raise TypeError
    length = len(message) * 8
    message.append(0x80)
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)
    message += length.to_bytes(8, 'big')
    assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"
    l1l1ll_opy_ = []
    for i in range(0, len(message), 64):
        l1l1ll_opy_.append(message[i:i+64])
    """Ініціалізація значень хеша.
    Це константи, що представляють перші 32 біти дробових
    частин квадратного коріння перших 8 простих чисел"""
    l11lll_opy_ = 0x6a09e667
    l11l1_opy_ = 0xbb67ae85
    l1l_opy_ = 0x3c6ef372
    l11ll1_opy_ = 0xa54ff53a
    l1lll1_opy_ = 0x9b05688c
    l111l_opy_ = 0x510e527f
    l1ll11_opy_ = 0x1f83d9ab
    l1l11l_opy_ = 0x5be0cd19
    for l1lll_opy_ in l1l1ll_opy_:
        l1l111_opy_ = []
        for t in range(0, 64):
            if t <= 15:
                l1l111_opy_.append(bytes(l1lll_opy_[t*4:(t*4)+4]))
            else:
                l11ll_opy_ = _1l11_opy_(int.from_bytes(l1l111_opy_[t-2], 'big'))
                l1ll_opy_ = int.from_bytes(l1l111_opy_[t-7], 'big')
                l111_opy_ = _1l1_opy_(int.from_bytes(l1l111_opy_[t-15], 'big'))
                ll_opy_ = int.from_bytes(l1l111_opy_[t-16], 'big')
                l11l1l_opy_ = ((l11ll_opy_ + l1ll_opy_ + l111_opy_ + ll_opy_) %
                            2**32).to_bytes(4, 'big')
                l1l111_opy_.append(l11l1l_opy_)
        assert len(l1l111_opy_) == 64
        a = l11lll_opy_
        b = l11l1_opy_
        c = l1l_opy_
        d = l11ll1_opy_
        e = l111l_opy_
        f = l1lll1_opy_
        g = l1ll11_opy_
        h = l1l11l_opy_
        for t in range(64):
            t1 = ((h + _1_opy_(e) + _1llll_opy_(e, f, g) + l1l1l1_opy_[t] +
                   int.from_bytes(l1l111_opy_[t], 'big')) % 2**32)
            l1ll1l_opy_ = (_111ll_opy_(a) + _11l11_opy_(a, b, c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + l1ll1l_opy_) % 2**32
        l11lll_opy_ = (l11lll_opy_ + a) % 2**32
        l11l1_opy_ = (l11l1_opy_ + b) % 2**32
        l1l_opy_ = (l1l_opy_ + c) % 2**32
        l11ll1_opy_ = (l11ll1_opy_ + d) % 2**32
        l111l_opy_ = (l111l_opy_ + e) % 2**32
        l1lll1_opy_ = (l1lll1_opy_ + f) % 2**32
        l1ll11_opy_ = (l1ll11_opy_ + g) % 2**32
        l1l11l_opy_ = (l1l11l_opy_ + h) % 2**32
    return ((l11lll_opy_).to_bytes(4, 'big') + (l11l1_opy_).to_bytes(4, 'big') +
            (l1l_opy_).to_bytes(4, 'big') + (l11ll1_opy_).to_bytes(4, 'big') +
            (l111l_opy_).to_bytes(4, 'big') + (l1lll1_opy_).to_bytes(4, 'big') +
            (l1ll11_opy_).to_bytes(4, 'big') + (l1l11l_opy_).to_bytes(4, 'big'))
def _1l1_opy_(l1ll1_opy_: int):
    """Виконує логічні операції та зсув вправо як визначено в реалізації."""
    l1ll1_opy_ = (_11l_opy_(l1ll1_opy_, 7) ^
           _11l_opy_(l1ll1_opy_, 18) ^
           (l1ll1_opy_ >> 3))
    return l1ll1_opy_
def _1l11_opy_(l1ll1_opy_: int):
    """Виконує логічні операції та зсув вправо як визначено в реалізації."""
    l1ll1_opy_ = (_11l_opy_(l1ll1_opy_, 17) ^
           _11l_opy_(l1ll1_opy_, 19) ^
           (l1ll1_opy_ >> 10))
    return l1ll1_opy_
def _111ll_opy_(l1ll1_opy_: int):
    """Виконує логічні операції та зсув вправо як визначено в реалізації."""
    l1ll1_opy_ = (_11l_opy_(l1ll1_opy_, 2) ^
           _11l_opy_(l1ll1_opy_, 13) ^
           _11l_opy_(l1ll1_opy_, 22))
    return l1ll1_opy_
def _1_opy_(l1ll1_opy_: int):
    """Виконує логічні операції та зсув вправо як визначено в реалізації."""
    l1ll1_opy_ = (_11l_opy_(l1ll1_opy_, 6) ^
           _11l_opy_(l1ll1_opy_, 11) ^
           _11l_opy_(l1ll1_opy_, 25))
    return l1ll1_opy_
def _1llll_opy_(x: int, y: int, z: int):
    """Виконує логічні операції як визначено в реалізації."""
    return (x & y) ^ (~x & z)
def _11l11_opy_(x: int, y: int, z: int):
    """Виконує логічні операції як визначено в реалізації."""
    return (x & y) ^ (x & z) ^ (y & z)
def _11l_opy_(l1ll1_opy_: int, shift: int, size: int = 32):
    """Побітовий зсув вправо на shift бітів."""
    return (l1ll1_opy_ >> shift) | (l1ll1_opy_ << size - shift)
if __name__ == "__main__":
    l1111_opy_ = 'Daniil Kulyk'
    print("Введений текст: " + l1111_opy_)
    print('Розроблений SHA256 = ', l11_opy_(l1111_opy_).hex())
    print('Hashlib SHA256     = ', hashlib.sha256(l1111_opy_.encode("utf-8")).hexdigest())