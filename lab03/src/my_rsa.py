import prime
import utils


def hex_or_none(x):
    """
    Функція, що переводить ціле число в шістнадцяткову систему зчислення
    """
    if type(x) in utils.IntTypes:
        return '0x%x' % x
    else:
        return None


class RSAKey(object):
    # ключі, що потрібні для генерації RSA-ключів
    KEYS = ['N', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qinv']

    def __init__(self, bits=None):
        """
        Повинен бути один із набору наступних параметрів:
        (bits)
        """

        if bits is None:
            raise ValueError('N or (p, q) or bits must be given')

        self.e = 0x10001
        self.gen_pq(bits)

        self.d = utils.modinv(self.e, self.phi)

        assert self.e < self.phi

        self.dp = utils.modinv(self.e, self.p - 1)
        self.dq = utils.modinv(self.e, self.q - 1)

        if self.p and self.q:
            self.qinv = utils.modinv(self.q, self.p)
        else:
            raise ValueError('dp, dq were given, but can not compute qinv')

    def gen_pq(self, bits):
        """
        Функція, що генерує пару ключів (p, q), що є дуже великими простими числами
        """
        assert bits >= 512, 'довжина ключа має бути не меншою ніж 512 бітів'
        l = bits >> 1

        while True:
            p = prime.randprime_bits(l)
            if prime.is_probable_prime(p, None, l // 8):
                break

        while True:
            q = prime.randprime_bits(bits - l)
            if p != q and prime.is_probable_prime(q, None, l // 8):
                break

        self.p = p
        self.q = q
        # перемножуємо N = p * q, де N - модуль для шифрування та дешифрування
        self.N = p * q
        # для розрахованого раніше N необхідна функція Ейлера
        self.phi = (p - 1) * (q - 1)

    @property
    def _can_encrypt(self):
        """
        Якщо N = p * q, то public ключ буде складатися з пари <N, e>
        """
        return self.N and self.e

    @property
    def _can_decrypt(self):
        """
        Якщо вираз d % phi = 1 вірний, то private ключ буде складатися з пари <N, d>
        """
        return self.N and self.d

    @property
    def _can_crt(self):
        return self.N and self.dq and self.dp and self.qinv and self.p and self.q

    @property
    def block_size(self):
        return (self.N.bit_length() + 7) >> 3


class RSA(object):
    """
    Клас, що шифрує та дешифрує текст за допомгою public і private ключів
    """
    def __init__(self, key=None, bits=1024):
        if key != None:
            self.key = key
        else:
            self.key = RSAKey(bits=bits)

    def encrypt(self, msg):
        """
        Функція, що генерує та повертає public ключ для шифрування
        """
        if not self.key._can_encrypt:
            raise AttributeError('This key object can not do encryption')
        if type(msg) not in utils.IntTypes:
            msg = utils.bytes2int(utils.ensure_bytes(msg))

        return pow(msg, self.key.e, self.key.N)

    def decrypt(self, msg, useCRT=False):
        """
        Функція, що генерує та повертає private ключ для дешифрування
        """
        if not self.key._can_decrypt:
            raise AttributeError('This key object can not do decryption')
        if type(msg) not in utils.IntTypes:
            msg = utils.bytes2int(utils.ensure_bytes(msg))

        if self.key._can_crt:
            return self._crt_decrypt(msg)
        elif useCRT:
            raise Exception('CRT optimize not available for this key object')
        else:
            return pow(msg, self.key.d, self.key.N)

    def _crt_decrypt(self, msg):
        m1 = pow(msg % self.key.p, self.key.dp, self.key.p)
        m2 = pow(msg % self.key.q, self.key.dq, self.key.q)
        k = (self.key.qinv * (m1 - m2 + self.key.p)) % self.key.p
        return m2 + k * self.key.q

    def encrypt_block(self, msg):
        """
        Функція, що шифрує один блок повідомлення
        """
        return utils.int2bytes(self.encrypt(msg), self.key.block_size)

    def decrypt_block(self, msg, useCRT=False):
        """
        Функція, що дешифрує один блок повідомлення
        """
        return utils.int2bytes(self.decrypt(msg), self.key.block_size - 1)

    def encrypt_data(self, data):
        """
        Функція, що шифрує усе повідомлення по всім блокам
        """
        bs = self.key.block_size - 1
        data_stream = (data[i:i + bs] for i in range(0, len(data), bs))
        return b''.join(self.encrypt_block(block) for block in data_stream)

    def decrypt_data(self, data):
        """
        Функція, що дешифрує усе повідомлення по всім блокам
        """
        useCRT = self.key._can_crt
        bs = self.key.block_size
        data_stream = (data[i:i + bs] for i in range(0, len(data), bs))
        return b''.join(self.decrypt_block(block, useCRT)[:bs - 1] for block in data_stream).rstrip(b'\x00')


def random_str(l):
    import os
    return utils.Bytes(bytearray(0x20 + i % (0x7f - 0x20) for i in bytearray(os.urandom(l))))
