## Лабораторна робота № 3 АСИМЕТРИЧНЕ ШИФРУВАННЯ. АЛГОРИТМ RSA

Виконав:
студент гр. КН-Н922б
Кулик Д.І.

Перевірив:
Бульба С.С.

## Мета
Дослідити і реалізувати механізм асиметричного алгоритму шифрування RSA.

## Завдання
Розробити додаток обміну таємними посиланнями між двома клієнтами за допомогою алгоритму шифрування RSA
•	Реалізувати алгоритм генерації ключів (public / private keys) для алгоритму RSA. Створити ключі заданої довжини (напр. 1024 біт)
•	Реалізувати та продемонструвати роботу алгоритму шифрування та дешифрування повідомлення RSA
•	Підтвердити роботу реалізованого алгоритму шляхом порівняння результату кодування з існуючим алгоритмом (наприклад, використовуючи утиліту openssl або вбудовані системи шифрування обраної мови програмування)

## Хід роботи
Алгоритм RSA є асиметричним алгоритмом шифрування. Асиметричний насправді означає, що він працює з двома різними ключами, тобто відкритим ключем і закритим ключем. Як видно з назви, відкритий ключ надається кожному, а закритий ключ залишається закритим. 
Алгоритм створення ключів можна представити як:
![Алгоритм створення ключів](/lab03/doc/generate_keys.png)

## Важливі фрагменти програми
Генерація пар ключів
```python
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
```
Шифрування та дешифрування даних
```python
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
```
Виклик власної реалізації алгоритму
```python
def my_rsa(text, bits):
    """Функція, що генерує private та public ключі заданої довжини
    bits (1024 в нашому випадку). Потім виконується шифрування і дешифрування
    переданого повідомлення"""
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
```
Виклик реалізації алгоритму з бібліотеки RSA
```python
def rsa_lib(text, bits):
    """Готова функція з бібліотеки rsa, що використовується
    у мові програмування Python"""
    public_key, private_key = rsa.newkeys(bits)
    print(f'RSA_LIB: public_key                    : {public_key}')
    print(f'RSA_LIB: private_key                   : {private_key}')

    encrypted = rsa.encrypt(text.encode(), public_key)

    print(f'RSA_LIB: Заданий текст                 : {text}')
    print(f'RSA_LIB: Зашифрований текст            : {encrypted.hex()}')

    decrypted = rsa.decrypt(encrypted, private_key)

    print(f'RSA_LIB: Розшифрований текст           : {decrypted.decode()}')
```
## Результати роботи програми

Результат виконання програми
![Результат виконання програми](/lab03/doc/result_rsa.png)

## Висновки
В результаті виконання лабораторної роботи було досліджено і реалізовано механізм асиметричного алгоритму шифрування RSA. В результаті порівняння власної реалізації алгоритму з вже реалізованими була виявлена ідентичність роботи, що доводить коректність першого.