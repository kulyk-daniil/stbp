## Лабораторна робота № 4 ВИКОРИСТАННЯ МНЕМОНІЧНИХ ФРАЗ ДЛЯ ФОРМУВАННЯ КЛЮЧІВ ШИФРУВАННЯ

Виконав:
студент гр. КН-Н922б
Кулик Д.І.

Перевірив:
Бульба С.С.

## Мета
Дослідити і реалізувати механізм використання мнемонічних фраз для формування ключів шифрування.

## Завдання
•	Використовуючи алгоритм bip39, створити seed генератора псевдовипадкових чисел за допомогою мнемонічної фрази та стосовні ключі шифрування.
•	Зашифрувати текст
•	Використовуючи раніше створену мнемонічну фразу, відновити ключі шифрування на дешифрувати текст. Вдосконалитись, що оригінальний та дешифрований тексти однакові.
З.І., для додаткових балів необхідно реалізувати підтримку україномовних мнемонічних фраз.

## Хід роботи
Алгоритм RSA є асиметричним алгоритмом шифрування. Асиметричний насправді означає, що він працює з двома різними ключами, тобто відкритим ключем і закритим ключем. Як видно з назви, відкритий ключ надається кожному, а закритий ключ залишається закритим. 
Алгоритм створення ключів можна представити як:
![Алгоритм створення ключів](/lab04/doc/bip39_keys.png)

## Важливі фрагменти програми
Зчитування слів зі словників
```python
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
```
Генерація seed
```python
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
```
Функції шифрування та дешифрування
```python
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
```
Словники українських та англійських слів

![Український словник](/lab04/doc/ua_dict.png)
![Англійський словник](/lab04/doc/en_dict.png)

## Результати роботи програми

Результат виконання програми для ua мнемонічних фраз

![Результат виконання програми ua](/lab04/doc/result_ua.png)
Результат виконання програми для en мнемонічних фраз

![Результат виконання програми en](/lab04/doc/result_en.png)

## Висновки
В результаті виконання лабораторної роботи було досліджено і реалізовано механізм використання мнемонічних фраз для формування ключів шифрування RSA. 