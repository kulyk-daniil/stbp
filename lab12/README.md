## Лабораторна робота № 12 ДОСЛІДЖЕННЯ ЗАСОБІВ ОБФУСКАЦІЇ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ

Виконав:
студент гр. КН-Н922б
Кулик Д.І.

Перевірив:
Бульба С.С.

## Мета
Дослідити існуючі утиліти обфускації програмного забезпечення.

## Завдання
Для обраної мови програмування слід обфускувати будь-який проект.
Слід використовувати декілька утиліт для обфускації. Мінімальна кількість обфускаторів - 4. У звіті навести порівняльну характеристику обраних обфускаторів, що складатиметься з:
•	інформації щодо використовуваних методів обфускації
•	плюсів та мінусів кожного з обфускаторів.
Навести опис використання кожного з обраних обфускаторів.

## Хід роботи
Обфускація в широкому значенні - приведення вихідного тексту або виконуваного коду програми до виду, що зберігає її функціональність, але утруднює аналіз, розуміння алгоритмів роботи та модифікацію при декомпіляції.
Більшість методів обфускації перетворюють такі аспекти коду:

• Дані: роблять елементи коду схожими на те, чим вони не є

• Потік коду: виставляють логіку програми абсурдної або навіть недетермінованої.

• Структура формату: застосовують різне форматування даних, перейменування ідентифікаторів, видалення коментарів коду тощо.

Інструменти обфускації можуть працювати як із source або байт кодом, так і з бінарним, проте обфускація двійкових файлів складніша, і повинна змінюватись в залежності від архітектури системи.

При обфускації коду важливо правильно оцінити, які частини коли можна ефективно заплутати. Слід уникати обфускації коду критичного щодо продуктивності.

## Важливі фрагменти програми
Початковий код (лабораторна робота 01)
![Початковий код](/lab12/doc/main01.png)
Проведемо обфускацію за допомогою утілити pyarmor.
Заплутувати сценарій Python за допомогою PyArmor так само просто, як виконати таку команду в консолі:
pyarmor obfuscate script.py 
Це створить папку dist, яка містить обфускований файл Python з такою самою назвою, як і вихідний, разом із залежностями середовища виконання, як показано в структурі папок нижче:
![Схема pyarmor](/lab12/doc/pyarmor_scheme.png)
Виконання команди для обфускації
![Обфускація pyarmor](/lab12/doc/pyarmor_result.png)
Текст програми обфускованого файлу
![Текст pyarmor](/lab12/doc/pyarmor_text.png)
Спробуємо запустити обфускований файл
![Перевірка pyarmor](/lab12/doc/pyarmor_check.png)
Проведемо обфускацію за допомогою утілити opy.
Утиліта opy заплутає наш вихідний код Python, але за допомогою іншого алгоритму.
Відомі обмеження:
•	Перед коментарем після рядкового літералу має стояти пробіл.
«або» всередині рядкового літералу слід екранувати \, а не подвоювати.
•	Обфускація рядкових літералів непридатна для конфіденційної інформації, оскільки її можна тривіально зламати. 
Виконання команди для обфускації
![Обфускація pyarmor](/lab12/doc/opy_result.png)
Текст програми обфускованого файлу
![Текст pyarmor](/lab12/doc/opy_text.png)
Спробуємо запустити обфускований файл
![Перевірка pyarmor](/lab12/doc/opy_check.png)
## Висновки
В результаті виконання лабораторної роботи було досліджено існуючі утиліти обфускації програмного забезпечення.