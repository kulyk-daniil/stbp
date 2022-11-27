from apscheduler.schedulers.background import BackgroundScheduler

import config
from _logging import logger as log
from util import write_to_file, read_from_file, get_totp_token


def task():
    log.debug('Generating TOTP...')
    totp = get_totp_token(config.SECRET)
    write_to_file(totp, config.FILENAME)
    log.debug(f'Wrote new TOTP [{totp}] to file.')

def set_background_update():
    scheduler = BackgroundScheduler()
    job = scheduler.add_job(task, 'interval', seconds=config.INTERVAL)
    job.func()
    scheduler.start()


def validate(user_code):
    totp = read_from_file(config.FILENAME)
    return user_code == totp


def enter_code():
    return input('Введіть код верифікації: ')


def login():
    while True:
        username = input('Введіть нікнейм: ')
        password = input('Введіть пароль: ')

        if username == config.CREDENTIALS['username'] and password == config.CREDENTIALS['password']:
            break
        else:
            print('Невірні дані. Спробуйте ще раз.')


if __name__ == '__main__':
    set_background_update()
    login()
    entered_code = enter_code()
    while not validate(entered_code):
        entered_code = input('Невірний код! Спробуйте ще раз:\n')
    print('Авторизація пройшла успішно!')
