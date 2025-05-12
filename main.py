import asyncio
import os
from bot import send_message, send_document
from event_logger import check_system_startup, check_security_events, check_service_modification, check_sysmon_process

# Путь к файлу блокировки
LOCK_FILE = "lockfile.lock"

# Основная функция для однократной проверки
async def check_events():
    print("Проверка событий 6005 (включение), 4624 (вход), 4672 (привилегии), 4698 (задачи), 4697/7045 (службы), Sysmon (процессы)...")
    await check_system_startup(send_message, send_document)
    await check_security_events(send_message)
    await check_service_modification(send_message)
    await check_sysmon_process(send_message)

# Точка входа
if __name__ == "__main__":
    if not os.path.exists("config.py"):
        print("Ошибка: файл config.py не найден")
        exit(1)

    # Проверка блокировки
    if os.path.exists(LOCK_FILE):
        print("Скрипт уже выполняется (lockfile.lock существует). Выход.")
        exit(1)

    try:
        # Создаем файл блокировки
        with open(LOCK_FILE, "w") as f:
            f.write(str(os.getpid()))
        asyncio.run(check_events())
    finally:
        # Удаляем файл блокировки
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
            print("Файл блокировки удален")