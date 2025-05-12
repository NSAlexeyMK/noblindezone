import win32evtlog
from datetime import datetime, timedelta
import datetime as dt
import os
import re
import xmltodict
import json
import requests
from config import VIRUSTOTAL_API_KEY
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import pkg_resources

# Конфигурация
TIME_RANGE_MINUTES = 1  # Временной диапазон для поиска (1 минута)
STARTUP_LOG_FILE = "last_startup.log"  # Файл для хранения времени последнего включения
LOGON_LOG_FILE = "last_logon.log"  # Файл для хранения времени последнего входа
PRIVILEGE_LOG_FILE = "last_privilege.log"  # Файл для хранения времени последнего события 4672
TASK_LOG_FILE = "last_task.log"  # Файл для хранения времени последнего события 4698
SERVICE_LOG_FILE = "last_service.log"  # Файл для хранения времени последнего события 4697/7045
SYSMON_LOG_FILE = "sysmon_seen.log"  # Файл для хранения ProcessGuid событий Sysmon
SYSMON_CACHE_FILE = "vt_cache.json"  # Файл для кэша VirusTotal

# Новые файлы для накопительного логирования
EVENTS_6005_LOG = "events_6005.json"  # Лог для включений ПК
EVENTS_4624_LOG = "events_4624.json"  # Лог для входов
EVENTS_4672_LOG = "events_4672.json"  # Лог для привилегий
EVENTS_4698_LOG = "events_4698.json"  # Лог для задач
EVENTS_SERVICE_LOG = "events_service.json"  # Лог для служб
EVENTS_SYSMON_LOG = "events_sysmon.json"  # Лог для Sysmon

# Регистрация шрифта DejaVuSans для поддержки кириллицы
try:
    font_path = pkg_resources.resource_filename('reportlab', 'fonts/DejaVuSans.ttf')
    if not os.path.exists(font_path):
        # Альтернативный путь к шрифту (нужно скачать и указать)
        font_path = os.path.join(os.path.dirname(__file__), "DejaVuSans.ttf")
    pdfmetrics.registerFont(TTFont("DejaVuSans", font_path))
    print("Шрифт DejaVuSans зарегистрирован")
except Exception as e:
    print(f"Ошибка регистрации шрифта DejaVuSans: {e}. Убедитесь, что файл DejaVuSans.ttf доступен.")


# Функция для чтения последнего времени из файла
def read_last_event_time(file_name):
    if not os.path.exists(file_name):
        return None
    try:
        with open(file_name, "r") as f:
            last_time_str = f.read().strip()
            if not last_time_str or last_time_str.isspace():
                print(f"Файл {file_name} пуст, удаляем")
                os.remove(file_name)
                return None
            if re.match(r'^[\dT:+\-\.Z]+$', last_time_str):
                return datetime.fromisoformat(last_time_str)
            print(f"Некорректный формат данных в {file_name}: {last_time_str}")
            os.remove(file_name)
            return None
    except PermissionError as e:
        print(f"Ошибка: файл {file_name} заблокирован: {e}. Удалите файл вручную.")
        return None
    except Exception as e:
        print(f"Ошибка чтения {file_name}: {e}")
        return None


# Функция для записи времени события в файл (перезапись)
async def write_last_event_time(file_name, event_time, send_message_func):
    try:
        with open(file_name, "w") as f:
            f.write(event_time.isoformat())
        print(f"Время события сохранено в {file_name}: {event_time}")
    except Exception as e:
        print(f"Ошибка записи в {file_name}: {e}")
        await send_message_func(f"📋 Ошибка: не удалось записать время события в {file_name} - {str(e)}")


# Функция для накопительного логирования событий
async def log_event_to_json(file_name, event_data, send_message_func):
    try:
        # Инициализируем пустой список, если файл не существует
        if not os.path.exists(file_name):
            with open(file_name, "w") as f:
                json.dump([], f)

        # Читаем существующие события
        with open(file_name, "r") as f:
            events = json.load(f)

        # Добавляем новое событие
        events.append(event_data)

        # Записываем обновленный список
        with open(file_name, "w") as f:
            json.dump(events, f, indent=4)
        print(f"Событие добавлено в {file_name}: {event_data}")
    except Exception as e:
        print(f"Ошибка записи в {file_name}: {e}")
        await send_message_func(f"📋 Ошибка: не удалось записать событие в {file_name} - {str(e)}")


# Функция для очистки накопительных логов
async def clear_event_logs(send_message_func):
    log_files = [
        EVENTS_6005_LOG, EVENTS_4624_LOG, EVENTS_4672_LOG,
        EVENTS_4698_LOG, EVENTS_SERVICE_LOG, EVENTS_SYSMON_LOG
    ]
    for file_name in log_files:
        try:
            with open(file_name, "w") as f:
                json.dump([], f)
            print(f"Лог {file_name} очищен")
        except Exception as e:
            print(f"Ошибка очистки {file_name}: {e}")
            await send_message_func(f"📋 Ошибка: не удалось очистить лог {file_name} - {str(e)}")


# Функция для генерации PDF-отчета
async def generate_pdf_report(date, send_message_func, send_document_func):
    output_file = f"report_{date.strftime('%Y-%m-%d')}.pdf"
    c = canvas.Canvas(output_file, pagesize=letter)
    c.setFont("DejaVuSans", 12)
    y = 750
    c.drawString(100, y, f"Отчет по событиям за {date.strftime('%Y-%m-%d')}")
    y -= 30

    # Собираем все события
    log_files = [
        (EVENTS_6005_LOG, "Включение компьютера"),
        (EVENTS_4624_LOG, "Входы в систему"),
        (EVENTS_4672_LOG, "Назначение привилегий"),
        (EVENTS_4698_LOG, "Создание задач"),
        (EVENTS_SERVICE_LOG, "Установка/изменение служб"),
        (EVENTS_SYSMON_LOG, "Запуск процессов (Sysmon)")
    ]

    for log_file, title in log_files:
        try:
            with open(log_file, "r") as f:
                events = json.load(f)
            # Фильтруем события по дате
            events = [e for e in events if datetime.fromisoformat(e["time"]).date() == date]
            if events:
                c.drawString(100, y, f"{title}:")
                y -= 20
                for event in events:
                    if y < 50:  # Новая страница, если мало места
                        c.showPage()
                        c.setFont("DejaVuSans", 12)
                        y = 750
                    summary = event.get("summary", str(event))
                    c.drawString(100, y, f"{event['time']}: {summary}")
                    y -= 20
                y -= 10
        except Exception as e:
            print(f"Ошибка чтения {log_file} для отчета: {e}")
            await send_message_func(f"📋 Ошибка: не удалось прочитать {log_file} - {str(e)}")

    c.save()
    print(f"PDF-отчет создан: {output_file}")

    # Отправка PDF в Telegram
    try:
        await send_document_func(output_file)
        print(f"PDF-отчет отправлен: {output_file}")
        # Очистка логов после отправки
        await clear_event_logs(send_message_func)
    except Exception as e:
        print(f"Ошибка отправки PDF: {e}")
        await send_message_func(f"📋 Ошибка: не удалось отправить PDF-отчет - {str(e)}")


# Функция поиска событий в журнале Security (4624, 4672, 4698)
async def check_security_events(send_message_func):
    print(f"Начало проверки событий Security (4624, 4672, 4698) за последнюю минуту...")

    try:
        security_log = win32evtlog.OpenEventLog("localhost", "Security")
        print("Журнал Security открыт")
    except Exception as e:
        print(f"Ошибка открытия журнала Security: {e}")
        await send_message_func(f"📋 Ошибка: не удалось открыть журнал Security - {str(e)}")
        return [], [], []

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    now = datetime.now(dt.timezone.utc)
    time_threshold = now - timedelta(minutes=TIME_RANGE_MINUTES)
    logon_events = []
    privilege_events = []
    task_events = []

    while True:
        try:
            events = win32evtlog.ReadEventLog(security_log, flags, 0)
            if not events:
                print("Событий больше нет.")
                break
        except Exception as e:
            print(f"Ошибка чтения журнала Security: {e}")
            break

        for event in events:
            event_id = event.EventID & 0xFFFF
            event_time = event.TimeGenerated.replace(tzinfo=dt.timezone.utc)

            if event_time < time_threshold:
                break

            if event_id == 4624:
                event_data = event.StringInserts or []
                if len(event_data) > 9:
                    logon_type = event_data[8]
                    user = event_data[5]
                    account_domain = event_data[6]
                    if logon_type in ["2", "7", "15"]:
                        event_info = {
                            "time": event_time.isoformat(),
                            "user": user,
                            "domain": account_domain,
                            "logon_type": logon_type,
                            "data": event_data
                        }
                        logon_events.append(event_info)
                        # Накопительное логирование
                        await log_event_to_json(EVENTS_4624_LOG, {
                            "time": event_time.isoformat(),
                            "summary": f"Пользователь: {user}, Тип: {logon_type}, Домен: {account_domain}"
                        }, send_message_func)

            elif event_id == 4672:
                event_data = event.StringInserts or []
                if len(event_data) >= 3:
                    sid = event_data[0]
                    user = event_data[1]
                    account_domain = event_data[2]
                    privileges = event_data[3] if len(event_data) > 3 else "Не определено"
                    if user not in ["СИСТЕМА", "SYSTEM"] and sid != "S-1-5-18":
                        if privileges and privileges != "Не определено":
                            privileges = ", ".join([p.strip() for p in privileges.split("\r\n") if p.strip()])
                        event_info = {
                            "time": event_time.isoformat(),
                            "user": user,
                            "domain": account_domain,
                            "privileges": privileges,
                            "data": event_data
                        }
                        privilege_events.append(event_info)
                        # Накопительное логирование
                        await log_event_to_json(EVENTS_4672_LOG, {
                            "time": event_time.isoformat(),
                            "summary": f"Пользователь: {user}, Привилегии: {privileges}, Домен: {account_domain}"
                        }, send_message_func)

            elif event_id == 4698:
                event_data = event.StringInserts or []
                if len(event_data) >= 5:
                    sid = event_data[0]
                    user = event_data[1]
                    account_domain = event_data[2]
                    task_name = event_data[4]
                    task_content = event_data[5] if len(event_data) > 5 else "Не определено"
                    if user not in ["СИСТЕМА", "SYSTEM"] and sid != "S-1-5-18":
                        event_info = {
                            "time": event_time.isoformat(),
                            "user": user,
                            "domain": account_domain,
                            "task_name": task_name,
                            "task_content": task_content,
                            "data": event_data
                        }
                        task_events.append(event_info)
                        # Накопительное логирование
                        await log_event_to_json(EVENTS_4698_LOG, {
                            "time": event_time.isoformat(),
                            "summary": f"Задача: {task_name}, Пользователь: {user}, Содержимое: {task_content}"
                        }, send_message_func)

    win32evtlog.CloseEventLog(security_log)
    print("Журнал Security закрыт")

    # Обработка событий входа (4624)
    last_saved_logon_time = read_last_event_time(LOGON_LOG_FILE)
    logon_types = {
        "2": "Локальный вход",
        "7": "Разблокировка",
        "15": "Удаленный вход (RDP)"
    }
    for event in sorted(logon_events, key=lambda x: datetime.fromisoformat(x["time"]), reverse=True):
        event_time = datetime.fromisoformat(event["time"])
        if last_saved_logon_time is None or event_time > last_saved_logon_time:
            event_time_str = event_time.strftime("%Y-%m-%d %H:%M:%S")
            message = (
                f"🔑 Вход пользователя:\n"
                f"Пользователь: {event['user'] or 'Не определён'}\n"
                f"Время: {event_time_str}\n"
                f"Домен: {event['domain'] or 'Не определён'}\n"
                f"Тип входа: {logon_types.get(event['logon_type'], 'Неизвестный тип')} "
                f"(тип {event['logon_type']})\n"
                f"Полные данные события: {event['data']}"
            )
            await send_message_func(message)
            print(
                f"🟢 Event ID: 4624\n    Время (МСК): {event_time_str}\n    Пользователь: {event['user']}\n    Домен: {event['domain']}\n    Тип входа: {event['logon_type']}")
            print("-" * 50)
    if logon_events:
        latest_logon_time = max(datetime.fromisoformat(event["time"]) for event in logon_events)
        if last_saved_logon_time is None or latest_logon_time > last_saved_logon_time:
            await write_last_event_time(LOGON_LOG_FILE, latest_logon_time, send_message_func)

    # Обработка событий привилегий (4672)
    last_saved_privilege_time = read_last_event_time(PRIVILEGE_LOG_FILE)
    for event in sorted(privilege_events, key=lambda x: datetime.fromisoformat(x["time"]), reverse=True):
        event_time = datetime.fromisoformat(event["time"])
        if last_saved_privilege_time is None or event_time > last_saved_privilege_time:
            event_time_str = event_time.strftime("%Y-%m-%d %H:%M:%S")
            message = (
                f"🔒 Назначение привилегий:\n"
                f"Пользователь: {event['user'] or 'Не определён'}\n"
                f"Время: {event_time_str}\n"
                f"Домен: {event['domain'] or 'Не определён'}\n"
                f"Привилегии: {event['privileges'] or 'Не определено'}\n"
                f"Полные данные события: {event['data']}"
            )
            await send_message_func(message)
            print(
                f"🟢 Event ID: 4672\n    Время (МСК): {event_time_str}\n    Пользователь: {event['user']}\n    Домен: {event['domain']}\n    Привилегии: {event['privileges']}")
            print("-" * 50)
    if privilege_events:
        latest_privilege_time = max(datetime.fromisoformat(event["time"]) for event in privilege_events)
        if last_saved_privilege_time is None or latest_privilege_time > last_saved_privilege_time:
            await write_last_event_time(PRIVILEGE_LOG_FILE, latest_privilege_time, send_message_func)

    # Обработка событий задач (4698)
    last_saved_task_time = read_last_event_time(TASK_LOG_FILE)
    for event in sorted(task_events, key=lambda x: datetime.fromisoformat(x["time"]), reverse=True):
        event_time = datetime.fromisoformat(event["time"])
        if last_saved_task_time is None or event_time > last_saved_task_time:
            event_time_msk = event_time + timedelta(hours=3)
            time_str = event_time_msk.strftime("%d.%m.%Y %H:%M:%S")
            event_time_str = event_time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"🟢 Event ID: 4698")
            print(f"    Время (МСК): {time_str}")
            print(f"    Пользователь: {event['user'] or 'Не определён'}")
            print(f"    Домен: {event['domain'] or 'Не определён'}")
            print(f"    Имя задачи: {event['task_name'] or 'Не определено'}")
            print(f"    Содержимое задачи: {event['task_content'] or 'Не определено'}")
            print("-" * 50)
            message = (
                f"📋 Создана задача: {event['task_name'] or 'Не определено'}\n"
                f"Пользователь: {event['user'] or 'Не определён'}\n"
                f"Домен: {event['domain'] or 'Не определён'}\n"
                f"Время: {event_time_str}\n"
                f"Содержимое: {event['task_content'] or 'Не определено'}"
            )
            await send_message_func(message)
    if task_events:
        latest_task_time = max(datetime.fromisoformat(event["time"]) for event in task_events)
        if last_saved_task_time is None or latest_task_time > last_saved_task_time:
            await write_last_event_time(TASK_LOG_FILE, latest_task_time, send_message_func)

    return logon_events, privilege_events, task_events


# Функция поиска последнего события включения компьютера (Event ID 6005)
async def check_system_startup(send_message_func, send_document_func):
    print(f"Начало проверки событий включения за последнюю минуту...")

    try:
        system_log = win32evtlog.OpenEventLog("localhost", "System")
        print("Журнал System открыт")
    except Exception as e:
        print(f"Ошибка открытия журнала: {e}")
        await send_message_func(f"📋 Ошибка: не удалось открыть журнал System - {str(e)}")
        return

    now = datetime.now(dt.timezone.utc)
    time_threshold = now - timedelta(minutes=TIME_RANGE_MINUTES)
    last_saved_time = read_last_event_time(STARTUP_LOG_FILE)
    last_startup_event = None

    # Проверка смены дня для генерации отчета
    if last_saved_time:
        last_date = last_saved_time.date()
        current_date = now.date()
        if last_date < current_date:
            print(f"Обнаружена смена дня: последняя дата {last_date}, текущая {current_date}")
            await generate_pdf_report(last_date, send_message_func, send_document_func)

    while True:
        try:
            events = win32evtlog.ReadEventLog(
                system_log,
                win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                0
            )
            if not events:
                print("События закончились")
                break
        except Exception as e:
            print(f"Ошибка чтения журнала: {e}")
            break

        for event in events:
            event_id = event.EventID & 0xFFFF
            event_time = event.TimeGenerated.replace(tzinfo=dt.timezone.utc)

            if event_time < time_threshold:
                break

            if event_id == 6005:
                event_data = event.StringInserts
                data_str = event_data[0] if event_data and isinstance(event_data, list) and len(
                    event_data) > 0 else None
                if not data_str:
                    try:
                        data_str = event.Message or "Нет данных"
                    except AttributeError:
                        data_str = "Нет данных"
                print(f"Отладка 6005: StringInserts={event_data}, Message={getattr(event, 'Message', 'Недоступно')}")
                if last_startup_event is None or event_time > last_startup_event["time"]:
                    last_startup_event = {
                        "time": event_time,
                        "data": data_str
                    }
                print(f"Обнаружено событие 6005: Время {event_time}, Данные {data_str}")
                # Накопительное логирование
                await log_event_to_json(EVENTS_6005_LOG, {
                    "time": event_time.isoformat(),
                    "summary": f"Включение ПК, Детали: {data_str}"
                }, send_message_func)

    win32evtlog.CloseEventLog(system_log)
    print("Журнал закрыт")

    if last_startup_event:
        event_time = last_startup_event["time"]
        if last_saved_time is None or event_time > last_saved_time:
            event_time_str = event_time.strftime("%Y-%m-%d %H:%M:%S")
            message = f"🖥️ Компьютер включен! Время: {event_time_str}" + \
                      (f", Детали: {last_startup_event['data']}" if last_startup_event['data'] != "Нет данных" else "")
            await write_last_event_time(STARTUP_LOG_FILE, event_time, send_message_func)
            await send_message_func(message)


# Функция поиска событий установки и изменения служб (Event ID 4697 и 7045)
async def check_service_modification(send_message_func):
    print(f"Начало проверки событий 4697 и 7045 (службы) за последнюю минуту...")

    now = datetime.now(dt.timezone.utc)
    time_threshold = now - timedelta(minutes=TIME_RANGE_MINUTES)
    last_saved_time = read_last_event_time(SERVICE_LOG_FILE)
    new_service_events = []

    # Проверка событий 4697 (Security)
    try:
        security_log = win32evtlog.OpenEventLog("localhost", "Security")
        print("Журнал Security открыт")
    except Exception as e:
        print(f"Ошибка открытия журнала Security: {e}")
        await send_message_func(f"📋 Ошибка: не удалось открыть журнал Security - {str(e)}")
        return

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        try:
            events = win32evtlog.ReadEventLog(security_log, flags, 0)
            if not events:
                print("Событий 4697 больше нет.")
                break
        except Exception as e:
            print(f"Ошибка чтения журнала Security: {e}")
            await send_message_func(f"📋 Ошибка: не удалось прочитать журнал Security - {str(e)}")
            break

        for event in events:
            event_id = event.EventID & 0xFFFF
            event_time = event.TimeGenerated.replace(tzinfo=dt.timezone.utc)

            if event_time < time_threshold:
                break

            if event_id == 4697:
                event_data = event.StringInserts or []
                sid = None
                user = None
                account_domain = None
                service_name = None
                service_file_name = None
                service_type = None
                service_start_type = None
                service_account = None

                if len(event_data) >= 8:
                    sid = event_data[0]
                    user = event_data[1]
                    account_domain = event_data[2]
                    service_name = event_data[4]
                    service_file_name = event_data[5]
                    service_type = event_data[6]
                    service_start_type = event_data[7]
                    service_account = event_data[8] if len(event_data) > 8 else "Не определено"

                if user in ["СИСТЕМА", "SYSTEM"] or sid == "S-1-5-18":
                    continue

                event_info = {
                    "event_id": 4697,
                    "time": event_time.isoformat(),
                    "user": user,
                    "domain": account_domain,
                    "service_name": service_name,
                    "service_file_name": service_file_name,
                    "service_type": service_type,
                    "service_start_type": service_start_type,
                    "service_account": service_account,
                    "data": event_data
                }
                new_service_events.append(event_info)
                # Накопительное логирование
                await log_event_to_json(EVENTS_SERVICE_LOG, {
                    "time": event_time.isoformat(),
                    "summary": f"Новая служба: {service_name}, Тип: {service_start_type}, Пользователь: {user}"
                }, send_message_func)

    win32evtlog.CloseEventLog(security_log)
    print("Журнал Security закрыт")

    # Проверка событий 7045 (System)
    try:
        system_log = win32evtlog.OpenEventLog("localhost", "System")
        print("Журнал System открыт")
    except Exception as e:
        print(f"Ошибка открытия журнала System: {e}")
        await send_message_func(f"📋 Ошибка: не удалось открыть журнал System - {str(e)}")
        return

    while True:
        try:
            events = win32evtlog.ReadEventLog(system_log, flags, 0)
            if not events:
                print("Событий 7045 больше нет.")
                break
        except Exception as e:
            print(f"Ошибка чтения журнала System: {e}")
            await send_message_func(f"📋 Ошибка: не удалось прочитать журнал System - {str(e)}")
            break

        for event in events:
            event_id = event.EventID & 0xFFFF
            event_time = event.TimeGenerated.replace(tzinfo=dt.timezone.utc)

            if event_time < time_threshold:
                break

            if event_id == 7045:
                event_data = event.StringInserts or []
                service_name = None
                service_file_name = None
                service_type = None
                service_start_type = None
                service_account = None
                user = None

                if len(event_data) >= 5:
                    service_name = event_data[0]
                    service_file_name = event_data[1]
                    service_start_type = event_data[2]
                    service_type = event_data[3]
                    service_account = event_data[4]
                    user = event_data[5] if len(event_data) > 5 else "Не определено"

                if user in ["СИСТЕМА", "SYSTEM"]:
                    continue

                event_info = {
                    "event_id": 7045,
                    "time": event_time.isoformat(),
                    "user": user,
                    "domain": "Не применимо",
                    "service_name": service_name,
                    "service_file_name": service_file_name,
                    "service_type": service_type,
                    "service_start_type": service_start_type,
                    "service_account": service_account,
                    "data": event_data
                }
                new_service_events.append(event_info)
                # Накопительное логирование
                await log_event_to_json(EVENTS_SERVICE_LOG, {
                    "time": event_time.isoformat(),
                    "summary": f"Изменена служба: {service_name}, Тип: {service_start_type}, Пользователь: {user}"
                }, send_message_func)

    win32evtlog.CloseEventLog(system_log)
    print("Журнал System закрыт")

    # Сортировка событий по времени (от новых к старым)
    new_service_events.sort(key=lambda x: datetime.fromisoformat(x["time"]), reverse=True)

    # Обработка и отправка всех новых событий
    if new_service_events:
        latest_event_time = max(datetime.fromisoformat(event["time"]) for event in new_service_events)
        for event in new_service_events:
            if last_saved_time is None or datetime.fromisoformat(event["time"]) > last_saved_time:
                event_time_str = datetime.fromisoformat(event["time"]).strftime("%Y-%m-%d %H:%M:%S")
                start_type = event["service_start_type"]
                # Для 4697 преобразуем числовой тип запуска
                if event["event_id"] == 4697:
                    start_types = {
                        "0": "Загрузка при старте системы",
                        "1": "Загрузка при старте ядра",
                        "2": "Автоматический запуск",
                        "3": "По требованию",
                        "4": "Отключена"
                    }
                    start_type = start_types.get(start_type, f"Неизвестный тип ({start_type})")
                event_type = "Новая служба" if event["event_id"] == 4697 else "Изменена служба"
                message = (
                    f"⚙️ {event_type}: \"{event['service_name'] or 'Не определено'}\" "
                    f"Тип: {start_type or 'Не определено'} "
                    f"Время: {event_time_str}"
                )
                await send_message_func(message)
                print(
                    f"⚙️ {event_type} за последнюю минуту:\n"
                    f"Служба: {event['service_name'] or 'Не определено'}\n"
                    f"Пользователь: {event['user'] or 'Не определён'}\n"
                    f"Время: {event_time_str}\n"
                    f"Домен: {event['domain'] or 'Не определён'}\n"
                    f"Путь: {event['service_file_name'] or 'Не определено'}\n"
                    f"Тип службы: {event['service_type'] or 'Не определено'}\n"
                    f"Тип запуска: {start_type or 'Не определено'}\n"
                    f"Учетная запись: {event['service_account'] or 'Не определено'}\n"
                    f"Полные данные события: {event['data']}"
                )
        if last_saved_time is None or latest_event_time > last_saved_time:
            await write_last_event_time(SERVICE_LOG_FILE, latest_event_time, send_message_func)
    else:
        print("Новых событий 4697 или 7045 не найдено.")


# Функция проверки событий Sysmon (Event ID 1)
async def check_sysmon_process(send_message_func):
    print(f"Начало проверки событий Sysmon (Event ID 1) за последнюю минуту...")

    # Загружаем log, очищаем от старых
    seen_guids = {}
    cutoff = datetime.now(dt.UTC) - timedelta(hours=24)
    if os.path.exists(SYSMON_LOG_FILE):
        try:
            with open(SYSMON_LOG_FILE, "r") as f:
                for line in f:
                    if '|' in line:
                        guid, timestr = line.strip().split('|', 1)
                        try:
                            ts = datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.UTC)
                            if ts > cutoff:
                                seen_guids[guid] = ts
                        except ValueError as e:
                            print(f"Ошибка парсинга строки в логе {SYSMON_LOG_FILE}: {line.strip()} - {e}")
                            continue
            print(f"Загружено {len(seen_guids)} ProcessGuid из {SYSMON_LOG_FILE}")
        except Exception as e:
            print(f"Ошибка чтения {SYSMON_LOG_FILE}: {e}")
            await send_message_func(f"📋 Ошибка: не удалось прочитать {SYSMON_LOG_FILE} - {str(e)}")

    # Сохраняем обновлённый лог без старых записей
    try:
        with open(SYSMON_LOG_FILE, "w") as f:
            for guid, ts in seen_guids.items():
                f.write(f"{guid}|{ts.strftime('%Y-%m-%dT%H:%M:%S')}\n")
        print(f"Обновлён {SYSMON_LOG_FILE} с {len(seen_guids)} записями")
    except Exception as e:
        print(f"Ошибка записи в {SYSMON_LOG_FILE}: {e}")
        await send_message_func(f"📋 Ошибка: не удалось записать в {SYSMON_LOG_FILE} - {str(e)}")

    # Загружаем кэш VirusTotal
    vt_cache = {}
    if os.path.exists(SYSMON_CACHE_FILE):
        try:
            with open(SYSMON_CACHE_FILE, "r") as f:
                vt_cache = json.load(f)
            print(f"Загружен кэш VirusTotal из {SYSMON_CACHE_FILE} ({len(vt_cache)} записей)")
        except Exception as e:
            print(f"Ошибка чтения кэша VirusTotal: {e}")

    # Время
    now_local = datetime.now()
    now_utc = now_local - timedelta(hours=3)
    one_minute_ago_utc = now_utc - timedelta(minutes=1)

    log_name = "Microsoft-Windows-Sysmon/Operational"
    query = (
        "*[System[TimeCreated[@SystemTime >= '{}']]]"
        .format(one_minute_ago_utc.strftime("%Y-%m-%dT%H:%M:%S.0000000Z"))
    )

    # Запрос событий
    try:
        h = win32evtlog.EvtQuery(log_name, win32evtlog.EvtQueryReverseDirection, query)
        print("Журнал Sysmon открыт")
    except Exception as e:
        print(f"Ошибка открытия журнала Sysmon: {e}")
        await send_message_func(f"📋 Ошибка: не удалось открыть журнал Sysmon - {str(e)}")
        return

    event_count = 0
    new_guids = []
    while True:
        try:
            events = win32evtlog.EvtNext(h, 10)
        except Exception:
            break
        if not events:
            break

        for evt in events:
            xml_str = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
            event_dict = xmltodict.parse(xml_str)

            system = event_dict.get("Event", {}).get("System", {})
            event_data = event_dict.get("Event", {}).get("EventData", {})
            event_id = system.get("EventID", "неизвестно")

            if event_id != "1":
                continue

            utc_time_raw = system.get("TimeCreated", {}).get("@SystemTime", "")
            computer = system.get("Computer", "неизвестно")

            # Обработка даты
            if '.' in utc_time_raw:
                prefix, suffix = utc_time_raw.split('.')
                fraction = suffix[:6]
                utc_time_clean = f"{prefix}.{fraction}Z"
            else:
                utc_time_clean = utc_time_raw

            try:
                dt_utc = datetime.strptime(utc_time_clean, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                continue

            dt_msk = dt_utc + timedelta(hours=3)
            time_str = dt_msk.strftime("%d.%m.%Y %H:%M:%S")

            user_sid = system.get("Security", {}).get("@UserID", "неизвестно")
            data_items = event_data.get("Data", [])

            process_image = None
            process_guid = None
            hashes = None
            command_line = None

            for d in data_items if isinstance(data_items, list) else []:
                name = d.get("@Name")
                text = d.get("#text", "")
                if name == "Image":
                    process_image = text
                elif name == "ProcessGuid":
                    process_guid = text
                elif name == "Hashes":
                    hashes = text
                elif name == "CommandLine":
                    command_line = text

            if not process_guid:
                print(f"Пропущено событие: отсутствует ProcessGuid")
                continue

            if process_guid in seen_guids:
                print(f"Пропущено событие: ProcessGuid {process_guid} уже обработан")
                continue

            # Извлечение SHA256
            sha256 = None
            if hashes:
                for h in hashes.split(","):
                    if h.startswith("SHA256="):
                        sha256 = h.split("=")[1]
                        break

            # Проверка VirusTotal
            vt_result = "<не проверено>"
            if sha256:
                if sha256 in vt_cache:
                    vt_result = vt_cache[sha256]
                else:
                    try:
                        response = requests.get(
                            f"https://www.virustotal.com/api/v3/files/{sha256}",
                            headers={"x-apikey": VIRUSTOTAL_API_KEY}
                        )
                        if response.status_code == 200:
                            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                            vt_result = f"{stats.get('malicious', 0)}/{stats.get('malicious', 0) + stats.get('undetected', 0)}"
                            vt_cache[sha256] = vt_result
                            try:
                                with open(SYSMON_CACHE_FILE, "w") as f:
                                    json.dump(vt_cache, f, indent=4)
                                print(f"Обновлён кэш VirusTotal: добавлен SHA256 {sha256}")
                            except Exception as e:
                                print(f"Ошибка записи в {SYSMON_CACHE_FILE}: {e}")
                        elif response.status_code == 404:
                            vt_result = "0/0 (файл не найден)"
                    except Exception as e:
                        vt_result = f"ошибка: {str(e)}"

            # Вывод
            print(f"🟢 Event ID: {event_id}")
            print(f"    Время (МСК): {time_str}")
            print(f"    Компьютер:   {computer}")
            print(f"    Пользователь: {user_sid}")
            print(f"    хэш:   {hashes}")
            print(f"    команлайн:   {command_line}")
            if process_image:
                print(f"    Процесс:     {process_image}")
            print("-" * 50)
            print(f"⚠️ Запущен процесс: {process_image}")
            print(f"Аргументы: {command_line or '<нет>'}")
            print(f"SHA256: {sha256 or '<неизвестно>'}")
            print(f"VirusTotal: {vt_result}")
            print()

            # Отправка в Telegram
            message = (
                f"⚠️ Запущен процесс: {process_image}\n"
                f"Время (МСК): {time_str}\n"
                f"Аргументы: {command_line or '<нет>'}\n"
                f"SHA256: {sha256 or '<неизвестно>'}\n"
                f"VirusTotal: {vt_result}"
            )
            await send_message_func(message)

            # Накопительное логирование
            await log_event_to_json(EVENTS_SYSMON_LOG, {
                "time": dt_utc.isoformat(),
                "summary": f"Процесс: {process_image}, Аргументы: {command_line or '<нет>'}, SHA256: {sha256 or '<неизвестно>'}, VirusTotal: {vt_result}"
            }, send_message_func)

            # Сохраняем новый GUID
            new_guids.append((process_guid, dt_utc))
            event_count += 1

    # Записываем новые GUIDs в лог
    if new_guids:
        try:
            with open(SYSMON_LOG_FILE, "a") as f:
                for guid, ts in new_guids:
                    f.write(f"{guid}|{ts.strftime('%Y-%m-%dT%H:%M:%S')}\n")
            print(f"Добавлено {len(new_guids)} новых ProcessGuid в {SYSMON_LOG_FILE}")
        except Exception as e:
            print(f"Ошибка записи новых GUIDs в {SYSMON_LOG_FILE}: {e}")
            await send_message_func(f"📋 Ошибка: не удалось записать новые GUIDs в {SYSMON_LOG_FILE} - {str(e)}")

    print(f"Всего событий Sysmon за минуту: {event_count}")