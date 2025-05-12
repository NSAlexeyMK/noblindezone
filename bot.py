import asyncio
from telegram import Bot
from config import TELEGRAM_TOKEN, CHAT_ID

# Инициализация бота
try:
    bot = Bot(token=TELEGRAM_TOKEN)
    if not CHAT_ID or not isinstance(CHAT_ID, (str, int)):
        raise ValueError("CHAT_ID не задан или имеет неверный тип")
    print(f"Бот инициализирован с CHAT_ID: {CHAT_ID}")
except Exception as e:
    print(f"Ошибка инициализации бота: {e}")
    exit(1)

# Функция отправки сообщения в Telegram
async def send_message(message):
    try:
        await bot.send_message(chat_id=CHAT_ID, text=message)
        print(f"Сообщение отправлено: {message}")
    except Exception as e:
        print(f"Ошибка отправки сообщения: {e}")

# Функция отправки документа в Telegram
async def send_document(file_path):
    try:
        with open(file_path, 'rb') as f:
            await bot.send_document(chat_id=CHAT_ID, document=f)
        print(f"Документ отправлен: {file_path}")
    except Exception as e:
        print(f"Ошибка отправки документа: {e}")
        raise