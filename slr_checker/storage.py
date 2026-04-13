"""
Хранилище данных сессии в %APPDATA%/SLRCheckBot/
Сохраняет участников сервера для восстановления при "Обновить".
При смене сервера старые данные удаляются.
"""

import os
import json
from datetime import datetime
from typing import Optional
from dataclasses import asdict

from .session import SessionParticipant

# Путь хранения: %APPDATA%/SLRCheckBot/
APP_DATA_DIR = os.path.join(os.environ.get('APPDATA', ''), 'SLRCheckBot')
DATA_FILE = os.path.join(APP_DATA_DIR, 'session.json')


def _ensure_dir():
    """Создать директорию если не существует"""
    if not os.path.exists(APP_DATA_DIR):
        os.makedirs(APP_DATA_DIR, exist_ok=True)


def save_session(server_ip: str, participants: list[SessionParticipant]):
    """Сохранить участников сервера в файл"""
    _ensure_dir()
    data = {
        'server_ip': server_ip,
        'saved_at': datetime.now().isoformat(),
        'participants': [
            {
                'name': p.name,
                'real_name': p.real_name,
                'participant_type': p.participant_type,
                'steam_id': p.steam_id,
                'secret_number': p.secret_number,
            }
            for p in participants
        ]
    }
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_session() -> Optional[dict]:
    """Загрузить сохранённых участников сервера"""
    if not os.path.exists(DATA_FILE):
        return None
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def clear_session():
    """Удалить сохранённые данные"""
    if os.path.exists(DATA_FILE):
        os.remove(DATA_FILE)


def get_server_ip() -> Optional[str]:
    """Получить IP сохранённого сервера"""
    data = load_session()
    return data.get('server_ip') if data else None
