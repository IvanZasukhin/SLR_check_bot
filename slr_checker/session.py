"""
Анализатор сессий - определение Player/Bot, извлечение имён и SteamID
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable

from .parser import scan_for_participants


@dataclass
class SessionParticipant:
    """Участник игровой сессии"""
    name: str = ""           # SteamID или AI_X
    real_name: str = ""      # Реальное имя (LeviathansCrown, Westnik)
    participant_type: str = "Unknown"  # Player, Bot, Unknown
    steam_id: str = ""
    secret_number: str = ""
    ip_address: str = ""
    timestamp: str = ""
    session_id: str = ""

    def to_dict(self) -> dict:
        return {
            "Имя": self.display_name,
            "Участник": self.name,
            "Тип": self.participant_type,
            "Секретный номер": self.secret_number,
        }

    @property
    def display_name(self) -> str:
        """Отображаемое имя для таблицы"""
        if not self.real_name:
            return "—"
        # Если реальное имя совпадает с идентификатором — скрываем дубль
        if self.real_name.strip() == self.name.strip():
            return "—"
        return self.real_name


class SessionTracker:
    """Отслеживание активных сессий и участников"""

    def __init__(self, on_server_change: Optional[Callable[[str, str], None]] = None):
        self.sessions: dict[str, list[SessionParticipant]] = {}
        self.packet_counters: dict[str, int] = {}
        self._current_server: str = ""
        self.on_server_change = on_server_change  # callback(old_server, new_server)

    @property
    def current_server(self) -> str:
        return self._current_server

    def _check_server_change(self, server_ip: str) -> bool:
        """Проверка смены сервера. Возвращает True если сервер сменился."""
        if not self._current_server:
            self._current_server = server_ip
            return False

        if self._current_server != server_ip:
            old = self._current_server
            self._current_server = server_ip
            if self.on_server_change:
                self.on_server_change(old, server_ip)
            return True
        return False

    def clear_current_session(self):
        """Очистить текущую сессию"""
        if self._current_server:
            self.sessions.clear()
            self.packet_counters.clear()
            # Не сбрасываем _current_server — чтобы не было ложных срабатываний

    def _get_session_key(self, src_ip: str, src_port: int, dst_ip: str) -> str:
        """Генерация ключа сессии из 5-кортежа"""
        return f"{src_ip}:{src_port}_{dst_ip}"

    def process_packet(self, data: bytes, src_ip: str, src_port: int,
                       dst_ip: str, timestamp: Optional[datetime] = None) -> list[SessionParticipant]:
        """
        Обработка одного пакета.
        Возвращает список найденных участников.
        """
        session_key = self._get_session_key(src_ip, src_port, dst_ip)

        # Проверяем смену сервера → авто-очистка
        server_changed = self._check_server_change(dst_ip)
        if server_changed:
            self.clear_current_session()

        # Инициализация счётчика пакетов сессии
        if session_key not in self.packet_counters:
            self.packet_counters[session_key] = 0
            self.sessions[session_key] = []

        self.packet_counters[session_key] += 1
        packet_num = self.packet_counters[session_key]

        # Анализируем ВСЕ пакеты с полезной нагрузкой > 10 байт
        if len(data) > 10:
            participants = self._extract_participants(data, session_key, dst_ip, timestamp)
            if participants:
                # Добавляем и возвращаем ТОЛЬКО новых участников
                existing_keys = {f"{p.name}_{p.steam_id}" for p in self.sessions[session_key]}
                new_participants = []
                for p in participants:
                    key = f"{p.name}_{p.steam_id}"
                    if key not in existing_keys:
                        existing_keys.add(key)
                        self.sessions[session_key].append(p)
                        new_participants.append(p)

                # Пытаемся улучшить имена из накопленных данных
                self._merge_names(session_key)

                return new_participants

        return []

    def _merge_names(self, session_key: str):
        """Объединить имена из разных пакетов одной сессии"""
        participants = self.sessions.get(session_key, [])
        if not participants:
            return

        # Собираем мапу: participant_id → лучшее реальное имя
        best_names: dict[str, str] = {}
        for p in participants:
            if p.real_name and p.real_name != p.name:
                best_names[p.name] = p.real_name

        # Применяем лучшие имена ко всем участникам
        for p in participants:
            if p.name in best_names:
                p.real_name = best_names[p.name]

    def _extract_participants(self, data: bytes, session_key: str,
                              server_ip: str, timestamp: Optional[datetime] = None) -> list[SessionParticipant]:
        """Извлечение участников из пакета"""
        participants = []
        ts = (timestamp or datetime.now()).isoformat()

        # Основной метод: глубокое сканирование protobuf
        found = scan_for_participants(data)

        for item in found:
            participant_id = item['name']       # steam_XXX или AI_X
            real_name = item.get('real_name', '')  # Реальное имя (LeviathansCrown, Westnik)
            ptype = item['type']
            secret_number = item['secret_number']
            steam_id = item.get('steam_id', '')

            # Если нет реального имени, но есть SteamID — используем SteamID как имя
            if not real_name and steam_id:
                real_name = steam_id

            p = SessionParticipant(
                name=participant_id,
                real_name=real_name,
                participant_type=ptype,
                steam_id=steam_id,
                secret_number=secret_number,
                ip_address=server_ip,
                timestamp=ts,
                session_id=session_key,
            )
            participants.append(p)

        # Фоллбэк: поиск ASCII-паттернов в сырых данных
        if not participants:
            participants.extend(
                self._search_raw_patterns(data, session_key, server_ip, ts)
            )

        return participants

    def _search_raw_patterns(self, data: bytes, session_key: str,
                             server_ip: str, timestamp: str) -> list[SessionParticipant]:
        """Поиск паттернов в сырых данных (фоллбэк)"""
        participants = []
        raw_str = data.decode('utf-8', errors='replace')

        # Поиск SteamID64
        steam_matches = re.findall(r'steam_\d{17}', raw_str)
        # Поиск AI_ имён
        ai_matches = re.findall(r'AI_\d+', raw_str)

        # Удаляем дубликаты
        steam_ids = list(set(steam_matches))
        ai_names = list(set(ai_matches))

        for steam_id in steam_ids:
            participants.append(SessionParticipant(
                name=steam_id,
                participant_type="Player",
                steam_id=steam_id,
                ip_address=server_ip,
                timestamp=timestamp,
                session_id=session_key,
            ))

        for ai_name in ai_names:
            participants.append(SessionParticipant(
                name=ai_name,
                participant_type="Bot",
                ip_address=server_ip,
                timestamp=timestamp,
                session_id=session_key,
            ))

        return participants

    def get_all_participants(self) -> list[SessionParticipant]:
        """Получить всех уникальных участников из всех сессий"""
        all_participants = []
        seen = set()

        for session_id, participants in self.sessions.items():
            for p in participants:
                unique_key = f"{p.name}_{p.steam_id}"
                if unique_key not in seen:
                    seen.add(unique_key)
                    all_participants.append(p)

        return all_participants

    def clear_session(self, session_key: str):
        """Очистка данных сессии"""
        self.sessions.pop(session_key, None)
        self.packet_counters.pop(session_key, None)
