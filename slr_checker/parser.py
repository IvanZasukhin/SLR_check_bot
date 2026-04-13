"""
Глубокий protobuf-сканер для пакетов игры
Рекурсивно обходит ВСЕ уровни вложенности
"""
from dataclasses import dataclass
import re
from typing import Any


@dataclass
class ParticipantBlock:
    """Блок данных одного участника"""
    ai_id: str = ""       # AI_1, AI_2 и т.д.
    real_name: str = ""   # Anderson, Vendeta и т.д.
    steam_id: str = ""    # steam_7656...
    numbers: list[int] = None

    def __post_init__(self):
        if self.numbers is None:
            self.numbers = []

    @property
    def display_name(self) -> str:
        """Отображаемое имя"""
        if self.steam_id:
            return self.steam_id
        if self.real_name:
            suffix = f" ({self.ai_id})" if self.ai_id else ""
            return f"{self.real_name}{suffix}"
        return self.ai_id or "Unknown"

    @property
    def participant_type(self) -> str:
        if self.steam_id:
            return "Player"
        # device_* — это игрок без steam_id
        if self.ai_id and self.ai_id.startswith("AI_"):
            return "Bot"
        # Если есть real_name и не AI_* — это игрок
        if self.real_name:
            return "Player"
        return "Unknown"

    @property
    def secret_number(self) -> str:
        """Первое «большое» число как секретный номер"""
        for n in self.numbers:
            if n > 10:
                return str(n)
        return ""


class DeepProtobufScanner:
    """
    Глубокий сканер protobuf.
    Рекурсивно обходит все вложенные сообщения.
    Ищет блоки с AI_X и steam_* на любом уровне.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.blocks: list[ParticipantBlock] = []

    def scan(self) -> list[ParticipantBlock]:
        """Полный обход, возвращает список ParticipantBlock"""
        self.blocks = []
        self._walk(self.data, max_depth=20)
        return self.blocks

    def _walk(self, data: bytes, max_depth: int):
        """Рекурсивный обход одного блока"""
        if max_depth <= 0:
            return

        pos = 0
        current_block = ParticipantBlock()
        in_participant_block = False
        import sys

        while pos < len(data):
            try:
                key, key_len = self._read_varint(data, pos)
                if key_len == 0 or key == 0:
                    pos += 1
                    continue

                pos += key_len
                field_number = key >> 3
                wire_type = key & 0x07

                if wire_type == 0:  # Varint
                    value, val_len = self._read_varint(data, pos)
                    pos += val_len
                    if in_participant_block:
                        current_block.numbers.append(value)

                elif wire_type == 1:  # 64-bit
                    pos += 8

                elif wire_type == 2:  # Length-delimited
                    length, len_len = self._read_varint(data, pos)
                    pos += len_len

                    if pos + length > len(data):
                        # Данные обрезаны — пробуем разобрать что есть
                        actual_length = len(data) - pos
                        nested_data = data[pos:pos + actual_length]
                        pos += actual_length
                        # Рекурсивный обход неполного блока
                        self._walk(nested_data, max_depth - 1)
                        continue

                    nested_data = data[pos:pos + length]
                    pos += length

                    # Пробуем декодировать как строку (UTF-8 → CP1251 → Latin1)
                    # Сначала UTF-8 strict
                    text = None
                    try:
                        text = nested_data.decode('utf-8', errors='strict')
                    except UnicodeDecodeError:
                        pass

                    if text is None:
                        # Попробуем latin-1 (всегда работает) и проверим printable
                        candidate = nested_data.decode('latin-1')
                        if self._is_printable(candidate):
                            text = candidate
                        else:
                            # Не строка — рекурсивный обход
                            self._walk(nested_data, max_depth - 1)
                            continue

                    if text and self._is_printable(text):
                        # AI_X идентификатор — только AI_1..AI_9
                        ai_match = re.match(r'^AI_[1-9]$', text)
                        if ai_match:
                            current_block.ai_id = text
                            in_participant_block = True
                        # Steam ID или device_* — это идентификатор участника
                        elif ("steam_" in text.lower() or "device_" in text.lower()) and len(text) > 5:
                            if "steam_" in text.lower():
                                current_block.steam_id = text
                            else:
                                current_block.ai_id = text
                            in_participant_block = True
                        # Реальное имя (в tag 2 рядом с идентификатором)
                        elif (current_block.ai_id or current_block.steam_id) and not current_block.real_name:
                            if 2 <= len(text) < 30:
                                cleaned = text.strip(' .\t\n\r')
                                if cleaned and len(cleaned) >= 2:
                                    current_block.real_name = cleaned

                elif wire_type == 5:  # 32-bit
                    pos += 4

                else:
                    # Неизвестный wire_type (3, 4, 6, 7) — пропускаем только key,
                    # НЕ добавляем +1 к pos (key_len уже применён)
                    pass

            except Exception:
                pos += 1
                continue

        # Сохраняем блок если нашли идентификатор
        if current_block.ai_id or current_block.steam_id:
            self.blocks.append(current_block)

    @staticmethod
    def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
        """Чтение varint: (значение, длина)"""
        result = 0
        shift = 0
        length = 0
        while pos + length < len(data):
            byte = data[pos + length]
            length += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                return result, length
            shift += 7
        raise ValueError("Неожиданный конец данных")

    @staticmethod
    def _is_printable(text: str) -> bool:
        """Проверка что строка — печатный текст (UTF-8 допустим)"""
        if not text:
            return False
        # Разрешаем UTF-8, но исключаем контрольные символы
        for c in text:
            code = ord(c)
            # Исключаем control chars кроме tab/newline/carriage
            if code < 0x20 and c not in '\t\n\r':
                return False
            # Исключаем DEL
            if code == 0x7F:
                return False
        return True


def scan_for_participants(data: bytes) -> list[dict]:
    """
    Главная функция сканирования.
    Возвращает список:
      {
        'name': str,          # Идентификатор (steam_XXX или AI_X)
        'real_name': str,     # Реальное имя (если есть)
        'steam_id': str,      # SteamID
        'type': str,          # Bot / Player
        'secret_number': str  # Секретный номер
      }
    """
    scanner = DeepProtobufScanner(data)
    blocks = scanner.scan()

    # Группировка по идентификатору — выбираем лучший блок (с именем)
    best_blocks: dict[str, ParticipantBlock] = {}
    for b in blocks:
        # Ключ группировки — всегда идентификатор
        key = b.steam_id or b.ai_id
        if not key:
            continue

        if key in best_blocks:
            # Заменяем если текущий блок лучше (есть имя а в старом нет)
            existing = best_blocks[key]
            if b.real_name and not existing.real_name:
                best_blocks[key] = b
        else:
            best_blocks[key] = b

    participants = []
    for b in best_blocks.values():
        # name = идентификатор, real_name = реальное имя
        participants.append({
            'name': b.steam_id or b.ai_id,
            'real_name': b.real_name if b.real_name else (b.steam_id if b.steam_id else b.ai_id),
            'steam_id': b.steam_id,
            'type': b.participant_type,
            'secret_number': b.secret_number,
        })

    return participants
