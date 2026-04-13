"""
Импорт hex-дампов пакетов для анализа
"""

import re
from typing import Optional


class HexDumpImporter:
    """Импорт и конвертация hex-дампов в бинарные данные"""

    @staticmethod
    def parse_hex_string(hex_string: str) -> bytes:
        """
        Парсинг hex-строки в байты.
        Поддерживает форматы:
        - "0a 04 41 49 5f 31" (с пробелами)
        - "0a0441495f31" (слитно)
        - "0A 04 41 49 5F 31" (верхний регистр)
        - С комментариями после # или //
        """
        # Удаляем комментарии
        hex_string = re.sub(r'[#//].*$', '', hex_string, flags=re.MULTILINE)

        # Удаляем всё кроме hex-символов и пробелов
        hex_string = re.sub(r'[^0-9a-fA-F\s]', '', hex_string)

        # Удаляем пробелы
        hex_string = hex_string.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')

        # Проверяем корректность длины
        if len(hex_string) % 2 != 0:
            raise ValueError(f"Нечётное количество hex-символов: {len(hex_string)}")

        return bytes.fromhex(hex_string)

    @staticmethod
    def parse_file(filepath: str) -> list[bytes]:
        """
        Чтение файла с hex-дампами.
        Каждый пакет может быть отделён новой строкой или маркером.
        Возвращает список пакетов в байтах.
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        return HexDumpImporter.parse_multi_packet(content)

    @staticmethod
    def parse_multi_packet(content: str) -> list[bytes]:
        """
        Парсинг мульти-пакетного дампа.
        Разделители: пустая строка, "---", "PACKET", "==="
        """
        # Разделяем по распространённым разделителям
        packets = re.split(r'\n\s*\n|---+|===+|PACKET\s*\d*', content)

        result = []
        for packet in packets:
            packet = packet.strip()
            if not packet:
                continue

            try:
                data = HexDumpImporter.parse_hex_string(packet)
                if data:
                    result.append(data)
            except ValueError as e:
                print(f"Предупреждение: пропуск блока данных - {e}")
                continue

        return result

    @staticmethod
    def parse_pcap_ng(filepath: str) -> list[dict]:
        """
        Заглушка для чтения pcap/pcapng файлов.
        Возвращает список пакетов с метаданными.
        Для полноценной работы требуется scapy.
        """
        try:
            from scapy.all import rdpcap, IP, UDP, TCP, Raw

            packets_data = []
            packets = rdpcap(filepath)

            for pkt in packets:
                if IP in pkt and (UDP in pkt or TCP in pkt):
                    # Определяем порт назначения
                    dst_port = 0
                    src_port = 0
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if UDP in pkt:
                        dst_port = pkt[UDP].dport
                        src_port = pkt[UDP].sport
                    elif TCP in pkt:
                        dst_port = pkt[TCP].dport
                        src_port = pkt[TCP].sport

                    # Фильтруем только порт 3040
                    if dst_port == 3040 and Raw in pkt:
                        packets_data.append({
                            'data': bytes(pkt[Raw].load),
                            'src_ip': src_ip,
                            'src_port': src_port,
                            'dst_ip': dst_ip,
                            'timestamp': float(pkt.time),
                        })

            return packets_data

        except ImportError:
            raise ImportError("Для чтения pcap требуется scapy: pip install scapy")
        except Exception as e:
            raise RuntimeError(f"Ошибка чтения pcap: {e}")
