"""
Сниффер для перехвата трафика на порту 3040 в реальном времени
С поддержкой сборки TCP-фрагментов
"""

import threading
import time
from datetime import datetime
from typing import Optional, Callable
from collections import defaultdict

from scapy.all import sniff, IP, UDP, TCP, Raw, conf


class PacketInfo:
    """Информация о перехваченном пакете"""
    def __init__(self, data: bytes, src_ip: str, src_port: int,
                 dst_ip: str, dst_port: int, timestamp: datetime):
        self.data = data
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.timestamp = timestamp


class FragmentReassembler:
    """
    Собирает TCP-фрагменты в единый логический пакет.
    Фрагменты от одного источника, пришедшие в течение
    FRAGMENT_TIMEOUT секунд, считаются частями одного пакета.
    """

    FRAGMENT_TIMEOUT = 0.1  # 100мс

    def __init__(self):
        self._buffers: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _make_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        return f"{src_ip}:{src_port}_{dst_ip}:{dst_port}"

    def add_fragment(self, src_ip: str, src_port: int,
                     dst_ip: str, dst_port: int,
                     payload: bytes, timestamp: float) -> Optional[bytes]:
        """
        Добавить фрагмент. Если собран полный пакет — вернуть его.
        Если фрагмент — продолжить сборку (вернуть None).
        Для UDP каждый пакет самостоятельный — сразу возвращаем payload.
        """
        key = self._make_key(src_ip, src_port, dst_ip, dst_port)

        with self._lock:
            now = timestamp

            if key in self._buffers:
                buf_info = self._buffers[key]
                elapsed = now - buf_info['first_seen']

                # Если прошло больше timeout — старый пакет завершаем и возвращаем
                if elapsed > self.FRAGMENT_TIMEOUT:
                    result = buf_info['data']
                    # Начинаем новый буфер
                    buf_info['data'] = payload
                    buf_info['first_seen'] = now
                    buf_info['fragment_count'] = 1
                    return result

                # Это фрагмент того же пакета — добавляем
                buf_info['data'] += payload
                buf_info['fragment_count'] += 1
                buf_info['first_seen'] = now
                return None  # Продолжаем сборку
            else:
                # Первый фрагмент нового пакета
                self._buffers[key] = {
                    'data': payload,
                    'first_seen': now,
                    'fragment_count': 1,
                }
                return None

    def flush(self) -> list[bytes]:
        """Сбросить все накопленные буферы"""
        with self._lock:
            results = [buf['data'] for buf in self._buffers.values()]
            self._buffers.clear()
            return results


class Port3040Sniffer:
    """
    Сниффер для перехвата UDP/TCP трафика на порту 3040.
    Работает в отдельном потоке.
    """

    def __init__(self, target_port: int = 3040):
        self.target_port = target_port
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_callback: Optional[Callable[[PacketInfo], None]] = None
        self._packets_captured = 0
        self._error: Optional[str] = None
        self._reassembler = FragmentReassembler()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packets_captured(self) -> int:
        return self._packets_captured

    @property
    def error(self) -> Optional[str]:
        return self._error

    def start(self, callback: Callable[[PacketInfo], None]):
        """
        Запуск сниффера в отдельном потоке.
        callback вызывается для каждого собранного пакета с портом 3040.
        """
        if self._running:
            raise RuntimeError("Сниффер уже запущен")

        self._packet_callback = callback
        self._running = True
        self._packets_captured = 0
        self._error = None
        self._reassembler = FragmentReassembler()

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Остановка сниффера"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _sniff_loop(self):
        """Основной цикл сниффера"""
        try:
            # Фильтр: ВСЕ пакеты с портом 3040 (входящие + исходящие)
            bpf_filter = f"port {self.target_port}"

            sniff(
                filter=bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except PermissionError:
            self._error = "Ошибка доступа. Запустите от имени администратора."
            self._running = False
        except Exception as e:
            self._error = f"Ошибка сниффера: {str(e)}"
            self._running = False

    def _process_packet(self, packet):
        """Обработка одного пакета (возможно фрагмента)"""
        if not self._running:
            return

        try:
            if IP not in packet:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Определяем порты
            src_port = 0
            dst_port = 0
            has_payload = False
            payload = b''
            is_tcp = False

            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    has_payload = True
            elif TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    has_payload = True
                    is_tcp = True

            # Проверяем что хотя бы один из портов == 3040
            if src_port != self.target_port and dst_port != self.target_port:
                return

            # Игнорируем пустые пакеты
            if not has_payload or len(payload) < 5:
                return

            # Пытаемся собрать фрагменты (для TCP и UDP)
            assembled = self._reassembler.add_fragment(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                payload=payload,
                timestamp=float(packet.time),
            )

            if assembled is None:
                return  # Продолжаем сборку фрагментов

            payload = assembled

            self._packets_captured += 1

            packet_info = PacketInfo(
                data=payload,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                timestamp=datetime.now()
            )

            if self._packet_callback:
                self._packet_callback(packet_info)

        except Exception:
            pass  # Игнорируем ошибки обработки отдельных пакетов

    @staticmethod
    def get_network_interfaces() -> list[dict]:
        """Получение списка сетевых интерфейсов"""
        interfaces = []
        try:
            ifaces = conf.ifaces
            for name, iface in ifaces.items():
                interfaces.append({
                    'name': name,
                    'description': iface.description,
                    'ip': iface.ip if hasattr(iface, 'ip') else 'N/A',
                    'mac': iface.mac if hasattr(iface, 'mac') else 'N/A',
                })
        except Exception:
            pass
        return interfaces

    @staticmethod
    def check_npcap_installed() -> bool:
        """Проверка наличия npcap/WinPcap"""
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            return len(ifaces) > 0
        except Exception:
            return False
