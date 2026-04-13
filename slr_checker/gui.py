"""
GUI приложение для мониторинга участников игровой сессии
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import threading
import csv
import os
import webbrowser

from .session import SessionTracker, SessionParticipant
from .sniffer import Port3040Sniffer, PacketInfo
from .storage import save_session, load_session, clear_session, get_server_ip


class SLRCheckerApp:
    """Главное приложение с GUI"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SLR Check Bot - Анализатор трафика port 3040")
        self.root.geometry("800x650")
        self.root.minsize(700, 500)

        # Счётчики
        self.total_bots = 0
        self.total_players = 0
        self.total_packets = 0

        # Набор уже добавленных участников (для предотвращения дублей)
        self._seen_participants = set()

        # Создаём трекер с callback на смену сервера
        self.session_tracker = SessionTracker(
            on_server_change=self._on_server_changed
        )
        self.sniffer = Port3040Sniffer(target_port=3040)
        self._sniffer_active = False

        self._setup_ui()
        self._start_update_loop()

    def _setup_ui(self):
        """Настройка интерфейса"""
        # Верхняя панель управления
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)

        # Кнопки управления сниффером
        self.start_btn = ttk.Button(control_frame, text="▶ Старт мониторинга", command=self._start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="⏹ Стоп", command=self._stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)

        ttk.Button(control_frame, text="Обновить", command=self._refresh_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Очистить", command=self._clear_table).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Экспорт CSV", command=self._export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Экспорт Excel", command=self._export_excel).pack(side=tk.LEFT, padx=5)

        # Статус
        self.status_var = tk.StringVar(value="⏸ Готов к работе")
        ttk.Label(control_frame, textvariable=self.status_var).pack(side=tk.RIGHT, padx=10)

        # Панель счётчиков
        counter_frame = ttk.Frame(self.root, padding="5")
        counter_frame.pack(fill=tk.X)

        # Счётчик ботов
        bot_frame = ttk.LabelFrame(counter_frame, text="🤖 БОТЫ", padding="5")
        bot_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)

        self.bot_count_var = tk.StringVar(value="0")
        bot_label = tk.Label(bot_frame, textvariable=self.bot_count_var, font=("Consolas", 24, "bold"), fg="orange")
        bot_label.pack()

        # Счётчик игроков
        player_frame = ttk.LabelFrame(counter_frame, text="👥 ИГРОКИ", padding="5")
        player_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)

        self.player_count_var = tk.StringVar(value="0")
        player_label = tk.Label(player_frame, textvariable=self.player_count_var, font=("Consolas", 24, "bold"), fg="green")
        player_label.pack()

        # Счётчик пакетов
        packet_frame = ttk.LabelFrame(counter_frame, text="📦 ПАКЕТЫ", padding="5")
        packet_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)

        self.packet_count_var = tk.StringVar(value="0")
        packet_label = tk.Label(packet_frame, textvariable=self.packet_count_var, font=("Consolas", 24, "bold"), fg="blue")
        packet_label.pack()

        # Таблица участников
        table_frame = ttk.Frame(self.root, padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Имя", "Участник", "Тип")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.tree.heading("Имя", text="Имя")
        self.tree.heading("Участник", text="Участник")
        self.tree.heading("Тип", text="Тип")

        self.tree.column("Имя", width=200, anchor=tk.W)
        self.tree.column("Участник", width=300, anchor=tk.W)
        self.tree.column("Тип", width=80, anchor=tk.CENTER)

        # Скроллбар
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Настройка цветов для типов
        self.tree.tag_configure("Player", foreground="green")
        self.tree.tag_configure("Bot", foreground="orange")
        self.tree.tag_configure("Unknown", foreground="red")

        # Бинды кликов
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Button-1>", self._on_single_click)

        # Нижняя панель с логами
        log_frame = ttk.LabelFrame(self.root, text="Лог", padding="10")
        log_frame.pack(fill=tk.X, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.X)

    def _on_server_changed(self, old_server: str, new_server: str):
        """Автоматическая очистка при смене сервера (новая игра)"""
        self._log(f"🔄 Сервер сменился: {old_server} → {new_server}")
        self._log("  Таблица автоматически очищена")

        # Удаляем старые данные из AppData
        clear_session()

        # Очищаем таблицу и счётчики
        for item in self.tree.get_children():
            self.tree.delete(item)

        self._seen_participants.clear()
        self.total_bots = 0
        self.total_players = 0

        self.bot_count_var.set("0")
        self.player_count_var.set("0")

    def _on_single_click(self, event):
        """Одинарный клик — копирование ника бота"""
        self.root.after(50, self._copy_bot_name_only)

    def _copy_bot_name_only(self):
        """Копировать ник бота при одинарном клике"""
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        values = item["values"]
        real_name = values[0]
        participant_id = values[1]
        participant_type = values[2]

        if participant_type == "Bot":
            copy_name = real_name if real_name != "—" else participant_id
            self.root.clipboard_clear()
            self.root.clipboard_append(copy_name)
            self._log(f"📋 Скопировано: {copy_name}")

    def _on_double_click(self, event):
        """Двойной клик — открыть Steam профиль игрока"""
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        values = item["values"]
        real_name = values[0]
        participant_id = values[1]
        participant_type = values[2]

        if participant_type == "Player":
            steam_id = participant_id.replace("steam_", "")
            if steam_id and steam_id.isdigit():
                url = f"https://steamcommunity.com/profiles/{steam_id}"
                webbrowser.open_new_tab(url)
                self._log(f"🌐 Steam профиль: {real_name or participant_id}")
            else:
                self._log(f"⚠ SteamID не найден: {participant_id}")
        elif participant_type == "Bot":
            copy_name = real_name if real_name != "—" else participant_id
            self.root.clipboard_clear()
            self.root.clipboard_append(copy_name)
            self._log(f"📋 Скопировано: {copy_name}")

    def _log(self, message: str):
        """Добавление записи в лог"""
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _start_monitoring(self):
        """Запуск мониторинга трафика"""
        if self._sniffer_active:
            return

        self._log("Запуск сниффера на порту 3040...")
        self.status_var.set("⏳ Мониторинг запущен...")

        try:
            self.sniffer.start(callback=self._on_packet_captured)
            self._sniffer_active = True

            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)

            self._log("✓ Сниффер запущен. Ожидание пакетов...")
            self._log("  Запустите игру для генерации трафика")

        except Exception as e:
            self._log(f"✗ ОШИБКА запуска: {e}")
            messagebox.showerror(
                "Ошибка",
                f"Не удалось запустить сниффер:\n{e}\n\n"
                "Убедитесь что:\n"
                "1. Npcap установлен\n"
                "2. Программа запущена от имени администратора"
            )
            self.status_var.set("⏸ Ошибка запуска")

    def _stop_monitoring(self):
        """Остановка мониторинга"""
        if not self._sniffer_active:
            return

        self._log("Остановка сниффера...")
        self.sniffer.stop()
        self._sniffer_active = False

        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        self.status_var.set(f"⏸ Остановлено. Пакетов: {self.total_packets}")
        self._log(f"✓ Сниффер остановлен. Перехвачено пакетов: {self.total_packets}")
        self._log(f"  Ботов обнаружено: {self.total_bots}")
        self._log(f"  Игроков обнаружено: {self.total_players}")

    def _on_packet_captured(self, packet_info: PacketInfo):
        """Обработка перехваченного пакета"""
        self.total_packets += 1
        self.packet_count_var.set(str(self.total_packets))

        # Логируем пакет
        hex_preview = packet_info.data[:20].hex()
        self._log(f"Пакет #{self.total_packets} | {len(packet_info.data)} байт | {hex_preview}...")

        try:
            participants = self.session_tracker.process_packet(
                data=packet_info.data,
                src_ip=packet_info.src_ip,
                src_port=packet_info.src_port,
                dst_ip=packet_info.dst_ip,
                timestamp=packet_info.timestamp
            )

            if participants:
                for p in participants:
                    # Дедупликация ТОЛЬКО по идентификатору (столбец "Участник")
                    unique_key = p.name
                    if unique_key not in self._seen_participants:
                        self._seen_participants.add(unique_key)
                        self._add_participant_to_tree(p)

                        display = p.display_name
                        if p.participant_type == "Bot":
                            self.total_bots += 1
                            self._log(f"  🤖 БОТ: {display}")
                        elif p.participant_type == "Player":
                            self.total_players += 1
                            self._log(f"  👥 ИГРОК: {display}")

                self.bot_count_var.set(str(self.total_bots))
                self.player_count_var.set(str(self.total_players))

                names = ", ".join([p.display_name for p in participants])
                self._log(f"  → Найдено: {len(participants)} уч. — {names}")

                # Сохраняем в AppData
                server_ip = self.session_tracker.current_server
                if server_ip:
                    all_p = self.session_tracker.get_all_participants()
                    save_session(server_ip, all_p)
            else:
                self._log(f"  — участников не найдено")

        except Exception as e:
            self._log(f"  ⚠ Ошибка: {e}")

    def _start_update_loop(self):
        """Запуск цикла обновления GUI"""
        self._update_gui()

    def _update_gui(self):
        """Периодическое обновление GUI"""
        if self._sniffer_active:
            packets = self.sniffer.packets_captured
            if self.total_packets != packets:
                self.total_packets = packets
                self.packet_count_var.set(str(self.total_packets))

            if self.sniffer.error:
                self._log(f"✗ Ошибка сниффера: {self.sniffer.error}")
                self._stop_monitoring()

            # Обновляем сервер в статусе
            srv = self.session_tracker.current_server
            if srv:
                self.status_var.set(f"⏳ Сервер: {srv} | Пакетов: {self.total_packets}")

        self.root.after(500, self._update_gui)

    def _add_participant_to_tree(self, participant: SessionParticipant):
        """Добавление участника в таблицу"""
        tag = participant.participant_type
        self.tree.insert("", tk.END, values=(
            participant.display_name,
            participant.name,
            participant.participant_type,
        ), tags=(tag,))

    def _clear_table(self):
        """Очистка таблицы и сессий"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.session_tracker = SessionTracker(
            on_server_change=self._on_server_changed
        )
        self._seen_participants.clear()
        self.total_bots = 0
        self.total_players = 0
        self.total_packets = 0

        self.bot_count_var.set("0")
        self.player_count_var.set("0")
        self.packet_count_var.set("0")

        self.status_var.set("⏸ Таблица очищена")
        self._log("Таблица и сессии очищены, счётчики сброшены")

    def _refresh_data(self):
        """Перезапрос данных из сессии и AppData, обновление таблицы"""
        # Загружаем из AppData (если есть сохранённые данные)
        saved = load_session()

        if saved and saved.get('participants'):
            # Восстанавливаем из сохранённых данных
            for item in self.tree.get_children():
                self.tree.delete(item)
            self._seen_participants.clear()
            self.total_bots = 0
            self.total_players = 0

            for pd in saved['participants']:
                p = SessionParticipant(
                    name=pd['name'],
                    real_name=pd['real_name'],
                    participant_type=pd['participant_type'],
                    steam_id=pd.get('steam_id', ''),
                    secret_number=pd.get('secret_number', ''),
                )
                unique_key = p.name
                if unique_key not in self._seen_participants:
                    self._seen_participants.add(unique_key)
                    self._add_participant_to_tree(p)
                    if p.participant_type == "Bot":
                        self.total_bots += 1
                    elif p.participant_type == "Player":
                        self.total_players += 1

            self.bot_count_var.set(str(self.total_bots))
            self.player_count_var.set(str(self.total_players))
            self._log(f"🔄 Загружено из кэша: {self.total_bots} ботов, {self.total_players} игроков")
        else:
            # Если нет кэша — берём из текущей сессии
            for item in self.tree.get_children():
                self.tree.delete(item)
            self._seen_participants.clear()
            self.total_bots = 0
            self.total_players = 0

            for p in self.session_tracker.get_all_participants():
                unique_key = p.name
                if unique_key not in self._seen_participants:
                    self._seen_participants.add(unique_key)
                    self._add_participant_to_tree(p)
                    if p.participant_type == "Bot":
                        self.total_bots += 1
                    elif p.participant_type == "Player":
                        self.total_players += 1

            self.bot_count_var.set(str(self.total_bots))
            self.player_count_var.set(str(self.total_players))

        # Сохраняем актуальные данные
        server_ip = self.session_tracker.current_server
        if server_ip:
            all_p = self.session_tracker.get_all_participants()
            if all_p:
                save_session(server_ip, all_p)

        self._log(f"🔄 Обновлено: {self.total_bots} ботов, {self.total_players} игроков")
        self.status_var.set(f"⏸ Обновлено: {self.total_bots + self.total_players} участников")

    def _export_csv(self):
        """Экспорт в CSV"""
        participants = self.session_tracker.get_all_participants()
        if not participants:
            messagebox.showwarning("Предупреждение", "Нет данных для экспорта")
            return

        filepath = filedialog.asksaveasfilename(
            title="Сохранить CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )

        if not filepath:
            return

        try:
            with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["Имя", "Участник", "Тип"])
                for p in participants:
                    writer.writerow([
                        p.display_name,
                        p.name,
                        p.participant_type,
                    ])

            self._log(f"Экспорт в CSV: {filepath} ({len(participants)} записей)")
            messagebox.showinfo("Успех", f"Экспортировано {len(participants)} записей в CSV")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать CSV:\n{e}")

    def _export_excel(self):
        """Экспорт в Excel"""
        participants = self.session_tracker.get_all_participants()
        if not participants:
            messagebox.showwarning("Предупреждение", "Нет данных для экспорта")
            return

        filepath = filedialog.asksaveasfilename(
            title="Сохранить Excel",
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
        )

        if not filepath:
            return

        try:
            import pandas as pd

            data = []
            for p in participants:
                data.append({
                    "Имя": p.display_name,
                    "Участник": p.name,
                    "Тип": p.participant_type,
                })

            df = pd.DataFrame(data)
            df.to_excel(filepath, index=False, engine='openpyxl')

            self._log(f"Экспорт в Excel: {filepath} ({len(participants)} записей)")
            messagebox.showinfo("Успех", f"Экспортировано {len(participants)} записей в Excel")
        except ImportError:
            messagebox.showerror("Ошибка", "Для экспорта в Excel требуются библиотеки:\npip install pandas openpyxl")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать Excel:\n{e}")

    def run(self):
        """Запуск приложения"""
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        """Обработка закрытия окна"""
        if self._sniffer_active:
            self._stop_monitoring()
        self.root.destroy()


def main():
    app = SLRCheckerApp()
    app.run()


if __name__ == "__main__":
    main()
