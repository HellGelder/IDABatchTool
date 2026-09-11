"""Виджет страницы конфигурации."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QPushButton, QGroupBox, QMessageBox,
    QFileDialog, QLabel
)
from PySide6.QtCore import Signal, Qt

from ida_batch_tool.config.loader import (
    load_config, save_config, get_ida_executable, get_bindiff_executable
)


_STATUS_UNCHECKED = "⚪"
_STATUS_OK = "✅"
_STATUS_MISSING = "⚠️"


class SettingsPage(QWidget):
    config_changed = Signal(dict)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.cfg = load_config()
        self._init_ui()
        self._load_to_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        # --- Группа IDA ---
        ida_group = QGroupBox("Путь к IDA (idat)")
        ida_layout = QFormLayout(ida_group)
        ida_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        ida_layout.setSpacing(12)

        self.idat_edit = QLineEdit()
        self.idat_edit.setPlaceholderText("idat (или idat.exe на Windows)")
        self.browse_ida_btn = QPushButton("Обзор...")
        self.auto_ida_btn = QPushButton("Автопоиск")

        ida_hbox = QHBoxLayout()
        ida_hbox.addWidget(self.idat_edit, 1)
        ida_hbox.addWidget(self.browse_ida_btn)
        ida_hbox.addWidget(self.auto_ida_btn)
        ida_layout.addRow("Исполняемый файл:", ida_hbox)

        # --- Группа BinDiff ---
        bindiff_group = QGroupBox("Путь к BinDiff")
        bindiff_layout = QFormLayout(bindiff_group)
        bindiff_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        bindiff_layout.setSpacing(12)

        self.bindiff_edit = QLineEdit()
        self.bindiff_edit.setPlaceholderText("bindiff (или bindiff.exe на Windows)")
        self.browse_bindiff_btn = QPushButton("Обзор...")
        self.auto_bindiff_btn = QPushButton("Автопоиск")

        bindiff_hbox = QHBoxLayout()
        bindiff_hbox.addWidget(self.bindiff_edit, 1)
        bindiff_hbox.addWidget(self.browse_bindiff_btn)
        bindiff_hbox.addWidget(self.auto_bindiff_btn)
        bindiff_layout.addRow("Исполняемый файл:", bindiff_hbox)

        # --- Группа темы ---
        theme_group = QGroupBox("Оформление")
        theme_layout = QFormLayout(theme_group)

        self.theme_light_btn = QPushButton("Светлая")
        self.theme_light_btn.setCheckable(True)
        self.theme_dark_btn = QPushButton("Тёмная")
        self.theme_dark_btn.setCheckable(True)

        theme_hbox = QHBoxLayout()
        theme_hbox.addWidget(self.theme_light_btn)
        theme_hbox.addWidget(self.theme_dark_btn)
        theme_layout.addRow("Тема:", theme_hbox)

        # --- Группа вспомогательных утилит ---
        utils_group = QGroupBox("Вспомогательные утилиты")
        utils_layout = QVBoxLayout(utils_group)
        utils_layout.setSpacing(8)

        # 7-Zip
        self._7z_icon = QLabel(_STATUS_UNCHECKED)
        self._7z_icon.setFixedWidth(24)
        self._7z_label = QLabel("7-Zip (распаковка DMG)")
        self._7z_path = QLabel("")
        self._7z_path.setStyleSheet("color: #8e8e93; font-size: 12px;")
        row_7z = QHBoxLayout()
        row_7z.addWidget(self._7z_icon)
        row_7z.addWidget(self._7z_label)
        row_7z.addWidget(self._7z_path, 1)
        utils_layout.addLayout(row_7z)

        # npx / Node.js
        self._npx_icon = QLabel(_STATUS_UNCHECKED)
        self._npx_icon.setFixedWidth(24)
        self._npx_label = QLabel("Node.js / npx (документация СФ)")
        self._npx_path = QLabel("")
        self._npx_path.setStyleSheet("color: #8e8e93; font-size: 12px;")
        row_npx = QHBoxLayout()
        row_npx.addWidget(self._npx_icon)
        row_npx.addWidget(self._npx_label)
        row_npx.addWidget(self._npx_path, 1)
        utils_layout.addLayout(row_npx)

        # Кнопка проверки
        check_btn_row = QHBoxLayout()
        check_btn_row.addStretch()
        self._check_utils_btn = QPushButton("Проверить наличие")
        check_btn_row.addWidget(self._check_utils_btn)
        utils_layout.addLayout(check_btn_row)

        # --- Группа документации man-pages (Linux) ---
        man_group = QGroupBox("Документация man-pages (Linux)")
        man_layout = QVBoxLayout(man_group)
        man_layout.setSpacing(8)

        man_hint = QLabel(
            "Загружает официальный архив man-pages и сохраняет его локально. "
            "После этого документация Linux-функций доступна офлайн."
        )
        man_hint.setWordWrap(True)
        man_hint.setStyleSheet("color: #8e8e93; font-size: 12px;")
        man_layout.addWidget(man_hint)

        self._man_status = QLabel("Статус: не проверено")
        self._man_status.setStyleSheet("font-size: 12px;")
        man_layout.addWidget(self._man_status)

        man_btn_row = QHBoxLayout()
        self._man_check_btn = QPushButton("Проверить")
        self._man_sync_btn = QPushButton("Скачать и импортировать")
        man_btn_row.addWidget(self._man_check_btn)
        man_btn_row.addWidget(self._man_sync_btn)
        man_btn_row.addStretch()
        man_layout.addLayout(man_btn_row)

        # Добавляем все группы
        main_layout.addWidget(ida_group)
        main_layout.addWidget(bindiff_group)
        main_layout.addWidget(theme_group)
        main_layout.addWidget(utils_group)
        main_layout.addWidget(man_group)

        # Кнопка сохранения
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.save_btn = QPushButton("Сохранить настройки")
        self.save_btn.setFixedWidth(200)
        btn_layout.addWidget(self.save_btn)
        main_layout.addLayout(btn_layout)
        main_layout.addStretch()

        # Сигналы
        self.browse_ida_btn.clicked.connect(self._browse_ida)
        self.auto_ida_btn.clicked.connect(self._autodetect_ida)
        self.browse_bindiff_btn.clicked.connect(self._browse_bindiff)
        self.auto_bindiff_btn.clicked.connect(self._autodetect_bindiff)
        self.save_btn.clicked.connect(self._save_settings)
        self._check_utils_btn.clicked.connect(self._check_utilities)
        self._man_check_btn.clicked.connect(self._check_manpages)
        self._man_sync_btn.clicked.connect(self._sync_manpages)

        self.theme_light_btn.clicked.connect(lambda: self._switch_theme("light"))
        self.theme_dark_btn.clicked.connect(lambda: self._switch_theme("dark"))

    def _load_to_ui(self):
        ida = self.cfg.get("ida", {})
        self.idat_edit.setText(ida.get("executable", "idat"))

        bindiff = self.cfg.get("bindiff", {})
        self.bindiff_edit.setText(bindiff.get("executable", "bindiff"))

        theme = self.cfg.get("theme", "light")
        self.theme_light_btn.setChecked(theme == "light")
        self.theme_dark_btn.setChecked(theme == "dark")

    def _check_utilities(self):
        """Проверяет наличие 7z и npx через запуск в терминале."""
        # 7-Zip
        status_7z, msg_7z = self._check_7z()
        if status_7z == "ok":
            self._7z_icon.setText(_STATUS_OK)
            self._7z_path.setText(msg_7z)
        else:
            self._7z_icon.setText(_STATUS_MISSING)
            self._7z_path.setText(msg_7z)

        # npx / Node.js
        status_npx, msg_npx = self._check_npx()
        if status_npx == "ok":
            self._npx_icon.setText(_STATUS_OK)
            self._npx_path.setText(msg_npx)
        else:
            self._npx_icon.setText(_STATUS_MISSING)
            self._npx_path.setText(msg_npx)

    @staticmethod
    def _check_7z() -> tuple[str, str]:
        """Пытается запустить 7z и получить версию через терминал."""
        candidates = ["7z", "7za", "7z.exe", "7za.exe",
                      r"C:\Program Files\7-Zip\7z.exe",
                      r"C:\Program Files (x86)\7-Zip\7z.exe"]
        for exe in candidates:
            try:
                proc = subprocess.run(
                    [exe],
                    capture_output=True, text=True, timeout=5,
                )
                output = proc.stdout + proc.stderr
                # Парсим версию
                ver = ""
                for line in output.splitlines():
                    line_lower = line.lower()
                    if "version" in line_lower or "версия" in line_lower:
                        ver = line.strip()[:80]
                        break
                if not ver:
                    # Пробуем 7-Zip (с) — признак того, что программа работает
                    for line in output.splitlines():
                        if "7-zip" in line.lower() or "7za" in line.lower():
                            ver = line.strip()[:80]
                            break
                if ver:
                    return ("ok", f"{exe}  ({ver})")
                # Если ответ есть, но версию не нашли — всё равно программа работает
                if output.strip():
                    return ("ok", exe)
            except (FileNotFoundError, PermissionError):
                pass
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        return ("error", "Не найден. Установите 7-Zip и перезапустите программу.")

    @staticmethod
    def _check_npx() -> tuple[str, str]:
        """Пытается запустить npx и получить версию через терминал."""
        candidates = ["npx", "npx.cmd", "npx.exe"]
        for exe in candidates:
            try:
                proc = subprocess.run(
                    [exe, "--version"],
                    capture_output=True, text=True, timeout=10,
                )
                ver = (proc.stdout or proc.stderr or "").strip()
                if ver:
                    return ("ok", f"{exe}  (v{ver})")
                # Если процесс завершился успешно, но без версии
                if proc.returncode == 0:
                    return ("ok", exe)
            except (FileNotFoundError, PermissionError):
                pass
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        # Типовые полные пути на Windows
        win_candidates = [
            r"C:\Program Files\nodejs\npx.cmd",
            r"C:\Program Files\nodejs\npx.exe",
            r"C:\Program Files (x86)\nodejs\npx.cmd",
            r"C:\Program Files (x86)\nodejs\npx.exe",
            r"C:\ProgramData\chocolatey\bin\npx.exe",
        ]
        for fullpath in win_candidates:
            if Path(fullpath).is_file():
                try:
                    proc = subprocess.run(
                        [fullpath, "--version"],
                        capture_output=True, text=True, timeout=10,
                    )
                    ver = (proc.stdout or proc.stderr or "").strip()
                    if ver:
                        return ("ok", f"{fullpath}  (v{ver})")
                    if proc.returncode == 0:
                        return ("ok", fullpath)
                except Exception:
                    pass
        return ("error", "Не найден. Установите Node.js и перезапустите программу.")

    def _switch_theme(self, theme: str):
        new_cfg = {**self.cfg, "theme": theme}
        save_config(new_cfg)
        self.cfg = new_cfg
        self.theme_light_btn.setChecked(theme == "light")
        self.theme_dark_btn.setChecked(theme == "dark")
        self.config_changed.emit(new_cfg)

    def _save_settings(self):
        new_cfg = {
            **self.cfg,
            "ida": {
                "executable": self.idat_edit.text().strip() or "idat"
            },
            "bindiff": {
                "executable": self.bindiff_edit.text().strip() or "bindiff"
            },
        }
        try:
            save_config(new_cfg)
            self.cfg = new_cfg
            QMessageBox.information(self, "Успех", "Настройки сохранены.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить конфиг:\n{e}")

    def _browse_ida(self):
        current = self.idat_edit.text()
        filter_str = "idat (idat.exe);;Все файлы (*)" if sys.platform == "win32" else "Все файлы (*)"
        path, _ = QFileDialog.getOpenFileName(
            self, "Укажите исполняемый файл IDA (idat)", current, filter_str
        )
        if path:
            self.idat_edit.setText(path)

    def _autodetect_ida(self):
        found = get_ida_executable()
        if not found or not Path(found).exists():
            QMessageBox.information(
                self, "Не найдено",
                "Не удалось автоматически найти idat.\nПроверьте PATH или укажите путь вручную."
            )
            return
        self.idat_edit.setText(found)
        QMessageBox.information(self, "Найдено", f"IDAT найден:\n{found}")

    def _browse_bindiff(self):
        current = self.bindiff_edit.text()
        if sys.platform == "win32":
            filter_str = "bindiff (bindiff.exe);;Все файлы (*)"
        else:
            filter_str = "Все файлы (*)"
        path, _ = QFileDialog.getOpenFileName(
            self, "Укажите исполняемый файл BinDiff", current, filter_str
        )
        if path:
            self.bindiff_edit.setText(path)

    def _autodetect_bindiff(self):
        found = get_bindiff_executable()
        if not found or not Path(found).exists():
            QMessageBox.information(
                self, "Не найдено",
                "Не удалось автоматически найти bindiff.\nПроверьте PATH или поместите файл в корень проекта."
            )
            return
        self.bindiff_edit.setText(found)
        QMessageBox.information(self, "Найдено", f"BinDiff найден:\n{found}")

    # ─── man-pages ──────────────────────────────────────────────────

    def _manpages_db_path(self) -> Path:
        """Путь к БД man-pages: папка отчётов рядом с входной директорией."""
        from ida_batch_tool.config.loader import get_default_inputdir
        from ida_batch_tool.database.man_pages_sync import get_manpages_db_path

        input_dir = Path(self.cfg.get("default_inputdir") or get_default_inputdir())
        reports_root = input_dir / "SFAReports"
        return get_manpages_db_path(reports_root)

    def _check_manpages(self) -> None:
        """Показывает состояние локальной БД man-pages."""
        from ida_batch_tool.database.man_pages_db import ManPagesDatabase

        db_path = self._manpages_db_path()
        if not db_path.is_file():
            self._man_status.setText(
                f"Статус: база не найдена ({db_path}). Нажмите «Скачать и импортировать»."
            )
            return
        db = ManPagesDatabase(db_path)
        if db.open():
            self._man_status.setText(
                f"Статус: база найдена — {db.count()} функций, "
                f"man-pages {db.version()}, {db_path.stat().st_size / 1024 / 1024:.1f} МБ"
            )
            db.close()
        else:
            self._man_status.setText(f"Статус: файл есть, но не читается ({db_path}).")

    def _sync_manpages(self) -> None:
        """Запускает фоновую загрузку и импорт man-pages."""
        from ida_batch_tool.database.man_pages_sync import ManPagesSyncWorker

        if getattr(self, "_man_worker", None) is not None and self._man_worker.isRunning():
            QMessageBox.information(self, "Синхронизация", "Загрузка уже выполняется.")
            return

        db_path = self._manpages_db_path()
        self._man_sync_btn.setEnabled(False)
        self._man_check_btn.setEnabled(False)
        self._man_status.setText("Статус: загрузка архива man-pages…")

        worker = ManPagesSyncWorker(db_path)
        worker.progress.connect(lambda msg, pct: self._man_status.setText(f"Статус: {msg} ({pct}%)"))
        worker.error.connect(lambda msg: self._man_status.setText(f"Статус: ошибка — {msg}"))
        worker.finished.connect(self._on_manpages_finished)
        self._man_worker = worker
        worker.start()

    def _on_manpages_finished(self, success: bool, message: str) -> None:
        self._man_sync_btn.setEnabled(True)
        self._man_check_btn.setEnabled(True)
        if success:
            QMessageBox.information(self, "Готово", f"Документация man-pages импортирована:\n{message}")
            self._check_manpages()
        else:
            QMessageBox.warning(self, "Ошибка", f"Не удалось импортировать man-pages:\n{message}")