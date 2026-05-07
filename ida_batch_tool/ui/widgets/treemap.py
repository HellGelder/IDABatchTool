"""Виджет Treemap для отображения статуса файлов (горизонтальная полоса)."""
from __future__ import annotations

import math
from typing import List, Dict, Any, Optional

from PySide6.QtWidgets import QWidget
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QPainter, QColor, QPen, QFont

from ida_batch_tool.ui.constants import AnalysisStatus


class TreemapWidget(QWidget):
    """Виджет, показывающий файлы в виде горизонтальной полосы, разделённой на прямоугольники пропорционально размеру."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.file_items: List[Dict[str, Any]] = []
        self._rects: List[Dict[str, float]] = []
        self.hovered_index: int = -1
        self._data_pending: bool = False
        self.setMouseTracking(True)
        self.setMinimumHeight(40)
        self.setMaximumHeight(60)

    def set_data(self, items: List[Dict[str, Any]]) -> None:
        self.file_items = items
        if self.width() > 0 and self.height() > 0:
            self._compute_layout()
        else:
            self._data_pending = True
        self.update()

    def update_status(self, file_path: str, status: AnalysisStatus) -> None:
        for item in self.file_items:
            if item['path'] == file_path:
                item['status'] = status.value
                break
        self.update()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._data_pending:
            self._compute_layout()
            self._data_pending = False

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.file_items:
            self._compute_layout()
            self.update()

    def _compute_layout(self) -> None:
        if not self.file_items:
            self._rects = []
            return

        w = self.width()
        h = self.height()
        if w <= 0 or h <= 0:
            self._rects = []
            return

        # Суммируем все размеры, чтобы вычислить долю каждого файла
        total_size = sum(max(item['size'], 1) for item in self.file_items)
        if total_size == 0:
            return

        # Минимальная ширина в пикселях для отображения номера (например, "99" – ~15px)
        min_width = 25
        x = 0.0
        self._rects = []
        for i, item in enumerate(self.file_items):
            # Пропорциональная ширина
            width = (max(item['size'], 1) / total_size) * w
            if width < min_width and i < len(self.file_items) - 1:
                width = min_width
            # Ограничиваем, чтобы не вылезти за правый край
            if x + width > w:
                width = w - x
            if width <= 0:
                continue
            self._rects.append({
                'x': x,
                'y': 0,
                'width': width,
                'height': h,
                'index': i,
            })
            x += width
            if x >= w - 1:
                break

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        if not self.file_items or not self._rects:
            painter.drawText(self.rect(), Qt.AlignCenter, "Нет данных для отображения")
            return

        font = QFont("Segoe UI", 8)
        painter.setFont(font)

        for rect_info in self._rects:
            i = rect_info['index']
            if i >= len(self.file_items):
                continue
            item = self.file_items[i]
            color = self._color_for_status(AnalysisStatus(item.get('status', 'not_analyzed')))
            rect = QRectF(rect_info['x'], rect_info['y'], rect_info['width'], rect_info['height'])
            painter.fillRect(rect, color)
            painter.setPen(QPen(Qt.black, 1))
            painter.drawRect(rect)

            # Рисуем номер файла, если достаточно места
            if rect.width() >= 20 and rect.height() >= 20:
                text = str(i + 1)
                painter.setPen(QPen(Qt.black, 1))
                painter.drawText(rect, Qt.AlignCenter, text)

        # Подсветка при наведении
        if 0 <= self.hovered_index < len(self.file_items):
            # Находим rect для этого индекса
            for rect_info in self._rects:
                if rect_info['index'] == self.hovered_index:
                    rect = QRectF(rect_info['x'], rect_info['y'], rect_info['width'], rect_info['height'])
                    painter.setPen(QPen(Qt.white, 2))
                    painter.drawRect(rect)
                    break

    @staticmethod
    def _color_for_status(status: AnalysisStatus) -> QColor:
        colors = {
            AnalysisStatus.NOT_ANALYZED: QColor(192, 192, 192),   # серый
            AnalysisStatus.IN_PROGRESS: QColor(255, 255, 0),     # жёлтый
            AnalysisStatus.SUCCESS: QColor(0, 122, 255),         # синий (#007aff)
            AnalysisStatus.ERROR: QColor(255, 0, 0),             # красный
        }
        return colors.get(status, QColor(128, 128, 128))

    def mouseMoveEvent(self, event) -> None:
        pos = event.position()
        new_index = -1
        for rect_info in self._rects:
            rect = QRectF(rect_info['x'], rect_info['y'], rect_info['width'], rect_info['height'])
            if rect.contains(pos):
                new_index = rect_info['index']
                break
        if new_index != self.hovered_index:
            self.hovered_index = new_index
            self.update()
            if new_index >= 0 and new_index < len(self.file_items):
                item = self.file_items[new_index]
                tip = f"#{new_index+1} {item['name']}\nРазмер: {item['size']} байт\nСтатус: {item.get('status', 'неизвестно')}"
            else:
                tip = ""
            self.setToolTip(tip)