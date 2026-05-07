"""Виджет Treemap для отображения статуса файлов (circle packing)."""
from __future__ import annotations

import math
from typing import List, Dict, Any, Optional

import circlify
from PySide6.QtWidgets import QWidget
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QPainter, QColor, QPen, QFont

from ida_batch_tool.ui.constants import AnalysisStatus


class TreemapWidget(QWidget):
    """Виджет, показывающий файлы в виде упакованных кругов."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.file_items: List[Dict[str, Any]] = []
        self._circles: List[Dict[str, float]] = []
        self.hovered_index: int = -1
        self._data_pending: bool = False
        self.setMouseTracking(True)
        self.setMinimumHeight(120)

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
            self._circles = []
            return
        sizes = [max(item['size'], 1) for item in self.file_items]
        w, h = self.width(), self.height()
        if w <= 0 or h <= 0:
            self._circles = []
            return
        circles = circlify.circlify(sizes, target_enclosure=circlify.Circle(x=0.5, y=0.5, r=0.5))
        scale_x = w
        scale_y = h
        self._circles = []
        for c in circles:
            self._circles.append({
                'x': c.x * scale_x,
                'y': c.y * scale_y,
                'r': c.r * min(scale_x, scale_y),
            })

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        if not self.file_items or not self._circles:
            painter.drawText(self.rect(), Qt.AlignCenter, "Нет данных для отображения")
            return

        max_r = max(c['r'] for c in self._circles) if self._circles else 1
        font = QFont("Segoe UI", 7)

        for i, circle in enumerate(self._circles):
            if i >= len(self.file_items):
                break
            item = self.file_items[i]
            color = self._color_for_status(AnalysisStatus(item.get('status', 'not_analyzed')))
            center = QPointF(circle['x'], circle['y'])
            radius = circle['r']
            painter.setBrush(color)
            painter.setPen(QPen(Qt.black, 1))
            painter.drawEllipse(center, radius, radius)

            painter.setFont(font)
            painter.setPen(Qt.black)
            text = str(i + 1)
            text_rect = QRectF(center.x() - radius, center.y() - radius, 2 * radius, 2 * radius)
            painter.drawText(text_rect, Qt.AlignCenter, text)

        if 0 <= self.hovered_index < len(self._circles) and self.hovered_index < len(self.file_items):
            circle = self._circles[self.hovered_index]
            painter.setPen(QPen(Qt.white, 2))
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(QPointF(circle['x'], circle['y']), circle['r'], circle['r'])

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
        for i, circle in enumerate(self._circles):
            dx = pos.x() - circle['x']
            dy = pos.y() - circle['y']
            if (dx * dx + dy * dy) <= circle['r'] * circle['r']:
                new_index = i
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