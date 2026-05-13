"""Виджет Treemap для отображения статуса файлов (горизонтальная полоса)."""
from __future__ import annotations

from typing import List, Dict, Any, Optional

from PySide6.QtWidgets import QWidget
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QPainter, QColor, QPen

from ida_batch_tool.ui.constants import AnalysisStatus


class TreemapWidget(QWidget):
    """Виджет, показывающий файлы в виде горизонтальной полосы равномерных блоков."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.file_items: List[Dict[str, Any]] = []
        self._rects: List[QRectF] = []
        self.setMouseTracking(False)   # отключаем отслеживание мыши
        self.setMinimumHeight(40)
        self.setMaximumHeight(60)

    def set_data(self, items: List[Dict[str, Any]]) -> None:
        self.file_items = items
        if self.width() > 0 and self.height() > 0:
            self._compute_layout()
        self.update()

    def update_status(self, file_path: str, status: AnalysisStatus) -> None:
        for item in self.file_items:
            if item['path'] == file_path:
                item['status'] = status.value
                break
        self.update()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.file_items:
            self._compute_layout()
            self.update()

    def _compute_layout(self) -> None:
        """Создаёт равномерные прямоугольники для всех файлов, игнорируя их размер."""
        self._rects.clear()
        if not self.file_items:
            return

        w = self.width()
        h = self.height()
        if w <= 0 or h <= 0:
            return

        count = len(self.file_items)
        if count == 0:
            return

        block_width = w / count
        x = 0.0
        for i in range(count):
            self._rects.append(QRectF(x, 0, block_width, h))
            x += block_width

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        if not self.file_items or not self._rects:
            painter.drawText(self.rect(), Qt.AlignCenter, "Нет данных для отображения")
            return

        for i, rect in enumerate(self._rects):
            item = self.file_items[i]
            color = self._color_for_status(AnalysisStatus(item.get('status', 'not_analyzed')))
            painter.fillRect(rect, color)
            painter.setPen(QPen(Qt.black, 1))
            painter.drawRect(rect)

    @staticmethod
    def _color_for_status(status: AnalysisStatus) -> QColor:
        colors = {
            AnalysisStatus.NOT_ANALYZED: QColor(192, 192, 192),
            AnalysisStatus.IN_PROGRESS: QColor(255, 255, 0),
            AnalysisStatus.SUCCESS: QColor(0, 122, 255),
            AnalysisStatus.ERROR: QColor(255, 0, 0),
        }
        return colors.get(status, QColor(128, 128, 128))