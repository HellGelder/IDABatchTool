"""Обработка архивов APK, IPA, DMG. Распаковка в соседнюю папку."""
from __future__ import annotations

import os
import shutil
import zipfile
import subprocess
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

ARCHIVE_EXTENSIONS = {'.apk', '.ipa', '.dmg'}

SEVEN_ZIP_PATHS = ['7z', '7z.exe', '7za', '7za.exe']


def find_7z() -> Optional[str]:
    """Возвращает путь к 7z, если он доступен в PATH."""
    for name in SEVEN_ZIP_PATHS:
        path = shutil.which(name)
        if path:
            return path
    return None


def extract_archive(archive_path: str | Path, output_dir: Optional[str | Path] = None) -> Optional[Path]:
    """
    Извлекает архив в указанную папку (по умолчанию рядом с архивом, имя = stem архива).
    Возвращает путь к папке с извлечёнными файлами или None.
    """
    archive_path = Path(archive_path)
    if not archive_path.is_file():
        logger.error(f"Архив не найден: {archive_path}")
        return None

    suffix = archive_path.suffix.lower()
    if suffix not in ARCHIVE_EXTENSIONS:
        logger.error(f"Неподдерживаемый формат архива: {suffix}")
        return None

    if output_dir is None:
        output_dir = archive_path.with_suffix('')  # папка с именем файла без расширения
    else:
        output_dir = Path(output_dir)

    # Если папка уже существует, считаем, что архив уже извлекался ранее
    if output_dir.is_dir() and any(output_dir.iterdir()):
        logger.info(f"Папка {output_dir} уже существует, используем её")
        return output_dir

    # Создаём папку
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Извлечение {archive_path} → {output_dir}")

    # APK / IPA
    if suffix in ('.apk', '.ipa'):
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(output_dir)
            logger.info("Извлечено через zipfile")
            return output_dir
        except Exception as e:
            logger.exception(f"Ошибка zipfile: {e}")
            shutil.rmtree(output_dir, ignore_errors=True)
            return None

    # DMG
    if suffix == '.dmg':
        seven_zip = find_7z()
        if not seven_zip:
            logger.error("7z не найден – требуется для DMG")
            shutil.rmtree(output_dir, ignore_errors=True)
            return None
        cmd = [seven_zip, 'x', str(archive_path), f'-o{output_dir}', '-y']
        logger.debug(f"7z: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                logger.error(f"7z ошибка: {proc.stderr.strip()}")
                shutil.rmtree(output_dir, ignore_errors=True)
                return None
            logger.info("Извлечено через 7z")
            return output_dir
        except Exception as e:
            logger.exception(f"Ошибка запуска 7z: {e}")
            shutil.rmtree(output_dir, ignore_errors=True)
            return None

    return None