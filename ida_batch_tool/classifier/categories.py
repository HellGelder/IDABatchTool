"""Логика классификации и группировка модулей по категориям."""
from difflib import get_close_matches
from typing import Dict, Optional, Tuple

# Импортируем словари из платформенных модулей
from .windows import WINDOWS_MODULES
from .linux import LINUX_MODULES
from .android import ANDROID_MODULES
from .macos import MACOS_MODULES
from .third_party import THIRD_PARTY_MODULES

# Импортируем отдельные словари для категорий
from .windows import (
    _WINDOWS_HAL, _WINDOWS_NATIVE_API, _WINDOWS_KERNEL_SUBSYSTEM,
    _WINDOWS_USER_SUBSYSTEM, _WINDOWS_SYSTEM_SERVICES,
    _WINDOWS_USB_DEVICE, _WINDOWS_DOTNET, _WINDOWS_SUBSYSTEM_COMPAT,
    _WINDOWS_API_SETS, _WINDOWS_SECURITY_CRYPTO, _WINDOWS_BCRYPTPRIMITIVES,
    _WINDOWS_NETWORK, _WINDOWS_GRAPHICS_MULTIMEDIA, _WINDOWS_RUNTIME,
    _WINDOWS_SERVER_CORE, _WINDOWS_OPENSSL_MODERN,
)
from .linux import (
    _LINUX_CORE_LIBS, _LINUX_DYNAMIC_LINKER, _LINUX_SYSTEM_SERVICES,
    _LINUX_SECURITY, _LINUX_COMPILER_RUNTIME, _LINUX_COMPRESSION,
    _LINUX_XML_PARSING, _LINUX_DATABASE, _LINUX_SYSTEMD_LIBS,
    _LINUX_SECURITY_EXTRA, _LINUX_CRYPTO_EXTRA,
)
from .android import (
    _ANDROID_CORE, _ANDROID_BINDER, _ANDROID_HARDWARE,
    _ANDROID_NATIVE_WINDOW, _ANDROID_MEDIA, _ANDROID_GRAPHICS,
    _ANDROID_NETWORK, _ANDROID_BLUETOOTH, _ANDROID_RUNTIME,
    _ANDROID_NETWORK_MONITORING, _ANDROID_CRYPTO, _ANDROID_NDK,
    _ANDROID_ICU, _ANDROID_CAMERA, _ANDROID_MEDIA_NDK,
    _ANDROID_AUDIO, _ANDROID_JNI, _ANDROID_EXPAT,
)
from .macos import (
    _MACOS_CORE, _MACOS_DISPATCH, _MACOS_FOUNDATION,
    _MACOS_NETWORK, _MACOS_DATABASE, _MACOS_SWIFT,
    _MACOS_CRYPTO, _MACOS_EXPAT, _MACOS_FONTCONFIG,
)
from .third_party import (
    _THIRD_PARTY_CRYPTO, _THIRD_PARTY_NETWORK, _THIRD_PARTY_BROWSER,
    _THIRD_PARTY_VPN, _THIRD_PARTY_RPC, _THIRD_PARTY_RPC_MORE,
    _THIRD_PARTY_JAVASCRIPT, _THIRD_PARTY_GRAPHICS,
    _THIRD_PARTY_IMAGE, _THIRD_PARTY_AUDIO, _THIRD_PARTY_CV,
    _THIRD_PARTY_GAME_MULTIMEDIA, _THIRD_PARTY_2D_GRAPHICS,
    _THIRD_PARTY_GUI_MORE, _THIRD_PARTY_TERMINAL,
    _THIRD_PARTY_ML, _THIRD_PARTY_ML_MORE,
    _THIRD_PARTY_COMPRESSION, _THIRD_PARTY_COMPRESSION_MORE,
    _THIRD_PARTY_DATABASE, _THIRD_PARTY_LOGGING,
    _THIRD_PARTY_XML, _THIRD_PARTY_CRYPTO_MORE,
    _THIRD_PARTY_VIRTUALIZATION, _THIRD_PARTY_QT,
)


# Объединяем все словари в один
_ALL_MODULES: Dict[str, str] = {}
_ALL_MODULES.update(WINDOWS_MODULES)
_ALL_MODULES.update(LINUX_MODULES)
_ALL_MODULES.update(ANDROID_MODULES)
_ALL_MODULES.update(MACOS_MODULES)
_ALL_MODULES.update(THIRD_PARTY_MODULES)


def _normalize_name(name: str) -> str:
    """Убирает расширение и приводит к нижнему регистру."""
    for ext in ('.dll', '.so', '.dylib', '.drv', '.sys', '.exe'):
        if name.endswith(ext):
            name = name[:-len(ext)]
            break
    return name.lower()


_NORMALIZED_MODULES: Dict[str, str] = {
    _normalize_name(k): v for k, v in _ALL_MODULES.items()
}


# ------------------------------------------------------------
# Расширенные эвристики (подсказки по префиксам)
# ------------------------------------------------------------
import re

_PREFIX_HINTS = [
    (re.compile(r'msvc', re.IGNORECASE), "Вероятно, библиотека времени выполнения Microsoft Visual C++"),
    (re.compile(r'vcruntime', re.IGNORECASE), "Вероятно, среда выполнения Visual C++"),
    (re.compile(r'msvcp', re.IGNORECASE), "Вероятно, стандартная библиотека C++ (MSVCP)"),
    (re.compile(r'concrt', re.IGNORECASE), "Вероятно, Concurrency Runtime"),
    (re.compile(r'vcomp', re.IGNORECASE), "Вероятно, OpenMP Runtime"),
    (re.compile(r'mfc', re.IGNORECASE), "Вероятно, Microsoft Foundation Classes"),
    (re.compile(r'atl', re.IGNORECASE), "Вероятно, Active Template Library"),
    (re.compile(r'libc\+\+', re.IGNORECASE), "Вероятно, стандартная библиотека C++ (libc++)"),
    (re.compile(r'libc\.|libc-', re.IGNORECASE), "Вероятно, стандартная библиотека C"),
    (re.compile(r'libm\.|libm-', re.IGNORECASE), "Вероятно, математическая библиотека"),
    (re.compile(r'libpthread', re.IGNORECASE), "Вероятно, библиотека потоков POSIX"),
    (re.compile(r'libdl\.|libdl-', re.IGNORECASE), "Вероятно, библиотека динамической загрузки"),
    (re.compile(r'libGL(ES)?', re.IGNORECASE), "Вероятно, OpenGL / OpenGL ES"),
    (re.compile(r'libEGL', re.IGNORECASE), "Вероятно, EGL"),
    (re.compile(r'libvulkan', re.IGNORECASE), "Вероятно, Vulkan"),
    (re.compile(r'liblog', re.IGNORECASE), "Вероятно, библиотека логирования Android"),
    (re.compile(r'libutils', re.IGNORECASE), "Вероятно, утилиты Android"),
    (re.compile(r'libbinder', re.IGNORECASE), "Вероятно, Android Binder IPC"),
    (re.compile(r'libhardware', re.IGNORECASE), "Вероятно, Android HAL"),
    (re.compile(r'libgui', re.IGNORECASE), "Вероятно, Android GUI"),
    (re.compile(r'libui', re.IGNORECASE), "Вероятно, Android UI"),
    (re.compile(r'libmedia', re.IGNORECASE), "Вероятно, Android Media"),
    (re.compile(r'libstagefright', re.IGNORECASE), "Вероятно, Android Stagefright"),
    (re.compile(r'libcrypto', re.IGNORECASE), "Вероятно, криптографическая библиотека"),
    (re.compile(r'libssl', re.IGNORECASE), "Вероятно, библиотека SSL/TLS"),
    (re.compile(r'libsqlite', re.IGNORECASE), "Вероятно, SQLite"),
    (re.compile(r'libcurl', re.IGNORECASE), "Вероятно, cURL"),
    (re.compile(r'libxml2', re.IGNORECASE), "Вероятно, XML-парсер"),
    (re.compile(r'libz\.|libz-', re.IGNORECASE), "Вероятно, библиотека сжатия zlib"),
    (re.compile(r'libbz2', re.IGNORECASE), "Вероятно, сжатие bzip2"),
    (re.compile(r'liblzma', re.IGNORECASE), "Вероятно, сжатие LZMA/XZ"),
    (re.compile(r'libpng', re.IGNORECASE), "Вероятно, обработка PNG"),
    (re.compile(r'libjpeg', re.IGNORECASE), "Вероятно, обработка JPEG"),
    (re.compile(r'libtiff', re.IGNORECASE), "Вероятно, обработка TIFF"),
    (re.compile(r'libwebp', re.IGNORECASE), "Вероятно, обработка WebP"),
    (re.compile(r'libav(codec|format|util|device|filter)', re.IGNORECASE), "Вероятно, FFmpeg"),
    (re.compile(r'libvlc', re.IGNORECASE), "Вероятно, VLC media framework"),
    (re.compile(r'libgstreamer', re.IGNORECASE), "Вероятно, GStreamer"),
    (re.compile(r'libpulse', re.IGNORECASE), "Вероятно, PulseAudio"),
    (re.compile(r'libasound', re.IGNORECASE), "Вероятно, ALSA"),
    (re.compile(r'libOpenSLES', re.IGNORECASE), "Вероятно, OpenSL ES"),
    (re.compile(r'libnetwork', re.IGNORECASE), "Вероятно, сетевая библиотека"),
    (re.compile(r'libdispatch', re.IGNORECASE), "Вероятно, Grand Central Dispatch"),
    (re.compile(r'libSystem', re.IGNORECASE), "Вероятно, системная библиотека Darwin"),
    (re.compile(r'libobjc', re.IGNORECASE), "Вероятно, Objective-C runtime"),
    (re.compile(r'libswift', re.IGNORECASE), "Вероятно, Swift runtime"),
    (re.compile(r'libicucore', re.IGNORECASE), "Вероятно, ICU (Unicode)"),
    (re.compile(r'libiconv', re.IGNORECASE), "Вероятно, преобразование кодировок"),
    (re.compile(r'libncurses', re.IGNORECASE), "Вероятно, библиотека терминального интерфейса"),
]


def _fuzzy_match_module(module_name: str) -> Optional[str]:
    """Пытается найти близкое совпадение (расстояние <= ~2) среди известных модулей."""
    norm = _normalize_name(module_name)
    if norm in _NORMALIZED_MODULES:
        return _NORMALIZED_MODULES[norm]
    all_keys = list(_NORMALIZED_MODULES.keys())
    close = get_close_matches(norm, all_keys, n=1, cutoff=0.8)
    if close:
        original_key = close[0]
        return f"Возможно, {original_key}: {_NORMALIZED_MODULES[original_key]}"
    return None


def _extract_prefix_hints(module_name: str) -> str:
    """Возвращает строку с подсказками на основе префиксов/подстрок."""
    hints = []
    for hint_re, hint_text in _PREFIX_HINTS:
        if hint_re.search(module_name):
            hints.append(hint_text)
    return " – " + "; ".join(hints) if hints else ""


def classify_module(module_name: str) -> str:
    """
    Возвращает наиболее точное описание модуля с использованием эвристик:
    1. Точное совпадение в нормализованной базе.
    2. Нечёткий поиск среди известных модулей.
    3. Эвристика по префиксам API Set.
    4. Подсказки по известным подстрокам/префиксам.
    """
    norm = _normalize_name(module_name)

    # 1. Точное совпадение
    if norm in _NORMALIZED_MODULES:
        return _NORMALIZED_MODULES[norm]

    # 2. Нечёткое совпадение
    fuzzy = _fuzzy_match_module(module_name)
    if fuzzy:
        return fuzzy

    # 3. API Set
    if norm.startswith("api-ms-win-"):
        return "Windows API Set (контрактная DLL с гарантированным присутствием на всех версиях Windows)"
    if norm.startswith("ext-ms-win-"):
        return "Windows API Set (расширенная контрактная DLL, может отсутствовать на некоторых редакциях Windows)"

    # 4. Общие подсказки по имени
    base = "Неопознанный модуль"
    hints = _extract_prefix_hints(module_name)
    return base + hints


# ------------------------------------------------------------
# Группировка словарей по категориям для сводного отчёта
# ------------------------------------------------------------
_CATEGORIES = {
    "Системные библиотеки ОС": {
        "description": (
            "Базовые библиотеки операционной системы: "
            "управление памятью, процессами, файлами, системные вызовы, "
            "аппаратная абстракция, подсистемы совместимости (WOW64), "
            "динамическая загрузка, POSIX-функции, runtime Android."
        ),
        "dicts": [
            _WINDOWS_HAL, _WINDOWS_NATIVE_API, _WINDOWS_KERNEL_SUBSYSTEM,
            _WINDOWS_USER_SUBSYSTEM, _WINDOWS_SYSTEM_SERVICES,
            _WINDOWS_USB_DEVICE, _WINDOWS_SUBSYSTEM_COMPAT,
            _WINDOWS_API_SETS, _WINDOWS_DOTNET,
            _LINUX_CORE_LIBS, _LINUX_DYNAMIC_LINKER, _LINUX_SYSTEM_SERVICES,
            _MACOS_CORE, _MACOS_DISPATCH, _MACOS_FOUNDATION,
            _ANDROID_CORE, _ANDROID_BINDER, _ANDROID_RUNTIME,
            _ANDROID_NETWORK_MONITORING,
            _ANDROID_HARDWARE,
            _ANDROID_JNI,
        ],
    },
    "Криптография и безопасность": {
        "description": (
            "Криптографические операции (шифрование, хеширование, цифровые подписи), "
            "протоколы SSL/TLS, управление сертификатами, "
            "системы аутентификации, контроль доступа (AppArmor, SELinux, PAM), "
            "хеширование паролей, генерация ключей."
        ),
        "dicts": [
            _WINDOWS_SECURITY_CRYPTO, _WINDOWS_BCRYPTPRIMITIVES,
            _LINUX_SECURITY, _MACOS_CRYPTO, _ANDROID_CRYPTO,
            _THIRD_PARTY_CRYPTO, _THIRD_PARTY_CRYPTO_MORE,
            _LINUX_SECURITY_EXTRA, _LINUX_CRYPTO_EXTRA,
        ],
    },
    "Сеть и коммуникации": {
        "description": (
            "Сетевые протоколы (TCP/UDP, HTTP, FTP, WebSocket), "
            "разрешение DNS, удалённый вызов процедур (RPC, gRPC, AMQP, Kafka), "
            "VPN-туннели, Bluetooth, браузерные движки (CEF, WebKit), "
            "JavaScript-движки (V8)."
        ),
        "dicts": [
            _WINDOWS_NETWORK, _MACOS_NETWORK,
            _ANDROID_NETWORK, _ANDROID_BLUETOOTH,
            _THIRD_PARTY_NETWORK, _THIRD_PARTY_BROWSER,
            _THIRD_PARTY_VPN, _THIRD_PARTY_RPC, _THIRD_PARTY_RPC_MORE,
            _THIRD_PARTY_JAVASCRIPT,
        ],
    },
    "Графика и мультимедиа": {
        "description": (
            "2D/3D-графика, видео и аудио, рендеринг шрифтов, "
            "обработка изображений (JPEG, PNG, WebP, RAW), "
            "звуковые системы (PulseAudio, ALSA, OpenAL), "
            "компьютерное зрение (OpenCV), игровые движки (OGRE, Bullet Physics), "
            "медиа-фреймворки (FFmpeg, GStreamer, VLC), GUI-тулкиты (Qt, GTK, wxWidgets)."
        ),
        "dicts": [
            _WINDOWS_GRAPHICS_MULTIMEDIA, _THIRD_PARTY_GRAPHICS,
            _THIRD_PARTY_IMAGE, _THIRD_PARTY_AUDIO,
            _THIRD_PARTY_CV, _THIRD_PARTY_GAME_MULTIMEDIA,
            _THIRD_PARTY_2D_GRAPHICS, _THIRD_PARTY_GUI_MORE,
            _THIRD_PARTY_TERMINAL,
            _ANDROID_NATIVE_WINDOW, _ANDROID_MEDIA, _ANDROID_GRAPHICS,
            _ANDROID_CAMERA, _ANDROID_MEDIA_NDK, _ANDROID_AUDIO,
        ],
    },
    "Среды выполнения, научные и ML-библиотеки": {
        "description": (
            "Библиотеки времени выполнения (MSVCRT, libstdc++), "
            "машинное обучение (TensorFlow, PyTorch, ONNX Runtime, TensorRT), "
            "высокопроизводительные вычисления (OpenBLAS, Armadillo, GSL, FFTW), "
            "арифметика произвольной точности (GMP, MPFR), "
            "NDK-библиотеки Android, ICU для интернационализации."
        ),
        "dicts": [
            _WINDOWS_RUNTIME, _LINUX_COMPILER_RUNTIME,
            _MACOS_SWIFT, _THIRD_PARTY_ML, _THIRD_PARTY_ML_MORE,
            _ANDROID_NDK, _ANDROID_ICU,
        ],
    },
    "Работа с данными, архивация и XML": {
        "description": (
            "Сжатие и архивация (zlib, bzip2, LZMA, Brotli, Zstd, Snappy, LZ4), "
            "работа с архивами (ZIP, RAR, tar, 7z), "
            "базы данных (SQLite, MySQL, PostgreSQL), "
            "парсеры XML (libxml2, Expat), логирование (log4cplus, log4net), "
            "сериализация (Protocol Buffers, MessagePack, Avro, FlatBuffers), "
            "шрифты (Fontconfig)."
        ),
        "dicts": [
            _THIRD_PARTY_COMPRESSION, _THIRD_PARTY_COMPRESSION_MORE,
            _THIRD_PARTY_DATABASE, _THIRD_PARTY_LOGGING,
            _THIRD_PARTY_XML, _THIRD_PARTY_RPC_MORE,
            _LINUX_COMPRESSION, _LINUX_XML_PARSING, _LINUX_DATABASE,
            _MACOS_DATABASE,
            _MACOS_FONTCONFIG, _MACOS_EXPAT,
            _ANDROID_EXPAT,
            _WINDOWS_SERVER_CORE,
            _WINDOWS_OPENSSL_MODERN,
            _LINUX_SYSTEMD_LIBS,
            _THIRD_PARTY_VIRTUALIZATION,
            _THIRD_PARTY_QT,
        ],
    },
}


def get_module_category_and_description(module_name: str) -> Tuple[str, str]:
    """
    Возвращает (category_name, category_description),
    если модуль найден в одном из словарей категорий,
    иначе — ("Неопознанные модули", "").
    """
    norm = _normalize_name(module_name)
    for category, info in _CATEGORIES.items():
        for d in info["dicts"]:
            if norm in [_normalize_name(k) for k in d.keys()]:
                return category, info["description"]
    return "Неопознанные модули", ""