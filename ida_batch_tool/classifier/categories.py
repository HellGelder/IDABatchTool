"""Логика классификации и группировка модулей по категориям."""
from typing import Dict, Optional, Tuple

# Импортируем словари для категорий
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
    _SYSTEM_CORE, _SECURITY_CRYPTO, _NETWORK_WEB, _UI_GRAPHICS,
    _MULTIMEDIA, _DATA_STORAGE, _ML_VISION, _DEVELOPER_TOOLS,
    _APP_SERVICES, _SWIFT_RUNTIME,
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

_CATEGORIES = {
    "Системные библиотеки ОС": {
        "description": (
            "Базовые библиотеки операционной системы: "
            "управление памятью, процессами, файлами, системные вызовы, "
            "аппаратная абстракция, подсистемы совместимости (WOW64), "
            "динамическая загрузка, POSIX-функции, runtime Android, "
            "фреймворки macOS/iOS."
        ),
        "dicts": [
            _WINDOWS_HAL, _WINDOWS_NATIVE_API, _WINDOWS_KERNEL_SUBSYSTEM,
            _WINDOWS_USER_SUBSYSTEM, _WINDOWS_SYSTEM_SERVICES,
            _WINDOWS_USB_DEVICE, _WINDOWS_SUBSYSTEM_COMPAT,
            _WINDOWS_API_SETS, _WINDOWS_DOTNET,
            _LINUX_CORE_LIBS, _LINUX_DYNAMIC_LINKER, _LINUX_SYSTEM_SERVICES,
            _SYSTEM_CORE, _APP_SERVICES, _SWIFT_RUNTIME,
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
            _LINUX_SECURITY, _SECURITY_CRYPTO,
            _ANDROID_CRYPTO,
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
            _WINDOWS_NETWORK,
            _NETWORK_WEB,
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
            _WINDOWS_GRAPHICS_MULTIMEDIA,
            _UI_GRAPHICS, _MULTIMEDIA, _ML_VISION,
            _ANDROID_NATIVE_WINDOW, _ANDROID_MEDIA, _ANDROID_GRAPHICS,
            _ANDROID_CAMERA, _ANDROID_MEDIA_NDK, _ANDROID_AUDIO,
            _THIRD_PARTY_GRAPHICS, _THIRD_PARTY_IMAGE, _THIRD_PARTY_AUDIO,
            _THIRD_PARTY_CV, _THIRD_PARTY_GAME_MULTIMEDIA,
            _THIRD_PARTY_2D_GRAPHICS, _THIRD_PARTY_GUI_MORE,
            _THIRD_PARTY_TERMINAL,
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
            _WINDOWS_RUNTIME,
            _LINUX_COMPILER_RUNTIME,
            _SWIFT_RUNTIME, _DEVELOPER_TOOLS,
            _ANDROID_NDK, _ANDROID_ICU,
            _THIRD_PARTY_ML, _THIRD_PARTY_ML_MORE,
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
            _LINUX_COMPRESSION, _LINUX_XML_PARSING, _LINUX_DATABASE,
            _DATA_STORAGE,
            _ANDROID_EXPAT,
            _THIRD_PARTY_COMPRESSION, _THIRD_PARTY_COMPRESSION_MORE,
            _THIRD_PARTY_DATABASE, _THIRD_PARTY_LOGGING,
            _THIRD_PARTY_XML, _THIRD_PARTY_RPC_MORE,
            _WINDOWS_SERVER_CORE,
            _WINDOWS_OPENSSL_MODERN,
            _LINUX_SYSTEMD_LIBS,
            _THIRD_PARTY_VIRTUALIZATION,
            _THIRD_PARTY_QT,
        ],
    },
}


def get_module_category_and_description(module_name: str) -> Tuple[str, str]:
    """Возвращает категорию и описание категории (используется в отчётах)."""
    from .platform_classifier import _normalize_name

    norm = _normalize_name(module_name)
    for category, info in _CATEGORIES.items():
        for d in info["dicts"]:
            if norm in [_normalize_name(k) for k in d.keys()]:
                return category, info["description"]
    return "Неопознанные модули", ""