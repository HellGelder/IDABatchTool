"""Словари для macOS / iOS модулей."""

_MACOS_CORE = {
    "libSystem.dylib": "Apple System Library — фундаментальная библиотека Darwin (macOS/iOS). Предоставляет тысячи базовых C-функций, формирующих настоящие «Core OS» службы. Включает в себя libc (стандартная библиотека C), libm (математика), libpthread (потоки POSIX), libdl (динамическая загрузка), libkvm (виртуальная память ядра), libinfo (NetInfo), libdbm (база данных). Синонимы libSystem.B.dylib и libSystem.C.dylib. Является единственной обязательной системной библиотекой для всех приложений Darwin.",
    "libSystem.B.dylib": "Apple System Library версии B — вариант libSystem.dylib. Обеспечивает обратную совместимость и плавное обновление системных компонентов без нарушения работы приложений.",
    "libc++.dylib": "Apple C++ Standard Library — реализация стандартной библиотеки C++ (libc++) для Darwin. Включает STL, потоки ввода-вывода, работу с файлами. Более современная альтернатива libstdc++.",
    "libc++abi.dylib": "Apple C++ ABI Library — поддержка ABI (Application Binary Interface) для C++: проброс исключений, динамическое приведение типов (dynamic_cast), RTTI.",
    "libobjc.A.dylib": "Objective-C Runtime — среда выполнения языка Objective-C. Реализует посылку сообщений (objc_msgSend), управление классами, протоколами, категориями. Фундамент всех Cocoa/Cocoa Touch приложений.",
    "libobjc.B.dylib": "Objective-C Runtime версии B — вариант libobjc с улучшенной производительностью и новыми возможностями среды выполнения (Associated Objects, Method Swizzling).",
}

_MACOS_DISPATCH = {
    "libdispatch.dylib": "Grand Central Dispatch (GCD) — библиотека для организации параллельных вычислений. Предоставляет очереди (dispatch queues), группы, семафоры, таймеры, управление пулом потоков. Фундаментальная технология многозадачности в macOS и iOS.",
}

_MACOS_FOUNDATION = {
    "libicucore.dylib": "ICU (International Components for Unicode) — библиотека для работы с Unicode. Обеспечивает правила сортировки, форматирования дат/чисел/валют, регулярные выражения, анализ текста. Используется Foundation для всех операций со строками.",
    "libiconv.dylib": "Libiconv — преобразование между различными кодировками текста (UTF-8, UTF-16, ISO-8859-*, Windows-*, KOI8-R, Shift-JIS и многими другими). Критически важна для интернационализации приложений.",
}

_MACOS_NETWORK = {
    "libnetwork.dylib": "Apple Network Library — современная сетевая библиотека Apple. Асинхронные соединения, TLS, управление состоянием сети, мониторинг connectivity. Используется URLSession и другими высокоуровневыми API.",
    "libcurl.dylib": "Curl Library (Apple) — библиотека для работы с URL (HTTP, HTTPS, FTP и т.д.). Версия, поставляемая Apple в составе macOS.",
}

_MACOS_DATABASE = {
    "libsqlite3.dylib": "SQLite Database Engine (Apple) — встраиваемая база данных SQLite. Используется практически всеми приложениями macOS/iOS для локального хранения данных (Core Data, настройки приложений, кэши, Spotlight).",
}

_MACOS_SWIFT = {
    "libswiftCore.dylib": "Swift Core Library — среда выполнения языка Swift. Реализует базовые типы (String, Array, Dictionary, Int), протоколы (Equatable, Hashable, Codable), управление памятью (ARC). Требуется для всех приложений, написанных на Swift.",
    "libswiftFoundation.dylib": "Swift Foundation Overlay — прослойка между Swift и Foundation. Предоставляет Swift-идиоматичный доступ к классам Foundation (Date, URL, Bundle, FileManager).",
    "libswiftUIKit.dylib": "Swift UIKit Overlay — прослойка между Swift и UIKit для приложений iOS.",
}

_MACOS_CRYPTO = {
    "libcrypto.dylib": "Apple Crypto Library — криптографические операции: шифрование (AES, RSA, ECC), хеширование (SHA), цифровые подписи.",
    "libcommonCrypto.dylib": "CommonCrypto — высокоуровневый криптографический API Apple. Симметричное/асимметричное шифрование, хеши, HMAC, PBKDF2.",
    "libboringssl.dylib": "BoringSSL (Google/Apple) — форк OpenSSL от Google, используемый Apple. Реализация протоколов SSL/TLS и криптографических примитивов.",
}

_MACOS_EXPAT = {
    "libexpat.1.dylib": "Expat XML Parser (macOS) — потоковый парсер XML, используемый системными компонентами.",
}

_MACOS_FONTCONFIG = {
    "libfontconfig.1.dylib": "Fontconfig — конфигурация и поиск шрифтов в macOS.",
}

# Объединение всех macOS-словарей
MACOS_MODULES = {}
MACOS_MODULES.update(_MACOS_CORE)
MACOS_MODULES.update(_MACOS_DISPATCH)
MACOS_MODULES.update(_MACOS_FOUNDATION)
MACOS_MODULES.update(_MACOS_NETWORK)
MACOS_MODULES.update(_MACOS_DATABASE)
MACOS_MODULES.update(_MACOS_SWIFT)
MACOS_MODULES.update(_MACOS_CRYPTO)
MACOS_MODULES.update(_MACOS_EXPAT)
MACOS_MODULES.update(_MACOS_FONTCONFIG)