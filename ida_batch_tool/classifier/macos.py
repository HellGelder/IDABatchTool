"""Словари для macOS / iOS модулей."""

_MACOS_CORE = {
    "libSystem.dylib": "Apple System Library — фундаментальная библиотека Darwin (macOS/iOS). Включает libc, libm, libpthread, libdl, libkvm, libinfo, libdbm.",
    "libSystem.B.dylib": "Apple System Library версии B — обеспечивает обратную совместимость.",
    "libc++.1.dylib": "Apple C++ Standard Library — реализация стандартной библиотеки C++ (libc++) для Darwin.",
    "libc++.dylib": "Apple C++ Standard Library — реализация стандартной библиотеки C++ для Darwin.",
    "libobjc.A.dylib": "Objective-C Runtime — среда выполнения языка Objective-C. Фундамент всех Cocoa/Cocoa Touch приложений.",
    "libcompression.dylib": "Compression Library — аппаратно ускоренное сжатие и распаковка данных (LZFSE, LZ4, ZLIB, LZMA).",
    "libsqlite3.dylib": "SQLite Database Engine — встраиваемая реляционная база данных SQLite (Apple).",
    "libz.1.dylib": "Zlib Compression Library — сжатие данных (Deflate).",
    "libtasn1.dylib": "Libtasn1 — библиотека кодирования/декодирования ASN.1, используемая в macOS для работы с сертификатами.",
    "libresolv.9.dylib": "DNS Resolver Library — функции для разрешения доменных имён (DNS).",
    "libcrypto.44.dylib": "OpenSSL/LibreSSL Crypto Library — криптографические операции (macOS).",
    "libssl.46.dylib": "OpenSSL/LibreSSL SSL/TLS Library — реализация протоколов SSL/TLS (macOS).",
}

_MACOS_DISPATCH = {
    "libdispatch.dylib": "Grand Central Dispatch (GCD) — библиотека для параллельных вычислений: очереди, группы, семафоры.",
}

_MACOS_FOUNDATION = {
    "libicucore.dylib": "ICU (International Components for Unicode) — сортировка, форматирование дат/чисел/валют, регулярные выражения.",
    "libiconv.dylib": "Libiconv — преобразование между различными кодировками текста.",
}

_MACOS_NETWORK = {
    "libnetwork.dylib": "Apple Network Library — современная сетевая библиотека Apple: асинхронные соединения, TLS, мониторинг сети.",
    "libcurl.dylib": "Curl Library (Apple) — работа с URL (HTTP, HTTPS, FTP и др.).",
}

_MACOS_DATABASE = {
    "libsqlite3.dylib": "SQLite Database Engine (Apple) — встраиваемая база данных.",
}

_MACOS_SWIFT = {
    "libswiftCore.dylib": "Swift Core Library — среда выполнения языка Swift: базовые типы, протоколы, управление памятью.",
    "libswiftFoundation.dylib": "Swift Foundation Overlay — Swift-интерфейс к Foundation.",
    "libswiftUIKit.dylib": "Swift UIKit Overlay — Swift-интерфейс к UIKit (iOS).",
    "libswiftCoreFoundation.dylib": "Swift CoreFoundation Overlay.",
    "libswiftCoreGraphics.dylib": "Swift CoreGraphics Overlay.",
    "libswiftCoreMedia.dylib": "Swift CoreMedia Overlay.",
    "libswiftCoreNFC.dylib": "Swift CoreNFC Overlay.",
    "libswiftDarwin.dylib": "Swift Darwin Overlay.",
    "libswiftDispatch.dylib": "Swift Dispatch Overlay (GCD).",
    "libswiftObjectiveC.dylib": "Swift ObjectiveC Overlay.",
    "libswiftQuartzCore.dylib": "Swift QuartzCore Overlay.",
    "libswiftUniformTypeIdentifiers.dylib": "Swift UniformTypeIdentifiers Overlay.",
    "libswiftVision.dylib": "Swift Vision Overlay.",
    "libswift_Concurrency.dylib": "Swift Concurrency Runtime — async/await, actors.",
    "libswift_StringProcessing.dylib": "Swift StringProcessing — регулярные выражения.",
}

_MACOS_CRYPTO = {
    "libcrypto.dylib": "Apple Crypto Library — шифрование (AES, RSA, ECC), хеширование (SHA), цифровые подписи.",
    "libcommonCrypto.dylib": "CommonCrypto — высокоуровневый криптографический API Apple.",
    "libboringssl.dylib": "BoringSSL (Google/Apple) — форк OpenSSL, используемый Apple.",
}

_MACOS_EXPAT = {
    "libexpat.1.dylib": "Expat XML Parser (macOS) — потоковый парсер XML.",
}

_MACOS_FONTCONFIG = {
    "libfontconfig.1.dylib": "Fontconfig — конфигурация и поиск шрифтов в macOS.",
}

# Все системные фреймворки macOS/iOS
_MACOS_FRAMEWORKS = {
    "AdSupport": "AdSupport.framework — функциональность для рекламы, включая идентификатор рекламы (IDFA).",
    "AudioToolbox": "AudioToolbox.framework — низкоуровневый аудио API для воспроизведения и записи звука.",
    "AVFAudio": "AVFAudio.framework — высокоуровневый аудио API для воспроизведения и записи, синтеза речи.",
    "AVFoundation": "AVFoundation.framework — ключевой фреймворк для работы с аудио и видео.",
    "CFNetwork": "CFNetwork.framework — низкоуровневый сетевой API на основе Core Foundation.",
    "Combine": "Combine.framework — реактивное программирование, асинхронные потоки событий.",
    "CoreFoundation": "CoreFoundation.framework — фундамент всех системных фреймворков Apple. Базовые типы данных, управление памятью.",
    "CoreGraphics": "CoreGraphics.framework — 2D-графический движок (Quartz 2D).",
    "CoreImage": "CoreImage.framework — обработка изображений в реальном времени, фильтры, распознавание лиц.",
    "CoreLocation": "CoreLocation.framework — геолокационные сервисы: GPS, геокодирование, мониторинг регионов.",
    "CoreMedia": "CoreMedia.framework — низкоуровневый мультимедийный API, управление потоками аудио/видео.",
    "CoreNFC": "CoreNFC.framework — чтение NFC-меток.",
    "CoreServices": "CoreServices.framework — вспомогательные сервисы: метаданные (Spotlight), управление файлами.",
    "CoreText": "CoreText.framework — низкоуровневая система верстки текста и рендеринга шрифтов.",
    "CoreVideo": "CoreVideo.framework — высокопроизводительные видеобуферы, работа с видео в реальном времени.",
    "Foundation": "Foundation.framework — основная библиотека Objective-C/Swift для работы с объектами, коллекциями, файловой системой.",
    "ImageIO": "ImageIO.framework — чтение и запись растровых изображений, метаданных EXIF, IPTC.",
    "LocalAuthentication": "LocalAuthentication.framework — биометрическая аутентификация (Touch ID, Face ID).",
    "MapKit": "MapKit.framework — встраиваемые карты, геокодирование, аннотации, 3D-сцены.",
    "MessageUI": "MessageUI.framework — отправка электронной почты и SMS из приложения.",
    "PDFKit": "PDFKit.framework — отображение, создание, аннотирование PDF-документов.",
    "Photos": "Photos.framework — доступ к медиатеке пользователя (фотографии, видео), редактирование.",
    "QuartzCore": "QuartzCore.framework — Core Animation: высокопроизводительная анимация слоев.",
    "SafariServices": "SafariServices.framework — встраиваемый браузер SFSafariViewController, менеджер паролей.",
    "Security": "Security.framework — криптография, управление сертификатами, keychain.",
    "SwiftUI": "SwiftUI.framework — современный декларативный фреймворк для построения UI.",
    "SystemConfiguration": "SystemConfiguration.framework — управление сетевыми конфигурациями, мониторинг состояния сети.",
    "UIKit": "UIKit.framework — основной фреймворк для построения интерфейсов iOS/tvOS.",
    "UserNotifications": "UserNotifications.framework — отправка и обработка локальных и удаленных уведомлений.",
    "Vision": "Vision.framework — компьютерное зрение: распознавание лиц, текста, штрихкодов, объектов.",
    "WebKit": "WebKit.framework — движок браузера WebKit: отображение веб-контента, поддержка JavaScript, взаимодействие с JS.",
}

# Объединение всех словарей
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
MACOS_MODULES.update(_MACOS_FRAMEWORKS)