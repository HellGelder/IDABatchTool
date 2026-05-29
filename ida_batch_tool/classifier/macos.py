"""
Словари для macOS / iOS модулей (переработанная функциональная группировка).

Исходные описания сохранены без изменений.
Группировка выполнена по следующим категориям:
- System Core (фундаментальные библиотеки)
- Security & Cryptography
- Network & Web
- UI & Graphics
- Multimedia
- Data & Storage
- Machine Learning & Vision
- Developer Tools & Diagnostics
- App Services (высокоуровневые сервисы)
- Swift Runtime
"""

# ========================
# 1. System Core
# ========================
_SYSTEM_CORE = {
    "libSystem.dylib": "Apple System Library — фундаментальная библиотека Darwin (macOS/iOS). Включает libc, libm, libpthread, libdl, libkvm, libinfo, libdbm.",
    "libSystem.B.dylib": "Apple System Library версии B — обеспечивает обратную совместимость.",
    "libc++.1.dylib": "Apple C++ Standard Library — реализация стандартной библиотеки C++ (libc++) для Darwin.",
    "libc++.dylib": "Apple C++ Standard Library.",
    "libc++abi.dylib": "Apple C++ ABI library — поддержка ABI для libc++ (исключения, RTTI).",
    "libobjc.A.dylib": "Objective-C Runtime — среда выполнения языка Objective-C. Фундамент всех Cocoa/Cocoa Touch приложений.",
    "libcompression.dylib": "Compression Library — аппаратно ускоренное сжатие и распаковка данных (LZFSE, LZ4, ZLIB, LZMA).",
    "libz.1.dylib": "Zlib Compression Library — сжатие данных (Deflate).",
    "libbz2.dylib": "Bzip2 Compression Library — алгоритм сжатия Burrows-Wheeler (bzip2).",
    "libxml2.2.dylib": "Libxml2 — XML-парсер (Apple).",
    "libtasn1.dylib": "Libtasn1 — библиотека кодирования/декодирования ASN.1, используемая в macOS для работы с сертификатами.",
    "libresolv.9.dylib": "DNS Resolver Library — функции для разрешения доменных имён (DNS).",
    "libstdc++.6.dylib": "GNU Standard C++ Library — стандартная библиотека C++ (используется в некоторых Darwin-системах).",
    "libicucore.A.dylib": "ICU (International Components for Unicode) — сортировка, форматирование дат/чисел/валют, регулярные выражения.",
    "libicucore.dylib": "ICU (International Components for Unicode) — сортировка, форматирование дат/чисел/валют, регулярные выражения.",
    "libiconv.dylib": "Libiconv — преобразование между различными кодировками текста.",
    "libexpat.1.dylib": "Expat XML Parser (macOS) — потоковый парсер XML.",
    "libdispatch.dylib": "Grand Central Dispatch (GCD) — библиотека для параллельных вычислений: очереди, группы, семафоры.",
    "CoreFoundation": "CoreFoundation.framework — фундамент всех системных фреймворков Apple. Базовые типы данных, управление памятью.",
    "<dynamic>": "Специальный маркер — ссылка на динамический загрузчик dyld.",
    "<loader>": "Специальный маркер — ссылка на исполняемый модуль (само приложение или загрузчик).",
    "<self>": "Собственный исполняемый модуль (само приложение).",
}

# ========================
# 2. Security & Cryptography
# ========================
_SECURITY_CRYPTO = {
    "libcrypto.44.dylib": "OpenSSL/LibreSSL Crypto Library — криптографические операции (macOS).",
    "libssl.46.dylib": "OpenSSL/LibreSSL SSL/TLS Library — реализация протоколов SSL/TLS (macOS).",
    "libcrypto.dylib": "Apple Crypto Library — шифрование (AES, RSA, ECC), хеширование (SHA), цифровые подписи.",
    "libcommonCrypto.dylib": "CommonCrypto — высокоуровневый криптографический API Apple.",
    "libboringssl.dylib": "BoringSSL (Google/Apple) — форк OpenSSL, используемый Apple.",
    "Security": "Security.framework — криптография, управление сертификатами, keychain.",
    "CryptoKit": "CryptoKit.framework — криптографические операции на Swift (хэши, шифрование, подписи).",
    "LocalAuthentication": "LocalAuthentication.framework — биометрическая аутентификация (Touch ID, Face ID).",
    "DeviceCheck": "DeviceCheck.framework — проверка безопасности устройства и снижение злоупотреблений.",
}

# ========================
# 3. Network & Web
# ========================
_NETWORK_WEB = {
    "libnetwork.dylib": "Apple Network Library — современная сетевая библиотека Apple: асинхронные соединения, TLS, мониторинг сети.",
    "libcurl.dylib": "Curl Library (Apple) — работа с URL (HTTP, HTTPS, FTP и др.).",
    "CFNetwork": "CFNetwork.framework — низкоуровневый сетевой API на основе Core Foundation.",
    "Network": "Network.framework — современный сетевой фреймворк Apple (асинхронные соединения, TLS, UDP).",
    "SystemConfiguration": "SystemConfiguration.framework — управление сетевыми конфигурациями, мониторинг состояния сети.",
    "WebKit": "WebKit.framework — движок браузера WebKit: отображение веб-контента, поддержка JavaScript, взаимодействие с JS.",
    "JavaScriptCore": "JavaScriptCore.framework — движок JavaScript, используемый WebKit.",
    "SafariServices": "SafariServices.framework — встраиваемый браузер SFSafariViewController, менеджер паролей.",
}

# ========================
# 4. UI & Graphics
# ========================
_UI_GRAPHICS = {
    "CoreGraphics": "CoreGraphics.framework — 2D-графический движок (Quartz 2D).",
    "CoreText": "CoreText.framework — низкоуровневая система верстки текста и рендеринга шрифтов.",
    "QuartzCore": "QuartzCore.framework — Core Animation: высокопроизводительная анимация слоев.",
    "Metal": "Metal.framework — низкоуровневый графический и вычислительный API с высокой производительностью.",
    "MetalKit": "MetalKit.framework — интеграция Metal с UIKit и другими фреймворками.",
    "OpenGLES": "OpenGLES.framework — OpenGL ES для встраиваемых систем (графика).",
    "UIKit": "UIKit.framework — основной фреймворк для построения интерфейсов iOS/tvOS.",
    "SwiftUI": "SwiftUI.framework — современный декларативный фреймворк для построения UI.",
    "PencilKit": "PencilKit.framework — работа с Apple Pencil (рисование, рукописный ввод).",
    "libfontconfig.1.dylib": "Fontconfig — конфигурация и поиск шрифтов в macOS.",
}

# ========================
# 5. Multimedia
# ========================
_MULTIMEDIA = {
    "CoreMedia": "CoreMedia.framework — низкоуровневый мультимедийный API, управление потоками аудио/видео.",
    "CoreVideo": "CoreVideo.framework — высокопроизводительные видеобуферы, работа с видео в реальном времени.",
    "AudioToolbox": "AudioToolbox.framework — низкоуровневый аудио API для воспроизведения и записи звука.",
    "AVFoundation": "AVFoundation.framework — ключевой фреймворк для работы с аудио и видео.",
    "AVKit": "AVKit.framework — высокоуровневый фреймворк для воспроизведения видео (tvOS, iOS).",
    "AVFAudio": "AVFAudio.framework — высокоуровневый аудио API для воспроизведения и записи, синтеза речи.",
    "ImageIO": "ImageIO.framework — чтение и запись растровых изображений, метаданных EXIF, IPTC.",
    "CoreImage": "CoreImage.framework — обработка изображений в реальном времени, фильтры, распознавание лиц.",
    "MediaPlayer": "MediaPlayer.framework — воспроизведение мультимедиа, управление удалённым управлением.",
    "Speech": "Speech.framework — распознавание и синтез речи.",
    "CoreMIDI": "CoreMIDI.framework — работа с MIDI-инструментами и устройствами.",
    "CoreAudioKit": "CoreAudioKit.framework — управление аудиоустройствами (панели настройки, AUAudioUnit).",
}

# ========================
# 6. Data & Storage
# ========================
_DATA_STORAGE = {
    "libsqlite3.dylib": "SQLite Database Engine — встраиваемая реляционная база данных SQLite (Apple).",
    "CoreData": "CoreData.framework — управление объектными графами и постоянным хранилищем.",
    "CoreServices": "CoreServices.framework — вспомогательные сервисы: метаданные (Spotlight), управление файлами.",
}

# ========================
# 7. Machine Learning & Vision
# ========================
_ML_VISION = {
    "CoreML": "CoreML.framework — машинное обучение на устройстве (вывод моделей).",
    "Vision": "Vision.framework — компьютерное зрение: распознавание лиц, текста, штрихкодов, объектов.",
    "NaturalLanguage": "NaturalLanguage.framework — обработка естественного языка (токенизация, тегирование).",
}

# ========================
# 8. Developer Tools & Diagnostics
# ========================
_DEVELOPER_TOOLS = {
    "MetricKit": "MetricKit.framework — сбор метрик производительности и энергопотребления.",
    "DeveloperToolsSupport": "DeveloperToolsSupport.framework — поддержка инструментов разработчика (Live Preview и др.).",
    "BackgroundTasks": "BackgroundTasks.framework — планирование фоновых задач в iOS.",
}

# ========================
# 9. App Services (высокоуровневые сервисы)
# ========================
_APP_SERVICES = {
    "Foundation": "Foundation.framework — основная библиотека Objective-C/Swift для работы с объектами, коллекциями, файловой системой.",
    "StoreKit": "StoreKit.framework — встроенные покупки и взаимодействие с App Store.",
    "AdSupport": "AdSupport.framework — функциональность для рекламы, включая идентификатор рекламы (IDFA).",
    "AppTrackingTransparency": "AppTrackingTransparency.framework — запрос разрешения на отслеживание пользователя.",
    "AdAttributionKit": "AdAttributionKit.framework — атрибуция рекламных кампаний и измерение эффективности.",
    "Intents": "Intents.framework — интеграция с Siri и предложениями.",
    "UserNotifications": "UserNotifications.framework — отправка и обработка локальных и удаленных уведомлений.",
    "WidgetKit": "WidgetKit.framework — создание виджетов для домашнего экрана iOS/macOS.",
    "ActivityKit": "ActivityKit.framework — Live Activities и Dynamic Island.",
    "WatchConnectivity": "WatchConnectivity.framework — взаимодействие с Apple Watch.",
    "GameController": "GameController.framework — поддержка игровых контроллеров (геймпадов, джойстиков).",
    "GameplayKit": "GameplayKit.framework — игровая логика, AI, система принятия решений.",
    "CallKit": "CallKit.framework — интеграция с вызовами (VoIP, телефон).",
    "Contacts": "Contacts.framework — работа с контактами пользователя.",
    "ContactsUI": "ContactsUI.framework — готовый интерфейс выбора и отображения контактов.",
    "EventKit": "EventKit.framework — работа с календарём и событиями.",
    "MapKit": "MapKit.framework — встраиваемые карты, геокодирование, аннотации, 3D-сцены.",
    "CoreLocation": "CoreLocation.framework — геолокационные сервисы: GPS, геокодирование, мониторинг регионов.",
    "Photos": "Photos.framework — доступ к медиатеке пользователя (фотографии, видео), редактирование.",
    "PDFKit": "PDFKit.framework — отображение, создание, аннотирование PDF-документов.",
    "Social": "Social.framework — интеграция с социальными сетями (Facebook, Twitter, Sina Weibo).",
    "CoreHaptics": "CoreHaptics.framework — управление тактильной обратной связью.",
    "CoreNFC": "CoreNFC.framework — чтение NFC-меток.",
    "CoreTelephony": "CoreTelephony.framework — информация о сотовой сети и операторе.",
    "CoreMotion": "CoreMotion.framework — обработка данных с акселерометра, гироскопа, шагомера.",
    "FamilyControls": "FamilyControls.framework — управление родительским контролем.",
    "ManagedSettings": "ManagedSettings.framework — управление настройками устройства в рамках семейного доступа.",
    "ManagedSettingsUI": "ManagedSettingsUI.framework — интерфейс для настройки семейного доступа.",
    "MarketplaceKit": "MarketplaceKit.framework — взаимодействие с альтернативными маркетплейсами приложений.",
    "MessageUI": "MessageUI.framework — отправка электронной почты и SMS из приложения.",
    "AuthenticationServices": "AuthenticationServices.framework — вход через Apple ID, Sign in with Apple.",
    "Combine": "Combine.framework — реактивное программирование, асинхронные потоки событий.",
    "Accelerate": "Accelerate.framework — высокопроизводительные численные вычисления, линейная алгебра, обработка сигналов.",
    "_AdAttributionKit_StoreKit": "Внутренний символ, связывающий AdAttributionKit и StoreKit.",
    "_AVKit_SwiftUI": "Внутренний символ, связывающий AVKit и SwiftUI.",
    "_StoreKit_SwiftUI": "Внутренний символ, связывающий StoreKit и SwiftUI.",
}

# ========================
# 10. Swift Runtime
# ========================
_SWIFT_RUNTIME = {
    "libswiftCore.dylib":
        "Среда выполнения языка Swift. Содержит базовые типы (Int, String, Array), управление памятью (ARC), "
        "протоколы и динамическую диспетчеризацию. Необходима для любого Swift-приложения.",

    "libswiftFoundation.dylib":
        "Мост между Swift и Foundation. Предоставляет удобные Swift-обёртки для классов NSObject, NSString, "
        "NSArray и других, а также дополнительные расширения, делающие работу с Foundation идиоматичной в Swift.",

    "libswiftUIKit.dylib":
        "Интерфейс Swift для UIKit. Позволяет использовать все компоненты пользовательского интерфейса iOS/tvOS "
        "(UIView, UIViewController, жесты, анимацию) с нативной поддержкой Swift-функций.",

    "libswiftCoreFoundation.dylib":
        "Swift-обёртка для CoreFoundation. Обеспечивает прямой доступ к низкоуровневым C-структурам и функциям "
        "CoreFoundation, таким как CFArray, CFDictionary, CFRunLoop, с автоматическим управлением памятью.",

    "libswiftCoreGraphics.dylib":
        "Swift-интерфейс для CoreGraphics. Упрощает работу с контекстами рисования, геометрическими структурами "
        "(CGPoint, CGRect), цветами и шрифтами, используя выразительные возможности Swift.",

    "libswiftCoreMedia.dylib":
        "Swift-обёртка для CoreMedia. Предоставляет удобные API для работы с медиа-конвейерами, временными метками, "
        "буферами и форматами аудио/видео, ускоряя разработку мультимедийных приложений.",

    "libswiftCoreNFC.dylib":
        "Swift-интерфейс для CoreNFC. Даёт возможность взаимодействовать с NFC-метками (чтение, запись, "
        "форматирование) с использованием высокоуровневых Swift-конструкций.",

    "libswiftDarwin.dylib":
        "Мост к Darwin-подсистеме. Открывает доступ к низкоуровневым системным вызовам и API ядра Darwin "
        "(bsd/kernel), позволяя Swift-коду напрямую управлять процессами, памятью и файловыми дескрипторами.",

    "libswiftDispatch.dylib":
        "Swift-обёртка для Grand Central Dispatch (GCD). Делает асинхронное программирование с очередями, "
        "группами и семафорами более безопасным и выразительным, интегрируясь с современными возможностями Swift.",

    "libswiftObjectiveC.dylib":
        "Взаимодействие Swift с Objective-C Runtime. Обеспечивает вызов Objective-C методов, динамическое "
        "связывание, поддержку KVO и селекторов, что критично для совместимости с фреймворками Apple.",

    "libswiftQuartzCore.dylib":
        "Swift-интерфейс для QuartzCore (Core Animation). Предоставляет простые API для создания и управления "
        "анимацией слоёв CALayer, трансформациями и визуальными эффектами в iOS и macOS.",

    "libswiftUniformTypeIdentifiers.dylib":
        "Swift-обёртка для UniformTypeIdentifiers. Позволяет элегантно работать с типами файлов и данных, "
        "определять MIME-типы и соответствие контента определённым форматам, используя Swift-перечисления.",

    "libswiftVision.dylib":
        "Swift-интерфейс для фреймворка Vision. Упрощает применение алгоритмов компьютерного зрения: "
        "распознавание лиц, текста, объектов, жестов и контуров, интегрируя их в Swift-пайплайны обработки.",

    "libswift_Concurrency.dylib":
        "Среда выполнения для конкурентности Swift. Обеспечивает поддержку async/await, Task, Actor и других "
        "механизмов структурной конкурентности, позволяя писать безопасный многопоточный код.",

    "libswift_StringProcessing.dylib":
        "Библиотека обработки строк Swift. Включает современный движок регулярных выражений, "
        "парсинга и трансформации текста, тесно интегрированный со стандартной библиотекой Swift.",

    "libswiftIntents.dylib":
        "Swift-обёртка для Intents. Позволяет интегрировать возможности Siri и Shortcuts: создавать "
        "настраиваемые голосовые команды, обрабатывать пользовательские намерения и управлять сценариями.",

    "libswiftos.dylib":
        "Swift-интерфейс для модуля os. Даёт доступ к функциям логирования (os_log), системным уведомлениям "
        "и другим низкоуровневым сервисам операционной системы, обёрнутым в удобные Swift-API.",

    "libswiftAVFoundation.dylib":
        "Swift-обёртка для AVFoundation. Предоставляет идиоматичный Swift-доступ к захвату, воспроизведению "
        "и редактированию аудио/видео, включая работу с камерой и микрофоном.",

    "libswiftCoreAudio.dylib":
        "Swift-интерфейс для CoreAudio. Упрощает взаимодействие с аудиоустройствами, потоками и обработкой "
        "звука в реальном времени, сохраняя всю мощь низкоуровневого фреймворка.",

    "libswiftNaturalLanguage.dylib":
        "Swift-обёртка для NaturalLanguage. Предоставляет простые API для токенизации, определения языка, "
        "лемматизации и анализа тональности текста, полностью интегрированные с экосистемой Swift.",

    "libswiftNetwork.dylib":
        "Swift-интерфейс для Network.framework. Даёт возможность создавать сетевые соединения, работать с "
        "TLS, UDP и Bonjour, используя современные Swift-абстракции и асинхронные потоки.",

    "libswiftObservation.dylib":
        "Swift-обёртка для Observation. Реализует реактивное отслеживание изменений свойств объектов в "
        "iOS 17+ и macOS 14+, обеспечивая автоматическое обновление UI при изменении модели данных.",
}

# ========================
# Итоговый объединённый словарь
# ========================
MACOS_MODULES = {}
for group in (_SYSTEM_CORE, _SECURITY_CRYPTO, _NETWORK_WEB, _UI_GRAPHICS,
              _MULTIMEDIA, _DATA_STORAGE, _ML_VISION, _DEVELOPER_TOOLS,
              _APP_SERVICES, _SWIFT_RUNTIME):
    MACOS_MODULES.update(group)