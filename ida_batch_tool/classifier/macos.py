"""Словари для macOS / iOS модулей."""

_MACOS_CORE = {
    "libSystem.dylib": "Apple System Library — фундаментальная библиотека Darwin (macOS/iOS). Включает libc, libm, libpthread, libdl, libkvm, libinfo, libdbm.",
    "libSystem.B.dylib": "Apple System Library версии B — обеспечивает обратную совместимость.",
    "libc++.1.dylib": "Apple C++ Standard Library — реализация стандартной библиотеки C++ (libc++) для Darwin.",
    "libc++.dylib": "Apple C++ Standard Library.",
    "libc++abi.dylib": "Apple C++ ABI library — поддержка ABI для libc++ (исключения, RTTI).",
    "libobjc.A.dylib": "Objective-C Runtime — среда выполнения языка Objective-C. Фундамент всех Cocoa/Cocoa Touch приложений.",
    "libcompression.dylib": "Compression Library — аппаратно ускоренное сжатие и распаковка данных (LZFSE, LZ4, ZLIB, LZMA).",
    "libsqlite3.dylib": "SQLite Database Engine — встраиваемая реляционная база данных SQLite (Apple).",
    "libz.1.dylib": "Zlib Compression Library — сжатие данных (Deflate).",
    "libbz2.dylib": "Bzip2 Compression Library — алгоритм сжатия Burrows-Wheeler (bzip2).",
    "libxml2.2.dylib": "Libxml2 — XML-парсер (Apple).",
    "libtasn1.dylib": "Libtasn1 — библиотека кодирования/декодирования ASN.1, используемая в macOS для работы с сертификатами.",
    "libresolv.9.dylib": "DNS Resolver Library — функции для разрешения доменных имён (DNS).",
    "libcrypto.44.dylib": "OpenSSL/LibreSSL Crypto Library — криптографические операции (macOS).",
    "libssl.46.dylib": "OpenSSL/LibreSSL SSL/TLS Library — реализация протоколов SSL/TLS (macOS).",
    "libstdc++.6.dylib": "GNU Standard C++ Library — стандартная библиотека C++ (используется в некоторых Darwin-системах).",
    "libicucore.A.dylib": "ICU (International Components for Unicode) — сортировка, форматирование дат/чисел/валют, регулярные выражения.",
    "<dynamic>": "Специальный маркер — ссылка на динамический загрузчик dyld.",
    "<loader>": "Специальный маркер — ссылка на исполняемый модуль (само приложение или загрузчик).",
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
    "libswift_Concurrency.dylib": "Swift Concurrency Runtime — поддержка async/await и акторов.",
    "libswift_StringProcessing.dylib": "Swift StringProcessing — регулярные выражения и обработка строк.",
    "libswiftIntents.dylib": "Swift Intents Overlay — интеграция с Siri Intents.",
    "libswiftos.dylib": "Swift os Overlay — обёртка для os_log и системных API.",
    "libswiftAVFoundation.dylib": "Swift AVFoundation Overlay.",
    "libswiftCoreAudio.dylib": "Swift CoreAudio Overlay.",
    "libswiftNaturalLanguage.dylib": "Swift NaturalLanguage Overlay — обработка естественного языка.",
    "libswiftNetwork.dylib": "Swift Network Overlay — доступ к Network.framework.",
    "libswiftObservation.dylib": "Swift Observation Overlay — поддержка модели наблюдения.",
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

_MACOS_FRAMEWORKS = {
    "AdSupport": "AdSupport.framework — функциональность для рекламы, включая идентификатор рекламы (IDFA).",
    "AudioToolbox": "AudioToolbox.framework — низкоуровневый аудио API для воспроизведения и записи звука.",
    "AVFAudio": "AVFAudio.framework — высокоуровневый аудио API для воспроизведения и записи, синтеза речи.",
    "AVFoundation": "AVFoundation.framework — ключевой фреймворк для работы с аудио и видео.",
    "AVKit": "AVKit.framework — высокоуровневый фреймворк для воспроизведения видео (tvOS, iOS).",
    "BackgroundTasks": "BackgroundTasks.framework — планирование фоновых задач в iOS.",
    "CallKit": "CallKit.framework — интеграция с вызовами (VoIP, телефон).",
    "CFNetwork": "CFNetwork.framework — низкоуровневый сетевой API на основе Core Foundation.",
    "Combine": "Combine.framework — реактивное программирование, асинхронные потоки событий.",
    "Contacts": "Contacts.framework — работа с контактами пользователя.",
    "ContactsUI": "ContactsUI.framework — готовый интерфейс выбора и отображения контактов.",
    "CoreData": "CoreData.framework — управление объектными графами и постоянным хранилищем.",
    "CoreFoundation": "CoreFoundation.framework — фундамент всех системных фреймворков Apple. Базовые типы данных, управление памятью.",
    "CoreGraphics": "CoreGraphics.framework — 2D-графический движок (Quartz 2D).",
    "CoreHaptics": "CoreHaptics.framework — управление тактильной обратной связью.",
    "CoreImage": "CoreImage.framework — обработка изображений в реальном времени, фильтры, распознавание лиц.",
    "CoreLocation": "CoreLocation.framework — геолокационные сервисы: GPS, геокодирование, мониторинг регионов.",
    "CoreMedia": "CoreMedia.framework — низкоуровневый мультимедийный API, управление потоками аудио/видео.",
    "CoreMotion": "CoreMotion.framework — обработка данных с акселерометра, гироскопа, шагомера.",
    "CoreNFC": "CoreNFC.framework — чтение NFC-меток.",
    "CoreServices": "CoreServices.framework — вспомогательные сервисы: метаданные (Spotlight), управление файлами.",
    "CoreTelephony": "CoreTelephony.framework — информация о сотовой сети и операторе.",
    "CoreText": "CoreText.framework — низкоуровневая система верстки текста и рендеринга шрифтов.",
    "CoreVideo": "CoreVideo.framework — высокопроизводительные видеобуферы, работа с видео в реальном времени.",
    "CoreAudioKit": "CoreAudioKit.framework — управление аудиоустройствами (панели настройки, AUAudioUnit).",
    "CoreMIDI": "CoreMIDI.framework — работа с MIDI-инструментами и устройствами.",
    "CoreML": "CoreML.framework — машинное обучение на устройстве (вывод моделей).",
    "CryptoKit": "CryptoKit.framework — криптографические операции на Swift (хэши, шифрование, подписи).",
    "DeveloperToolsSupport": "DeveloperToolsSupport.framework — поддержка инструментов разработчика (Live Preview и др.).",
    "DeviceCheck": "DeviceCheck.framework — проверка безопасности устройства и снижение злоупотреблений.",
    "DeviceActivity": "DeviceActivity.framework — мониторинг использования устройства (Screen Time).",
    "EventKit": "EventKit.framework — работа с календарём и событиями.",
    "FamilyControls": "FamilyControls.framework — управление родительским контролем.",
    "Foundation": "Foundation.framework — основная библиотека Objective-C/Swift для работы с объектами, коллекциями, файловой системой.",
    "GameController": "GameController.framework — поддержка игровых контроллеров (геймпадов, джойстиков).",
    "GameplayKit": "GameplayKit.framework — игровая логика, AI, система принятия решений.",
    "ImageIO": "ImageIO.framework — чтение и запись растровых изображений, метаданных EXIF, IPTC.",
    "Intents": "Intents.framework — интеграция с Siri и предложениями.",
    "JavaScriptCore": "JavaScriptCore.framework — движок JavaScript, используемый WebKit.",
    "LocalAuthentication": "LocalAuthentication.framework — биометрическая аутентификация (Touch ID, Face ID).",
    "ManagedSettings": "ManagedSettings.framework — управление настройками устройства в рамках семейного доступа.",
    "ManagedSettingsUI": "ManagedSettingsUI.framework — интерфейс для настройки семейного доступа.",
    "MapKit": "MapKit.framework — встраиваемые карты, геокодирование, аннотации, 3D-сцены.",
    "MarketplaceKit": "MarketplaceKit.framework — взаимодействие с альтернативными маркетплейсами приложений.",
    "MediaPlayer": "MediaPlayer.framework — воспроизведение мультимедиа, управление удалённым управлением.",
    "MessageUI": "MessageUI.framework — отправка электронной почты и SMS из приложения.",
    "Metal": "Metal.framework — низкоуровневый графический и вычислительный API с высокой производительностью.",
    "MetalKit": "MetalKit.framework — интеграция Metal с UIKit и другими фреймворками.",
    "MetricKit": "MetricKit.framework — сбор метрик производительности и энергопотребления.",
    "NaturalLanguage": "NaturalLanguage.framework — обработка естественного языка (токенизация, тегирование).",
    "Network": "Network.framework — современный сетевой фреймворк Apple (асинхронные соединения, TLS, UDP).",
    "OpenGLES": "OpenGLES.framework — OpenGL ES для встраиваемых систем (графика).",
    "PDFKit": "PDFKit.framework — отображение, создание, аннотирование PDF-документов.",
    "PencilKit": "PencilKit.framework — работа с Apple Pencil (рисование, рукописный ввод).",
    "Photos": "Photos.framework — доступ к медиатеке пользователя (фотографии, видео), редактирование.",
    "QuartzCore": "QuartzCore.framework — Core Animation: высокопроизводительная анимация слоев.",
    "SafariServices": "SafariServices.framework — встраиваемый браузер SFSafariViewController, менеджер паролей.",
    "Security": "Security.framework — криптография, управление сертификатами, keychain.",
    "Social": "Social.framework — интеграция с социальными сетями (Facebook, Twitter, Sina Weibo).",
    "Speech": "Speech.framework — распознавание и синтез речи.",
    "StoreKit": "StoreKit.framework — встроенные покупки и взаимодействие с App Store.",
    "SwiftUI": "SwiftUI.framework — современный декларативный фреймворк для построения UI.",
    "SystemConfiguration": "SystemConfiguration.framework — управление сетевыми конфигурациями, мониторинг состояния сети.",
    "UIKit": "UIKit.framework — основной фреймворк для построения интерфейсов iOS/tvOS.",
    "UserNotifications": "UserNotifications.framework — отправка и обработка локальных и удаленных уведомлений.",
    "Vision": "Vision.framework — компьютерное зрение: распознавание лиц, текста, штрихкодов, объектов.",
    "WatchConnectivity": "WatchConnectivity.framework — взаимодействие с Apple Watch.",
    "WebKit": "WebKit.framework — движок браузера WebKit: отображение веб-контента, поддержка JavaScript, взаимодействие с JS.",
    "WidgetKit": "WidgetKit.framework — создание виджетов для домашнего экрана iOS/macOS.",
    "ActivityKit": "ActivityKit.framework — Live Activities и Dynamic Island.",
    "AppTrackingTransparency": "AppTrackingTransparency.framework — запрос разрешения на отслеживание пользователя.",
    "AuthenticationServices": "AuthenticationServices.framework — вход через Apple ID, Sign in with Apple.",
    "AdAttributionKit": "AdAttributionKit.framework — атрибуция рекламных кампаний и измерение эффективности.",
    "Accelerate": "Accelerate.framework — высокопроизводительные численные вычисления, линейная алгебра, обработка сигналов.",
    "<self>": "Собственный исполняемый модуль (само приложение).",
    "_AdAttributionKit_StoreKit": "Внутренний символ, связывающий AdAttributionKit и StoreKit.",
    "_AVKit_SwiftUI": "Внутренний символ, связывающий AVKit и SwiftUI.",
    "_StoreKit_SwiftUI": "Внутренний символ, связывающий StoreKit и SwiftUI.",
}

# Объединение всех словарей
MACOS_MODULES = {}
for d in (_MACOS_CORE, _MACOS_DISPATCH, _MACOS_FOUNDATION, _MACOS_NETWORK,
          _MACOS_DATABASE, _MACOS_SWIFT, _MACOS_CRYPTO, _MACOS_EXPAT,
          _MACOS_FONTCONFIG, _MACOS_FRAMEWORKS):
    MACOS_MODULES.update(d)