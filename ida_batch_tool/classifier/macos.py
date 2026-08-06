"""Словари для macOS / iOS модулей.

Правила поддержки словарей:
1. Каждый модуль присутствует ровно в одной группе (без дубликатов).
2. Группы соответствуют реальным подсистемам Apple (Darwin, Cocoa, 
   Core OS, Media, Graphics, и т.д.)
3. Описания — на русском, подробные, технически точные.
4. Модули представлены либо как .dylib (нативные библиотеки), либо как
   .framework (фреймворки Apple).
"""

# ═══════════════════════════════════════════════════════════════════════════
# 1. SYSTEM CORE — фундаментальные библиотеки Darwin/BSD
# ═══════════════════════════════════════════════════════════════════════════

_SYSTEM_CORE = {
    "libSystem.dylib": (
        "Apple System Library — фундаментальная библиотека Darwin (macOS/iOS). "
        "Включает libc (стандартная C), libm (математика), libpthread (потоки), "
        "libdl (динамическая загрузка), libinfo (сетевая информация), libdbm."
    ),
    "libSystem.B.dylib": (
        "Apple System Library версии B — предыдущая мажорная версия libSystem. "
        "Обеспечивает обратную совместимость со старыми приложениями."
    ),
    "libsystem_c.dylib": (
        "Darwin libc — часть libSystem, содержащая стандартные функции C: "
        "printf, malloc, fopen, memcpy, strcpy. Является сердцем системной "
        "библиотеки Darwin."
    ),
    "libsystem_malloc.dylib": (
        "Darwin Malloc Library — реализация malloc/calloc/realloc/free. "
        "Содержит различные зоны распределения (nanomalloc, scalable_malloc) "
        "и включает проверки безопасности (magic cookies, guard pages)."
    ),
    "libsystem_pthread.dylib": (
        "Darwin POSIX Threads — реализация многопоточности по стандарту "
        "POSIX. Управление потоками (pthread_create), мьютексами, условными "
        "переменными, барьерами, rw-lock."
    ),
    "libsystem_kernel.dylib": (
        "Darwin Kernel Library — содержит функции-мосты к ядру XNU: "
        "syscall(), mach_msg(), thread_switch(), semaphore_wait_signal(). "
        "Проксирует системные вызовы через Mach IPC."
    ),
    "libsystem_blocks.dylib": (
        "Darwin Blocks Runtime — реализация языка Blocks (closures) "
        "для C/Objective-C. Управление памятью для Block-объектов, "
        "копирование на стеке и в куче."
    ),
    "libsystem_platform.dylib": (
        "Darwin Platform Library — платформенно-специфичные функции: "
        "OSAtomicBarrier, OSAtomicAdd32, _OSSpinLockLock, os_fault_with_payload."
    ),
    "libsystem_notify.dylib": (
        "Darwin Notification Library — система уведомлений Darwin. "
        "Позволяет процессам подписываться на системные события "
        "(изменение файлов, состояние сети)."
    ),
    "libsystem_info.dylib": (
        "Darwin System Information — библиотека для получения информации "
        "о системе: сетевые интерфейсы, DNS, пользователи, группы. "
        "Реализует getaddrinfo(), getnameinfo(), getpwuid()."
    ),
    "libsystem_trace.dylib": (
        "Darwin Tracing Library — низкоуровневое трассирование (os_log, "
        "os_signpost). Используется для профилирования и диагностики."
    ),
    "libsystem_symptoms.dylib": (
        "Darwin Network Symptoms — библиотека для диагностики сетевых "
        "проблем: обнаружение потери пакетов, задержек, DNS-ошибок."
    ),
    "libsystem_featureflags.dylib": (
        "Darwin Feature Flags — библиотека для проверки системных "
        "флагов функций (A/B тестирование, rollout новых возможностей ОС)."
    ),
    "libsystem_dnssd.dylib": (
        "DNS Service Discovery (Bonjour) — реализация протоколов mDNS "
        "и DNS-SD (Bonjour). Используется для обнаружения служб "
        "в локальной сети: AirPrint, AirPlay, iTunes Sharing."
    ),
    "libxpc.dylib": (
        "XPC Library — система межпроцессного взаимодействия (IPC) "
        "в macOS/iOS. Асинхронные сообщения между процессами, "
        "управление сервисами XPC. Замена старых механизмов IPC."
    ),
    "libc++.1.dylib": (
        "Apple C++ Standard Library (libc++) — реализация стандартной "
        "библиотеки C++ от LLVM. Содержит STL, iostream, контейнеры."
    ),
    "libc++abi.dylib": (
        "Apple C++ ABI Library — поддержка ABI для libc++: обработка "
        "исключений (C++ ABI), RTTI (dynamic_cast, typeid)."
    ),
    "libobjc.A.dylib": (
        "Objective-C Runtime — среда выполнения языка Objective-C. "
        "Фундамент всех Cocoa/Cocoa Touch приложений. Реализует "
        "динамическую диспетчеризацию, KVO, ARC (automatic reference counting)."
    ),
    "libdispatch.dylib": (
        "Grand Central Dispatch (GCD) — библиотека для параллельных "
        "вычислений: диспетчерские очереди (dispatch_queue), группы, "
        "семафоры, блокировки. Основа async-программирования на Apple."
    ),
    "libcompression.dylib": (
        "Compression Library — аппаратно ускоренное сжатие и распаковка "
        "данных. Поддержка LZFSE, LZ4, ZLIB, LZMA, LZBITMAP."
    ),
    "libresolv.9.dylib": (
        "DNS Resolver Library — функции для разрешения доменных имён "
        "(DNS). Реализует res_query(), res_search(), gethostbyname()."
    ),
    "libicucore.A.dylib": (
        "ICU (International Components for Unicode) — международная "
        "поддержка: сортировка, форматирование дат/чисел/валют, "
        "регулярные выражения, нормализация Unicode."
    ),
    "libicucore.dylib": (
        "ICU API Compatibility — версия ICU для обратной совместимости."
    ),
    "libiconv.dylib": (
        "Libiconv — преобразование между различными кодировками текста "
        "(UTF-8, UTF-16, Latin1, KOI8, CP1251)."
    ),
    "libz.1.dylib": (
        "Zlib Compression Library — сжатие/распаковка DEFLATE. "
        "Используется для gzip, PNG, HTTP сжатия."
    ),
    "libbz2.dylib": (
        "Bzip2 Compression Library — алгоритм сжатия Burrows-Wheeler "
        "(bzip2). Более высокая степень сжатия чем zlib."
    ),
    "libxml2.2.dylib": (
        "Libxml2 — XML-парсер Apple. Предоставляет функции для разбора, "
        "валидации и манипуляции XML-документами."
    ),
    "libexpat.1.dylib": (
        "Expat XML Parser (macOS) — потоковый парсер XML. Быстрый, "
        "не требующий валидации, используется WebKit и другими."
    ),
    "libcups.dylib": (
        "CUPS (Common Unix Printing System) — библиотека для "
        "взаимодействия с системой печати Apple."
    ),
    "libxslt.1.dylib": (
        "Libxslt — XSLT-процессор для трансформации XML-документов "
        "в HTML, текст и другие форматы."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 2. SECURITY & CRYPTO — криптография, аутентификация, сертификаты
# ═══════════════════════════════════════════════════════════════════════════

_SECURITY_CRYPTO = {
    "libcrypto.44.dylib": (
        "LibreSSL/OpenSSL Crypto Library — криптографическая библиотека "
        "Apple. Шифрование (AES, ChaCha20), хеширование (SHA-2/3, BLAKE2), "
        "цифровые подписи (RSA, ECDSA, Ed25519)."
    ),
    "libssl.46.dylib": (
        "LibreSSL/OpenSSL SSL/TLS Library — реализация протоколов "
        "SSL/TLS для защищённых соединений. Используется многими "
        "сетевыми приложениями."
    ),
    "libcrypto.dylib": (
        "Apple Crypto Library (совместимость) — ссылка на текущую "
        "реализацию криптобиблиотеки Apple."
    ),
    "libcommonCrypto.dylib": (
        "CommonCrypto — высокоуровневый криптографический API Apple. "
        "Предоставляет унифицированный интерфейс для хеширования "
        "(CC_SHA256), шифрования (CCCrypt), HMAC."
    ),
    "libboringssl.dylib": (
        "BoringSSL — форк OpenSSL от Google, используемый Apple "
        "в некоторых компонентах (WebKit, Networking)."
    ),
    "Security": (
        "Security.framework — центральный фреймворк безопасности Apple. "
        "Управление сертификатами X.509, keychain (связка ключей), "
        "цифровые подписи, доверенные корневые сертификаты."
    ),
    "SecurityInterface": (
        "SecurityInterface.framework — пользовательский интерфейс "
        "для Security: диалоги импорта сертификатов, выбор "
        "удостоверяющего центра, управление keychain."
    ),
    "CryptoKit": (
        "CryptoKit.framework — криптографическая библиотека на Swift. "
        "Хеширование (SHA-512), шифрование (ChaCha20-Poly1305, AES-GCM), "
        "цифровые подписи (Curve25519, P-521)."
    ),
    "LocalAuthentication": (
        "LocalAuthentication.framework — биометрическая аутентификация "
        "(Touch ID, Face ID). Запрос аутентификации через LAContext, "
        "проверка наличия биометрии на устройстве."
    ),
    "DeviceCheck": (
        "DeviceCheck.framework — проверка безопасности устройства. "
        "Позволяет разработчикам верифицировать, что приложение "
        "запущено на подлинном устройстве Apple."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 3. NETWORK & WEB — сетевые протоколы, браузер, DNS (Darwin + Apple)
# ═══════════════════════════════════════════════════════════════════════════

_NETWORK_WEB = {
    "libnetwork.dylib": (
        "Apple Network Library — современная сетевая библиотека Apple. "
        "Асинхронные соединения с TLS 1.3, мониторинг сети (NWPathMonitor), "
        "Bonjour Discovery, WebSocket."
    ),
    "libcurl.dylib": (
        "Curl Library (Apple) — работа с URL через HTTP/HTTPS/FTP. "
        "Используется в системных компонентах и утилитах."
    ),
    "CFNetwork": (
        "CFNetwork.framework — низкоуровневый сетевой API на основе "
        "Core Foundation. HTTP/HTTPS, FTP, BSD Sockets, прокси, "
        "аутентификация, кэширование."
    ),
    "Network": (
        "Network.framework — современный сетевой фреймворк Apple. "
        "Асинхронные UDP/TCP/TLS соединения, WebSocket, Bonjour, "
        "мониторинг состояния сети. Замена CFNetwork."
    ),
    "SystemConfiguration": (
        "SystemConfiguration.framework — управление сетевыми "
        "конфигурациями: DHCP, VPN, прокси, DNS, мониторинг "
        "изменения состояния сети (SCNetworkReachability)."
    ),
    "WebKit": (
        "WebKit.framework — движок браузера WebKit (Safari). "
        "Отображение веб-контента (WKWebView), поддержка JavaScript "
        "через JavaScriptCore, взаимодействие с web-страницами."
    ),
    "JavaScriptCore": (
        "JavaScriptCore.framework — высокопроизводительный движок "
        "JavaScript с JIT-компиляцией. Используется в Safari, "
        "WebKit, и нативно (JSContext)."
    ),
    "SafariServices": (
        "SafariServices.framework — встраиваемый браузер "
        "SFSafariViewController, менеджер паролей, расширения "
        "Safari."
    ),
    "NetworkExtension": (
        "NetworkExtension.framework — управление сетевыми "
        "расширениями: VPN (приватные/защищённые туннели), "
        "NEDNSProxy, NEFilter (контент-фильтрация)."
    ),
    "MultipeerConnectivity": (
        "MultipeerConnectivity.framework — пиринговая связь "
        "между устройствами Apple через Wi-Fi и Bluetooth. "
        "Используется в AirDrop, игровых приложениях."
    ),
    "CoreWLAN": (
        "CoreWLAN.framework — управление Wi-Fi интерфейсами "
        "macOS: сканирование сетей, подключение, управление "
        "профилями, получение статистики."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 4. UI & GRAPHICS — отображение, анимация, Metal, текст, шрифты
# ═══════════════════════════════════════════════════════════════════════════

_UI_GRAPHICS = {
    "CoreGraphics": (
        "CoreGraphics.framework — 2D-графический движок Apple (Quartz 2D). "
        "Рисование примитивов, работа с путями, трансформации, "
        "управление контекстами устройства (CGContext)."
    ),
    "CoreText": (
        "CoreText.framework — низкоуровневая система вёрстки текста "
        "и рендеринга шрифтов. CTLine, CTFrame, работа "
        "с атрибутированными строками."
    ),
    "QuartzCore": (
        "QuartzCore.framework — Core Animation: высокопроизводительная "
        "анимация слоёв CALayer. Анимации свойств, ключевые кадры, "
        "3D-трансформации слоёв."
    ),
    "Metal": (
        "Metal.framework — низкоуровневый графический и вычислительный "
        "API Apple. Прямой доступ к GPU, минимальные накладные расходы, "
        "продвинутое управление памятью GPU."
    ),
    "MetalKit": (
        "MetalKit.framework — интеграция Metal с Cocoa: управление "
        "Metal-девайсами, текстуры (MTKTextureLoader), работа "
        "с Metal-вью (MTKView)."
    ),
    "MetalPerformanceShaders": (
        "MetalPerformanceShaders.framework — оптимизированные "
        "графические и вычислительные шейдеры для Metal. "
        "Размытие, свёртки, нейросетевые операции (MPSNN)."
    ),
    "MetalPerformanceShadersGraph": (
        "MetalPerformanceShadersGraph.framework — графовые "
        "вычисления на Metal для ML-моделей."
    ),
    "MetalFX": (
        "MetalFX.framework — технология масштабирования разрешения "
        "(FSR, Temporal Anti-Aliasing Upscaling) для Metal-игр."
    ),
    "AppKit": (
        "AppKit.framework — основной фреймворк для построения "
        "интерфейсов macOS (десктоп). NSApplication, NSWindow, "
        "NSView, NSMenu, NSTableView."
    ),
    "UIKit": (
        "UIKit.framework — основной фреймворк для построения "
        "интерфейсов iOS/tvOS: UIApplication, UIView, UIViewController, "
        "анимации, жесты, работа с экраном."
    ),
    "SwiftUI": (
        "SwiftUI.framework — современный декларативный фреймворк "
        "для построения UI на Swift (iOS 13+, macOS 10.15+)."
    ),
    "SwiftUICore": (
        "SwiftUICore — ядро SwiftUI: базовые типы, протоколы "
        "(View, Scene), property wrappers, система вёрстки."
    ),
    "PencilKit": (
        "PencilKit.framework — работа с Apple Pencil: распознавание "
        "рукописного ввода, рисование пером, палитры инструментов."
    ),
    "SceneKit": (
        "SceneKit.framework — высокоуровневый 3D-движок Apple. "
        "Сцены, материалы, освещение, анимация, физика."
    ),
    "SpriteKit": (
        "SpriteKit.framework — 2D-игровой движок Apple. Спрайты, "
        "физика частиц, анимация скелета, warp-деформация."
    ),
    "libfontconfig.1.dylib": (
        "Fontconfig — конфигурация и поиск шрифтов. Используется "
        "для совместимости с кроссплатформенными приложениями."
    ),
    "ColorSync": (
        "ColorSync.framework — управление цветовыми профилями "
        "(ICC) в macOS. Калибровка монитора, конвертация "
        "цветовых пространств."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 5. MULTIMEDIA — аудио, видео, захват, MIDI
# ═══════════════════════════════════════════════════════════════════════════

_MULTIMEDIA = {
    "CoreMedia": (
        "CoreMedia.framework — низкоуровневый мультимедийный API. "
        "Управление медиа-потоками (CMTime, CMSampleBuffer, "
        "CMClock), синхронизация аудио/видео."
    ),
    "CoreVideo": (
        "CoreVideo.framework — высокопроизводительные видеобуферы "
        "(CVPixelBuffer, CVImageBuffer, CVOpenGLTexture). Работа "
        "с видео в реальном времени."
    ),
    "CoreAudio": (
        "CoreAudio.framework — основная аудиобиблиотека Apple. "
        "Низкоуровневый доступ к аудиоустройствам, управление "
        "потоками, Audio Units, MIDI."
    ),
    "AudioToolbox": (
        "AudioToolbox.framework — низкоуровневый аудио API: "
        "воспроизведение звука (AudioQueue), запись, системные "
        "звуки (AudioServicesPlaySystemSound), AU AudioUnit."
    ),
    "AudioUnit": (
        "AudioUnit.framework — аудио-обработчики в реальном "
        "времени: эквалайзер, реверберация, Audio Unit "
        "Host (хост для VST/AU плагинов)."
    ),
    "AVFoundation": (
        "AVFoundation.framework — ключевой фреймворк для работы "
        "с аудио и видео. Захват (камера, микрофон), воспроизведение, "
        "редактирование, экспорт."
    ),
    "AVKit": (
        "AVKit.framework — высокоуровневый фреймворк для "
        "воспроизведения видео с готовым UI (AVPlayerViewController)."
    ),
    "AVFAudio": (
        "AVFAudio.framework — высокоуровневый аудио API: "
        "воспроизведение, запись, синтез речи (AVSpeechSynthesizer)."
    ),
    "ImageIO": (
        "ImageIO.framework — чтение и запись растровых изображений. "
        "Поддерживает JPEG, PNG, TIFF, HEIF, RAW. Доступ "
        "к метаданным EXIF, IPTC, XMP."
    ),
    "CoreImage": (
        "CoreImage.framework — обработка изображений в реальном "
        "времени на GPU. Фильтры (размытие, коррекция цвета, "
        "скачок лица), распознавание лиц (CIDetector)."
    ),
    "MediaPlayer": (
        "MediaPlayer.framework — воспроизведение мультимедиа, "
        "интеграция с системными элементами управления (Now Playing)."
    ),
    "Speech": (
        "Speech.framework — распознавание речи (SFSpeechRecognizer) "
        "и синтез речи из текста (AVSpeechSynthesizer)."
    ),
    "CoreMIDI": (
        "CoreMIDI.framework — работа с MIDI-инструментами: "
        "отправка/получение MIDI-сообщений, управление MIDI-клавиатурами."
    ),
    "CoreAudioKit": (
        "CoreAudioKit.framework — пользовательский интерфейс "
        "для настройки аудиоустройств и AUAudioUnit."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 6. DATA, STORAGE & SERVICES — хранение данных, облачные сервисы
# ═══════════════════════════════════════════════════════════════════════════

_DATA_STORAGE = {
    "libsqlite3.dylib": (
        "SQLite Database Engine — встраиваемая реляционная база "
        "данных. Не требует сервера, используется всеми системными "
        "и пользовательскими приложениями на Apple."
    ),
    "CoreData": (
        "CoreData.framework — управление объектными графами "
        "и постоянным хранилищем в приложениях Apple. Работает "
        "поверх SQLite, XML, Binary."
    ),
    "CoreServices": (
        "CoreServices.framework — вспомогательные сервисы: "
        "метаданные (Spotlight), управление файлами (FSEvents), "
        "Carbon Core, словари."
    ),
    "CloudKit": (
        "CloudKit.framework — облачное хранилище iCloud. "
        "Синхронизация структурированных данных, документов, "
        "ассетов между устройствами пользователя."
    ),
    "FileProvider": (
        "FileProvider.framework — поддержка облачных файловых "
        "провайдеров (iCloud Drive, Dropbox, Google Drive)."
    ),
    "FileProviderUI": (
        "FileProviderUI.framework — пользовательский интерфейс "
        "для File Provider (действия, контекстные меню)."
    ),
    "PDFKit": (
        "PDFKit.framework — отображение, создание, аннотирование "
        "PDF-документов, работа с формами."
    ),
    "QuickLook": (
        "QuickLook.framework — быстрый просмотр файлов (Preview) "
        "без открытия приложения."
    ),
    "QuickLookThumbnailing": (
        "QuickLookThumbnailing.framework — генерация миниатюр "
        "(thumbnail) для произвольных типов файлов."
    ),
    "DiskArbitration": (
        "DiskArbitration.framework — управление монтированием "
        "и размонтированием дисков. Уведомления о подключении "
        "USB/CD/DVD."
    ),
    "IOKit": (
        "IOKit.framework — доступ к драйверам устройств в режиме "
        "ядра. Управление USB, Bluetooth, Thunderbolt, SCSI. "
        "Ключевой фреймворк для оборудования macOS."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 7. MACHINE LEARNING & VISION — машинное обучение и компьютерное зрение
# ═══════════════════════════════════════════════════════════════════════════

_ML_VISION = {
    "CoreML": (
        "CoreML.framework — среда выполнения моделей машинного "
        "обучения на устройстве. Оптимизация под Apple Neural Engine, "
        "GPU, CPU. Поддержка моделей PyTorch, TensorFlow, ONNX."
    ),
    "Vision": (
        "Vision.framework — компьютерное зрение: распознавание лиц, "
        "обнаружение лиц и контуров, распознавание текста (OCR), "
        "анализ штрихкодов, отслеживание объектов."
    ),
    "NaturalLanguage": (
        "NaturalLanguage.framework — обработка естественного языка. "
        "Токенизация, определение языка, лемматизация, тегирование "
        "частей речи, анализ тональности."
    ),
    "CreateML": (
        "CreateML.framework — обучение моделей машинного обучения "
        "на устройстве: классификация изображений, текста, табулярных "
        "данных, звука."
    ),
    "CreateMLComponents": (
        "CreateMLComponents.framework — компоненты для конструирования "
        "пайплайнов машинного обучения в Create ML."
    ),
    "SoundAnalysis": (
        "SoundAnalysis.framework — анализ звука: классификация "
        "звуковых событий (лай собаки, сирена, музыка, дверь)."
    ),
    "SensorKit": (
        "SensorKit.framework — доступ к датчикам для медицинских "
        "и фитнес-исследований: акселерометр, гироскоп, шаги."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 8. SYSTEM SERVICES — IOKit, OpenDirectory, Kerberos, ServiceManagement
# ═══════════════════════════════════════════════════════════════════════════

_SYSTEM_SERVICES = {
    "ServiceManagement": (
        "ServiceManagement.framework — управление системными "
        "службами macOS: запуск входа (launchd), сервисы "
        "доступа (Accessibility, Privacy)."
    ),
    "SystemExtensions": (
        "SystemExtensions.framework — системные расширения macOS. "
        "Замена kext (драйверов ядра) безопасными пользовательскими "
        "расширениями: сетевые фильтры, endpoint security."
    ),
    "EndpointSecurity": (
        "EndpointSecurity.framework — мониторинг событий "
        "безопасности: запуск процессов, загрузка библиотек, "
        "файловые операции. Альтернатива KAuth."
    ),
    "OpenDirectory": (
        "OpenDirectory.framework — управление учётными записями "
        "и политиками доступа macOS. Интеграция с Active Directory, "
        "LDAP, локальными пользователями."
    ),
    "GSS": (
        "GSS.framework — Generic Security Services API. Единый "
        "интерфейс для аутентификации через Kerberos, NTLM, "
        "SPNEGO. Интеграция с Active Directory."
    ),
    "Kerberos": (
        "Kerberos.framework — реализация протокола Kerberos "
        "в macOS. Получение и проверка билетов (tickets), "
        "keytab-файлы, kinit/klist."
    ),
    "DirectoryService": (
        "DirectoryService.framework — справочные службы macOS: "
        "локальные пользователи и группы, LDAP, Active Directory, "
        "NIS. (Устаревает в пользу OpenDirectory.)"
    ),
    "os_log": (
        "os_log (OSLog.framework) — система логирования macOS/iOS. "
        "Структурированные логи, уровни (default, info, debug, "
        "error, fault), сбор для диагностики."
    ),
    "CoreFoundation": (
        "CoreFoundation.framework — фундамент всех системных "
        "фреймворков Apple. Классовые типы CFString, CFArray, "
        "CFRunLoop, CFStream, управление памятью (CFRetain/Release)."
    ),
    "Foundation": (
        "Foundation.framework — основная библиотека Objective-C/Swift. "
        "Строки (NSString), коллекции (NSArray, NSDictionary), "
        "даты, файловая система, сеть, сериализация (JSON, XML)."
    ),
    "IOBluetooth": (
        "IOBluetooth.framework — работа с Bluetooth в macOS: "
        "сканирование устройств, подключение, управление "
        "профилями (A2DP, HID, PAN)."
    ),
    "CoreBluetooth": (
        "CoreBluetooth.framework — Bluetooth Low Energy (BLE) "
        "на iOS/macOS. Управление BLE-периферией, сервисы, "
        "характеристики, уведомления."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 9. DEVELOPER TOOLS & DIAGNOSTICS — профилирование, метрики
# ═══════════════════════════════════════════════════════════════════════════

_DEVELOPER_TOOLS = {
    "MetricKit": (
        "MetricKit.framework — сбор метрик производительности "
        "и энергопотребления: CPU, память, диск, анимация, "
        "запуск приложения."
    ),
    "DeveloperToolsSupport": (
        "DeveloperToolsSupport.framework — поддержка инструментов "
        "разработчика: Live Preview в Xcode, SwiftUI Previews."
    ),
    "BackgroundTasks": (
        "BackgroundTasks.framework — планирование фоновых задач "
        "в iOS: обработка данных, обновление контента."
    ),
    "OSLog": (
        "OSLog.framework — система структурированного логирования "
        "(ос_log) и динамического трассирования (os_signpost)."
    ),
    "InstrumentsKit": (
        "InstrumentsKit.framework — интеграция с Xcode Instruments "
        "для профилирования приложений."
    ),
    "UniformTypeIdentifiers": (
        "UniformTypeIdentifiers.framework — работа с типами файлов "
        "(UTType, MIME), совместимость с файловыми ассоциациями."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 10. HIGH-LEVEL APP SERVICES — встроенные покупки, уведомления, Siri,
#     карты, календари, контакты, локация, NFC, управление устройством
# ═══════════════════════════════════════════════════════════════════════════

_APP_SERVICES = {
    "StoreKit": (
        "StoreKit.framework — встроенные покупки, подписки, "
        "взаимодействие с App Store."
    ),
    "StoreKit2": (
        "StoreKit2.framework — новая версия StoreKit с улучшенной "
        "производительностью, async/await API."
    ),
    "AdSupport": (
        "AdSupport.framework — функциональность для рекламы, "
        "идентификатор рекламы (IDFA)."
    ),
    "AppTrackingTransparency": (
        "AppTrackingTransparency.framework — запрос разрешения "
        "на отслеживание пользователя (ATTrackingManager)."
    ),
    "AdAttributionKit": (
        "AdAttributionKit.framework — атрибуция рекламных "
        "кампаний, измерение эффективности (SKAdNetwork)."
    ),
    "Intents": (
        "Intents.framework — интеграция с Siri: обрабатывает "
        "пользовательские намерения (Intents) и предоставляет "
        "их результаты."
    ),
    "IntentsUI": (
        "IntentsUI.framework — пользовательский интерфейс "
        "для настройки интентов Siri в приложениях."
    ),
    "UserNotifications": (
        "UserNotifications.framework — отправка и обработка "
        "локальных и удалённых уведомлений."
    ),
    "UserNotificationsUI": (
        "UserNotificationsUI.framework — кастомизация "
        "пользовательского интерфейса уведомлений."
    ),
    "WidgetKit": (
        "WidgetKit.framework — создание виджетов для домашнего "
        "экрана iOS/macOS (iOS 14+, macOS 11+)."
    ),
    "ActivityKit": (
        "ActivityKit.framework — Live Activities на Lock Screen "
        "и Dynamic Island (iOS 16.1+)."
    ),
    "WatchConnectivity": (
        "WatchConnectivity.framework — двусторонняя связь "
        "с Apple Watch: передача файлов, сообщений, контекстов."
    ),
    "WatchKit": (
        "WatchKit.framework — создание интерфейсов для Apple Watch."
    ),
    "GameController": (
        "GameController.framework — поддержка игровых контроллеров "
        "(геймпады Xbox, PlayStation, MFi)."
    ),
    "GameplayKit": (
        "GameplayKit.framework — игровая логика: AI (A* поиск, "
        "State Machines), система принятия решений, генерация "
        "случайных чисел."
    ),
    "CallKit": (
        "CallKit.framework — интеграция с вызовами: VoIP-звонки "
        "через системный интерфейс, Call Directory (блокировка)."
    ),
    "Contacts": (
        "Contacts.framework — программный доступ к адресной книге "
        "пользователя (CNContact, CNContactStore)."
    ),
    "ContactsUI": (
        "ContactsUI.framework — готовый UI для выбора, просмотра "
        "и редактирования контактов (CNContactPickerViewController)."
    ),
    "EventKit": (
        "EventKit.framework — работа с календарём: чтение/запись "
        "событий, напоминаний (EKEventStore)."
    ),
    "EventKitUI": (
        "EventKitUI.framework — UI для просмотра и создания "
        "календарных событий."
    ),
    "MapKit": (
        "MapKit.framework — встраиваемые карты Apple, геокодирование, "
        "аннотации, маршруты, 3D-сцены, ETA."
    ),
    "CoreLocation": (
        "CoreLocation.framework — геолокация: GPS, Wi-Fi positioning, "
        "геокодирование, мониторинг регионов, heading, beacon."
    ),
    "Photos": (
        "Photos.framework — доступ к медиатеке пользователя: "
        "изображения, видео, альбомы, редактирование (PHPhotoLibrary)."
    ),
    "PhotosUI": (
        "PhotosUI.framework — UI для выбора фотографий и видео "
        "(PHPickerViewController)."
    ),
    "CoreHaptics": (
        "CoreHaptics.framework — управление тактильной обратной "
        "связью (Haptic Engine на iPhone)."
    ),
    "CoreNFC": (
        "CoreNFC.framework — чтение NFC-меток (NDEF), FeliCa."
    ),
    "CoreTelephony": (
        "CoreTelephony.framework — информация о сотовой сети: "
        "оператор, сигнал, тип сети (4G/5G), состояние вызова."
    ),
    "CoreMotion": (
        "CoreMotion.framework — обработка данных с акселерометра, "
        "гироскопа, шагомера, магнитометра."
    ),
    "FamilyControls": (
        "FamilyControls.framework — управление родительским "
        "контролем: ограничение приложений, контента."
    ),
    "ManagedSettings": (
        "ManagedSettings.framework — управление настройками "
        "устройства в рамках семейного доступа."
    ),
    "ManagedSettingsUI": (
        "ManagedSettingsUI.framework — UI для настройки "
        "семейного доступа."
    ),
    "MarketplaceKit": (
        "MarketplaceKit.framework — взаимодействие с альтернативными "
        "маркетплейсами приложений (EU DMA)."
    ),
    "MessageUI": (
        "MessageUI.framework — отправка электронной почты "
        "и SMS из приложения (MFMailComposeViewController)."
    ),
    "AuthenticationServices": (
        "AuthenticationServices.framework — Sign in with Apple, "
        "ASWebAuthenticationSession (OAuth), Password Manager."
    ),
    "Combine": (
        "Combine.framework — реактивное программирование: "
        "Publisher, Subscriber, async event streams."
    ),
    "Accelerate": (
        "Accelerate.framework — высокопроизводительные численные "
        "вычисления: BLAS, LAPACK, vDSP (обработка сигналов), "
        "vImage (обработка изображений)."
    ),
    "PushKit": (
        "PushKit.framework — push-уведомления для VoIP "
        "и watchOS-приложений с фоновой обработкой."
    ),
    "PushToTalk": (
        "PushToTalk.framework — реализация Push-to-Talk "
        "(рация) для VoIP-приложений (iOS 16+)."
    ),
    "PassKit": (
        "PassKit.framework — Wallet: Apple Pay, билеты, "
        "купоны, пропуска (PKPass)."
    ),
    "SafetyKit": (
        "SafetyKit.framework — обнаружение аварий (Crash "
        "Detection) и падений на iPhone/Apple Watch."
    ),
    "ScreenTime": (
        "ScreenTime.framework — управление экранным временем, "
        "ограничения приложений, мониторинг использования."
    ),
    "ScreenCaptureKit": (
        "ScreenCaptureKit.framework — захват экрана с высоким "
        "разрешением и низкой задержкой (macOS 12+)."
    ),
    "ReplayKit": (
        "ReplayKit.framework — запись экрана и трансляция "
        "в реальном времени."
    ),
    "DeviceActivity": (
        "DeviceActivity.framework — мониторинг активности "
        "устройства: использование приложений, уведомления."
    ),
    "ClassKit": (
        "ClassKit.framework — интеграция образовательных "
        "приложений с Schoolwork (Apple School Manager)."
    ),
    "HealthKit": (
        "HealthKit.framework — доступ к данным здоровья: "
        "шаги, пульс, сон, питание (HKHealthStore)."
    ),
    "HomeKit": (
        "HomeKit.framework — управление умным домом: "
        "освещение, замки, термостаты, камеры."
    ),
    "Social": (
        "Social.framework — интеграция с социальными сетями "
        "(Facebook, Twitter, Sina Weibo, Tencent Weibo)."
    ),
    "TipKit": (
        "TipKit.framework — система подсказок для пользователей: "
        "контекстные советы по использованию приложения."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 11. SWIFT RUNTIME — библиотеки поддержки языка Swift
# ═══════════════════════════════════════════════════════════════════════════

_SWIFT_RUNTIME = {
    "libswiftCore.dylib": (
        "Среда выполнения языка Swift. Содержит базовые типы "
        "(Int, String, Array), управление памятью (ARC), "
        "протоколы и динамическую диспетчеризацию. Необходима "
        "для любого Swift-приложения."
    ),
    "libswiftFoundation.dylib": (
        "Мост между Swift и Foundation. Предоставляет удобные "
        "Swift-обёртки для классов NSObject, NSString, NSArray."
    ),
    "libswiftUIKit.dylib": (
        "Интерфейс Swift для UIKit. Позволяет использовать "
        "компоненты пользовательского интерфейса iOS/tvOS "
        "с нативной поддержкой Swift."
    ),
    "libswiftCoreFoundation.dylib": (
        "Swift-обёртка для CoreFoundation. Обеспечивает доступ "
        "к CFArray, CFDictionary, CFRunLoop с управлением памятью."
    ),
    "libswiftCoreGraphics.dylib": (
        "Swift-интерфейс для CoreGraphics. Работа с контекстами "
        "рисования, геометрическими структурами (CGPoint, CGRect)."
    ),
    "libswiftCoreMedia.dylib": (
        "Swift-обёртка для CoreMedia. API для работы с медиа-"
        "конвейерами, временными метками, медиа-буферами."
    ),
    "libswiftCoreNFC.dylib": (
        "Swift-интерфейс для CoreNFC. Взаимодействие с NFC-"
        "метками через Swift API."
    ),
    "libswiftDarwin.dylib": (
        "Мост к Darwin-подсистеме. Доступ к низкоуровневым "
        "системным вызовам (bsd/kernel) из Swift."
    ),
    "libswiftDispatch.dylib": (
        "Swift-обёртка для Grand Central Dispatch (GCD). "
        "Асинхронное программирование с очередями и семафорами."
    ),
    "libswiftObjectiveC.dylib": (
        "Взаимодействие Swift с Objective-C Runtime. Вызов "
        "Objective-C методов, KVO, селекторы."
    ),
    "libswiftQuartzCore.dylib": (
        "Swift-интерфейс для QuartzCore (Core Animation). "
        "Создание и управление анимацией слоёв CALayer."
    ),
    "libswiftUniformTypeIdentifiers.dylib": (
        "Swift-обёртка для UniformTypeIdentifiers. Работа "
        "с типами файлов и MIME-типами из Swift."
    ),
    "libswiftVision.dylib": (
        "Swift-интерфейс для Vision. Распознавание лиц, "
        "текста, объектов через Swift API."
    ),
    "libswift_Concurrency.dylib": (
        "Среда выполнения для конкурентности Swift. Поддержка "
        "async/await, Task, Actor, structured concurrency."
    ),
    "libswift_StringProcessing.dylib": (
        "Библиотека обработки строк Swift. Регулярные выражения, "
        "парсинг и трансформация текста."
    ),
    "libswiftIntents.dylib": (
        "Swift-обёртка для Intents. Интеграция с Siri "
        "и Shortcuts: голосовые команды, намерения."
    ),
    "libswiftos.dylib": (
        "Swift-интерфейс для os. Функции логирования (os_log), "
        "системные уведомления."
    ),
    "libswiftAVFoundation.dylib": (
        "Swift-обёртка для AVFoundation. Захват, воспроизведение "
        "и редактирование аудио/видео из Swift."
    ),
    "libswiftCoreAudio.dylib": (
        "Swift-интерфейс для CoreAudio. Взаимодействие "
        "с аудиоустройствами и потоками."
    ),
    "libswiftNaturalLanguage.dylib": (
        "Swift-обёртка для NaturalLanguage. Токенизация, "
        "определение языка, анализ тональности."
    ),
    "libswiftNetwork.dylib": (
        "Swift-интерфейс для Network.framework. Сетевые "
        "соединения с TLS, UDP, Bonjour."
    ),
    "libswiftObservation.dylib": (
        "Swift-обёртка для Observation. Реактивное отслеживание "
        "изменений свойств объектов (iOS 17+, macOS 14+)."
    ),
    "libswiftAppKit.dylib": (
        "Swift-интерфейс для AppKit на macOS."
    ),
    "libswiftCloudKit.dylib": (
        "Swift-обёртка для CloudKit: облачное хранение через iCloud."
    ),
    "libswiftCreateML.dylib": (
        "Swift-интерфейс для Create ML: обучение ML-моделей."
    ),
    "libswiftMapKit.dylib": (
        "Swift-обёртка для MapKit на macOS/iOS."
    ),
    "libswiftMetal.dylib": (
        "Swift-интерфейс для Metal: GPU-вычисления и графика."
    ),
    "libswiftSpriteKit.dylib": (
        "Swift-обёртка для SpriteKit: 2D-игры и анимации."
    ),
    "libswiftSceneKit.dylib": (
        "Swift-обёртка для SceneKit: 3D-контент."
    ),
    "libswiftWidgetKit.dylib": (
        "Swift-обёртка для WidgetKit: создание виджетов."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# ОБЪЕДИНЕНИЕ ВСЕХ macOS-СЛОВАРЕЙ
# ═══════════════════════════════════════════════════════════════════════════

MACOS_MODULES = {}
for group in (
    _SYSTEM_CORE,
    _SECURITY_CRYPTO,
    _NETWORK_WEB,
    _UI_GRAPHICS,
    _MULTIMEDIA,
    _DATA_STORAGE,
    _ML_VISION,
    _SYSTEM_SERVICES,
    _DEVELOPER_TOOLS,
    _APP_SERVICES,
    _SWIFT_RUNTIME,
):
    MACOS_MODULES.update(group)