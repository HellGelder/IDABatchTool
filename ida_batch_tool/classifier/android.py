"""Словари для Android-модулей.

Правила поддержки словарей:
1. Каждый модуль присутствует ровно в одной группе (без дубликатов).
2. Группы соответствуют структуре AOSP (Android Open Source Project),
   Android NDK и документации Android.
3. Описания — на русском, подробные, технически точные.
"""

# ═══════════════════════════════════════════════════════════════════════════
# 1. CORE — Bionic libc и базовые системные библиотеки Android
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_CORE = {
    "libc.so": (
        "Bionic libc — реализация стандартной библиотеки C "
        "для Android. Включает функции стандарта C11 (printf, "
        "malloc, fopen), системные вызовы Linux. В отличие от "
        "glibc, включает pthread, dl, и real-time-расширения "
        "без отдельных библиотек."
    ),
    "libm.so": (
        "Bionic libm — математическая библиотека Android. "
        "Реализует математические функции с плавающей точкой "
        "(sin, cos, sqrt, log, pow). Автоматически линкуется "
        "сборочной системой вместе с libc."
    ),
    "libdl.so": (
        "Bionic libdl — поддержка динамической загрузки "
        "библиотек (dlopen, dlsym, dlclose). Необходима для "
        "плагинов и интерпретируемых языков на Android."
    ),
    "libstdc++.so": (
        "GNU libstdc++ для Android — реализация стандартной "
        "библиотеки C++ для Android. Предоставляет STL "
        "и потоки ввода-вывода для C++ приложений."
    ),
    "libc++_shared.so": (
        "LLVM libc++ (shared) — современная реализация "
        "стандартной библиотеки C++ на базе Clang/LLVM. "
        "Используется по умолчанию в Android NDK для новых "
        "проектов."
    ),
    "liblog.so": (
        "Android Logging Library — система логирования Android "
        "logcat. Предоставляет API для записи сообщений "
        "в системный журнал. Используется всеми компонентами "
        "системы, от ядра до приложений."
    ),
    "libcutils.so": (
        "Android C Utilities — набор утилит на C для системного "
        "программирования: работа с сокетами, атомарные "
        "операции, управление процессами, конфигурация."
    ),
    "libutils.so": (
        "Android C++ Utilities — вспомогательные классы C++: "
        "работа со строками (String8, String16), потоками "
        "(Thread, Mutex, Condition), IPC (Binder), логирование."
    ),
    "libbase.so": (
        "Android Base Library — библиотека базовых функций "
        "и классов C++ (strings, logging, properties, "
        "filesystem). Используется во всех нативных "
        "компонентах Android."
    ),
    "libprocinfo.so": (
        "Android Process Info Library — библиотека для "
        "получения информации о процессах Linux: PID, "
        "командная строка, состояние, использование памяти."
    ),
    "libprocessgroup.so": (
        "Android Process Group Library — библиотека для "
        "управления группами процессов (cgroups v1/v2). "
        "Ограничение ресурсов CPU, памяти, I/O для "
        "приложений и служб Android."
    ),
    "libsysutils.so": (
        "Android System Utilities — библиотека системных "
        "утилит: работа с сокетами Netlink, сетевыми "
        "интерфейсами, событиями системы."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 2. BINDER / HWBINDER — межпроцессное взаимодействие Android
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_BINDER = {
    "libbinder.so": (
        "Binder IPC Library — реализация механизма межпроцессного "
        "взаимодействия Binder. Позволяет процессам вызывать "
        "методы объектов в других процессах с проверкой "
        "разрешений и автоматической сериализацией параметров."
    ),
    "libbinder_ndk.so": (
        "Binder NDK Library — стабильная версия Binder API "
        "для нативных приложений через NDK (Android 10+). "
        "Предоставляет AIDL-коммуникацию без привязки "
        "к внутренним API."
    ),
    "libhwbinder.so": (
        "Hardware Binder — расширение Binder для HIDL "
        "(Hardware Interface Definition Language). Используется "
        "для IPC между framework и аппаратными компонентами."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 3. HIDL — Hardware Interface Definition Language
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_HIDL = {
    "libhidlbase.so": (
        "HIDL Base Library — базовая библиотека HIDL, "
        "реализующая инфраструктуру для передачи данных "
        "между процессами через hwbinder."
    ),
    "libhidltransport.so": (
        "HIDL Transport Library — библиотека транспортного "
        "уровня HIDL. Обеспечивает маршалинг/демаршалинг "
        "данных и управление соединениями."
    ),
    "libhidlmemory.so": (
        "HIDL Memory Library — библиотека для передачи "
        "больших блоков памяти между процессами через "
        "ashmem (Android Shared Memory)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 4. HARDWARE — HAL, сенсоры, WiFi, USB, аудио- и видео- HAL
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_HARDWARE = {
    "libhardware.so": (
        "Hardware Abstraction Library (HAL) — интерфейс между "
        "Android framework и аппаратными драйверами. "
        "Предоставляет стандартизированный доступ к сенсорам, "
        "камере, аудио, GPS через общий API."
    ),
    "libhardware_legacy.so": (
        "Legacy Hardware Library — поддержка устаревшего "
        "оборудования и обратная совместимость со старыми "
        "драйверами Android."
    ),
    "libsensorservice.so": (
        "Sensor Service Library — библиотека для управления "
        "аппаратными сенсорами: акселерометр, гироскоп, "
        "магнитометр, датчик освещённости, барометр."
    ),
    "libcameraservice.so": (
        "Camera Service Library — библиотека сервиса камеры. "
        "Управление камерами, захват изображений, "
        "обработка параметров съёмки."
    ),
    "libusbhost.so": (
        "USB Host Library — библиотека для работы с USB-"
        "устройствами в режиме хоста (OTG). Позволяет "
        "подключать флешки, клавиатуры, мыши, MIDI-"
        "устройства."
    ),
    "libwpa_client.so": (
        "WPA Supplicant Client Library — клиентская библиотека "
        "для взаимодействия с wpa_supplicant. Управление "
        "Wi-Fi подключениями, сканирование сетей, ввод "
        "паролей."
    ),
    "libwifi-hal.so": (
        "Wi-Fi HAL Library — HAL для беспроводных интерфейсов. "
        "Предоставляет низкоуровневый доступ к Wi-Fi чипсету "
        "через wpa_supplicant."
    ),
    "libaudiohal.so": (
        "Audio HAL Library — HAL для аудио. Обеспечивает "
        "взаимодействие между AudioFlinger и аппаратными "
        "аудио-драйверами."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 5. NATIVE WINDOW — графический конвейер Android
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_NATIVE_WINDOW = {
    "libandroid.so": (
        "Android Native Window API — интерфейс для работы "
        "с native-окнами. Управление буферами кадров, "
        "форматами пикселей, синхронизация с SurfaceFlinger."
    ),
    "libgui.so": (
        "Android GUI Library — управление буферами графики, "
        "работа с Surface и SurfaceComposerClient. Связующее "
        "звено между приложениями и системой отображения."
    ),
    "libui.so": (
        "Android UI Library — низкоуровневые графические "
        "примитивы: управление регионами, форматами "
        "пикселей, объектами GraphicBuffer."
    ),
    "libnativewindow.so": (
        "Native Window Library — библиотека NDK для работы "
        "с native окнами: ANativeWindow_lock/unlock, "
        "получение буфера, настройка формата."
    ),
    "libsync.so": (
        "Android Sync Library — библиотека синхронизации "
        "графических буферов с использованием fence-"
        "дескрипторов (sync_file). Обеспечивает координацию "
        "между GPU и CPU."
    ),
    "librenderengine.so": (
        "Render Engine Library — движок рендеринга Android. "
        "Используется SurfaceFlinger для композиции окон "
        "с аппаратным ускорением (OpenGL ES / Vulkan)."
    ),
    "libEGL.so": (
        "EGL Library — интерфейс между API рендеринга "
        "(OpenGL ES) и оконной системой Android. Управление "
        "контекстами, поверхностями, конфигурациями дисплея."
    ),
    "libGLESv1_CM.so": (
        "OpenGL ES 1.x — реализация фиксированного "
        "графического конвейера OpenGL ES 1.0/1.1."
    ),
    "libGLESv2.so": (
        "OpenGL ES 2.0 — реализация программируемого "
        "графического конвейера с вершинными и фрагментными "
        "шейдерами."
    ),
    "libGLESv3.so": (
        "OpenGL ES 3.x — расширенный графический API "
        "с множественными буферами рендеринга, compute-"
        "шейдерами и улучшенным сжатием текстур."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 6. GRAPHICS — libhwui, Skia, Vulkan, RenderScript, кодеки изображений
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_GRAPHICS = {
    "libhwui.so": (
        "Hardware UI Renderer (libhwui) — аппаратно-ускоренный "
        "рендерер пользовательского интерфейса Android. "
        "Отрисовка View-иерархии через OpenGL ES / Vulkan."
    ),
    "libandroidfw.so": (
        "Android Framework Library — управление ресурсами, "
        "темами, конфигурациями, ассетами приложений."
    ),
    "libskia.so": (
        "Skia — библиотека 2D-графики, используемая в Android "
        "(Chrome, Flutter, Firefox). Аппаратно-ускоренный "
        "рендеринг текста, фигур, изображений."
    ),
    "libvulkan_loader.so": (
        "Vulkan Loader (Android) — загрузчик Vulkan ICD. "
        "Обнаружение и загрузка драйверов Vulkan от "
        "производителей GPU (Qualcomm, ARM, Mali)."
    ),
    "libvulkan.so": (
        "Vulkan API (Android) — низкоуровневый графический "
        "и вычислительный API. Высокая производительность "
        "в играх и требовательных приложениях."
    ),
    "libRS.so": (
        "RenderScript Runtime — библиотека для вычислительных "
        "задач на GPU/CPU. Параллельная обработка данных "
        "(фильтры изображений, математические расчёты)."
    ),
    "libRSCpuRef.so": (
        "RenderScript CPU Reference — эталонная реализация "
        "RenderScript на CPU. Используется, когда GPU-"
        "ускорение недоступно."
    ),
    "libETC1.so": (
        "ETC1 Texture Compression — поддержка формата сжатия "
        "текстур ETC1 (Ericsson Texture Compression)."
    ),
    "libjpeg.so": (
        "JPEG Library (Android) — кодирование и декодирование "
        "изображений в формате JPEG. Оптимизированная версия "
        "libjpeg-turbo."
    ),
    "libpng.so": (
        "PNG Library (Android) — кодирование и декодирование "
        "изображений в формате PNG."
    ),
    "libjnigraphics.so": (
        "Android JNI Graphics API — библиотека NDK для прямого "
        "доступа к пиксельным буферам объектов Bitmap "
        "(AndroidBitmap_lockPixels, AndroidBitmap_getInfo)."
    ),
    "libblas.so": (
        "BLAS Library (Android) — библиотека линейной алгебры "
        "для RenderScript и научных вычислений."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 7. MEDIA — Media Framework, Stagefright, AudioFlinger, codecs
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_MEDIA = {
    "libmedia.so": (
        "Android Media Library — воспроизведение и запись "
        "аудио/видео. Управление кодеками, форматами, "
        "синхронизация аудио-видео потоков."
    ),
    "libstagefright.so": (
        "Stagefright Media Engine — нативный медиа-фреймворк "
        "Android. Кодеки, форматы, потоковая передача, DRM."
    ),
    "libstagefright_foundation.so": (
        "Stagefright Foundation — базовые классы для "
        "Stagefright: управление памятью, метаданные, "
        "синхронизация."
    ),
    "libmedia_codec.so": (
        "Media Codec Library — реализация MediaCodec API "
        "для программного кодирования/декодирования аудио "
        "и видео в Android."
    ),
    "libstagefright_omx.so": (
        "Stagefright OMX Plugin — интеграция OpenMAX IL "
        "кодеков с фреймворком Stagefright."
    ),
    "libaudioflinger.so": (
        "AudioFlinger — аудио-микшер Android. Микширование "
        "аудиопотоков от разных приложений, управление "
        "аудиоустройствами, эффекты."
    ),
    "libaudiopolicyservice.so": (
        "Audio Policy Service — библиотека управления "
        "аудиополитиками. Определяет маршрутизацию звука: "
        "динамики, наушники, Bluetooth, HDMI."
    ),
    "libeffects.so": (
        "Audio Effects Library — библиотека аудио-эффектов: "
        "эквалайзер, бас-усиление, реверберация, виртуализатор, "
        "подавление шума."
    ),
    "libsoundtrigger.so": (
        "Sound Trigger Library — библиотека для обнаружения "
        "голосовых команд (OK Google) при пониженном "
        "энергопотреблении через DSP."
    ),
    "libsonivox.so": (
        "Sonivox MIDI Synthesizer — программный MIDI-"
        "синтезатор для воспроизведения MIDI-файлов "
        "и генерации звуковых эффектов."
    ),
    "libaudioutils.so": (
        "Audio Utilities Library — вспомогательные функции "
        "для обработки звука: преобразование форматов, "
        "ресемплинг, микширование."
    ),
    "libmediandk.so": (
        "Media NDK API — предоставляет доступ к аудио- "
        "и видеокодекам через стандартный интерфейс NDK "
        "для нативных приложений."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 8. NETWORK — сетевые библиотеки Android
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_NETWORK = {
    "libnetutils.so": (
        "Android Network Utilities — управление сетевыми "
        "интерфейсами, DHCP-клиент, настройка маршрутизации."
    ),
    "libpackagelistparser.so": (
        "Package List Parser — библиотека для парсинга "
        "/data/system/packages.list. Используется для "
        "получения информации об установленных приложениях."
    ),
    "libmdnssd.so": (
        "mDNS Service Discovery Library — реализация "
        "Multicast DNS и DNS Service Discovery для Android. "
        "Обнаружение служб в локальной сети."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 9. BLUETOOTH — стек Bluetooth Android
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_BLUETOOTH = {
    "libbluetooth.so": (
        "Android Bluetooth Stack — реализация стека Bluetooth "
        "(Bluedroid/Floss). Управление адаптерами, профилями "
        "(A2DP, HFP, AVRCP, GATT), сопряжением устройств."
    ),
    "libbluetooth_jni.so": (
        "Bluetooth JNI — прослойка между Java Bluetooth API "
        "и нативной реализацией стека Bluetooth."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 10. RUNTIME — ART, Dalvik, JNI, Java core
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_RUNTIME = {
    "libandroid_runtime.so": (
        "Android Runtime JNI — мост между Java-фреймворком "
        "Android и нативным кодом. Содержит JNI-вызовы "
        "для всех системных служб."
    ),
    "libdvm.so": (
        "Dalvik Virtual Machine (устарело) — виртуальная "
        "машина Dalvik. Использовалась в Android до версии "
        "4.4. Заменена на ART."
    ),
    "libart.so": (
        "Android Runtime (ART) — современная среда выполнения "
        "Android. Ahead-of-Time (AOT) компиляция, JIT, "
        "сборка мусора, профилирование."
    ),
    "libart-compiler.so": (
        "ART Compiler Library — компилятор для ART. "
        "Отвечает за AOT- и JIT-компиляцию DEX-байткода "
        "в машинный код."
    ),
    "libart-dexlayout.so": (
        "ART Dex Layout Library — библиотека для "
        "оптимизации размещения DEX-файлов в памяти, "
        "улучшения локальности и времени загрузки."
    ),
    "libnativeloader.so": (
        "Native Loader Library — библиотека для загрузки "
        "нативных библиотек в ART. Управляет поиском, "
        "загрузкой и связыванием .so файлов."
    ),
    "libjavacore.so": (
        "Java Core Library — реализация базовых классов "
        "Java (java.lang, java.io, java.net, java.util) "
        "для ART."
    ),
    "libopenjdk.so": (
        "OpenJDK Library — реализация Java API на базе "
        "OpenJDK для Android. Включает криптографию, "
        "сжатие, работу с XML."
    ),
    "libjdwp.so": (
        "JDWP (Java Debug Wire Protocol) Library — "
        "библиотека для отладки Java-приложений на "
        "Android через JDWP."
    ),
    "libsigchain.so": (
        "Signal Chain Library — библиотека управления "
        "цепочками сигналов для ART. Обеспечивает "
        "правильную обработку сигналов SIGSEGV, "
        "SIGABRT в среде выполнения."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 11. CRYPTO — криптография Android (BoringSSL + keystore)
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_CRYPTO = {
    "libcrypto.so": (
        "BoringSSL Crypto Library — форк OpenSSL от Google. "
        "Криптографические операции на Android: шифрование, "
        "хеширование, цифровые подписи, генерация ключей."
    ),
    "libssl.so": (
        "BoringSSL SSL/TLS Library — реализация протоколов "
        "SSL/TLS на Android для защищённых сетевых "
        "соединений."
    ),
    "libkeystore.so": (
        "Android Keystore Library — библиотека для "
        "безопасного хранения криптографических ключей "
        "в аппаратном хранилище (TEE, StrongBox)."
    ),
    "libkeymaster.so": (
        "Keymaster HAL Library — библиотека аппаратной "
        "поддержки криптографических операций (TEE, "
        "TrustZone). Подпись, шифрование, генерация "
        "ключей на защищённом сопроцессоре."
    ),
    "libgatekeeper.so": (
        "Gatekeeper Library — библиотека для проверки "
        "PIN-кодов и паролей экрана блокировки. "
        "Использует аппаратно-подкреплённый счётчик "
        "попыток (TEE)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 12. SECURITY — minijail, SELinux, TPM
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_SECURITY = {
    "libminijail.so": (
        "Minijail — легковесная система sandboxing'а "
        "для Android. Ограничивает syscall-интерфейс, "
        "capabilities, пользователя/группу, namespace "
        "для изоляции процессов."
    ),
    "libselinux-android.so": (
        "SELinux Android Library — интерфейс SELinux "
        "для Android. Управление контекстами безопасности "
        "и политиками на платформе Android."
    ),
    "libsepol-android.so": (
        "SELinux Policy Library (Android) — библиотека "
        "для работы с SELinux-политиками на Android."
    ),
    "libtpm-android.so": (
        "TPM Library (Android) — библиотека для "
        "взаимодействия с TPM (Trusted Platform Module) "
        "на устройствах Android с TPM-чипом."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 13. NDK — стабильные API из Android NDK
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_NDK = {
    "libvulkan.so": (
        "Vulkan API (Android NDK) — низкоуровневый "
        "графический и вычислительный API. Обеспечивает "
        "высокую производительность в играх и требовательных "
        "приложениях."
    ),
    "libneuralnetworks.so": (
        "Android Neural Networks API (NNAPI) — аппаратно-"
        "ускоренный вывод нейронных сетей на устройстве. "
        "Используется для задач машинного обучения."
    ),
    "libaaudio.so": (
        "AAudio API — высокопроизводительный аудио API "
        "для Android NDK (Android 8.1+). Низкая задержка, "
        "потоковый ввод/вывод, управление буферами."
    ),
    "liboboe.so": (
        "Oboe Library — C++ обёртка над AAudio для "
        "Android NDK. Обеспечивает кроссплатформенную "
        "совместимость с OpenSL ES на старых устройствах."
    ),
    "libnativewindow.so": (
        "Native Window NDK Library — стабильная NDK-"
        "библиотека для работы с native окнами "
        "(ANativeWindow API)."
    ),
    "libsync.so": (
        "Sync NDK Library — стабильная NDK-библиотека "
        "для синхронизации с fence-дескрипторами."
    ),
    "libcpufeatures.so": (
        "CPU Features Library — библиотека для обнаружения "
        "возможностей CPU (ARM NEON, ARMv8, x86 SSE, "
        "CRC32, AES). Используется для runtime-"
        "диспетчеризации оптимизированного кода."
    ),
    "libamidi.so": (
        "Android MIDI API — библиотека для работы "
        "с MIDI-устройствами через NDK (Android 6+)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 14. ICU — интернационализация
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_ICU = {
    "libicui18n.so": (
        "ICU Internationalization — форматирование дат, "
        "чисел, валют, сообщений, правила сортировки "
        "для множества языков."
    ),
    "libicuuc.so": (
        "ICU Common — базовые службы Unicode: преобразование "
        "кодировок, работа с текстом, нормализация."
    ),
    "libicudata.so": (
        "ICU Data — статические данные ICU: таблицы "
        "символов Unicode, правила сортировки, календари, "
        "часовые пояса."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 15. CAMERA — клиентские и NDK библиотеки камеры
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_CAMERA = {
    "libcamera_client.so": (
        "Android Camera Client — клиентская библиотека "
        "для взаимодействия с сервисом камеры. Используется "
        "приложениями для доступа к камере."
    ),
    "libcamera2ndk.so": (
        "Android Camera2 NDK — нативный API для управления "
        "камерой (фокус, экспозиция, захват кадров) "
        "через Android NDK."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 16. AUDIO — OpenSL ES
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_AUDIO = {
    "libOpenSLES.so": (
        "OpenSL ES (Android) — нативный аудио API для "
        "высокопроизводительного воспроизведения и записи "
        "звука. Базовая библиотека для аудио в NDK."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 17. JNI / NATIVEHELPER
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_JNI = {
    "libnativehelper.so": (
        "Native Helper — вспомогательная библиотека JNI, "
        "упрощающая взаимодействие между Java и C/C++ "
        "кодом в Android Runtime."
    ),
    "libnativeloader.so": (
        "Native Loader — библиотека для загрузки нативных "
        "библиотек в контексте Android Runtime. Управляет "
        "поиском и связыванием .so файлов."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 18. COMPRESSION — библиотеки сжатия в AOSP
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_COMPRESSION = {
    "libz.so": (
        "Zlib Compression (Android) — реализация алгоритма "
        "сжатия DEFLATE для Android."
    ),
    "libziparchive.so": (
        "ZIP Archive Library — библиотека для работы "
        "с ZIP-архивами. Используется для APK, JAR, "
        "ресурсных архивов."
    ),
    "liblzma.so": (
        "LZMA Compression (Android) — алгоритм сжатия "
        "LZMA для Android."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 19. XML — Expat XML parser
# ═══════════════════════════════════════════════════════════════════════════

_ANDROID_EXPAT = {
    "libexpat.so": (
        "Expat XML Parser (Android) — потоковый парсер XML, "
        "используемый системными компонентами Android."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# ОБЪЕДИНЕНИЕ ВСЕХ ANDROID-СЛОВАРЕЙ
# ═══════════════════════════════════════════════════════════════════════════

ANDROID_MODULES = {}
ANDROID_MODULES.update(_ANDROID_CORE)
ANDROID_MODULES.update(_ANDROID_BINDER)
ANDROID_MODULES.update(_ANDROID_HIDL)
ANDROID_MODULES.update(_ANDROID_HARDWARE)
ANDROID_MODULES.update(_ANDROID_NATIVE_WINDOW)
ANDROID_MODULES.update(_ANDROID_GRAPHICS)
ANDROID_MODULES.update(_ANDROID_MEDIA)
ANDROID_MODULES.update(_ANDROID_NETWORK)
ANDROID_MODULES.update(_ANDROID_BLUETOOTH)
ANDROID_MODULES.update(_ANDROID_RUNTIME)
ANDROID_MODULES.update(_ANDROID_CRYPTO)
ANDROID_MODULES.update(_ANDROID_SECURITY)
ANDROID_MODULES.update(_ANDROID_NDK)
ANDROID_MODULES.update(_ANDROID_ICU)
ANDROID_MODULES.update(_ANDROID_CAMERA)
ANDROID_MODULES.update(_ANDROID_AUDIO)
ANDROID_MODULES.update(_ANDROID_JNI)
ANDROID_MODULES.update(_ANDROID_COMPRESSION)
ANDROID_MODULES.update(_ANDROID_EXPAT)