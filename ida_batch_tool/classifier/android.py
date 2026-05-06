"""Словари для Android-модулей."""

_ANDROID_CORE = {
    "libc.so": "Bionic libc — реализация стандартной библиотеки C для Android. Включает функции стандарта C11 (printf, malloc, fopen), системные вызовы Linux, и — в отличие от glibc — включает поддержку многопоточности (pthread), динамической загрузки (dl), и real-time-расширений без отдельных библиотек.",
    "libm.so": "Bionic libm — математическая библиотека Android. Реализует математические функции (sin, cos, sqrt, log, pow) с плавающей точкой. Автоматически линкуется сборочной системой, как и libc.",
    "libdl.so": "Bionic libdl — поддержка динамической загрузки библиотек (dlopen, dlsym, dlclose). Необходима для плагинов и интерпретируемых языков на Android.",
    "libstdc++.so": "GNU libstdc++ для Android — реализация стандартной библиотеки C++ для Android. Предоставляет STL и потоки ввода-вывода для C++ приложений.",
    "liblog.so": "Android Logging Library — система логирования Android. Предоставляет API для записи сообщений в системный журнал logcat. Используется всеми компонентами системы, от ядра до приложений, для диагностики и отладки.",
    "libcutils.so": "Android C Utilities — набор утилит на языке C для системного программирования Android: работа с сокетами, атомарные операции, управление процессами, конфигурация системы.",
    "libutils.so": "Android Utilities — вспомогательные классы C++: работа со строками (String8, String16), потоками (Thread, Mutex, Condition), IPC (Binder), логирование. Базовый инструментарий для всех системных служб Android.",
}

_ANDROID_BINDER = {
    "libbinder.so": "Binder IPC Library — реализация механизма межпроцессного взаимодействия Binder. Позволяет процессам вызывать методы объектов в других процессах с проверкой разрешений и автоматической сериализацией/десериализацией параметров. Является центральной технологией IPC в Android, через которую работают все системные службы.",
}

_ANDROID_HARDWARE = {
    "libhardware.so": "Hardware Abstraction Library (HAL) — интерфейс между Android framework и аппаратными драйверами. Предоставляет стандартизированный способ доступа к оборудованию (сенсоры, камера, аудио, GPS) через общий API.",
    "libhardware_legacy.so": "Legacy Hardware Library — поддержка устаревшего оборудования и обратная совместимость со старыми драйверами Android.",
}

_ANDROID_NATIVE_WINDOW = {
    "libandroid.so": "Android Native Window API — интерфейс для работы с native-окнами. Предоставляет управление буферами кадров, форматами пикселей, синхронизацией с системой композиции SurfaceFlinger.",
    "libgui.so": "Android GUI Library — управление буферами графики, работа с Surface и SurfaceComposerClient. Связующее звено между приложениями и системой отображения.",
    "libui.so": "Android UI Library — низкоуровневые графические примитивы: управление регионами, форматами пикселей, объектами GraphicBuffer.",
    "libEGL.so": "EGL Library — интерфейс между API рендеринга (OpenGL ES) и оконной системой Android. Управление контекстами, поверхностями, конфигурациями дисплея.",
    "libGLESv1_CM.so": "OpenGL ES 1.x — реализация фиксированного графического конвейера OpenGL ES 1.0/1.1 для Android.",
    "libGLESv2.so": "OpenGL ES 2.0 — реализация программируемого графического конвейера с поддержкой вершинных и фрагментных шейдеров.",
    "libGLESv3.so": "OpenGL ES 3.x — реализация расширенного графического API с поддержкой множественных буферов рендеринга, compute-шейдеров и улучшенного сжатия текстур.",
}

_ANDROID_MEDIA = {
    "libmedia.so": "Android Media Library — воспроизведение и запись аудио/видео. Управление кодеками, форматами, синхронизация аудио-видео потоков.",
    "libstagefright.so": "Stagefright Media Engine — нативный медиа-фреймворк Android. Кодеки, форматы, потоковая передача, DRM. Основной движок воспроизведения мультимедиа в Android.",
    "libstagefright_foundation.so": "Stagefright Foundation — базовые классы для Stagefright: управление памятью, метаданные, синхронизация.",
    "libmediandk.so": "Media NDK API — предоставляет доступ к аудио- и видеокодекам через стандартный интерфейс NDK для нативных приложений.",
    "libaudioutils.so": "Audio Utilities Library — вспомогательные функции для обработки звука: преобразование форматов, ресемплинг, микширование.",
    "libsonivox.so": "Sonivox MIDI Synthesizer — программный MIDI-синтезатор для воспроизведения MIDI-файлов и генерации звуковых эффектов.",
}

_ANDROID_GRAPHICS = {
    "libhwui.so": "Hardware UI Renderer (libhwui) — аппаратно-ускоренный рендерер пользовательского интерфейса Android. Использует Skia для 2D-графики и OpenGL ES/Vulkan для рендеринга. Отрисовывает View-иерархию в Android-приложениях.",
    "libandroidfw.so": "Android Framework Library — управление ресурсами (res/values/*.xml), темами, конфигурациями, ассетами приложений.",
    "libETC1.so": "ETC1 Texture Compression — поддержка формата сжатия текстур ETC1, используемого для экономии памяти GPU на Android-устройствах.",
    "libjpeg.so": "JPEG Library — кодирование и декодирование изображений в формате JPEG.",
    "libpng.so": "PNG Library — кодирование и декодирование изображений в формате PNG.",
}

_ANDROID_NETWORK = {
    "libnetutils.so": "Android Network Utilities — управление сетевыми интерфейсами, DHCP-клиент, настройка маршрутизации.",
}

_ANDROID_BLUETOOTH = {
    "libbluetooth.so": "Android Bluetooth Stack — реализация стека Bluetooth (BlueZ/Bluedroid). Управление адаптерами, профилями, сопряжением устройств.",
    "libbluetooth_jni.so": "Bluetooth JNI — прослойка между Java Bluetooth API и нативной реализацией.",
}

_ANDROID_RUNTIME = {
    "libandroid_runtime.so": "Android Runtime JNI — мост между Java-фреймворком Android и нативным кодом. Содержит JNI-вызовы для всех системных служб.",
    "libdvm.so": "Dalvik Virtual Machine (устарело) — виртуальная машина Dalvik. Использовалась в Android до версии 4.4. Заменена на ART (Android Runtime).",
    "libart.so": "Android Runtime (ART) — современная среда выполнения Android. Ahead-of-Time (AOT) компиляция, сборка мусора, профилирование.",
}

_ANDROID_NETWORK_MONITORING = {
    "libnetd_client.so": "Netd Client Library — клиентская библиотека для взаимодействия с сетевым демоном Android. Управление DNS, маршрутизацией, tethering.",
}

_ANDROID_CRYPTO = {
    "libcrypto.so": "OpenSSL Crypto (Android) — криптографические операции на Android: шифрование, хеширование, цифровые подписи, генерация ключей.",
    "libssl.so": "OpenSSL SSL/TLS (Android) — реализация протоколов SSL/TLS на Android для защищённых сетевых соединений.",
}

_ANDROID_NDK = {
    "libvulkan.so": "Vulkan API (Android) — низкоуровневый графический и вычислительный API. Обеспечивает высокую производительность в играх и требовательных приложениях.",
    "libneuralnetworks.so": "Android Neural Networks API (NNAPI) — аппаратно-ускоренный вывод нейронных сетей на устройстве. Используется для задач машинного обучения.",
}

_ANDROID_ICU = {
    "libicui18n.so": "ICU Internationalization — форматирование дат, чисел, валют, сообщений, правила сортировки для множества языков.",
    "libicuuc.so": "ICU Common — базовые службы Unicode: преобразование кодировок, работа с текстом, нормализация.",
}

_ANDROID_CAMERA = {
    "libcamera_client.so": "Android Camera Client — клиентская библиотека для взаимодействия с сервисом камеры. Используется приложениями для доступа к камере.",
    "libcamera2ndk.so": "Android Camera2 NDK — нативный API для управления камерой (фокус, экспозиция, захват кадров) через Android NDK.",
}

_ANDROID_MEDIA_NDK = {
    "libmediandk.so": "Media NDK — нативный доступ к аудио- и видеокодекам Android. Позволяет декодировать и кодировать медиапотоки в C/C++ приложениях.",
}

_ANDROID_AUDIO = {
    "libOpenSLES.so": "OpenSL ES (Android) — нативный аудио API для высокопроизводительного воспроизведения и записи звука. Альтернатива AAudio.",
}

_ANDROID_JNI = {
    "libnativehelper.so": "Native Helper — вспомогательная библиотека JNI, упрощающая взаимодействие между Java и C/C++ кодом в Android Runtime.",
}

_ANDROID_EXPAT = {
    "libexpat.so": "Expat XML Parser (Android) — потоковый парсер XML, используемый системными компонентами Android.",
}

# Объединение всех Android-словарей
ANDROID_MODULES = {}
ANDROID_MODULES.update(_ANDROID_CORE)
ANDROID_MODULES.update(_ANDROID_BINDER)
ANDROID_MODULES.update(_ANDROID_HARDWARE)
ANDROID_MODULES.update(_ANDROID_NATIVE_WINDOW)
ANDROID_MODULES.update(_ANDROID_MEDIA)
ANDROID_MODULES.update(_ANDROID_GRAPHICS)
ANDROID_MODULES.update(_ANDROID_NETWORK)
ANDROID_MODULES.update(_ANDROID_BLUETOOTH)
ANDROID_MODULES.update(_ANDROID_RUNTIME)
ANDROID_MODULES.update(_ANDROID_NETWORK_MONITORING)
ANDROID_MODULES.update(_ANDROID_CRYPTO)
ANDROID_MODULES.update(_ANDROID_NDK)
ANDROID_MODULES.update(_ANDROID_ICU)
ANDROID_MODULES.update(_ANDROID_CAMERA)
ANDROID_MODULES.update(_ANDROID_MEDIA_NDK)
ANDROID_MODULES.update(_ANDROID_AUDIO)
ANDROID_MODULES.update(_ANDROID_JNI)
ANDROID_MODULES.update(_ANDROID_EXPAT)