"""Словари для сторонних библиотек (third-party)."""

_THIRD_PARTY_BROWSER = {
    "cef.dll": "Chromium Embedded Framework — встраиваемый браузерный движок на базе Chromium (Windows)",
    "libcef.so": "Chromium Embedded Framework — встраиваемый браузерный движок на базе Chromium (Linux)",
    "libcef.dylib": "Chromium Embedded Framework — встраиваемый браузерный движок на базе Chromium (macOS)",
    "awesomium.dll": "Awesomium — встраиваемый браузерный движок на базе Chromium (устарел, заменён на CEF)",
    "libwebkitgtk-3.0.so": "WebKitGTK — браузерный движок WebKit для GTK-приложений (Linux)",
    "libwebkit2gtk-4.0.so": "WebKitGTK2 — современная версия WebKit для GTK с поддержкой мультипроцессной архитектуры (Linux)",
}

_THIRD_PARTY_CRYPTO = {
    "libeay32.dll": "OpenSSL Encryption Library (Windows) — криптографические операции: шифрование, хеширование, цифровые подписи, генерация ключей. Полное название: libeay32 (OpenSSL).",
    "ssleay32.dll": "OpenSSL SSL/TLS Library (Windows) — реализация протоколов SSL и TLS. Полное название: ssleay32 (OpenSSL).",
    "libcrypto.so": "OpenSSL/LibreSSL Encryption Library (Linux) — криптографическая библиотека. Используется большинством серверных и сетевых приложений.",
    "libssl.so": "OpenSSL/LibreSSL SSL/TLS Library (Linux) — реализация протоколов SSL/TLS.",
    "libsodium.dll": "Libsodium (Windows) — современная, простая в использовании криптографическая библиотека (шифрование, хеширование, подписи, обмен ключами).",
    "libsodium.so": "Libsodium (Linux) — современная криптографическая библиотека.",
    "libtls.dll": "LibreSSL TLS Library — реализация TLS от проекта LibreSSL (форк OpenSSL).",
}

_THIRD_PARTY_COMPRESSION = {
    "zlib1.dll": "Zlib Compression Library (Windows) — библиотека сжатия данных. Реализует алгоритм DEFLATE. Используется для gzip, PNG, HTTP сжатия.",
    "libz.so.1": "Zlib Compression Library (Linux/macOS) — библиотека сжатия данных.",
    "liblzma.so.5": "LZMA Compression Library — алгоритм сжатия LZMA (XZ). Высокая степень сжатия.",
    "7z.dll": "7-Zip Compression Engine — движок архивации и сжатия с поддержкой форматов 7z, ZIP, GZIP, BZIP2, TAR, RAR. Обеспечивает одно из лучших соотношений сжатия среди популярных архиваторов.",
    "libzip.dll": "Libzip (Windows) — библиотека для создания и чтения ZIP-архивов.",
    "libzip.so": "Libzip (Linux) — библиотека для работы с ZIP-архивами.",
}

_THIRD_PARTY_DATABASE = {
    "sqlite3.dll": "SQLite Database Engine (Windows) — встраиваемая реляционная база данных.",
    "libsqlite3.so.0": "SQLite Database Engine (Linux) — встраиваемая реляционная база данных.",
    "libmysql.dll": "MySQL Connector/C (Windows) — клиентская библиотека для подключения к серверу MySQL.",
    "libmysqlclient.so": "MySQL Client Library (Linux) — клиентская библиотека MySQL.",
    "libpq.dll": "Libpq (Windows) — клиентская библиотека PostgreSQL.",
    "libpq.so.5": "Libpq (Linux) — клиентская библиотека PostgreSQL.",
    "libmariadb.so.3": "MariaDB Connector/C — клиентская библиотека MariaDB (форк MySQL).",
}

_THIRD_PARTY_NETWORK = {
    "libcurl.dll": "Curl Library (Windows) — работа с URL (HTTP, HTTPS, FTP, SMTP, IMAP, LDAP, MQTT и многие другие протоколы).",
    "libcurl.so.4": "Curl Library (Linux) — работа с URL.",
    "nghttp2.dll": "Nghttp2 (Windows) — реализация протокола HTTP/2. Обеспечивает мультиплексирование потоков, server push, header compression (HPACK).",
    "libnghttp2.so.14": "Nghttp2 (Linux) — реализация протокола HTTP/2.",
    "libssh2.dll": "Libssh2 (Windows) — клиентская библиотека для SSH2-соединений.",
    "libssh2.so.1": "Libssh2 (Linux) — клиентская библиотека SSH2.",
}

_THIRD_PARTY_GRAPHICS = {
    "sdl2.dll": "SDL2 (Simple DirectMedia Layer) — кроссплатформенная библиотека для работы с графикой, звуком и устройствами ввода (Windows)",
    "libsdl2.so.0": "SDL2 (Simple DirectMedia Layer) — кроссплатформенная библиотека для работы с графикой, звуком и устройствами ввода (Linux)",
    "opencv_core.dll": "OpenCV Core Module (Windows) — библиотека компьютерного зрения: базовые структуры данных и алгоритмы.",
    "opencv_imgproc.dll": "OpenCV Image Processing Module (Windows) — обработка изображений: фильтры, геометрические преобразования, цветовые пространства.",
    "libopencv_core.so": "OpenCV Core Module (Linux) — библиотека компьютерного зрения.",
    "libgtk-3.so.0": "GTK+ 3 Toolkit (Linux) — библиотека графического интерфейса. Создание окон, меню, кнопок и других элементов UI.",
    "libgtk-4.so.1": "GTK 4 Toolkit (Linux) — современная версия библиотеки графического интерфейса GTK.",
}

_THIRD_PARTY_LOGGING = {
    "log4cplus.dll": "Log4cplus (Windows) — библиотека логирования для C++. Предоставляет гибкую настройку уровней логирования, форматов вывода (консоль, файл, syslog, сокеты).",
    "log4cxx.dll": "Log4cxx (Windows) — библиотека логирования для C++ (Apache). Портирована с Java-фреймворка log4j, обеспечивает enterprise-уровень логирования.",
    "log4net.dll": "Log4net (Windows) — библиотека логирования для .NET (Apache). Позволяет настраивать вывод логов в различные приемники (файлы, базы данных, консоль) через XML-конфигурацию.",
    "liblog4cplus.so": "Log4cplus (Linux) — библиотека логирования для C++.",
}

_THIRD_PARTY_XML = {
    "libpdf.dll": "PDF Library (Windows) — библиотека для работы с PDF-документами: создание, чтение, модификация.",
    "libxml2.so.2": "Libxml2 (Linux) — XML-парсер.",
}

_THIRD_PARTY_VIRTUALIZATION = {
    "tcg.dll": "QEMU Tiny Code Generator (TCG) — динамический транслятор машинного кода. Используется в QEMU для эмуляции процессоров на других архитектурах путём трансляции гостевых инструкций в хостовые.",
    "libtcg.so": "QEMU Tiny Code Generator (Linux) — динамический транслятор кода для QEMU.",
}

_THIRD_PARTY_VPN = {
    "wireguard.dll": "WireGuard VPN (Windows) — современный VPN-протокол. Обеспечивает быстрое, безопасное соединение с минимальным кодом.",
    "libwg.dll": "WireGuard Library (Windows) — библиотека WireGuard.",
    "openvpn.dll": "OpenVPN Client Library (Windows) — клиентская библиотека для OpenVPN-соединений.",
}

_THIRD_PARTY_QT = {
    "qt5core.dll": "Qt5 Core (Windows) — основа фреймворка: сигналы/слоты, строки, контейнеры, потоки.",
    "qt5gui.dll": "Qt5 GUI (Windows) — графический интерфейс: окна, виджеты, OpenGL.",
    "qt5widgets.dll": "Qt5 Widgets (Windows) — классические виджеты (кнопки, списки, таблицы).",
    "qt6core.dll": "Qt6 Core (Windows) — основа Qt6.",
    "qt6gui.dll": "Qt6 GUI (Windows) — графический интерфейс Qt6.",
}

_THIRD_PARTY_ML = {
    "tensorflow.dll": "TensorFlow C API — библиотека машинного обучения. Поддержка нейронных сетей, градиентного спуска, автоматического дифференцирования.",
    "onnxruntime.dll": "ONNX Runtime — выполнение моделей машинного обучения в формате ONNX. Кроссплатформенный и оптимизированный для инференса.",
}

_THIRD_PARTY_RPC = {
    "grpc.dll": "gRPC — высокопроизводительный фреймворк для удалённых вызовов процедур (RPC). Использует Protocol Buffers для сериализации и HTTP/2 для транспорта.",
    "protobuf.dll": "Protocol Buffers — библиотека сериализации структурированных данных. Обеспечивает компактное, быстрое бинарное представление для обмена между сервисами.",
}

_THIRD_PARTY_JAVASCRIPT = {
    "v8.dll": "Google V8 JavaScript Engine — высокопроизводительный движок JavaScript. Используется в Chrome, Node.js и других проектах. Обеспечивает JIT-компиляцию JavaScript в машинный код.",
}

_THIRD_PARTY_IMAGE = {
    "libjpeg-8.dll": "LibJPEG — кодирование/декодирование JPEG (формат сжатых фотографических изображений с потерями).",
    "libjpeg.so.8": "LibJPEG — кодирование/декодирование JPEG (Linux)",
    "libjpeg.dylib": "LibJPEG — кодирование/декодирование JPEG (macOS)",
    "libpng16.dll": "LibPNG — чтение/запись изображений PNG (Portable Network Graphics — сжатие без потерь с поддержкой прозрачности).",
    "libpng16.so.16": "LibPNG — чтение/запись PNG (Linux)",
    "libpng.dylib": "LibPNG — чтение/запись PNG (macOS)",
    "libtiff-5.dll": "LibTIFF — работа с TIFF (формат для хранения растровых изображений с высоким качеством, используется в полиграфии и медицине).",
    "libtiff.so.5": "LibTIFF — работа с TIFF (Linux)",
    "libtiff.dylib": "LibTIFF — работа с TIFF (macOS)",
    "libwebp.dll": "LibWebP — кодирование/декодирование WebP (современный формат сжатия от Google с поддержкой прозрачности и анимации, превосходит PNG и JPEG).",
    "libwebp.so.7": "LibWebP — кодирование/декодирование WebP (Linux)",
    "libvips-42.dll": "LibVips — высокопроизводительная потоковая обработка изображений без распаковки целиком в память (поддерживает JPEG, PNG, TIFF, WebP, HEIC, PDF, SVG).",
    "libvips.so.42": "LibVips — потоковая обработка изображений (Linux)",
    "ImageMagick.dll": "ImageMagick — создание, редактирование, компоновка и конвертация растровых изображений (поддерживает >200 форматов: JPEG, PNG, SVG, PDF, GIF, TIFF, HEIC, WebP).",
    "libGraphicsMagick-3.Q16.dll": "GraphicsMagick — форк ImageMagick с улучшенной стабильностью и многопоточной обработкой изображений.",
    "libGraphicsMagick.so.3": "GraphicsMagick — обработка изображений (Linux)",
    "libopenjp2.dll": "OpenJPEG — реализация JPEG 2000 (формат сжатия с вейвлет-преобразованием, используется в архивах, медицине и цифровом кино).",
    "libopenjp2.so.7": "OpenJPEG — JPEG 2000 (Linux)",
    "libraw.dll": "LibRaw — чтение RAW-файлов цифровых камер (CR2, NEF, ARW, DNG), извлечение метаданных и предварительная обработка перед конвертацией.",
    "libraw.so.23": "LibRaw — чтение RAW (Linux)",
    "libjxl.dll": "LibJXL — JPEG XL (новый формат сжатия следующего поколения с поддержкой lossless, HDR, анимации и прогрессивной загрузки).",
    "libjxl.so.0": "LibJXL — JPEG XL (Linux)",
}

_THIRD_PARTY_AUDIO = {
    "libmpg123.dll": "libmpg123 — быстрый декодер MPEG Audio Layer 1/2/3 (MP3) для воспроизведения и конвертации аудио.",
    "libmpg123.so.0": "libmpg123 — декодер MP3 (Linux)",
    "libmp3lame.dll": "LAME — кодировщик MP3 (MPEG Audio Layer III). Создание MP3-файлов из несжатых аудиоданных.",
    "libmp3lame.so.0": "LAME — кодировщик MP3 (Linux)",
    "libvorbis.dll": "LibVorbis — кодирование/декодирование Ogg Vorbis (свободный формат сжатия аудио с потерями без патентных ограничений, альтернатива MP3).",
    "libvorbis.so.0": "LibVorbis — кодирование/декодирование Ogg Vorbis (Linux)",
    "libvorbisfile.dll": "LibVorbisFile — высокоуровневый API для чтения Ogg Vorbis из файлов.",
    "libvorbisfile.so.3": "LibVorbisFile — API для чтения Ogg Vorbis (Linux)",
    "libogg.dll": "LibOgg — работа с контейнерным форматом Ogg (основа для Vorbis, Theora, Opus, FLAC).",
    "libogg.so.0": "LibOgg — контейнер Ogg (Linux)",
    "libopus.dll": "Opus — современный аудиокодек с низкой задержкой (используется в VoIP, WebRTC, потоковом аудио; объединяет технологии SILK и CELT).",
    "libopus.so.0": "Opus — аудиокодек (Linux)",
    "libFLAC.dll": "FLAC — Free Lossless Audio Codec. Сжатие аудио без потерь качества.",
    "libFLAC.so.8": "FLAC — сжатие аудио без потерь (Linux)",
    "libsndfile-1.dll": "LibSndFile — чтение/запись звуковых файлов (WAV, AIFF, AU, FLAC, и многие другие) через единый API без необходимости знать формат.",
    "libsndfile.so.1": "LibSndFile — работа со звуковыми файлами (Linux)",
    "libasound.so.2": "ALSA — Advanced Linux Sound Architecture. Низкоуровневый звуковой API для Linux.",
    "libpulse.so.0": "PulseAudio — звуковой сервер для Linux (микширование, маршрутизация, сетевая передача звука).",
    "openal32.dll": "OpenAL — кроссплатформенное 3D-позиционирование звука (эффекты окружения, доплер-эффект, используется в играх и симуляторах).",
    "libopenal.so.1": "OpenAL — 3D-звук (Linux)",
    "libportaudio-2.dll": "PortAudio — кроссплатформенный аудиоввод/вывод с низкой задержкой (используется Audacity, Python PyAudio, профессиональными DAW).",
    "libportaudio.so.2": "PortAudio — аудиоввод/вывод (Linux)",
    "libsoxr.dll": "libsoxr — высококачественный ресемплинг (изменение частоты дискретизации) аудио.",
    "libsoxr.so.0": "libsoxr — ресемплинг аудио (Linux)",
}

_THIRD_PARTY_CV = {
    "opencv_world480.dll": "OpenCV World — объединённый модуль OpenCV (компьютерное зрение: обнаружение объектов, трекинг, сегментация, калибровка камер, стереозрение).",
    "libopencv_world.so.408": "OpenCV World — компьютерное зрение (Linux)",
    "opencv_core480.dll": "OpenCV Core — базовые структуры данных и алгоритмы: матрицы, массивы, линейная алгебра, работа с памятью.",
    "opencv_imgproc480.dll": "OpenCV Image Processing — фильтры, геометрические преобразования, цветовые пространства, гистограммы.",
    "opencv_dnn480.dll": "OpenCV DNN — инференс нейронных сетей (TensorFlow, Caffe, ONNX, PyTorch) внутри OpenCV.",
    "opencv_face480.dll": "OpenCV Face — обнаружение и распознавание лиц (LBPH, EigenFaces, FisherFaces).",
    "opencv_objdetect480.dll": "OpenCV Object Detection — детекторы объектов (HOG, Haar Cascades, QR-коды).",
    "opencv_calib3d480.dll": "OpenCV Calib3D — калибровка камер, стереозрение, восстановление 3D-структуры.",
}

_THIRD_PARTY_ML_MORE = {
    "libtorch.dll": "LibTorch — C++ API для PyTorch. Обучение и инференс нейронных сетей с поддержкой GPU (CUDA).",
    "libtorch.so": "LibTorch — PyTorch C++ API (Linux)",
    "torch_cuda.dll": "Torch CUDA — модуль PyTorch для GPU-вычислений NVIDIA (CUDA).",
    "libtensorflow_lite.so": "TensorFlow Lite — облегчённый инференс ML-моделей на мобильных устройствах (Android, iOS) и встраиваемых системах.",
    "tensorflow_lite.dll": "TensorFlow Lite — инференс ML (Windows)",
    "caffe.dll": "Caffe — фреймворк глубокого обучения. Свёрточные нейронные сети, классификация изображений, сегментация.",
    "libcaffe.so": "Caffe — глубокое обучение (Linux)",
    "libopenblas.dll": "OpenBLAS — оптимизированная библиотека линейной алгебры (BLAS, LAPACK). Ускорение матричных операций на CPU.",
    "libopenblas.so.0": "OpenBLAS — линейная алгебра (Linux)",
    "libarmadillo.dll": "Armadillo — библиотека линейной алгебры (матрицы, векторы, разложения) с синтаксисом, похожим на MATLAB.",
    "libarmadillo.so.10": "Armadillo — линейная алгебра (Linux)",
    "libgsl.dll": "GSL — GNU Scientific Library. Обширная коллекция математических функций (спецфункции, БПФ, статистика, интегрирование, Монте-Карло).",
    "libgsl.so.25": "GSL — научная библиотека (Linux)",
    "libfftw3.dll": "FFTW — Fastest Fourier Transform in the West. Высокопроизводительное быстрое преобразование Фурье.",
    "libfftw3.so.3": "FFTW — БПФ (Linux)",
    "libgmp-10.dll": "GMP — GNU Multiple Precision. Арифметика произвольной точности (целые, рациональные, плавающие).",
    "libgmp.so.10": "GMP — арифметика произвольной точности (Linux)",
    "libmpfr.dll": "MPFR — многократная точность плавающей запятой с правильным округлением (расширение GMP).",
    "libmpfr.so.6": "MPFR — точная плавающая арифметика (Linux)",
    "libnvinfer.dll": "NVIDIA TensorRT — высокопроизводительный инференс глубокого обучения (оптимизация под GPU NVIDIA).",
    "libnvinfer.so.10": "TensorRT — инференс ML (Linux)",
}

_THIRD_PARTY_RPC_MORE = {
    "libzmq.dll": "ZeroMQ — высокопроизводительная асинхронная библиотека обмена сообщениями (внутрипроцессный, межпроцессный, TCP, multicast).",
    "libzmq.so.5": "ZeroMQ — обмен сообщениями (Linux)",
    "libnanomsg.dll": "Nanomsg — лёгкая библиотека обмена сообщениями (предшественник ZeroMQ, фиксированный набор транспортных протоколов).",
    "libnanomsg.so.5": "Nanomsg — обмен сообщениями (Linux)",
    "libnng.dll": "NNG — Nanomsg Next Generation. Современная библиотека обмена сообщениями с поддержкой TLS, HTTP и WebSocket.",
    "libnng.so.1": "NNG — обмен сообщениями (Linux)",
    "librabbitmq.dll": "RabbitMQ C Client — AMQP-клиент для взаимодействия с брокером сообщений RabbitMQ.",
    "librabbitmq.so.4": "RabbitMQ C Client — AMQP (Linux)",
    "libkafka.dll": "librdkafka — клиент Apache Kafka (очереди сообщений) на C/C++. Высокопроизводительный продюсер/консьюмер событий.",
    "librdkafka.so.1": "librdkafka — клиент Kafka (Linux)",
    "libmsgpackc.dll": "MessagePack — бинарная сериализация (компактнее JSON, быстрее).",
    "libmsgpackc.so.2": "MessagePack — сериализация (Linux)",
    "libavlrcodec.dll": "Avro C — сериализация данных в формат Apache Avro (используется Kafka, Hadoop).",
    "libavro.so.23": "Avro — сериализация (Linux)",
    "libcapnp.dll": "Cap'n Proto — сверхбыстрая сериализация и RPC (разработана создателем Protocol Buffers v2).",
    "libcapnp.so.1": "Cap'n Proto — сериализация/RPC (Linux)",
    "flatbuffers.dll": "FlatBuffers — сериализация без копирования в память (разработана Google, используется TensorFlow Lite).",
    "libflatbuffers.so.1": "FlatBuffers — сериализация (Linux)",
}

_THIRD_PARTY_GAME_MULTIMEDIA = {
    "libBulletDynamics.dll": "Bullet Physics — физический движок: обнаружение столкновений, динамика твёрдых/мягких тел, ray casting.",
    "libBulletDynamics.so.3.25": "Bullet Physics — физический движок (Linux)",
    "libBulletCollision.dll": "Bullet Collision — модуль обнаружения столкновений физического движка Bullet.",
    "libgodot-cpp.dll": "Godot Engine — нативные расширения Godot, написанные на C++ (встраиваемый скриптинг).",
    "libgodot-cpp.so": "Godot Engine — нативные расширения (Linux)",
    "libOgreMain.dll": "OGRE 3D — объектно-ориентированный движок рендеринга (используется в играх, симуляторах, VR).",
    "libOgreMain.so.1.12": "OGRE 3D — движок рендеринга (Linux)",
    "libIrrlicht.dll": "Irrlicht — простой и быстрый 3D-движок реального времени (Direct3D, OpenGL, программный рендеринг).",
    "libIrrlicht.so.1.8": "Irrlicht — 3D-движок (Linux)",
    "libosg.dll": "OpenSceneGraph — высокопроизводительный 3D-графический движок (OpenGL, используется в симуляторах и ГИС).",
    "libosg.so.161": "OpenSceneGraph — 3D-графика (Linux)",
    "libavcodec.dll": "FFmpeg libavcodec — кодирование/декодирование аудио/видео (сотни кодеков: H.264, H.265, VP9, AV1, AAC, MP3, Opus).",
    "libavcodec.so.60": "FFmpeg libavcodec — аудио/видео кодеки (Linux)",
    "libavformat.dll": "FFmpeg libavformat — демультиплексирование/мультиплексирование аудио/видео контейнеров (MP4, MKV, AVI, WebM, MOV, TS).",
    "libavformat.so.60": "FFmpeg libavformat — мультиплексирование (Linux)",
    "libavutil.dll": "FFmpeg libavutil — вспомогательные функции: математика, строки, криптографические хеши, управление памятью.",
    "libavutil.so.58": "FFmpeg libavutil — утилиты (Linux)",
    "libswscale.dll": "FFmpeg libswscale — масштабирование, конвертация цветовых пространств и форматов пикселей изображений.",
    "libswscale.so.7": "FFmpeg libswscale — масштабирование (Linux)",
    "libswresample.dll": "FFmpeg libswresample — ресемплинг, конвертация формата сэмплов и микширование аудио.",
    "libswresample.so.4": "FFmpeg libswresample — ресемплинг аудио (Linux)",
    "libvlc.dll": "LibVLC — медиа-движок VLC (воспроизведение, стриминг, транскодирование практически всех аудио/видео форматов).",
    "libvlc.so.5": "LibVLC — медиа-движок (Linux)",
    "libvlccore.dll": "LibVLC Core — ядро медиа-движка VLC (управление модулями, потоками, синхронизацией).",
    "libvlccore.so.9": "LibVLC Core — ядро медиа-движка (Linux)",
    "libgstreamer-1.0-0.dll": "GStreamer — мультимедийный фреймворк (обработка аудио/видео цепочками элементов: источники, кодеки, фильтры, приёмники).",
    "libgstreamer-1.0.so.0": "GStreamer — мультимедиа фреймворк (Linux)",
    "libtag.dll": "TagLib — чтение/запись метаданных аудиофайлов (ID3v1, ID3v2, APE, Vorbis Comments, MP4, ASF).",
    "libtag.so.1": "TagLib — метаданные аудио (Linux)",
    "libcdio.dll": "libcdio — работа с CD-ROM/CD-RW/DVD устройствами: чтение/запись треков, анализ файловых систем CD (ISO 9660).",
    "libcdio.so.19": "libcdio — работа с CD/DVD (Linux)",
}

_THIRD_PARTY_2D_GRAPHICS = {
    "cairo.dll": "Cairo — библиотека векторной 2D-графики с аппаратным ускорением. Отрисовка одинакового качества на экране и при печати (PDF, SVG, PS).",
    "libcairo.so.2": "Cairo — векторная графика (Linux)",
    "libcairo.dylib": "Cairo — векторная графика (macOS)",
    "libpixman-1-0.dll": "Pixman — низкоуровневая библиотека пиксельной графики (композитинг, альфа-смешение, используется Cairo и X server).",
    "libpixman-1.so.0": "Pixman — пиксельная графика (Linux)",
    "librsvg-2-2.dll": "librsvg — рендеринг SVG (Scalable Vector Graphics). Используется для отображения векторных иконок, иллюстраций.",
    "librsvg-2.so.2": "librsvg — рендеринг SVG (Linux)",
    "libSkia.dll": "Skia — библиотека 2D-графики (используется в Chrome, Android, Flutter, Firefox). Аппаратно-ускоренный рендеринг текста, фигур, изображений.",
    "libskia.so": "Skia — 2D-графика (Linux)",
    "libqrencode.dll": "libqrencode — генерация QR-кодов (Quick Response codes) в виде PNG, SVG, текста.",
    "libqrencode.so.4": "libqrencode — QR-коды (Linux)",
    "libzxing.dll": "ZXing — Zebra Crossing. Декодирование штрихкодов (QR, Data Matrix, EAN, UPC, Code128).",
    "libzxing.so": "ZXing — штрихкоды (Linux)",
}

_THIRD_PARTY_GUI_MORE = {
    "libwx_mswu_core-3.2.dll": "wxWidgets — кроссплатформенный GUI-фреймворк (нативные элементы управления через Win32 API, GTK, Cocoa).",
    "libwx_gtk3u_core-3.2.so.0": "wxWidgets — GUI-фреймворк (Linux GTK3)",
    "libfltk.dll": "FLTK — Fast Light Toolkit. Лёгкий GUI-фреймворк (игры, встраиваемые системы, САПР).",
    "libfltk.so.1.3": "FLTK — GUI-фреймворк (Linux)",
    "libnuklear.dll": "Nuklear — немедленный режим GUI (immediate mode), полностью в одном заголовочном файле.",
    "libnuklear.so": "Nuklear — GUI immediate mode (Linux)",
    "libimgui.dll": "Dear ImGui — немедленный режим GUI, популярный в инструментах разработки игр, профилировщиках, отладчиках.",
    "libimgui.so": "Dear ImGui — GUI для dev-инструментов (Linux)",
    "libIUP.dll": "IUP — кроссплатформенный GUI-фреймворк, использующий нативные элементы управления (Win32 API, Motif, GTK).",
    "libiup.so": "IUP — GUI (Linux)",
    "libnana.dll": "Nana C++ Library — кроссплатформенный GUI-фреймворк с современным C++11 API.",
    "libnana.so": "Nana C++ — GUI (Linux)",
}

_THIRD_PARTY_TERMINAL = {
    "libncursesw6.dll": "Ncurses — библиотека для создания текстовых пользовательских интерфейсов (TUI) в терминале: окна, меню, формы, работа с цветом.",
    "libncursesw.so.6": "Ncurses — TUI (Linux)",
    "libncurses.dylib": "Ncurses — TUI (macOS)",
    "libpanelw6.dll": "Panel — надстройка над ncurses для работы с панелями (перекрывающиеся окна, z-order).",
    "libpanelw.so.6": "Panel — панели для ncurses (Linux)",
    "libformw6.dll": "Form — надстройка над ncurses для создания форм ввода данных.",
    "libformw.so.6": "Form — формы ввода (Linux)",
    "libmenuw6.dll": "Menu — надстройка над ncurses для создания меню.",
    "libmenuw.so.6": "Menu — меню (Linux)",
    "libreadline8.dll": "GNU Readline — редактирование командной строки с историей, автодополнением и Emacs/vi-режимами.",
    "libreadline.so.8": "GNU Readline — командная строка (Linux)",
}

_THIRD_PARTY_COMPRESSION_MORE = {
    "liblz4.dll": "LZ4 — сверхбыстрое сжатие/распаковка (скорость > 500 МБ/с, используется в реальном времени, СУБД, ядре Linux).",
    "liblz4.so.1": "LZ4 — сверхбыстрое сжатие (Linux)",
    "libzstd.dll": "Zstandard (zstd) — современное сжатие от Facebook: высокая степень + высокая скорость (превосходит zlib).",
    "libzstd.so.1": "Zstandard — сжатие (Linux)",
    "libbrotlicommon.dll": "Brotli — сжатие общего назначения от Google (используется в HTTP Content-Encoding, веб-шрифтах WOFF2).",
    "libbrotlicommon.so.1": "Brotli — сжатие (Linux)",
    "libbrotlienc.dll": "Brotli Encoder — кодирование данных алгоритмом Brotli.",
    "libbrotlidec.dll": "Brotli Decoder — декодирование Brotli-сжатых данных.",
    "libsnappy.dll": "Snappy — быстрое сжатие от Google (средняя степень, очень высокая скорость). Используется в LevelDB, BigTable, Cassandra.",
    "libsnappy.so.1": "Snappy — быстрое сжатие (Linux)",
    "libzopfli.dll": "Zopfli — медленное, но максимально эффективное сжатие DEFLATE/zlib/gzip. Уменьшает размер на 3-8%.",
    "libzopfli.so.1": "Zopfli — высокоэффективное сжатие (Linux)",
    "libminizip.dll": "Minizip — работа с ZIP-архивами на основе zlib (создание, чтение, добавление файлов).",
    "libminizip.so.1": "Minizip — ZIP (Linux)",
    "libunrar.dll": "UnRAR — распаковка RAR-архивов (проприетарный формат сжатия, широко используемый в интернете).",
    "libunrar.so.5": "UnRAR — распаковка RAR (Linux)",
    "libarchive.dll": "libarchive — чтение/запись архивов: tar, pax, cpio, zip, xar, lha, ar, cab, 7-Zip, Warc, ISO 9660.",
    "libarchive.so.13": "libarchive — работа с архивами (Linux)",
}

_THIRD_PARTY_CRYPTO_MORE = {
    "libsodium.dll": "Libsodium — современная, простая криптографическая библиотека (шифрование, хеши, подписи, обмен ключами).",
    "libsodium.so.23": "Libsodium — криптография (Linux)",
    "libsodium.dylib": "Libsodium — криптография (macOS)",
    "libcryptopp.dll": "Crypto++ — обширная C++ библиотека криптографических алгоритмов (RSA, AES, ECC, SHA-3, ChaCha20-Poly1305).",
    "libcryptopp.so.8": "Crypto++ — криптография (Linux)",
    "libmbedtls.dll": "Mbed TLS — компактная реализация TLS и криптографии для встраиваемых систем (SSL/TLS, X.509, шифры).",
    "libmbedtls.so.14": "Mbed TLS — TLS/криптография (Linux)",
    "libmbedcrypto.dll": "Mbed Crypto — криптографический модуль Mbed TLS (шифры, хеши, ECC, RSA).",
    "libmbedcrypto.so.7": "Mbed Crypto — криптография (Linux)",
    "libmbedx509.dll": "Mbed X.509 — работа с сертификатами X.509 в экосистеме Mbed TLS.",
    "libwolfssl.dll": "wolfSSL — лёгкая реализация TLS/SSL (сертифицирована FIPS), оптимизирована для встраиваемых систем.",
    "libwolfssl.so.35": "wolfSSL — TLS (Linux)",
    "libgpg-error.dll": "Libgpg-error — общие коды ошибок для GnuPG и связанных библиотек (GPGME, libgcrypt, libksba).",
    "libgpg-error.so.0": "Libgpg-error — коды ошибок (Linux)",
    "libgpgme-11.dll": "GPGME — GnuPG Made Easy. Высокоуровневый API для шифрования, подписи, управления ключами PGP.",
    "libgpgme.so.11": "GPGME — GPG API (Linux)",
    "libtasn1.dll": "Libtasn1 — библиотека ASN.1 (Abstract Syntax Notation One). Кодирование/декодирование структур данных.",
    "libtasn1.so.6": "Libtasn1 — ASN.1 (Linux)",
}

# Объединение всех сторонних словарей
THIRD_PARTY_MODULES = {}
THIRD_PARTY_MODULES.update(_THIRD_PARTY_BROWSER)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_CRYPTO)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_COMPRESSION)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_DATABASE)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_NETWORK)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_GRAPHICS)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_LOGGING)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_XML)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_VIRTUALIZATION)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_VPN)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_QT)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_ML)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_RPC)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_JAVASCRIPT)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_IMAGE)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_AUDIO)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_CV)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_ML_MORE)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_RPC_MORE)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_GAME_MULTIMEDIA)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_2D_GRAPHICS)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_GUI_MORE)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_TERMINAL)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_COMPRESSION_MORE)
THIRD_PARTY_MODULES.update(_THIRD_PARTY_CRYPTO_MORE)