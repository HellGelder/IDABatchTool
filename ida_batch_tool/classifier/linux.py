"""Словари для Linux-модулей.

Правила поддержки словарей:
1. Каждый модуль присутствует ровно в одной группе (без дубликатов).
2. Группы соответствуют структуре LSB (Linux Standard Base), glibc,
   freedesktop.org, systemd, X.Org и другим компонентам Linux.
3. Описания — на русском, подробные, технически точные.
"""

# ═══════════════════════════════════════════════════════════════════════════
# 1. CORE — GNU C Library (glibc) и базовые компоненты пользовательского
#    пространства, специфицированные в LSB (Linux Standard Base).
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_CORE_LIBS = {
    "libc.so.6": (
        "GNU C Library (glibc) — основная библиотека языка C. Реализует "
        "стандарт ISO C (printf, malloc, fopen, memcpy) и интерфейс системных "
        "вызовов POSIX (open, read, write, fork, exec). Начиная с glibc 2.34 "
        "включает функции libpthread, libdl, librt, libutil, libanl."
    ),
    "libm.so.6": (
        "Math Library (libm) — математическая библиотека glibc. Реализует "
        "функции с плавающей точкой (sin, cos, sqrt, log, pow), соответствующие "
        "стандарту IEEE 754."
    ),
    "libmvec.so.1": (
        "Math Vector Library (libmvec) — расширение glibc для векторных "
        "математических операций с использованием SIMD (AVX, SSE, NEON). "
        "Оптимизированные вычисления sin, cos, pow, log на массивах."
    ),
    "libpthread.so.0": (
        "POSIX Threads Library (libpthread) — реализация многопоточности "
        "по стандарту POSIX. Управление потоками, мьютексами, условными "
        "переменными, барьерами, rw-lock. Начиная с glibc 2.34 встроена "
        "в libc, но может присутствовать как отдельная библиотека для совместимости."
    ),
    "libdl.so.2": (
        "Dynamic Linker Library (libdl) — поддержка динамической загрузки "
        "разделяемых объектов: dlopen(), dlsym(), dlclose(). Начиная с "
        "glibc 2.34 функциональность встроена в libc."
    ),
    "librt.so.1": (
        "POSIX Real-time Extensions (librt) — расширения реального времени: "
        "семафоры POSIX, очереди сообщений, разделяемая память, таймеры "
        "высокого разрешения, асинхронный ввод/вывод (AIO)."
    ),
    "libresolv.so.2": (
        "DNS Resolver Library (libresolv) — функции для разрешения доменных "
        "имён (DNS). Реализует res_query(), res_send(), gethostbyname(), "
        "getaddrinfo(), работу с /etc/resolv.conf."
    ),
    "libnsl.so.1": (
        "Network Services Library (libnsl) — сетевые службы: работа с NIS "
        "(Network Information Service), сетевыми базами данных (ethers, "
        "netgroup, rpc). Устаревшая библиотека, но сохраняется для совместимости."
    ),
    "libutil.so.1": (
        "Utility Library (libutil) — вспомогательные функции: работа "
        "с терминалом (openpty, forkpty), управление учётными записями "
        "(login, logout). Начиная с glibc 2.34 встроена в libc."
    ),
    "libcrypt.so.1": (
        "Crypt Library (libcrypt) — шифрование и хеширование паролей. "
        "Функции crypt(), crypt_r(), encrypt() для одностороннего "
        "хеширования DES, MD5, SHA-256/512. В glibc 2.39+ удалена, "
        "заменена на libxcrypt (libcrypt.so.2)."
    ),
    "libcrypt.so.2": (
        "libxcrypt — современная библиотека хеширования паролей. Замена "
        "libcrypt от glibc с поддержкой bcrypt, yescrypt, gost_yescrypt, "
        "scrypt, SHA-256/512, MD5, DES. Используется в современных "
        "дистрибутивах (Fedora 39+, Debian 12+)."
    ),
    "libanl.so.1": (
        "Asynchronous Name Lookup Library (libanl) — асинхронное разрешение "
        "имён хостов (getaddrinfo_a, gai_suspend) без блокировки "
        "вызывающего потока. Начиная с glibc 2.34 встроена в libc."
    ),
    "libBrokenLocale.so.1": (
        "Broken Locale Library — библиотека-заглушка для исправления "
        "некорректной локализации. Используется некоторыми приложениями "
        "для переопределения несовместимых с glibc реализаций locale."
    ),
    "libpcprofile.so.1": (
        "PC Profiling Library (libpcprofile) — поддержка профилирования "
        "программ на уровне процессора (prof, gprof)."
    ),
    "libnss_compat.so.2": (
        "NSS Compatibility Module — библиотека для совместимости с "
        "устаревшими сетевыми базами данных (files, NIS, DNS). "
        "Часть Name Service Switch (NSS), управляемого через /etc/nsswitch.conf."
    ),
    "libnss_files.so.2": (
        "NSS Files Module — библиотека Name Service Switch для доступа "
        "к локальным файлам (/etc/passwd, /etc/group, /etc/hosts, "
        "/etc/services). Базовый провайдер NSS."
    ),
    "libnss_dns.so.2": (
        "NSS DNS Module — библиотека Name Service Switch для разрешения "
        "имён через DNS. Используется совместно с libresolv."
    ),
    "libnss_mdns.so.2": (
        "NSS mDNS Module — библиотека Name Service Switch для разрешения "
        "имён через Multicast DNS (Bonjour/Avahi). Обеспечивает "
        "обнаружение .local имён в локальной сети."
    ),
    "libnss_myhostname.so.2": (
        "NSS myhostname Module — библиотека NSS от systemd, предоставляющая "
        "разрешение локального hostname без обращения к /etc/hosts."
    ),
    "libnss_mymachines.so.2": (
        "NSS mymachines Module — библиотека NSS от systemd для разрешения "
        "имён контейнеров, управляемых systemd-machined."
    ),
    "libnss_resolve.so.2": (
        "NSS resolve Module — библиотека NSS от systemd-resolved для "
        "разрешения имён через systemd-resolved (Caching DNS stub)."
    ),
    "libnss_systemd.so.2": (
        "NSS systemd Module — библиотека NSS от systemd для разрешения "
        "имён динамических пользователей (DynamicUser)."
    ),
    "libnss_sss.so.2": (
        "NSS SSS Module — библиотека Name Service Switch от SSSD (System "
        "Security Services Daemon) для интеграции с Active Directory, "
        "LDAP, Kerberos."
    ),
    "libnss_ldap.so.2": (
        "NSS LDAP Module — библиотека Name Service Switch для доступа "
        "к LDAP-каталогам (OpenLDAP)."
    ),
    "libnss_hesiod.so.2": (
        "NSS Hesiod Module — библиотека Name Service Switch для доступа "
        "к Hesiod (система имён на основе DNS, использовалась в Athena)."
    ),
    "libnss_db.so.2": (
        "NSS DB Module — библиотека Name Service Switch для доступа "
        "к Berkeley DB (/var/db/misc.dat)."
    ),
    "libnss_test1.so.2": (
        "NSS Test Module — библиотека Name Service Switch для тестирования "
        "и отладки NSS-конфигурации."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 2. DYNAMIC LINKER — загрузчики ELF для разных архитектур
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_DYNAMIC_LINKER = {
    "ld-linux.so.2": (
        "Dynamic Linker/Loader (32-bit) — загружает исполняемые файлы ELF, "
        "разрешает зависимости разделяемых библиотек, выполняет релокации. "
        "Для архитектуры x86 (32-bit)."
    ),
    "ld-linux-x86-64.so.2": (
        "Dynamic Linker/Loader (x86-64) — загрузчик ELF для 64-битной "
        "архитектуры x86-64."
    ),
    "ld-linux-aarch64.so.1": (
        "Dynamic Linker/Loader (AArch64) — загрузчик ELF для архитектуры "
        "ARM 64-bit (AArch64)."
    ),
    "ld-linux-armhf.so.3": (
        "Dynamic Linker/Loader (ARM hard-float) — загрузчик ELF для "
        "архитектуры ARM с аппаратной поддержкой floating-point."
    ),
    "ld-linux-riscv64.so.1": (
        "Dynamic Linker/Loader (RISC-V 64-bit) — загрузчик ELF для "
        "архитектуры RISC-V 64-bit."
    ),
    "ld-linux-powerpc64le.so.1": (
        "Dynamic Linker/Loader (ppc64le) — загрузчик ELF для архитектуры "
        "PowerPC 64-bit little-endian."
    ),
    "ld-linux-s390x.so.2": (
        "Dynamic Linker/Loader (s390x) — загрузчик ELF для архитектуры "
        "IBM System/390 64-bit."
    ),
    "linux-vdso.so.1": (
        "Linux Virtual Dynamic Shared Object — виртуальная библиотека, "
        "внедряемая ядром в адресное пространство каждого процесса. "
        "Предоставляет оптимизированные реализации часто используемых "
        "системных вызовов (gettimeofday, clock_gettime, getcpu) без "
        "переключения в режим ядра."
    ),
    "linux-gate.so.1": (
        "Linux Gate DSO — виртуальная библиотека для 32-bit x86, "
        "обеспечивающая доступ к расширенным системным вызовам (sysenter). "
        "Аналог linux-vdso для старых ядер."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 3. GRAPHICS — X11, Wayland, Mesa, DRM, шрифты, 2D-графика
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_GRAPHICS = {
    # --- X11 Window System ---
    "libX11.so.6": (
        "X11 Client Library (libX11) — основной клиентский интерфейс "
        "к X Window System. Создание окон, управление событиями, "
        "работа с колор-картами, передача изображений между клиентом "
        "и сервером."
    ),
    "libX11-xcb.so.1": (
        "X11 XCB Integration — библиотека, обеспечивающая взаимодействие "
        "между libX11 и libxcb. Позволяет использовать XCB для "
        "асинхронного доступа к X-серверу."
    ),
    "libxcb.so.1": (
        "XCB (X C Binding) — современная замена libX11 с асинхронным "
        "протоколом. Предоставляет прямой доступ к X11-протоколу "
        "с минимальными накладными расходами."
    ),
    "libxcb-dri3.so.0": (
        "XCB DRI3 Extension — расширение XCB для Direct Rendering "
        "Infrastructure 3. Позволяет клиентам напрямую получать "
        "буферы от драйвера GPU через X-сервер."
    ),
    "libXext.so.6": (
        "X11 Extension Library — поддержка стандартных расширений "
        "X11: SHAPE (окна непрямоугольной формы), MIT-SHM (разделяемая "
        "память), DPMS (управление питанием монитора), XTEST."
    ),
    "libXrender.so.1": (
        "X Rendering Extension — библиотека для рендеринга с "
        "поддержкой альфа-смешивания, композитинга и преобразований "
        "изображений. Используется современными тулкитами (GTK, Qt)."
    ),
    "libXcomposite.so.1": (
        "X Composite Extension — библиотека поддержки композитинга "
        "окон. Позволяет оконным менеджерам (Compiz, KWin, Mutter) "
        "рендерить окна в offscreen-буферы."
    ),
    "libXdamage.so.1": (
        "X Damage Extension — библиотека для отслеживания изменений "
        "(повреждений) в окнах. Используется композиционными оконными "
        "менеджерами для перерисовки только изменившихся областей."
    ),
    "libXfixes.so.3": (
        "X Fixes Extension — библиотека расширений для исправления "
        "недостатков X11: сохранение содержимого затенённых областей, "
        "видимые регионы, улучшенная работа с курсором."
    ),
    "libXcursor.so.1": (
        "X Cursor Library — библиотека для работы с темами курсоров "
        "в X11. Загрузка, масштабирование и изменение форм курсоров."
    ),
    "libXinerama.so.1": (
        "Xinerama Extension — библиотека для поддержки многомониторных "
        "конфигураций. Предоставляет информацию о расположении "
        "и размерах каждого монитора."
    ),
    "libXrandr.so.2": (
        "X Resize and Rotate Extension — библиотека для динамического "
        "изменения разрешения, ориентации и обновления мониторов "
        "без перезапуска X-сервера."
    ),
    "libXxf86vm.so.1": (
        "X Free86 Video Mode Extension — библиотека для управления "
        "видеорежимами: изменение разрешения, частоты обновления, "
        "получение информации о модели."
    ),
    "libXi.so.6": (
        "X Input Extension — библиотека для работы с расширенным "
        "вводом: поддержка мультитач, сенсорных экранов, графических "
        "планшетов, дополнительных кнопок мыши."
    ),
    "libXt.so.6": (
        "X Toolkit Intrinsics — библиотека базовых виджетов X11 "
        "(Athena Widgets). Предоставляет каркас для построения "
        "GUI-приложений на X11."
    ),
    "libXmu.so.6": (
        "X Miscellaneous Utilities — библиотека вспомогательных "
        "функций для X11 Toolkit Intrinsics: управление виджетами, "
        "синтаксический анализ командной строки."
    ),
    "libXpm.so.4": (
        "X Pixmap Library — библиотека для работы с X Pixmap (XPM) "
        "форматом изображений с поддержкой прозрачности."
    ),
    "libXau.so.1": (
        "X11 Authorization Library — библиотека аутентификации X11. "
        "Реализует механизмы MIT-MAGIC-COOKIE-1 и XDM-AUTHORIZATION-1."
    ),
    # --- Wayland ---
    "libwayland-client.so.0": (
        "Wayland Client Library — библиотека для создания Wayland-"
        "клиентов. Управление поверхностями, буферами, событиями "
        "ввода через протокол Wayland."
    ),
    "libwayland-server.so.0": (
        "Wayland Server Library — библиотека для создания Wayland-"
        "композиторов (серверов). Реализует диспетчеризацию "
        "протоколов, управление клиентами и глобальными объектами."
    ),
    "libwayland-cursor.so.0": (
        "Wayland Cursor Library — библиотека для работы с курсорами "
        "в Wayland. Загрузка и отображение тем курсоров через "
        "wl_buffer."
    ),
    "libwayland-egl.so.1": (
        "Wayland EGL Library — связующая библиотека между Wayland "
        "и EGL. Позволяет создавать EGL-поверхности из Wayland-"
        "поверхностей для аппаратно-ускоренного рендеринга."
    ),
    # --- Mesa / DRM / OpenGL / Vulkan ---
    "libdrm.so.2": (
        "Direct Rendering Manager (DRM) Library — библиотека "
        "пользовательского пространства для взаимодействия с "
        "DRM-драйверами ядра. Управление буферами (GEM/KMS), "
        "контекстами, синхронизацией GPU."
    ),
    "libdrm_amdgpu.so.1": (
        "DRM AMDGPU Library — библиотека DRM для драйвера AMDGPU. "
        "Управление буферами, планами, синхронизацией для GPU AMD."
    ),
    "libdrm_intel.so.1": (
        "DRM Intel Library — библиотека DRM для интегрированной "
        "графики Intel. Управление буферами, релокациями, "
        "контекстами."
    ),
    "libdrm_nouveau.so.2": (
        "DRM Nouveau Library — библиотека DRM для открытого "
        "драйвера NVIDIA Nouveau."
    ),
    "libdrm_radeon.so.1": (
        "DRM Radeon Library — библиотека DRM для драйвера AMD Radeon."
    ),
    "libEGL.so.1": (
        "EGL Library — интерфейс между API рендеринга (OpenGL ES, "
        "Vulkan) и оконной системой (X11, Wayland). Управление "
        "контекстами, поверхностями, конфигурациями дисплея."
    ),
    "libGL.so.1": (
        "OpenGL Library — реализация OpenGL API от Mesa. "
        "Обеспечивает аппаратно-ускоренную 2D/3D-графику через "
        "стандартизированный кроссплатформенный интерфейс."
    ),
    "libGLX.so.0": (
        "GLX Extension — связующее звено между OpenGL и X11. "
        "Позволяет создавать OpenGL-контексты, связанные "
        "с X11-окнами."
    ),
    "libGLESv2.so.2": (
        "OpenGL ES 2.0 Library — реализация OpenGL ES 2.0 "
        "с программируемым графическим конвейером."
    ),
    "libGLESv1_CM.so.1": (
        "OpenGL ES 1.1 Common Profile — реализация OpenGL ES 1.1 "
        "с фиксированным графическим конвейером."
    ),
    "libgbm.so.1": (
        "Generic Buffer Management (GBM) — библиотека для "
        "управления буферами GPU. Используется Mesa, kmscube, "
        "и Wayland-композиторами для выделения и управления "
        "фреймбуферами."
    ),
    "libvulkan.so.1": (
        "Vulkan Loader — библиотека-загрузчик Vulkan. Обеспечивает "
        "обнаружение и загрузку ICD (Installable Client Driver) "
        "для Vulkan от разных производителей (NVIDIA, AMD, Intel)."
    ),
    # --- VA-API / VDPAU ---
    "libva.so.2": (
        "Video Acceleration API (VA-API) — библиотека аппаратного "
        "ускорения кодирования/декодирования видео. Поддерживает "
        "H.264, H.265, VP9, AV1 на GPU Intel, AMD."
    ),
    "libva-drm.so.2": (
        "VA-API DRM Backend — бэкенд VA-API для взаимодействия "
        "с DRM. Используется для аппаратного ускорения видео "
        "через DRM."
    ),
    "libva-x11.so.2": (
        "VA-API X11 Backend — бэкенд VA-API для взаимодействия "
        "с X11."
    ),
    "libvdpau.so.1": (
        "Video Decode and Presentation API for Unix (VDPAU) — "
        "библиотека аппаратного ускорения видео для NVIDIA. "
        "Декодирование H.264, MPEG-2, VC-1 на GPU."
    ),
    # --- Fonts & Text ---
    "libfreetype.so.6": (
        "FreeType 2 — библиотека рендеринга шрифтов. Загрузка "
        "и растеризация TrueType, OpenType, Type1, CFF, PDF-шрифтов. "
        "Используется почти всеми GUI-приложениями."
    ),
    "libfontconfig.so.1": (
        "Fontconfig — библиотека настройки и обнаружения шрифтов. "
        "Управление списком установленных шрифтов, подбор шрифта "
        "по параметрам, работает с /etc/fonts/fonts.conf."
    ),
    "libpango-1.0.so.0": (
        "Pango — библиотека для отрисовки и разметки текста. "
        "Поддержка сложных скриптов (арабский, деванагари), "
        "BiDi, форматирование, работа с разными тулкитами."
    ),
    "libpangocairo-1.0.so.0": (
        "Pango Cairo Backend — бэкенд отрисовки Pango через Cairo. "
        "Обеспечивает рендеринг текста с использованием библиотеки "
        "векторной графики Cairo."
    ),
    "libpangoft2-1.0.so.0": (
        "Pango FreeType Backend — бэкенд отрисовки Pango через "
        "FreeType. Используется для интеграции с X11 (Xft)."
    ),
    "libharfbuzz.so.0": (
        "HarfBuzz — библиотека shaping'а текста (OpenType layout). "
        "Обработка сложных шрифтовых функций: лигатуры, кернинг, "
        "позиционирование глифов, арабские формы."
    ),
    "libfribidi.so.0": (
        "FriBidi — библиотека для работы с двунаправленным текстом "
        "(BiDi). Реализация Unicode Bidirectional Algorithm для "
        "корректного отображения смешанного текста (арабский + "
        "английский, иврит + цифры)."
    ),
    # --- 2D Graphics ---
    "libcairo.so.2": (
        "Cairo — библиотека векторной 2D-графики с аппаратным "
        "ускорением. Отрисовка одинакового качества на экране "
        "и при печати (PDF, SVG, PS). Используется GTK, Firefox, "
        "WebKit."
    ),
    "libpixman-1.so.0": (
        "Pixman — низкоуровневая библиотека пиксельной графики. "
        "Композитинг, альфа-смешение, преобразования изображений. "
        "Используется Cairo и X-сервером."
    ),
    "libgdk_pixbuf-2.0.so.0": (
        "GDK Pixbuf — библиотека загрузки изображений для GTK. "
        "Поддерживает JPEG, PNG, TIFF, GIF, BMP, ICO, SVG через "
        "librsvg. Автоматическое масштабирование и изменение "
        "размера."
    ),
    "librsvg-2.so.2": (
        "librsvg — библиотека рендеринга SVG (Scalable Vector "
        "Graphics). Используется GTK для отображения векторных "
        "иконок и иллюстраций."
    ),
    "libatk-1.0.so.0": (
        "ATK (Accessibility Toolkit) — библиотека доступности "
        "для GTK-приложений. Предоставляет интерфейсы для "
        "экранных дикторов и других вспомогательных технологий."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 4. AUDIO — ALSA, PulseAudio, PipeWire, JACK
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_AUDIO = {
    "libasound.so.2": (
        "ALSA (Advanced Linux Sound Architecture) — библиотека "
        "низкоуровневого звукового API. Управление аудиоустройствами, "
        "микширование, PCM-потоки, MIDI. Используется PulseAudio, "
        "PipeWire и напрямую приложениями."
    ),
    "libpulse.so.0": (
        "PulseAudio Client Library — клиентская библиотека звукового "
        "сервера PulseAudio. Микширование, маршрутизация потоков, "
        "сетевая передача звука, управление громкостью."
    ),
    "libpulse-simple.so.0": (
        "PulseAudio Simple API — упрощённый API PulseAudio для "
        "базового воспроизведения и записи звука без управления "
        "контекстом и потоком."
    ),
    "libpipewire-0.3.so.0": (
        "PipeWire — мультимедийный фреймворк нового поколения. "
        "Управление аудио- и видеопотоками с низкой задержкой. "
        "Замена PulseAudio и JACK в современных дистрибутивах."
    ),
    "libspa-0.2.so.0": (
        "SPA (Simple Plugin API) — плагинная архитектура PipeWire. "
        "Управление узлами, портами, буферами, планированием "
        "обработки аудио/видео."
    ),
    "libjack.so.0": (
        "JACK (JACK Audio Connection Kit) — профессиональный "
        "звуковой сервер с низкой задержкой. Используется в "
        "DAW (Logic, Ardour) и профессиональных аудио-приложениях."
    ),
    "libsndfile.so.1": (
        "libsndfile — библиотека для чтения/записи звуковых файлов. "
        "Поддерживает WAV, AIFF, AU, FLAC, Ogg Vorbis и другие "
        "форматы через единый API."
    ),
    "libsamplerate.so.0": (
        "libsamplerate (SRC) — библиотека преобразования частоты "
        "дискретизации аудио (sample rate conversion). Высокое "
        "качество ресемплинга (Sinc, ZOH, Linear)."
    ),
    "libmysofa.so.0": (
        "libmysofa — библиотека для работы с HRTF (Head-Related "
        "Transfer Function), используемая для пространственного "
        "аудио в PipeWire."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 5. NETWORK — libnl, NetworkManager, firewall, Avahi, libpcap, LDAP/SASL
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_NETWORK = {
    "libnl-3.so.200": (
        "Netlink Protocol Library (libnl-3) — библиотека для работы "
        "с netlink-сокетами Linux. Взаимодействие с ядром для "
        "управления сетевыми интерфейсами, маршрутизацией, "
        "соседями (ARP), мостами, VLAN."
    ),
    "libnl-route-3.so.200": (
        "Netlink Route Library — библиотека для управления "
        "маршрутизацией через netlink. Работа с таблицами "
        "маршрутизации, правилами, nexthop."
    ),
    "libnl-idiag-3.so.200": (
        "Netlink Inet Diag Library — библиотека для диагностики "
        "сетевых соединений через netlink (INET_DIAG). "
        "Аналог /proc/net/tcp."
    ),
    "libnm.so.0": (
        "NetworkManager Client Library — клиентская библиотека "
        "для взаимодействия с NetworkManager. Управление "
        "сетевыми подключениями, Wi-Fi, VPN, модемами."
    ),
    "libnma.so.0": (
        "NetworkManager Applet Library — библиотека GUI-виджетов "
        "для NetworkManager. Используется в апплете nm-applet "
        "и аналогичных интерфейсах."
    ),
    "libfwupd.so.2": (
        "Firmware Update Daemon Library — библиотека для "
        "обновления прошивок устройств через fwupd (LVFS)."
    ),
    "libpcap.so.1": (
        "Packet Capture Library (libpcap) — библиотека захвата "
        "сетевых пакетов. Используется tcpdump, Wireshark, "
        "nmap, IDS/IPS системами."
    ),
    "libcap-ng.so.0": (
        "Libcap-ng — упрощённое управление POSIX capabilities. "
        "Предоставляет процессы только необходимые привилегии "
        "без полного доступа root."
    ),
    "libavahi-client.so.3": (
        "Avahi Client Library — клиентская библиотека для "
        "mDNS/DNS-SD (Bonjour). Обнаружение служб в локальной "
        "сети: принтеры, серверы, мультимедиа-устройства."
    ),
    "libavahi-common.so.3": (
        "Avahi Common Library — общая библиотека Avahi. "
        "Содержит базовые типы, строки, обработку ошибок, "
        "используемые всеми компонентами Avahi."
    ),
    "libavahi-glib.so.1": (
        "Avahi GLib Integration — интеграция Avahi с GLib "
        "main loop. Позволяет использовать Avahi в GTK/GLib-"
        "приложениях."
    ),
    "libndp.so.1": (
        "Neighbor Discovery Protocol Library — библиотека для "
        "отправки и получения NDP-пакетов (Neighbor Discovery "
        "Protocol, IPv6). Используется для SLAAC."
    ),
    "libldap-2.5.so.0": (
        "OpenLDAP Library — клиентская библиотека LDAP (Lightweight "
        "Directory Access Protocol). Доступ к каталогам LDAP: "
        "поиск, аутентификация, модификация записей."
    ),
    "liblber-2.5.so.0": (
        "OpenLDAP BER Library — библиотека кодирования/декодирования "
        "BER (Basic Encoding Rules) для LDAP."
    ),
    "libsasl2.so.2": (
        "Cyrus SASL Library — библиотека Simple Authentication "
        "and Security Layer. Поддержка множества механизмов "
        "аутентификации: PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5, "
        "GSSAPI, EXTERNAL."
    ),
    "libcups.so.2": (
        "CUPS (Common Unix Printing System) — библиотека для "
        "взаимодействия с сервером печати. Отправка заданий "
        "печати, управление принтерами, получение статуса."
    ),
    "libnetsnmp.so.40": (
        "Net-SNMP Library — реализация протокола SNMP (Simple "
        "Network Management Protocol). Управление сетевыми "
        "устройствами, сбор статистики, SNMP-ловушки."
    ),
    "libsoup-3.0.so.0": (
        "libsoup — HTTP клиент-серверная библиотека для GLib. "
        "Используется в GNOME для HTTP-запросов (WebDAV, "
        "REST API, загрузка файлов)."
    ),
    "libcurl-gnutls.so.4": (
        "libcurl (GnuTLS variant) — библиотека работы с URL, "
        "собранная с GnuTLS вместо OpenSSL. Используется "
        "в системах, где OpenSSL нежелателен."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 6. SECURITY — PAM, SELinux, AppArmor, Audit, keyutils, PC/SC, FIDO2
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_SECURITY = {
    "libpam.so.0": (
        "Pluggable Authentication Modules (PAM) — гибкая система "
        "аутентификации. Позволяет настраивать способы проверки "
        "подлинности пользователей: пароль, биометрия, токены, "
        "LDAP, Kerberos, SSH-ключи."
    ),
    "libpam_misc.so.0": (
        "PAM Miscellaneous Library — вспомогательные функции "
        "для PAM-модулей: обработка ввода пароля, диалоги "
        "с пользователем."
    ),
    "libpamc.so.0": (
        "PAM Conversation Library — библиотека для организации "
        "диалога (conversation) между PAM-модулями и приложением."
    ),
    "libcap.so.2": (
        "Linux Capabilities Library — управление POSIX capabilities. "
        "Позволяет предоставлять процессам отдельные привилегии "
        "суперпользователя (CAP_NET_RAW, CAP_SYS_ADMIN) без "
        "полного доступа root."
    ),
    "libseccomp.so.2": (
        "Secure Computing Mode (seccomp) Library — фильтрация "
        "системных вызовов. Позволяет процессам ограничивать "
        "набор доступных системных вызовов для повышения "
        "безопасности (sandbox, контейнеры, браузеры)."
    ),
    "libselinux.so.1": (
        "SELinux Userspace Library — интерфейс к Security-Enhanced "
        "Linux. Управление контекстами безопасности, политиками, "
        "метками файлов. Обязательное управление доступом (MAC) "
        "для Linux."
    ),
    "libsemanage.so.1": (
        "SELinux Policy Management Library — библиотека для "
        "управления SELinux-политиками: установка, обновление, "
        "компиляция политик."
    ),
    "libsepol.so.1": (
        "SELinux Policy Library — библиотека для работы с "
        "SELinux-политиками на низком уровне: чтение, запись, "
        "анализ бинарных политик."
    ),
    "libapparmor.so.1": (
        "AppArmor Library — интерфейс к системе принудительного "
        "контроля доступа AppArmor. Ограничивает возможности "
        "приложений на основе профилей безопасности."
    ),
    "libaudit.so.1": (
        "Audit Library — система аудита Linux. Предоставляет API "
        "для отслеживания событий безопасности, системных вызовов, "
        "изменений файлов в соответствии с правилами аудита."
    ),
    "libauparse.so.0": (
        "Audit Parser Library — библиотека для разбора и анализа "
        "сообщений аудита Linux. Преобразование сырых событий "
        "в структурированные данные."
    ),
    "libkeyutils.so.1": (
        "Keyutils Library — библиотека для управления ключами "
        "ядра Linux (keyrings). Позволяет хранить криптографические "
        "ключи, сертификаты, токены в защищённом пространстве "
        "ядра."
    ),
    "libp11-kit.so.0": (
        "PKCS#11 Kit — библиотека для загрузки и управления "
        "PKCS#11 модулями (токенами, смарт-картами, TPM). "
        "Обеспечивает единый интерфейс доступа к аппаратным "
        "криптографическим устройствам."
    ),
    "libpcsclite.so.1": (
        "PC/SC Lite — библиотека для работы со смарт-картами "
        "через PC/SC API. Используется для доступа к USB-токенам, "
        "смарт-картам, электронным подписям."
    ),
    "libfido2.so.1": (
        "libfido2 — библиотека для работы с FIDO2/U2F токенами. "
        "Поддержка WebAuthn, FIDO2 CTAP, U2F. Аутентификация "
        "с помощью аппаратных ключей (YubiKey, SoloKey)."
    ),
    "libtss2-esys.so.0": (
        "TPM2 Enhanced System API (ESAPI) — библиотека для "
        "взаимодействия с TPM 2.0 (Trusted Platform Module) "
        "на системном уровне. Шифрование, подпись, измерение "
        "состояния системы."
    ),
    "libtss2-mu.so.0": (
        "TPM2 Marshaling/Unmarshaling Library — библиотека "
        "сериализации/десериализации TPM2-команд (TSS2 MU)."
    ),
    "libtss2-rc.so.0": (
        "TPM2 Return Code Library — библиотека для преобразования "
        "кодов возврата TPM2 в читаемые сообщения об ошибках."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 7. CRYPTO — системные криптобиблиотеки (GnuTLS, Nettle, GnuPG)
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_CRYPTO = {
    "libgnutls.so.30": (
        "GnuTLS — библиотека безопасной передачи данных. Реализует "
        "протоколы TLS 1.3, DTLS, SRP. Является альтернативой "
        "OpenSSL во многих системных приложениях (NetworkManager, "
        "CUPS, systemd-resolved)."
    ),
    "libnettle.so.8": (
        "Nettle — низкоуровневая криптографическая библиотека. "
        "Содержит реализации AES, RSA, DSA, ECDSA, SHA-1/2/3, "
        "ChaCha20-Poly1305. Используется GnuTLS и GnuPG."
    ),
    "libhogweed.so.6": (
        "Hogweed — библиотека криптографии с эллиптическими "
        "кривыми (ECC) на основе Nettle. Реализует ECDSA, "
        "ECDH, Ed25519, Curve25519."
    ),
    "libgcrypt.so.20": (
        "Libgcrypt — криптографическая библиотека общего "
        "назначения от GnuPG. Шифрование, хеширование, цифровые "
        "подписи, генерация ключей. Используется systemd, "
        "GnuPG, LUKS."
    ),
    "libgpg-error.so.0": (
        "Libgpg-error — общие коды ошибок для GnuPG и связанных "
        "библиотек (libgcrypt, libksba, libassuan)."
    ),
    "libksba.so.1": (
        "KSBA (X.509 Library) — библиотека для работы с "
        "сертификатами X.509, CMS, PKCS#7, PKCS#12, CRL, "
        "OCSP. Часть экосистемы GnuPG."
    ),
    "libassuan.so.0": (
        "Assuan — библиотека для межпроцессного взаимодействия "
        "(IPC), используемая в GnuPG. Обеспечивает канал связи "
        "между gpg и gpg-agent."
    ),
    "libcryptsetup.so.12": (
        "Cryptsetup Library — библиотека для управления "
        "шифрованием блочных устройств (LUKS, LUKS2, plain, "
        "BitLocker, TrueCrypt/VeraCrypt). Интерфейс к dm-crypt."
    ),
    "libverto.so.1": (
        "Libverto — библиотека абстракции циклов событий "
        "(event loop). Используется в криптографических "
        "приложениях (MIT Kerberos) для асинхронных операций."
    ),
    "libgmp.so.10": (
        "GMP (GNU Multiple Precision Arithmetic Library) — "
        "библиотека арифметики произвольной точности. "
        "Используется в GnuTLS, Nettle, GnuPG, cryptsetup "
        "для криптографических расчётов."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 8. SYSTEM — systemd, D-Bus, polkit, udev, elogind, fwupd, btrfs
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_SYSTEM = {
    "libsystemd.so.0": (
        "Systemd Client Library — интерфейс для взаимодействия "
        "с системным менеджером systemd. Управление службами, "
        "сокетами, таймерами, журналами."
    ),
    "libsystemd-shared.so": (
        "Systemd Internal Shared Library — общий код для всех "
        "компонентов systemd: journal, pid1, logind, resolved, "
        "timedated, localed, hostnamed."
    ),
    "libdbus-1.so.3": (
        "D-Bus Message Bus System — система межпроцессного "
        "взаимодействия (IPC). Обеспечивает обмен сообщениями "
        "между приложениями и службами через system bus "
        "(системные события) и session bus (пользовательские "
        "приложения)."
    ),
    "libdbus-glib-1.so.2": (
        "D-Bus GLib Bindings — интеграция D-Bus с GLib main loop. "
        "Позволяет GTK/GLib-приложениям использовать D-Bus "
        "асинхронно."
    ),
    "libpolkit-gobject-1.so.0": (
        "PolicyKit Authorization Library — библиотека для "
        "управления привилегиями. Позволяет непривилегированным "
        "процессам выполнять административные действия через "
        "политики авторизации."
    ),
    "libpolkit-agent-1.so.0": (
        "PolicyKit Agent Library — библиотека для создания "
        "агентов аутентификации PolicyKit. Запрашивает пароль "
        "или подтверждение от пользователя."
    ),
    "libudev.so.1": (
        "Udev Device Manager Library — интерфейс к менеджеру "
        "устройств Linux. Обнаружение, перечисление и управление "
        "устройствами (udev). Критически важен для корректной "
        "работы драйверов и пользовательских приложений."
    ),
    "libmount.so.1": (
        "Libmount — монтирование и размонтирование файловых "
        "систем. Основа утилит mount/umount. Предоставляет "
        "безопасный парсинг /etc/fstab."
    ),
    "libblkid.so.1": (
        "Libblkid — идентификация блочных устройств по "
        "сигнатурам файловых систем. Определяет тип ФС (ext4, "
        "XFS, Btrfs, NTFS, FAT32) и метаданные (UUID, LABEL)."
    ),
    "libkmod.so.2": (
        "Libkmod — управление модулями ядра Linux: загрузка, "
        "выгрузка, получение информации о модулях."
    ),
    "libsmartcols.so.1": (
        "Libsmartcols — библиотека для форматирования табличного "
        "вывода. Используется утилитами util-linux (lsblk, fdisk, "
        "findmnt)."
    ),
    "libuuid.so.1": (
        "Libuuid — библиотека для генерации UUID (Universally "
        "Unique Identifiers) по стандарту RFC 4122."
    ),
    "libfdisk.so.1": (
        "Libfdisk — библиотека для работы с разделами дисков "
        "(MBR, GPT). Используется утилитами fdisk, cfdisk, "
        "sfdisk."
    ),
    "libkpartx.so.0": (
        "Libkpartx — библиотека для создания устройств-карт "
        "разделов (partition mapping) на multipath-устройствах."
    ),
    "libbtrfs.so.0": (
        "Btrfs Library — библиотека для работы с файловой "
        "системой Btrfs: управление подтомами, снапшотами, "
        "размерами, RAID."
    ),
    "libbtrfsutil.so.1": (
        "Btrfs Utility Library — высокоуровневая библиотека "
        "для управления Btrfs: создание/удаление подтомов, "
        "снапшотов, получение информации."
    ),
    "libelfin.so.0": (
        "libelfin — библиотека для чтения и анализа ELF-файлов. "
        "Используется systemd для загрузки и разбора образов "
        "ядра и initrd."
    ),
    "libelf.so.1": (
        "libelf (elfutils) — библиотека для работы с ELF-файлами, "
        "DWARF-отладочной информацией, построения backlog."
    ),
    "libdw.so.1": (
        "libdw (elfutils) — библиотека для работы с DWARF-"
        "отладочной информацией. Используется для анализа "
        "стек-трейсов, профилирования, отладки."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 9. GLIB / GIO — основные библиотеки GNOME/GLib platform
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_GLIB = {
    "libglib-2.0.so.0": (
        "GLib — основная библиотека общего назначения. "
        "Предоставляет базовые типы данных (GString, GList, "
        "GHashTable, GTree), main loop, потоки, модули, "
        "регулярные выражения, парсинг опций."
    ),
    "libgobject-2.0.so.0": (
        "GObject — объектно-ориентированная система типов GLib. "
        "Реализует классы, интерфейсы, сигналы, свойства, "
        "интроспекцию. Фундамент для всех библиотек GNOME."
    ),
    "libgio-2.0.so.0": (
        "GIO — библиотека ввода/вывода GLib. Предоставляет "
        "абстракции для работы с файлами, сокетами, DBus, "
        "GIcon, мониторинг файлов (inotify)."
    ),
    "libgmodule-2.0.so.0": (
        "GModule — библиотека динамической загрузки модулей "
        "для GLib. Обёртка над dlopen/dlsym с поддержкой "
        "кроссплатформенности."
    ),
    "libgthread-2.0.so.0": (
        "GThread — библиотека многопоточности GLib. Обёртка "
        "над pthreads с интеграцией в GLib main loop."
    ),
    "libgobject-introspection-1.0.so.0": (
        "GObject Introspection — библиотека для интроспекции "
        "GObject-библиотек во время выполнения. Используется "
        "для генерации языковых привязок (Python, JavaScript, "
        "Rust) к C-библиотекам."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 10. COMPILER RUNTIME — GCC, libstdc++, libgomp, Fortran, ObjC, sanitizers
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_COMPILER_RUNTIME = {
    "libgcc_s.so.1": (
        "GCC Runtime Library — библиотека поддержки выполнения "
        "для кода, скомпилированного GCC. Содержит обработчики "
        "исключений (DWARF, SJLJ), арифметику с плавающей точкой, "
        "эмуляцию отсутствующих инструкций."
    ),
    "libstdc++.so.6": (
        "GNU Standard C++ Library (libstdc++) — реализация "
        "стандартной библиотеки C++. Включает STL (std::string, "
        "std::vector, std::map), потоки ввода-вывода (iostream), "
        "работу с файлами."
    ),
    "libgomp.so.1": (
        "GNU Offloading and Multi Processing Runtime — библиотека "
        "поддержки OpenMP (параллельные вычисления) для GCC. "
        "Автоматическое распараллеливание циклов и секций."
    ),
    "libatomic.so.1": (
        "GCC Atomic Library — библиотека поддержки атомарных "
        "операций (__atomic_*) для архитектур, где отсутствуют "
        "аппаратные инструкции для некоторых операций."
    ),
    "libitm.so.1": (
        "GCC Intel Transactional Memory — библиотека поддержки "
        "транзакционной памяти (Transactional Memory, TSX). "
        "Позволяет выполнять блоки кода атомарно."
    ),
    "libquadmath.so.0": (
        "GCC Quad-Precision Math Library — библиотека для "
        "арифметики с четверной точностью (128-bit floating "
        "point, __float128)."
    ),
    "libgfortran.so.5": (
        "GNU Fortran Runtime Library (libgfortran) — библиотека "
        "времени выполнения для Fortran-программ, скомпилированных "
        "gfortran."
    ),
    "libobjc.so.4": (
        "GNU Objective-C Runtime — библиотека времени выполнения "
        "для Objective-C, скомпилированного GCC."
    ),
    "libubsan.so.1": (
        "GCC Undefined Behavior Sanitizer (ubsan) — библиотека "
        "для обнаружения неопределённого поведения во время "
        "выполнения: переполнение целых, выход за границы, "
        "нулевые указатели, некорректные сдвиги."
    ),
    "libasan.so.8": (
        "GCC Address Sanitizer (asan) — библиотека для "
        "обнаружения ошибок работы с памятью: переполнения "
        "буфера, use-after-free, double-free, утечки памяти."
    ),
    "libtsan.so.2": (
        "GCC Thread Sanitizer (tsan) — библиотека для "
        "обнаружения гонок данных (data races) в многопоточных "
        "программах."
    ),
    "liblsan.so.0": (
        "GCC Leak Sanitizer (lsan) — библиотека для обнаружения "
        "утечек памяти. Является частью AddressSanitizer."
    ),
    "libcilkrts.so.5": (
        "GCC Cilk Plus Runtime — библиотека времени выполнения "
        "для Cilk Plus (параллельные расширения C/C++). "
        "Устаревшая, заменена OpenMP."
    ),
    "libssp.so.0": (
        "GCC Stack Smashing Protection Library — библиотека "
        "защиты от переполнения стека (stack smashing). "
        "Обнаруживает повреждение canary-значений."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 11. CONTAINERS — cgroup, numa, libfuse, libslirp, libcriu
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_CONTAINERS = {
    "libcgroup.so.1": (
        "Control Groups Library (libcgroup) — библиотека для "
        "управления cgroups v1/v2. Ограничение ресурсов (CPU, "
        "память, I/O) для процессов и контейнеров."
    ),
    "libnuma.so.1": (
        "NUMA (Non-Uniform Memory Access) Library — библиотека "
        "для управления привязкой процессов и памяти к "
        "конкретным NUMA-узлам. Оптимизация производительности "
        "на многопроцессорных системах."
    ),
    "libfuse3.so.3": (
        "Filesystem in Userspace (FUSE 3) — библиотека для "
        "создания файловых систем в пользовательском пространстве. "
        "Используется для sshfs, s3fs, fuse-overlayfs, "
        "encfs, mergerfs."
    ),
    "libfuse.so.2": (
        "Filesystem in Userspace (FUSE 2) — предыдущая версия "
        "FUSE, всё ещё используемая для совместимости."
    ),
    "libslirp.so.0": (
        "libslirp — библиотека для эмуляции TCP/IP стека "
        "в пользовательском пространстве. Используется QEMU "
        "(user-mode networking) и контейнерными средами."
    ),
    "libcriu.so.1": (
        "CRIU (Checkpoint/Restore In Userspace) — библиотека "
        "для создания и восстановления снапшотов процессов. "
        "Используется в контейнерах (Docker, Podman) для "
        "live migration."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 12. DATA — SQLite, JSON, YAML, PCRE, XML (только системные)
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_DATA = {
    "libsqlite3.so.0": (
        "SQLite Database Engine — встраиваемая реляционная "
        "база данных. Не требует сервера, хранит всю базу "
        "в одном файле. Используется практически во всех "
        "приложениях и системах."
    ),
    "libjson-c.so.5": (
        "JSON-C — библиотека для работы с JSON (JavaScript "
        "Object Notation). Парсинг, генерация, манипуляция "
        "JSON-объектами. Используется systemd, NetworkManager, "
        "libblockdev."
    ),
    "libjansson.so.4": (
        "Jansson — библиотека для кодирования, декодирования "
        "и манипуляции JSON-данными. Компактная, простой API."
    ),
    "libyaml-0.so.2": (
        "LibYAML — библиотека для парсинга и генерации YAML-"
        "документов. Используется Kubernetes, Docker Compose, "
        "Ansible, systemd и многими другими."
    ),
    "libpcre.so.3": (
        "PCRE (Perl Compatible Regular Expressions) — библиотека "
        "регулярных выражений, совместимая с Perl 5. "
        "Используется в grep, sed, и множестве приложений."
    ),
    "libpcre2-8.so.0": (
        "PCRE2 (Perl Compatible Regular Expressions 2) — "
        "второе поколение библиотеки PCRE с поддержкой "
        "Unicode, JIT-компиляции, улучшенной производительностью."
    ),
    "libxml2.so.2": (
        "Libxml2 — XML-парсер. Предоставляет полный набор "
        "функций для разбора, валидации и манипуляции "
        "XML-документами. Поддерживает DTD, XPath, XInclude, "
        "каталоги."
    ),
    "libexpat.so.1": (
        "Expat — потоковый XML-парсер. Быстрый, не требующий "
        "валидации парсер XML. Используется Python, Apache, "
        "Firefox, systemd, D-Bus."
    ),
    "libxslt.so.1": (
        "Libxslt — XSLT-процессор. Применяет XSL-трансформации "
        "к XML-документам для преобразования в другие форматы "
        "(HTML, текст, XML)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 13. TERMINAL — ncurses, readline, editline, slang
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_TERMINAL = {
    "libncursesw.so.6": (
        "Ncurses (wide char) — библиотека для создания "
        "текстовых пользовательских интерфейсов (TUI) "
        "в терминале: окна, меню, формы, работа с цветом. "
        "Wide-char версия с поддержкой Unicode."
    ),
    "libncurses.so.6": (
        "Ncurses (narrow char) — библиотека TUI без поддержки "
        "Unicode (8-bit). Для совместимости со старыми "
        "приложениями."
    ),
    "libtinfo.so.6": (
        "Terminal Info Library — библиотека работы с базой "
        "данных terminfo. Управление возможностями терминала, "
        "escape-последовательностями, управление курсором."
    ),
    "libpanelw.so.6": (
        "Panel (wide char) — надстройка над ncurses для "
        "работы с панелями (перекрывающиеся окна)."
    ),
    "libformw.so.6": (
        "Form (wide char) — надстройка над ncurses для "
        "создания форм ввода данных."
    ),
    "libmenuw.so.6": (
        "Menu (wide char) — надстройка над ncurses для "
        "создания меню."
    ),
    "libreadline.so.8": (
        "GNU Readline — библиотека редактирования командной "
        "строки с историей, автодополнением по Tab, Emacs/vi-"
        "режимами. Используется bash, gdb, psql, python."
    ),
    "libhistory.so.8": (
        "GNU History Library — библиотека управления историей "
        "команд (часть Readline). Хранение, загрузка, поиск "
        "в истории команд."
    ),
    "libedit.so.0": (
        "Editline (libedit) — альтернатива Readline, разработанная "
        "в NetBSD. Предоставляет аналогичный API с меньшим "
        "размером. Используется во многих проектах."
    ),
    "libslang.so.2": (
        "S-Lang — библиотека TUI с поддержкой цвета, слотов "
        "и подключаемых модулей. Используется в Midnight "
        "Commander (mc), joe."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 14. UTILITIES — attr, acl, sensors, procps, e2fsprogs, com_err, gdbm
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_UTILITIES = {
    "libattr.so.1": (
        "Extended Attributes Library — библиотека для работы "
        "с расширенными атрибутами файлов (xattr). Установка "
        "и получение произвольных метаданных: ACL, SELinux "
        "context, capabilities."
    ),
    "libacl.so.1": (
        "Access Control List Library — библиотека для работы "
        "с POSIX ACL (списками контроля доступа). Предоставляет "
        "тонкое управление правами доступа к файлам."
    ),
    "libcom_err.so.2": (
        "Common Error Library — библиотека единых кодов ошибок "
        "для e2fsprogs (ext2/ext3/ext4). Используется для "
        "обработки и сообщения об ошибках."
    ),
    "libe2p.so.2": (
        "Ext2fs Extended Functions — библиотека для работы "
        "с параметрами файловой системы ext2/ext3/ext4: "
        "чтение/запись суперблока, управление флагами."
    ),
    "libext2fs.so.2": (
        "Ext2fs Library — библиотека для работы с файловыми "
        "системами ext2/ext3/ext4. Создание, проверка, "
        "восстановление, управление журналом, резервные "
        "суперблоки."
    ),
    "libss.so.2": (
        "Subsystem Library — библиотека для создания "
        "интерактивных командных интерфейсов (debugfs, "
        "tune2fs)."
    ),
    "libsensors.so.5": (
        "lm-sensors Library — библиотека для мониторинга "
        "температуры, напряжения, скорости вентиляторов "
        "через аппаратные датчики (sensors)."
    ),
    "libproc2.so.0": (
        "proc2 Library — библиотека для чтения /proc и /sys "
        "файловых систем. Получение информации о процессах, "
        "памяти, CPU, дисках. Используется ps, top, kill."
    ),
    "libgdbm.so.6": (
        "GNU dbm (GDBM) — библиотека для работы с базами "
        "данных в формате key-value. Используется для "
        "кэширования, хранения конфигураций, индексов."
    ),
    "libgdbm_compat.so.4": (
        "GDBM Compatibility Library — библиотека для "
        "совместимости со старыми форматами dbm/ndbm."
    ),
    "libpopt.so.0": (
        "POPTLib — библиотека для разбора аргументов "
        "командной строки. Используется во многих утилитах "
        "(rpm, mount, rsync, curl)."
    ),
    "libcrack.so.2": (
        "CrackLib — библиотека проверки паролей на стойкость. "
        "Проверка по словарям, правилам, минимальной длине. "
        "Используется PAM (pam_cracklib)."
    ),
    "libpwquality.so.1": (
        "libpwquality — библиотека оценки и генерации "
        "качественных паролей. Используется PAM "
        "(pam_pwquality) в современных дистрибутивах."
    ),
    "libatasmart.so.4": (
        "libatasmart — библиотека для чтения S.M.A.R.T. "
        "данных с ATA/SATA/SAS дисков. Используется "
        "udisks, systemd."
    ),
    "libblockdev.so.2": (
        "libblockdev — библиотека для управления блочными "
        "устройствами: разделы, файловые системы, LVM, "
        "шифрование, RAID. Используется udisks2."
    ),
    "libvolume-key.so.1": (
        "libvolume-key — библиотека для управления ключами "
        "шифрования томов (LUKS). Используется udisks2."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 15. COMPRESSION — системные библиотеки сжатия
# ═══════════════════════════════════════════════════════════════════════════

_LINUX_COMPRESSION = {
    "libz.so.1": (
        "Zlib Compression Library — реализация алгоритма "
        "сжатия DEFLATE. Используется для gzip, zlib, "
        "PNG, HTTP-сжатия."
    ),
    "libbz2.so.1.0": (
        "Bzip2 Compression Library — алгоритм сжатия "
        "Burrows-Wheeler (bzip2). Обеспечивает более "
        "высокую степень сжатия по сравнению с zlib, "
        "но работает медленнее."
    ),
    "liblzma.so.5": (
        "LZMA Compression Library (XZ Utils) — реализация "
        "алгоритма сжатия LZMA (XZ). Используется в "
        "пакетных менеджерах (dpkg, rpm), systemd, "
        "и многих других системных компонентах."
    ),
    "libzstd.so.1": (
        "Zstandard (zstd) — современное сжатие от Facebook: "
        "высокая степень + высокая скорость. Используется "
        "в ядре Linux (Zstd-compressed modules, Btrfs, "
        "squashfs), systemd, dpkg, rpm."
    ),
    "liblz4.so.1": (
        "LZ4 — сверхбыстрое сжатие/распаковка (скорость "
        "> 500 МБ/с). Используется в ядре Linux (initrd, "
        "zram), systemd, контейнерах."
    ),
    "libsnappy.so.1": (
        "Snappy — быстрое сжатие от Google. Используется "
        "в LevelDB, BigTable, Cassandra, RocksDB."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# ОБЪЕДИНЕНИЕ ВСЕХ LINUX-СЛОВАРЕЙ
# ═══════════════════════════════════════════════════════════════════════════

LINUX_MODULES = {}
LINUX_MODULES.update(_LINUX_CORE_LIBS)
LINUX_MODULES.update(_LINUX_DYNAMIC_LINKER)
LINUX_MODULES.update(_LINUX_GRAPHICS)
LINUX_MODULES.update(_LINUX_AUDIO)
LINUX_MODULES.update(_LINUX_NETWORK)
LINUX_MODULES.update(_LINUX_SECURITY)
LINUX_MODULES.update(_LINUX_CRYPTO)
LINUX_MODULES.update(_LINUX_SYSTEM)
LINUX_MODULES.update(_LINUX_GLIB)
LINUX_MODULES.update(_LINUX_COMPILER_RUNTIME)
LINUX_MODULES.update(_LINUX_CONTAINERS)
LINUX_MODULES.update(_LINUX_DATA)
LINUX_MODULES.update(_LINUX_TERMINAL)
LINUX_MODULES.update(_LINUX_UTILITIES)
LINUX_MODULES.update(_LINUX_COMPRESSION)