"""Словари для Linux-модулей."""

_LINUX_CORE_LIBS = {
    "libc.so.6": "GNU C Library (glibc) — основная библиотека языка C. Реализует стандарт ISO C (printf, malloc, fopen, memcpy) и интерфейс системных вызовов POSIX (open, read, write, fork, exec). Является обязательной для всех пользовательских программ Linux. Включает поддержку многопоточности (libpthread) и динамической загрузки (libdl) начиная с glibc 2.34.",
    "libm.so.6": "Math Library (libm) — математическая библиотека, реализующая функции с плавающей точкой (sin, cos, sqrt, log, pow), соответствующие стандарту IEEE 754. Используется всеми вычислительными и научными приложениями.",
    "libdl.so.2": "Dynamic Linker Library (libdl) — поддержка динамической загрузки разделяемых объектов. Функции dlopen(), dlsym(), dlclose() для загрузки библиотек во время выполнения. Критически важна для плагинных архитектур и интерпретируемых языков (Python, Lua). Начиная с glibc 2.34 функциональность встроена в libc.",
    "libpthread.so.0": "POSIX Threads Library (libpthread) — реализация многопоточности по стандарту POSIX. Управление потоками, мьютексами, условными переменными, барьерами, блокировками чтения/записи. Начиная с glibc 2.34 встроена в libc.",
    "librt.so.1": "POSIX Real-time Extensions — расширения реального времени: семафоры POSIX, очереди сообщений, разделяемая память, таймеры высокого разрешения, асинхронный ввод/вывод (AIO).",
    "libresolv.so.2": "DNS Resolver Library — функции для разрешения доменных имён (DNS). Реализует gethostbyname(), getaddrinfo(), работу с /etc/resolv.conf.",
    "libnsl.so.1": "Network Services Library — сетевые службы: работа с NIS (Network Information Service), сетевыми базами данных (ethers, netgroup, rpc).",
    "libutil.so.1": "Utility Library — вспомогательные функции: работа с терминалом (openpty, forkpty), управление учётными записями (login, logout).",
    "libcrypt.so.1": "Crypt Library — шифрование и хеширование паролей. Функции crypt(), crypt_r(), encrypt() для одностороннего хеширования DES, MD5, SHA-256/512.",
    "libanl.so.1": "Asynchronous Name Lookup Library — асинхронное разрешение имён хостов без блокировки вызывающего потока.",
}

_LINUX_DYNAMIC_LINKER = {
    "ld-linux.so.2": "Dynamic Linker/Loader (32-bit) — загружает исполняемые файлы ELF, разрешает зависимости разделяемых библиотек, выполняет релокации. Для архитектуры x86.",
    "ld-linux-x86-64.so.2": "Dynamic Linker/Loader (x86-64) — то же для 64-битной архитектуры x86-64.",
    "ld-linux-aarch64.so.1": "Dynamic Linker/Loader (AArch64) — то же для архитектуры ARM 64-bit.",
    "ld-linux-armhf.so.3": "Dynamic Linker/Loader (ARM hard-float) — то же для архитектуры ARM с аппаратной поддержкой floating-point.",
    "linux-vdso.so.1": "Linux Virtual Dynamic Shared Object — виртуальная библиотека, внедряемая ядром в адресное пространство каждого процесса. Предоставляет оптимизированные реализации часто используемых системных вызовов (gettimeofday, clock_gettime) без переключения в режим ядра.",
}

_LINUX_SYSTEM_SERVICES = {
    "libdbus-1.so.3": "D-Bus Message Bus System — система межпроцессного взаимодействия (IPC). Обеспечивает обмен сообщениями между приложениями и службами, включая шину system bus (системные события, уведомления оборудования) и session bus (пользовательские приложения, desktop environment).",
    "libsystemd.so.0": "Systemd Client Library — интерфейс для взаимодействия с системным менеджером systemd. Управление службами, сокетами, таймерами, журналами. Используется современными дистрибутивами Linux (Fedora, Ubuntu, Debian).",
    "libudev.so.1": "Udev Device Manager Library — интерфейс к менеджеру устройств Linux. Обнаружение, перечисление и управление устройствами (udev). Критически важен для корректной работы драйверов и пользовательских приложений, взаимодействующих с аппаратурой.",
}

_LINUX_SECURITY = {
    "libpam.so.0": "Pluggable Authentication Modules (PAM) — гибкая система аутентификации. Позволяет настраивать способы проверки подлинности пользователей (пароль, биометрия, токены, LDAP, Kerberos).",
    "libcap.so.2": "Linux Capabilities Library — управление POSIX capabilities. Позволяет предоставлять процессам отдельные привилегии суперпользователя без полного доступа root.",
    "libseccomp.so.2": "Secure Computing Mode (seccomp) Library — фильтрация системных вызовов. Позволяет процессам ограничивать набор доступных системных вызовов для повышения безопасности (используется в sandbox-средах, контейнерах, браузерах).",
    "libselinux.so.1": "SELinux Userspace Library — интерфейс к Security-Enhanced Linux. Управление контекстами безопасности, политиками, метками файлов. Обязательное управление доступом (MAC) для Linux.",
    "libaudit.so.1": "Audit Library — система аудита Linux. Предоставляет API для отслеживания событий безопасности, системных вызовов и изменений файлов в соответствии с настроенными правилами аудита.",
}

_LINUX_COMPILER_RUNTIME = {
    "libgcc_s.so.1": "GCC Runtime Library — библиотека поддержки выполнения для кода, скомпилированного GCC. Содержит обработчики исключений (DWARF, SJLJ), арифметику с плавающей точкой, эмуляцию отсутствующих инструкций.",
    "libstdc++.so.6": "GNU Standard C++ Library — реализация стандартной библиотеки C++ (libstdc++). Включает STL (std::string, std::vector, std::map), потоки ввода-вывода (iostream), работу с файлами. Требуется для всех C++ приложений на Linux.",
}

_LINUX_COMPRESSION = {
    "libz.so.1": "Zlib Compression Library — реализация алгоритма сжатия DEFLATE. Используется для сжатия/распаковки данных в форматах gzip, zlib, PNG, HTTP.",
    "libbz2.so.1": "Bzip2 Compression Library — алгоритм сжатия Burrows-Wheeler (bzip2). Обеспечивает более высокую степень сжатия по сравнению с zlib, но работает медленнее.",
    "liblzma.so.5": "LZMA Compression Library — реализация алгоритма сжатия LZMA (XZ). Используется в пакетных менеджерах (dpkg, rpm), systemd, и многих других системных компонентах.",
}

_LINUX_XML_PARSING = {
    "libxml2.so.2": "Libxml2 — XML-парсер. Предоставляет полный набор функций для разбора, валидации и манипуляции XML-документами. Поддерживает DTD, XPath, XInclude, каталоги.",
    "libexpat.so.1": "Expat — потоковый XML-парсер. Быстрый, не требующий валидации парсер XML. Используется во многих проектах (Python, Apache, Firefox).",
    "libxslt.so.1": "Libxslt — XSLT-процессор. Применяет XSL-трансформации к XML-документам для преобразования в другие форматы (HTML, текст, XML).",
}

_LINUX_DATABASE = {
    "libsqlite3.so.0": "SQLite Database Engine — встраиваемая реляционная база данных. Не требует сервера, хранит всю базу в одном файле. Используется практически во всех приложениях и системах.",
}

_LINUX_SYSTEMD_LIBS = {
    "libsystemd-shared.so": "Systemd Internal Shared Library — общий код для всех компонентов systemd (journal, pid1, logind, resolved).",
    "libmount.so.1": "Libmount — монтирование и размонтирование файловых систем. Основа утилит mount/umount.",
    "libkmod.so.2": "Libkmod — управление модулями ядра (загрузка, выгрузка, получение информации).",
    "libblkid.so.1": "Libblkid — идентификация блочных устройств по сигнатурам файловых систем.",
}

_LINUX_SECURITY_EXTRA = {
    "libapparmor.so.1": "AppArmor Library — интерфейс к системе принудительного контроля доступа AppArmor. Ограничивает возможности приложений на основе профилей безопасности.",
    "libcap-ng.so.0": "Libcap-ng — упрощённое управление POSIX capabilities (альтернатива libcap). Позволяет процессам получать только необходимые привилегии.",
}

_LINUX_CRYPTO_EXTRA = {
    "libgcrypt.so.20": "Libgcrypt — криптографическая библиотека общего назначения (GnuPG, systemd, другие проекты).",
}

# Объединение всех Linux-словарей
LINUX_MODULES = {}
LINUX_MODULES.update(_LINUX_CORE_LIBS)
LINUX_MODULES.update(_LINUX_DYNAMIC_LINKER)
LINUX_MODULES.update(_LINUX_SYSTEM_SERVICES)
LINUX_MODULES.update(_LINUX_SECURITY)
LINUX_MODULES.update(_LINUX_COMPILER_RUNTIME)
LINUX_MODULES.update(_LINUX_COMPRESSION)
LINUX_MODULES.update(_LINUX_XML_PARSING)
LINUX_MODULES.update(_LINUX_DATABASE)
LINUX_MODULES.update(_LINUX_SYSTEMD_LIBS)
LINUX_MODULES.update(_LINUX_SECURITY_EXTRA)
LINUX_MODULES.update(_LINUX_CRYPTO_EXTRA)