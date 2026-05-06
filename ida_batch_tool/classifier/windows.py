"""Словари для Windows-модулей."""

_WINDOWS_HAL = {
    "hal.dll": "Hardware Abstraction Layer — HAL. Предоставляет единый интерфейс для работы ядра и драйверов с оборудованием (прерывания, таймеры, DMA, управление питанием), скрывая различия между чипсетами и платформами. Загружается в режиме ядра и недоступен пользовательским приложениям напрямую.",
}

_WINDOWS_NATIVE_API = {
    "ntdll.dll": "NT Layer DLL — диспетчер системных вызовов Native API. Предоставляет точки входа для системных вызовов (syscall), функции загрузчика образов (Ldr), кучу процессов (RtlHeap), отладку и обработку исключений. Является обязательной зависимостью всех подсистемных DLL (kernel32, user32 и др.), но редко используется приложениями напрямую.",
    "ntoskrnl.exe": "NT Operating System Kernel — ядро ОС и исполнительная система. Содержит диспетчер объектов, диспетчер памяти, диспетчер ввода/вывода, диспетчер процессов и потоков, подсистему безопасности (SRM), монитор безопасности. Выполняется в режиме ядра и реализует всю низкоуровневую логику ОС.",
    "win32k.sys": "Драйвер режима ядра, реализующий поддержку графического интерфейса Windows (GDI) и оконной системы. Управляет окнами, меню, курсорами, шрифтами и другими элементами пользовательского интерфейса.",
    "basesrv.dll": "Windows NT BASE API Server DLL — серверная библиотека CSRSS, отвечающая за базовые функции подсистемы Win32: управление процессами и потоками, обработку событий создания/завершения процессов, взаимодействие с LPC (Local Procedure Call). Загружается процессом csrss.exe на ранних этапах инициализации системы.",
    "winsrv.dll": "Windows Server DLL — серверная библиотека CSRSS, предоставляющая функциональность оконной подсистемы: управление консольными окнами (Console Windows), обработка аппаратных ошибок (hard error), поддержка Virtual DOS Machine (VDM). В ранних версиях Windows NT была основным компонентом оконной функциональности, позже значительная часть была перенесена в win32k.sys.",
    "csrsrv.dll": "Client/Server Runtime Subsystem Server DLL — основная серверная библиотека CSRSS, реализующая диспетчеризацию API-вызовов от клиентских приложений. Содержит функции для обслуживания запросов, поступающих через ntdll.dll (CsrClientCallServer), и управления таблицами диспетчеризации.",
    "smss.exe": "Session Manager Subsystem (smss.exe) — первый пользовательский процесс, запускаемый ядром Windows. Является нативным приложением (Native Application), использующим исключительно Native API через ntdll.dll. Отвечает за запуск подсистем (csrss.exe, winlogon.exe), инициализацию переменных окружения, выполнение программ из BootExecute (например, autochk.exe) и управление сессиями.",
    "autochk.exe": "Auto Check Utility — нативное приложение (Native Application), выполняющее проверку диска (chkdsk) на раннем этапе загрузки системы, до запуска Win32-подсистемы. Использует Native API через ntdll.dll для прямого доступа к дисковым устройствам в монопольном режиме. Запускается процессом smss.exe согласно значению реестра BootExecute.",
    "ntkrnlpa.exe": "NT Kernel Physical Addressing — вариант ядра NTOSKRNL с поддержкой расширения физических адресов (PAE), позволяющий 32-битным системам адресовать более 4 ГБ оперативной памяти. Используется на 32-битных версиях Windows Server и Windows XP+ с PAE.",
    "dbghelp.dll": "Debug Help Library — библиотека поддержки отладки в пользовательском режиме. Предоставляет функции для работы с отладочной информацией (символы, формат PDB), анализ стека вызовов, создание минидампов. Хотя формально относится к Win32 API, тесно взаимодействует с Native API для доступа к памяти процессов.",
    "kernel32.dll": "Kernel32 — клиентская библиотека Win32, предоставляющая высокоуровневые обертки над Native API. Реализует функции управления памятью, файлового ввода/вывода, синхронизации, процессов и потоков. Являясь основным интерфейсом для приложений, сама активно использует Native API через ntdll.dll.",
}

_WINDOWS_KERNEL_SUBSYSTEM = {
    "kernel32.dll": "Kernel32 — базовые службы Win32: управление памятью (VirtualAlloc, HeapAlloc), файловый ввод/вывод (CreateFile, ReadFile), процессы и потоки (CreateProcess, CreateThread), синхронизация (Mutex, Event, Semaphore), время и дата, консоль, обработка ошибок. Инкапсулирует вызовы к ntdll.dll, предоставляя документированный API.",
    "kernelbase.dll": "KernelBase — облегчённая версия kernel32 для приложений UWP и OneCore. Содержит ту же базовую функциональность, но без устаревших и desktop-специфичных API. Используется на всех устройствах Windows (ПК, Xbox, HoloLens). Начиная с Windows 7, kernel32.dll перенаправляет большинство вызовов в kernelbase.dll.",
    "wow64.dll": "Wow64.dll — основной интерфейс к ядру Windows NT для подсистемы WOW64. Реализует инфраструктуру эмуляции ядра и преобразует (thunks) 32-битные вызовы в 64-битные, включая манипуляции с указателями и стеком вызовов. Загружается во все 32-битные процессы, работающие в 64-битной Windows.",
    "wow64win.dll": "Wow64Win.dll — предоставляет точки входа для 32-битных приложений в WOW64. Содержит thunks для функций win32k.sys (графическая и оконная подсистема). Обеспечивает корректную работу 32-битных GUI-приложений в 64-битной среде.",
    "wow64cpu.dll": "Wow64Cpu.dll — отвечает за переключение процессора между 32-битным и 64-битным режимами на архитектуре x86-64 (x64). Обеспечивает аппаратно-ускоренное выполнение 32-битного кода без программной эмуляции, так как процессор x86-64 имеет нативный режим для 32-битных инструкций.",
    "wowarmw.dll": "Wowarmw.dll — поддержка запуска ARM32-приложений на ARM64-версиях Windows. Аналог wow64cpu.dll для архитектуры ARM64. Обеспечивает совместимость 32-битных ARM-приложений с 64-битной средой.",
    "xtajit.dll": "XtaJIT.dll — программный эмулятор x86 для ARM64-версий Windows. Содержит JIT-компилятор (Just-In-Time), транслирующий x86-инструкции в ARM64-инструкции. Аналог wow64cpu.dll для архитектуры ARM64, где процессор не имеет нативной поддержки x86.",
    "api-ms-win-core-sysinfo-l1-1-0.dll": "API Set: Core System Information — виртуальная DLL, предоставляющая доступ к функциям системной информации (GetSystemInfo, GetVersionEx и др.). Гарантированно присутствует на всех версиях Windows (контракт api-).",
    "api-ms-win-core-memory-l1-1-0.dll": "API Set: Core Memory Management — виртуальная DLL для функций управления виртуальной памятью (VirtualAlloc, VirtualFree, VirtualQuery). Входит в базовый набор API, доступный на всех устройствах Windows.",
    "api-ms-win-core-processenvironment-l1-1-0.dll": "API Set: Core Process Environment — виртуальная DLL для функций работы с переменными окружения процесса (GetEnvironmentVariable, SetEnvironmentVariable). Гарантированно присутствует на всех версиях Windows.",
    "api-ms-win-core-handle-l1-1-0.dll": "API Set: Core Handle Management — виртуальная DLL для функций управления дескрипторами (CloseHandle, DuplicateHandle). Входит в базовый набор API, доступный на всех устройствах Windows.",
    "api-ms-win-core-synch-l1-1-0.dll": "API Set: Core Synchronization — виртуальная DLL для функций синхронизации (WaitForSingleObject, CreateEvent, CreateMutex). Гарантированно присутствует на всех версиях Windows.",
    "api-ms-win-core-file-l1-1-0.dll": "API Set: Core File I/O — виртуальная DLL для функций файлового ввода/вывода (CreateFile, ReadFile, WriteFile). Входит в базовый набор API, доступный на всех устройствах Windows.",
    "api-ms-win-core-processthreads-l1-1-0.dll": "API Set: Core Process Threads — виртуальная DLL для функций управления процессами и потоками (CreateProcess, CreateThread). Гарантированно присутствует на всех версиях Windows.",
    "api-ms-win-core-libraryloader-l1-1-0.dll": "API Set: Core Library Loader — виртуальная DLL для функций загрузки динамических библиотек (LoadLibrary, GetProcAddress). Входит в базовый набор API, доступный на всех устройствах Windows.",
    "api-ms-win-core-util-l1-1-0.dll": "API Set: Core Utility — виртуальная DLL для вспомогательных функций (Beep, MulDiv, QueryPerformanceCounter). Гарантированно присутствует на всех версиях Windows.",
    "api-ms-win-core-heap-l1-1-0.dll": "API Set: Core Heap — виртуальная DLL для функций управления кучей (HeapAlloc, HeapFree, HeapCreate). Входит в базовый набор API, доступный на всех устройствах Windows.",
}

_WINDOWS_USER_SUBSYSTEM = {
    "user32.dll": "User32 — управление окнами, сообщениями, элементами управления. Реализует оконную процедуру (WindowProc), диспетчеризацию сообщений (GetMessage/DispatchMessage), создание окон (CreateWindowEx), меню, курсоры, иконки, буфер обмена, DDE. Все графические приложения Windows зависят от этой DLL.",
    "gdi32.dll": "GDI32 — Graphics Device Interface. Примитивы рисования: линии, кривые, прямоугольники, эллипсы; работа с кистями, перьями, шрифтами; растровые операции (BitBlt); метафайлы; управление контекстом устройства (DC). Используется user32.dll для отрисовки окон и элементов управления.",
    "gdi32full.dll": "GDI32Full — расширенная версия GDI32 с дополнительными функциями рендеринга и поддержкой современных форматов.",
    "comctl32.dll": "Comctl32 — Common Controls Library. Предоставляет стандартные элементы управления: кнопки, списки, деревья (TreeView), списки изображений (ImageList), панели инструментов (Toolbar), вкладки (Tab), индикаторы прогресса, календари. Построена поверх user32 и gdi32.",
    "comdlg32.dll": "ComDlg32 — Common Dialog Box Library. Стандартные диалоговые окна: открытие/сохранение файла (GetOpenFileName), выбор цвета (ChooseColor), выбор шрифта (ChooseFont), печать (PrintDlg), поиск/замена.",
    "shlwapi.dll": "Shlwapi — Shell Lightweight API. Вспомогательные функции для работы с реестром, строками, путями, URL. Используется оболочкой Windows и проводником.",
    "shell32.dll": "Shell32 — оболочка Windows: рабочий стол, панель задач, проводник, контекстные меню, ассоциации файлов, корзина. Предоставляет API для работы с пространством имён оболочки (Shell Namespace), ярлыками, извлечения иконок.",
    "ole32.dll": "Ole32 — Object Linking and Embedding (OLE) и Component Object Model (COM). Базовые службы COM: фабрики классов, маршалинг, моникеры, хранение (Structured Storage). Фундамент для всех технологий COM, включая ActiveX и OLE.",
    "oleaut32.dll": "OleAut32 — OLE Automation. Поддержка типов VARIANT, BSTR, SAFEARRAY; диспетчерские интерфейсы (IDispatch); библиотеки типов (ITypeLib/ITypeInfo). Необходима для скриптовых языков (VBScript, JScript) и взаимодействия с Automation-объектами.",
    "combase.dll": "Combase — базовая поддержка COM и Windows Runtime (WinRT). Содержит фундаментальные функции COM, используемые как классическим COM, так и новыми приложениями WinRT/UWP. Заменила ole32 во многих сценариях.",
    "uxtheme.dll": "UxTheme — Microsoft UxTheme Library. Реализует движок рендеринга визуальных стилей (Visual Styles), отвечающий за современный внешний вид элементов управления и окон. Загружается библиотекой ComCtl32.dll версии 6 и выше для отрисовки themed-контролов.",
    "themeui.dll": "ThemeUI — Windows Theme API. Предоставляет функции для отображения и настройки визуальных тем рабочего стола, включая фоновые изображения, цвета окон и звуковые схемы. Содержит ресурсы для рендеринга элементов темы (кнопки, скроллбары, рамки окон) в координации с uxtheme.dll.",
    "themeservice.dll": "ThemeService — Windows Themes Service. Системная служба, управляющая загрузкой и применением визуальных тем. Координирует работу uxtheme.dll и themeui.dll, обеспечивая корректное переключение и обновление тем на лету.",
    "dwmapi.dll": "DWMAPI — Desktop Window Manager API. Клиентская библиотека для взаимодействия с Desktop Window Manager (DWM). Предоставляет программный доступ к функциям композиции рабочего стола: управление прозрачностью окон (Aero Glass), миниатюрами панели задач, Flip3D, живыми эскизами.",
    "msimg32.dll": "Msimg32 — GDIEXT Client DLL. Предоставляет расширенные функции графического вывода поверх стандартного GDI, включая GradientFill для создания градиентных заливок и AlphaBlend для полупрозрачного наложения изображений с альфа-каналом.",
    "gdiplus.dll": "GDI+ — библиотека двухмерной графики, созданная как преемник GDI (Gdi32.dll). Поддерживает работу со сложными векторными формами, градиентными кистями, путями, альфа-каналами и множеством форматов изображений (JPEG, PNG, BMP, GIF, TIFF), а также плюсовую модель программирования на C++.",
    "oleacc.dll": "OLEACC — Microsoft Active Accessibility (MSAA) Core Component. Предоставляет инфраструктуру accessibility для стандартных элементов управления Windows. Создаёт прокси-объекты IAccessible для USER-контролов, меню и элементов Comctl32.dll, позволяя экранным дикторам и другим вспомогательным технологиям взаимодействовать с GUI приложения без дополнительной разработки со стороны приложения.",
    "propsys.dll": "Propsys — Microsoft Property System. Реализует систему метаданных Windows Vista и новее, позволяющую приложениям регистрировать и запрашивать расширенные свойства файлов (автор, рейтинг, теги, размеры изображений и т.д.). Ключевой компонент Windows Search, обеспечивающий индексацию и быстрый поиск файлов по их свойствам.",
    "windows.storage.dll": "Windows.Storage — Windows Storage API. Предоставляет функции для работы с файловой системой, библиотеками и виртуальными папками в стиле Windows Runtime. Используется приложениями UWP и оболочкой Windows для унифицированного доступа к локальным и облачным хранилищам.",
    "winspool.drv": "Winspool.drv — Windows Print Spooler Driver. Управляет очередями печати, принтерами и заданиями печати. Является частью подсистемы печати Windows.",
    "comdlg32.ocx": "ComDlg32.ocx — ActiveX-версия библиотеки общих диалоговых окон, предоставляющая те же функции, что и comdlg32.dll, но в виде ActiveX-элементов управления для использования в средах разработки, таких как Visual Basic.",
}

_WINDOWS_SECURITY_CRYPTO = {
    "advapi32.dll": "Advapi32 — Advanced API: службы безопасности (управление ACL, токенами, привилегиями), реестр (RegCreateKey, RegQueryValue), сервисы Windows (Service Control Manager), криптография (CryptAcquireContext).",
    "crypt32.dll": "Crypt32 — CryptoAPI: управление сертификатами (X.509), хранилищами сертификатов, кодирование/декодирование ASN.1, проверка цифровых подписей, работа с цепочками сертификатов.",
    "wintrust.dll": "WinTrust — Microsoft Trust Verification: проверка подлинности исполняемых файлов (Authenticode), проверка цифровых подписей ActiveX-компонентов, управление поставщиками доверия.",
    "ncrypt.dll": "Ncrypt — Cryptography API Next Generation (CNG): современный криптографический API. Поддержка алгоритмов AES, RSA, ECDSA, SHA-2/3, управление ключами (Key Storage), изоляция ключей.",
    "bcrypt.dll": "Bcrypt — Cryptographic Primitives: низкоуровневые криптографические примитивы, включая хеширование (SHA, MD5), симметричное шифрование (AES, 3DES), генерация случайных чисел.",
    "dpapi.dll": "DPAPI — Data Protection API: шифрование и расшифровка данных с привязкой к учётной записи пользователя или компьютеру. Используется для безопасного хранения паролей и ключей без управления ключами шифрования.",
    "secur32.dll": "Secur32 — Security Support Provider Interface (SSPI): аутентификация (NTLM, Kerberos, Negotiate), управление учётными данными, контексты безопасности.",
    "sspicli.dll": "SspiCli — SSPI Client: клиентская часть Security Support Provider Interface. Используется приложениями для аутентификации и установки защищённых соединений.",
    "msasn1.dll": "Msasn1 — ASN.1 Runtime: кодирование/декодирование данных в формате ASN.1 для криптографических операций, сертификатов, Kerberos.",
    "samlib.dll": "Samlib — Security Account Manager Library: API для управления локальной базой учётных записей (SAM), включая пользователей, группы, пароли.",
    "cryptsp.dll": "CryptSP — Cryptographic Service Provider API: библиотека, обеспечивающая взаимодействие между CryptoAPI и криптографическими провайдерами (CSP). Реализует маршрутизацию криптографических операций к конкретным поставщикам услуг шифрования.",
    "cryptdll.dll": "CryptDll — Cryptography Helper DLL: вспомогательная библиотека для CryptoAPI. Предоставляет дополнительные криптографические функции и управление цифровыми сертификатами.",
    "cryptnet.dll": "CryptNet — Cryptographic Network Services: обеспечивает сетевую поддержку для CryptoAPI, включая проверку сертификатов по сети, работу со списками отзыва сертификатов (CRL) и построение цепочек сертификатов с использованием сетевых ресурсов.",
    "cryptui.dll": "CryptUI — Cryptographic User Interface: предоставляет стандартные диалоговые окна и интерфейсы для работы с сертификатами, включая отображение, выбор и управление сертификатами.",
    "cryptngc.dll": "CryptNgc — Cryptographic Next Generation API: расширение CNG с поддержкой PIN-кодов и биометрических данных для входа в систему, а также взаимодействие с Trusted Platform Module (TPM) для современных методов аутентификации Windows Hello.",
    "bcryptprimitives.dll": "BCryptPrimitives — высокопроизводительные криптографические примитивы Windows: симметричное шифрование, хеширование, генерация случайных чисел. Фундамент для bcrypt.dll.",
    "msv1_0.dll": "MSV1_0 — Microsoft Authentication Package v1.0: реализует протокол аутентификации NTLM (NT LAN Manager). Обеспечивает проверку подлинности для локальных учётных записей и доменных служб в средах, предшествующих Windows 2000.",
    "kerberos.dll": "Kerberos Security Package: реализует протокол аутентификации Kerberos для доменов Active Directory. Обеспечивает взаимную аутентификацию клиентов и серверов с использованием билетов (tickets), выданных центром распространения ключей (KDC). С обновлением Windows Vista добавлена поддержка шифрования AES.",
    "schannel.dll": "Schannel — Secure Channel: реализует протоколы аутентификации TLS/SSL. Обеспечивает шифрование и целостность сетевых соединений, включая проверку сертификатов X.509. Используется всеми защищёнными сетевыми приложениями Windows, включая HTTPS, RDP и SMB поверх TLS.",
    "wdigest.dll": "WDigest — Digest Authentication SSP: реализует Digest-аутентификацию по протоколам HTTP и SASL. Используется для проверки подлинности в средах, где Kerberos недоступен.",
    "tspkg.dll": "TSPkg — Terminal Services Security Package: обеспечивает аутентификацию для служб терминалов (Remote Desktop Services). Используется при установке соединений удалённого рабочего стола для проверки подлинности пользователей и передачи учётных данных.",
    "pku2u.dll": "PKU2U — Public Key Cryptography User-to-User: реализует аутентификацию на основе сертификатов и криптографии с открытым ключом для прямых соединений между пользователями в одноранговых сетях.",
    "cloudap.dll": "CloudAP — Cloud Authentication Provider: современный SSP, обеспечивающий аутентификацию с использованием облачных учётных записей Microsoft (Microsoft Account, Azure AD/Entra ID). Отвечает за единый вход (SSO) в Windows 10/11 и сопоставление облачных идентификаторов с локальными профилями пользователей.",
    "negoexts.dll": "NegoExts — Negotiate Extensions: расширения для протокола Negotiate, обеспечивающие согласование между различными поставщиками безопасности (SSP). Позволяет клиенту и серверу динамически выбирать наиболее подходящий протокол аутентификации (Kerberos, NTLM, CredSSP).",
    "credssp.dll": "CredSSP — Credential Security Support Provider: реализует делегирование учётных данных для сценариев, требующих передачи пароля или токена на удалённый сервер (например, PowerShell Remoting, WinRM).",
    "lsasrv.dll": "Lsasrv — Local Security Authority Server DLL: основной модуль подсистемы локальной безопасности (LSASS). Реализует большинство функций безопасности Windows: управление политиками безопасности, аутентификацию пользователей, проверку привилегий, генерацию сообщений аудита.",
    "samsrv.dll": "Samsrv — Security Accounts Manager Server DLL: управляет локальной базой учётных записей (SAM). Хранит локальные учётные записи пользователей и групп, пароли (в виде хешей), параметры политик безопасности.",
    "netlogon.dll": "NetLogon — Net Logon Service: поддерживает безопасный канал между компьютером и контроллером домена. Участвует в аутентификации пользователей домена, синхронизации паролей и передаче учётных данных.",
}

_WINDOWS_NETWORK = {
    "ws2_32.dll": "Ws2_32 — Windows Sockets 2 (Winsock): реализация Berkeley Sockets API для Windows. Создание и управление сокетами TCP/UDP, асинхронные операции, поддержка IPv4/IPv6. Основная сетевая библиотека Windows-приложений.",
    "winhttp.dll": "WinHTTP — Windows HTTP Services: клиентская библиотека для отправки HTTP/HTTPS-запросов к веб-серверам. Предназначена для серверных приложений и служб (в отличие от WinINet, ориентированной на интерактивные приложения).",
    "wininet.dll": "WinINet — Windows Internet: реализация протоколов HTTP, FTP, Gopher для интерактивных приложений. Поддерживает кэширование, автонастройку прокси, обработку cookie. Используется Internet Explorer и приложениями, встраивающими веб-компоненты.",
    "urlmon.dll": "Urlmon — URL Moniker: связывание URL с объектами, асинхронная загрузка данных, поддержка MIME-типов, security zones. Используется Internet Explorer и компонентами ActiveX.",
    "iertutil.dll": "Iertutil — Internet Explorer Runtime Utility: вспомогательные функции для WinINet и UrlMon, включая работу со строками, памятью и кэшем.",
    "dnsapi.dll": "Dnsapi — DNS Client API: преобразование имён хостов в IP-адреса (DNS resolution), управление локальным кэшем DNS, асинхронные запросы.",
    "iphlpapi.dll": "IpHlpApi — IP Helper API: информация о сетевых интерфейсах, таблице маршрутизации, ARP-таблице, статистика TCP/UDP, управление адаптерами.",
    "mpr.dll": "Mpr — Multiple Provider Router: маршрутизация вызовов к сетевым провайдерам (LAN Manager, NetWare, Novell). Перенаправление сетевых запросов к нужному провайдеру.",
    "netapi32.dll": "Netapi32 — Network Management API: управление общими ресурсами, пользователями и группами домена, сетевыми соединениями. Основа для администрирования Windows-сетей.",
    "wtsapi32.dll": "Wtsapi32 — Windows Terminal Services API: управление сеансами удалённого рабочего стола (RDP), отправка сообщений между сессиями, запрос информации о терминальных сессиях.",
    "httpapi.dll": "Httpapi — HTTP Server API: реализация серверного HTTP-стека Windows. Предоставляет интерфейс для создания высокопроизводительных веб-серверов и обработки HTTP-запросов напрямую из приложений без участия IIS.",
    "webio.dll": "Webio — Windows Web IO Library: низкоуровневая библиотека ввода-вывода для веб-протоколов. Обеспечивает асинхронную передачу данных по HTTP и HTTPS, реализует базовые операции с сокетами для веб-трафика.",
    "mswsock.dll": "MSWSock — Microsoft Winsock Service Provider: реализация поставщика услуг Winsock от Microsoft. Предоставляет функции, специфичные для Windows, включая поддержку перекрывающегося (overlapped) ввода-вывода, AcceptEx, ConnectEx и другие расширения Winsock 2.",
    "wsock32.dll": "Wsock32 — Windows Sockets 1.1 API (устаревшая версия): оригинальная реализация Winsock для 16/32-битных приложений. В современных системах является оболочкой над ws2_32.dll для обеспечения обратной совместимости.",
    "rpcrt4.dll": "Rpcrt4 — Remote Procedure Call Runtime: реализация клиентской и серверной частей RPC в Windows. Обеспечивает маршалинг параметров, передачу данных по сети, управление портами и конечными точками. Является фундаментом для множества системных служб.",
    "authz.dll": "Authz — Authorization Framework: библиотека авторизации на основе ролей и политик. Предоставляет механизмы для проверки прав доступа к ресурсам в распределённых системах, включая поддержку Active Directory и групп безопасности.",
    "mgmtapi.dll": "Mgmtapi — SNMP Management API: реализация протокола SNMP (Simple Network Management Protocol) для управления сетевыми устройствами.",
    "snmpapi.dll": "Snmpapi — SNMP Utility API: дополнительные функции для работы с протоколом SNMP, включая кодирование и декодирование сообщений SNMP, управление MIB.",
    "traffic.dll": "Traffic — Quality of Service Traffic Control: библиотека управления качеством обслуживания (QoS) сетевого трафика. Предоставляет механизмы приоритезации пакетов, ограничения пропускной способности.",
    "mprapi.dll": "Mprapi — Multi-Protocol Routing API: интерфейс для администрирования служб маршрутизации и удалённого доступа (RRAS). Позволяет управлять VPN-подключениями, маршрутизацией между сетями, NAT и серверами удалённого доступа.",
    "rtutils.dll": "Rtutils — Routing Utilities: вспомогательная библиотека для служб маршрутизации и удалённого доступа. Предоставляет утилиты трассировки, управления памятью и отладки для компонентов RRAS.",
    "security.dll": "Security — RAS Security Library: библиотека безопасности для служб удалённого доступа. Обеспечивает аутентификацию пользователей при подключении по VPN и dial-up.",
    "clusapi.dll": "Clusapi — Cluster API: интерфейс для управления отказоустойчивыми кластерами Windows. Предоставляет функции для создания, настройки и мониторинга кластерных групп, ресурсов и узлов.",
    "resutils.dll": "Resutils — Cluster Resource Utilities: вспомогательная библиотека ресурсов кластера. Содержит общие функции для работы с ресурсами кластера (IP-адреса, сетевые имена, общие диски).",
    "netshell.dll": "Netshell — Network Shell: библиотека поддержки утилиты netsh (Network Shell). Предоставляет интерфейс для скриптового управления сетевыми конфигурациями через командную строку.",
    "fwpuclnt.dll": "Fwpuclnt — Windows Filtering Platform (WFP) User Mode Client: клиентская библиотека для взаимодействия с подсистемой фильтрации сетевых пакетов Windows. Позволяет приложениям и службам регистрировать правила фильтрации, проверять сетевые пакеты и управлять политиками безопасности на уровне ядра.",
    "dhcpsvc.dll": "Dhcpsvc — DHCP Server Service: реализация сервера DHCP (Dynamic Host Configuration Protocol) в Windows. Отвечает за автоматическое назначение IP-адресов, масок подсети, шлюзов и DNS-серверов клиентским устройствам в сети.",
}

_WINDOWS_GRAPHICS_MULTIMEDIA = {
    "winmm.dll": "WinMM — Windows Multimedia: аудио (waveOut, midiOut), таймеры высокого разрешения (timeGetTime), управление джойстиком. Устаревший API, заменён DirectX.",
    "d2d1.dll": "D2D1 — Direct2D: аппаратно-ускоренная двухмерная графика. Рендеринг векторной графики, текста, растровых изображений через GPU. Современная замена GDI/GDI+.",
    "dwrite.dll": "DWrite — DirectWrite: высококачественный рендеринг текста с поддержкой ClearType, OpenType-шрифтов, сложных скриптов (арабский, деванагари).",
    "dxgi.dll": "DXGI — DirectX Graphics Infrastructure: управление адаптерами дисплея, цепочками переключения (swap chains), перечисление видеорежимов. Фундамент для Direct3D.",
    "d3d11.dll": "D3D11 — Direct3D 11: трёхмерная графика и GPGPU-вычисления с использованием шейдерной модели 5.0. Поддержка тесселяции, compute-шейдеров, многопоточного рендеринга.",
    "d3d9.dll": "D3D9 — Direct3D 9: трёхмерная графика предыдущего поколения. Поддерживает шейдерную модель 3.0. Всё ещё широко используется для совместимости со старыми приложениями и играми.",
    "opengl32.dll": "OpenGL32 — реализация OpenGL API для Windows. Обеспечивает доступ к аппаратно-ускоренной 2D/3D-графике через стандартизированный кроссплатформенный интерфейс.",
    "glu32.dll": "GLU32 — OpenGL Utility Library: вспомогательные функции для OpenGL: построение квадратичных поверхностей (сферы, цилиндры), NURBS-кривые, матричные преобразования.",
    "uiautomationcore.dll": "UIAutomationCore — UI Automation Core: инфраструктура для accessibility-инструментов (экранные дикторы, программы для людей с ограниченными возможностями). Предоставляет дерево элементов управления и их свойств.",
}

_WINDOWS_RUNTIME = {
    "msvcrt.dll": "MSVCRT — Microsoft Visual C Runtime: стандартная библиотека C (printf, malloc, fopen, memcpy) для приложений, скомпилированных с Visual C++. Версия по умолчанию в системном каталоге.",
    "vcruntime140.dll": "VCRuntime140 — Visual C++ 2015/2017/2019 Runtime: базовые функции времени выполнения (инициализация/завершение потока, проброс исключений, проверки безопасности).",
    "msvcp140.dll": "MSVCP140 — Microsoft Visual C++ 2015/2017/2019 Standard Library: реализация STL (std::string, std::vector, std::map), ввод/вывод (iostream), работа с файлами.",
    "ucrtbase.dll": "UCRTBase — Universal CRT: универсальная библиотека времени выполнения C для Windows 10+. Включает стандартные функции C99, математические функции, locale-поддержку. Часть рефакторинга CRT на компоненты ОС.",
    "concrt140.dll": "ConcRT140 — Concurrency Runtime: поддержка параллельных вычислений (PPL — Parallel Patterns Library), асинхронных операций, агентов. Часть Visual C++ Runtime.",
    "atl.dll": "ATL — Active Template Library: набор шаблонных классов C++ для COM-разработки. Упрощает создание COM-объектов, ActiveX-компонентов, элементов управления.",
    "vcruntime140_1.dll": "VCRuntime140_1 — Microsoft C Runtime Library: расширенная версия vcruntime140.dll, содержащая дополнительные функции поддержки компилятора Visual C++.",
    "msvcp140_1.dll": "MSVCP140_1 — Microsoft C++ Standard Library Extension: дополнительная библиотека стандартной библиотеки C++. Введена в Visual Studio 2017 версии 15.6 для поддержки расширенных функций.",
    "msvcp140_2.dll": "MSVCP140_2 — Microsoft C++ Standard Library Extension 2: второй уровень расширения стандартной библиотеки C++. Содержит дополнительные функции, появившиеся в более поздних обновлениях Visual Studio 2017/2019.",
    "msvcp140_atomic_wait.dll": "MSVCP140_Atomic_Wait — Microsoft C++ Atomic Wait Library: специализированная библиотека для поддержки атомарных операций ожидания в C++20.",
    "msvcp140_codecvt_ids.dll": "MSVCP140_Codecvt_IDs — Microsoft C Runtime Library codecvt_ids: небольшая библиотека, отвечающая за идентификацию и поддержку кодировок символов (codecvt facets) в стандартной библиотеке C++.",
    "vccorlib140.dll": "VCCorLib140 — Microsoft VC WinRT Core Library: библиотека времени выполнения для управляемого кода C++/CX и C++/CLI, обеспечивающая поддержку Windows Runtime (WinRT).",
    "vcomp140.dll": "VCOMP140 — Microsoft C/C++ OpenMP Runtime: библиотека поддержки параллельных вычислений по стандарту OpenMP. Обеспечивает автоматическое распараллеливание циклов и секций кода.",
    "vcamp140.dll": "VCAMP140 — Microsoft C++ AMP Runtime: библиотека поддержки технологии C++ Accelerated Massive Parallelism (C++ AMP). Позволяет выполнять параллельные вычисления на графических процессорах (GPU).",
    "mfc140.dll": "MFC140 — Microsoft Foundation Classes Library: основная библиотека MFC для приложений, скомпилированных с Visual Studio 2015/2017/2019. Предоставляет объектно-ориентированную обёртку над Win32 API.",
    "mfc140u.dll": "MFC140U — Microsoft Foundation Classes Library (Unicode): Unicode-версия библиотеки MFC140.",
    "mfcm140.dll": "MFCM140 — MFC Managed Library: управляемая библиотека MFC для приложений, использующих Windows Forms Controls совместно с MFC.",
    "mfcmifc140.dll": "MFCMifc140 — MFC Managed Interfaces Library: библиотека управляемых интерфейсов для MFC.",
}

_WINDOWS_SYSTEM_SERVICES = {
    "psapi.dll": "PSAPI — Process Status API: получение информации о процессах и потоках, включая список загруженных модулей, использование памяти, количество handles.",
    "dbghelp.dll": "DbgHelp — Debug Help Library: функции для работы с отладочной информацией (символы, формат PDB), анализ стека вызовов, создание минидампов.",
    "powrprof.dll": "PowrProf — Power Profile: управление схемами электропитания, запрос состояния батареи, управление спящим режимом.",
    "setupapi.dll": "SetupAPI — Setup API: установка и удаление устройств Plug and Play, драйверов, классов устройств.",
    "winspool.drv": "Winspool.drv — Windows Spooler: управление принтерами и очередями печати.",
    "pdh.dll": "PDH — Performance Data Helper: сбор данных о производительности системы (счётчики производительности CPU, памяти, дисков, сети).",
    "sfc.dll": "SFC — System File Checker: проверка целостности системных файлов.",
    "sfc_os.dll": "SFC_OS — System File Checker OS Support: вспомогательная библиотека для SFC, обеспечивающая низкоуровневый доступ к защищённым системным файлам.",
    "apphelp.dll": "AppHelp — Application Compatibility: реализация механизма совместимости приложений (shim engine). Позволяет старым приложениям работать на новых версиях Windows через слой совместимости.",
    "profapi.dll": "ProfApi — Profile API: управление пользовательскими профилями. Загрузка и выгрузка профилей, управление реестром профиля, уведомления об изменениях.",
    "win32u.dll": "Win32U — Windows 32-bit User-mode: содержит реализацию части user32 и gdi32 для поддержки UWP-приложений и изоляции syscall-интерфейса.",
    "wdfldr.sys": "WDF Loader (Windows Driver Framework Loader) — загрузчик сред выполнения драйверов (KMDF/UMDF). Обеспечивает динамическую привязку и управление драйверами режима ядра, повышая стабильность системы.",
}

_WINDOWS_USB_DEVICE = {
    "winusb.dll": "WinUSB — Windows USB Driver API: предоставляет приложениям прямой доступ к USB-устройствам без написания драйвера.",
    "hid.dll": "HID — Human Interface Device API: взаимодействие с HID-устройствами (клавиатуры, мыши, джойстики, сенсорные панели) через стандартизированный протокол USB HID.",
}

_WINDOWS_DOTNET = {
    "mscoree.dll": "MSCoree — .NET Runtime Execution Engine: точка входа для запуска управляемого кода .NET (CLR).",
    "mscorlib.dll": "MSCorLib — Multilanguage Standard Common Object Runtime Library: основная библиотека классов .NET Framework.",
    "clr.dll": "CLR — Common Language Runtime: исполняющая среда .NET.",
    "clrjit.dll": "CLRJIT — CLR Just-In-Time Compiler: компилятор MSIL в машинный код во время выполнения.",
}

_WINDOWS_SUBSYSTEM_COMPAT = {
    "wow64.dll": "WOW64 — Windows on Windows 64: эмуляция 32-битной среды на 64-битной Windows.",
    "wow64cpu.dll": "WOW64 CPU — CPU-специфичная часть WOW64: эмуляция 32-битного режима процессора на архитектуре x86-64.",
    "wow64win.dll": "WOW64 Win — Windows-специфичная часть WOW64: эмуляция 32-битных Windows API вызовов в 64-битной среде.",
}

_WINDOWS_API_SETS = {
    "api-ms-win-core-ums-l1-1-0": "Windows API Set: User-Mode Scheduling (UMS). Обеспечивает планирование потоков в пользовательском режиме.",
    "ext-ms-win-com-ole32-l1-1-5": "Windows API Set: COM OLE32 расширения. Дополнительные функции Component Object Model для специфических платформ.",
    "ext-ms-win-ntuser-window-l1-1-0": "Windows API Set: NTUser Window расширения. Функции оконного интерфейса, доступные не на всех редакциях Windows.",
}

_WINDOWS_SERVER_CORE = {
    "cryptdll.dll": "CryptDll — расширение CryptoAPI: дополнительные криптографические функции и управление цифровыми сертификатами.",
    "cryptnet.dll": "CryptNet — сетевая поддержка для CryptoAPI: проверка сертификатов по сети, работа с CRL (списками отзыва сертификатов).",
    "credui.dll": "CredUI — Credential User Interface: диалоговое окно для ввода, сохранения и управления учётными данными пользователя (пароли, PIN-коды, сертификаты).",
}

_WINDOWS_OPENSSL_MODERN = {
    "libcrypto-1_1-x64.dll": "OpenSSL 1.1+ Encryption Library (64-bit) — современная криптографическая библиотека OpenSSL.",
    "libssl-1_1-x64.dll": "OpenSSL 1.1+ SSL/TLS Library (64-bit) — реализация протоколов TLS/SSL.",
    "libcrypto-1_1.dll": "OpenSSL 1.1+ Encryption Library (32-bit) — 32-битная версия криптографической библиотеки OpenSSL.",
    "libssl-1_1.dll": "OpenSSL 1.1+ SSL/TLS Library (32-bit) — 32-битная реализация TLS/SSL.",
}

_WINDOWS_BCRYPTPRIMITIVES = {
    "bcryptprimitives.dll": "BCryptPrimitives — высокопроизводительные криптографические примитивы Windows (симметричное шифрование, хеширование). Фундамент для bcrypt.dll.",
}

# Объединение всех Windows-словарей
WINDOWS_MODULES = {}
WINDOWS_MODULES.update(_WINDOWS_HAL)
WINDOWS_MODULES.update(_WINDOWS_NATIVE_API)
WINDOWS_MODULES.update(_WINDOWS_KERNEL_SUBSYSTEM)
WINDOWS_MODULES.update(_WINDOWS_USER_SUBSYSTEM)
WINDOWS_MODULES.update(_WINDOWS_SECURITY_CRYPTO)
WINDOWS_MODULES.update(_WINDOWS_NETWORK)
WINDOWS_MODULES.update(_WINDOWS_GRAPHICS_MULTIMEDIA)
WINDOWS_MODULES.update(_WINDOWS_RUNTIME)
WINDOWS_MODULES.update(_WINDOWS_SYSTEM_SERVICES)
WINDOWS_MODULES.update(_WINDOWS_USB_DEVICE)
WINDOWS_MODULES.update(_WINDOWS_DOTNET)
WINDOWS_MODULES.update(_WINDOWS_SUBSYSTEM_COMPAT)
WINDOWS_MODULES.update(_WINDOWS_API_SETS)
WINDOWS_MODULES.update(_WINDOWS_SERVER_CORE)
WINDOWS_MODULES.update(_WINDOWS_OPENSSL_MODERN)
WINDOWS_MODULES.update(_WINDOWS_BCRYPTPRIMITIVES)