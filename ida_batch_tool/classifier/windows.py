"""Словари для Windows-модулей.

Правила поддержки словарей:
1. Каждый модуль присутствует ровно в одной группе (без дубликатов).
2. Группы имеют семантически связную тематику, соответствующую
   документации Microsoft (learn.microsoft.com).
3. Описания — на русском, подробные, технически точные.
"""

# ═══════════════════════════════════════════════════════════════════════════
# 1. АППАРАТНАЯ АБСТРАКЦИЯ (HAL)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_HAL = {
    "hal.dll": (
        "Hardware Abstraction Layer — HAL. Предоставляет единый интерфейс для "
        "работы ядра и драйверов с оборудованием (прерывания, таймеры, DMA, "
        "управление питанием), скрывая различия между чипсетами и платформами. "
        "Загружается в режиме ядра и недоступен пользовательским приложениям напрямую."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 2. NATIVE API — базовый интерфейс системных вызовов
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_NATIVE_API = {
    "ntdll.dll": (
        "NT Layer DLL — диспетчер системных вызовов Native API. Предоставляет точки "
        "входа для системных вызовов (syscall), функции загрузчика образов (Ldr), "
        "кучу процессов (RtlHeap), отладку и обработку исключений. Является "
        "обязательной зависимостью всех подсистемных DLL (kernel32, user32 и др.), "
        "но редко используется приложениями напрямую."
    ),
    "ntoskrnl.exe": (
        "NT Operating System Kernel — ядро ОС и исполнительная система. Содержит "
        "диспетчер объектов, диспетчер памяти, диспетчер ввода/вывода, диспетчер "
        "процессов и потоков, подсистему безопасности (SRM), монитор безопасности. "
        "Выполняется в режиме ядра и реализует всю низкоуровневую логику ОС."
    ),
    "ntkrnlpa.exe": (
        "NT Kernel Physical Addressing — вариант ядра NTOSKRNL с поддержкой "
        "расширения физических адресов (PAE), позволяющий 32-битным системам "
        "адресовать более 4 ГБ оперативной памяти."
    ),
    "ntkrla57.exe": (
        "ARM64-вариант ядра Windows. Содержит реализацию исполнительной системы "
        "(Object Manager, Memory Manager, I/O Manager) для архитектуры ARM64."
    ),
    "win32k.sys": (
        "Драйвер режима ядра, реализующий поддержку графического интерфейса "
        "Windows (GDI) и оконной системы. Управляет окнами, меню, курсорами, "
        "шрифтами и другими элементами пользовательского интерфейса."
    ),
    "win32kbase.sys": (
        "Базовая часть win32k.sys в Windows 8+. Содержит фундаментальные "
        "функции оконной системы и GDI, общие для всех SKU Windows."
    ),
    "win32kfull.sys": (
        "Полная часть win32k.sys в Windows 8+. Содержит расширенные функции "
        "оконной системы и GDI для desktop-редакций Windows."
    ),
    "basesrv.dll": (
        "Windows NT BASE API Server DLL — серверная библиотека CSRSS, отвечающая "
        "за базовые функции подсистемы Win32: управление процессами и потоками, "
        "обработку событий создания/завершения процессов, взаимодействие с LPC "
        "(Local Procedure Call). Загружается процессом csrss.exe."
    ),
    "winsrv.dll": (
        "Windows Server DLL — серверная библиотека CSRSS, предоставляющая "
        "функциональность оконной подсистемы: управление консольными окнами "
        "(Console Windows), обработка аппаратных ошибок (hard error), поддержка "
        "Virtual DOS Machine (VDM)."
    ),
    "csrsrv.dll": (
        "Client/Server Runtime Subsystem Server DLL — основная серверная библиотека "
        "CSRSS, реализующая диспетчеризацию API-вызовов от клиентских приложений."
    ),
    "smss.exe": (
        "Session Manager Subsystem (smss.exe) — первый пользовательский процесс, "
        "запускаемый ядром Windows. Является нативным приложением (Native Application), "
        "использующим исключительно Native API через ntdll.dll."
    ),
    "autochk.exe": (
        "Auto Check Utility — нативное приложение (Native Application), выполняющее "
        "проверку диска (chkdsk) на раннем этапе загрузки системы, до запуска "
        "Win32-подсистемы."
    ),
    "kdcom.dll": (
        "Kernel Debugger Communication — реализует транспортный уровень для "
        "отладки ядра Windows через последовательный порт (COM), USB, IEEE 1394 "
        "или сетевое подключение."
    ),
    "kd.dll": (
        "Kernel Debugger — реализация отладчика ядра Windows. Обеспечивает "
        "управление точками останова, чтение/запись памяти ядра, управление "
        "целевой системой на ранних этапах загрузки."
    ),
    "kdexts.dll": (
        "Kernel Debugger Extensions — набор расширений ядерного отладчика "
        "Windows. Предоставляет команды для анализа структур ядра: !process, "
        "!thread, !pool, !object и др."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 3. ПОДСИСТЕМА ЯДРА (Kernel32 + WOW64 + API Sets core)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_KERNEL_SUBSYSTEM = {
    "kernel32.dll": (
        "Kernel32 — клиентская библиотека Win32, предоставляющая высокоуровневые "
        "обёртки над Native API. Реализует функции управления памятью (VirtualAlloc, "
        "HeapAlloc), файлового ввода/вывода (CreateFile, ReadFile), синхронизации "
        "(Mutex, Event, Semaphore), процессов и потоков (CreateProcess, CreateThread)."
    ),
    "kernelbase.dll": (
        "KernelBase — облегчённая версия kernel32 для приложений UWP и OneCore. "
        "Начиная с Windows 7, kernel32.dll перенаправляет большинство вызовов в "
        "kernelbase.dll. Используется на всех устройствах Windows (ПК, Xbox, HoloLens)."
    ),
    "wow64.dll": (
        "Wow64.dll — основной интерфейс к ядру Windows NT для подсистемы WOW64. "
        "Реализует инфраструктуру эмуляции ядра и преобразует (thunks) 32-битные "
        "вызовы в 64-битные. Загружается во все 32-битные процессы, работающие "
        "в 64-битной Windows."
    ),
    "wow64win.dll": (
        "Wow64Win.dll — предоставляет точки входа для 32-битных приложений "
        "в WOW64. Содержит thunks для функций win32k.sys (графическая и оконная "
        "подсистема). Обеспечивает корректную работу 32-битных GUI-приложений "
        "в 64-битной среде."
    ),
    "wow64cpu.dll": (
        "Wow64Cpu.dll — отвечает за переключение процессора между 32-битным "
        "и 64-битным режимами на архитектуре x86-64. Обеспечивает аппаратно-"
        "ускоренное выполнение 32-битного кода без программной эмуляции."
    ),
    "wowarmw.dll": (
        "Wowarmw.dll — поддержка запуска ARM32-приложений на ARM64-версиях "
        "Windows. Аналог wow64cpu.dll для архитектуры ARM64."
    ),
    "xtajit.dll": (
        "XtaJIT.dll — программный эмулятор x86 для ARM64-версий Windows. "
        "Содержит JIT-компилятор (Just-In-Time), транслирующий x86-инструкции "
        "в ARM64-инструкции."
    ),
    # API Sets — ядро (Core)
    "api-ms-win-core-sysinfo-l1-1-0.dll": (
        "API Set: Core System Information — виртуальная DLL, предоставляющая "
        "доступ к функциям системной информации (GetSystemInfo, GetVersionEx и др.)."
    ),
    "api-ms-win-core-memory-l1-1-0.dll": (
        "API Set: Core Memory Management — виртуальная DLL для функций управления "
        "виртуальной памятью (VirtualAlloc, VirtualFree, VirtualQuery)."
    ),
    "api-ms-win-core-processenvironment-l1-1-0.dll": (
        "API Set: Core Process Environment — виртуальная DLL для функций работы "
        "с переменными окружения процесса."
    ),
    "api-ms-win-core-handle-l1-1-0.dll": (
        "API Set: Core Handle Management — виртуальная DLL для функций управления "
        "дескрипторами (CloseHandle, DuplicateHandle)."
    ),
    "api-ms-win-core-synch-l1-1-0.dll": (
        "API Set: Core Synchronization — виртуальная DLL для функций синхронизации "
        "(WaitForSingleObject, CreateEvent, CreateMutex)."
    ),
    "api-ms-win-core-file-l1-1-0.dll": (
        "API Set: Core File I/O — виртуальная DLL для функций файлового "
        "ввода/вывода (CreateFile, ReadFile, WriteFile)."
    ),
    "api-ms-win-core-processthreads-l1-1-0.dll": (
        "API Set: Core Process Threads — виртуальная DLL для функций управления "
        "процессами и потоками (CreateProcess, CreateThread)."
    ),
    "api-ms-win-core-libraryloader-l1-1-0.dll": (
        "API Set: Core Library Loader — виртуальная DLL для функций загрузки "
        "динамических библиотек (LoadLibrary, GetProcAddress)."
    ),
    "api-ms-win-core-util-l1-1-0.dll": (
        "API Set: Core Utility — виртуальная DLL для вспомогательных функций "
        "(Beep, MulDiv, QueryPerformanceCounter)."
    ),
    "api-ms-win-core-heap-l1-1-0.dll": (
        "API Set: Core Heap — виртуальная DLL для функций управления кучей "
        "(HeapAlloc, HeapFree, HeapCreate)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 4. ПОЛЬЗОВАТЕЛЬСКАЯ ПОДСИСТЕМА (User32, GDI, COM, Shell, Theme, Input)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_USER_SUBSYSTEM = {
    "user32.dll": (
        "User32 — управление окнами, сообщениями, элементами управления. "
        "Реализует оконную процедуру (WindowProc), диспетчеризацию сообщений "
        "(GetMessage/DispatchMessage), создание окон (CreateWindowEx), меню, "
        "курсоры, иконки, буфер обмена, DDE."
    ),
    "gdi32.dll": (
        "GDI32 — Graphics Device Interface. Примитивы рисования: линии, кривые, "
        "прямоугольники, эллипсы; работа с кистями, перьями, шрифтами; растровые "
        "операции (BitBlt); метафайлы; управление контекстом устройства (DC)."
    ),
    "gdi32full.dll": (
        "GDI32Full — расширенная версия GDI32 с дополнительными функциями "
        "рендеринга и поддержкой современных форматов."
    ),
    "comctl32.dll": (
        "Comctl32 — Common Controls Library. Предоставляет стандартные элементы "
        "управления: кнопки, списки, деревья (TreeView), списки изображений "
        "(ImageList), панели инструментов (Toolbar), вкладки (Tab), индикаторы "
        "прогресса, календари."
    ),
    "comdlg32.dll": (
        "ComDlg32 — Common Dialog Box Library. Стандартные диалоговые окна: "
        "открытие/сохранение файла (GetOpenFileName), выбор цвета (ChooseColor), "
        "выбор шрифта (ChooseFont), печать (PrintDlg), поиск/замена."
    ),
    "shlwapi.dll": (
        "Shlwapi — Shell Lightweight API. Вспомогательные функции для работы "
        "с реестром, строками, путями, URL. Используется оболочкой Windows "
        "и проводником."
    ),
    "shell32.dll": (
        "Shell32 — оболочка Windows: рабочий стол, панель задач, проводник, "
        "контекстные меню, ассоциации файлов, корзина. Предоставляет API для "
        "работы с пространством имён оболочки (Shell Namespace)."
    ),
    "ole32.dll": (
        "Ole32 — Object Linking and Embedding (OLE) и Component Object Model (COM). "
        "Базовые службы COM: фабрики классов, маршалинг, моникеры, хранение "
        "(Structured Storage). Фундамент для всех технологий COM, включая ActiveX и OLE."
    ),
    "oleaut32.dll": (
        "OleAut32 — OLE Automation. Поддержка типов VARIANT, BSTR, SAFEARRAY; "
        "диспетчерские интерфейсы (IDispatch); библиотеки типов (ITypeLib/ITypeInfo)."
    ),
    "combase.dll": (
        "Combase — базовая поддержка COM и Windows Runtime (WinRT). Содержит "
        "фундаментальные функции COM, используемые как классическим COM, так "
        "и новыми приложениями WinRT/UWP."
    ),
    "uxtheme.dll": (
        "UxTheme — Microsoft UxTheme Library. Реализует движок рендеринга "
        "визуальных стилей (Visual Styles), отвечающий за современный внешний "
        "вид элементов управления и окон."
    ),
    "themeui.dll": (
        "ThemeUI — Windows Theme API. Предоставляет функции для отображения "
        "и настройки визуальных тем рабочего стола."
    ),
    "themeservice.dll": (
        "ThemeService — Windows Themes Service. Системная служба, управляющая "
        "загрузкой и применением визуальных тем."
    ),
    "dwmapi.dll": (
        "DWMAPI — Desktop Window Manager API. Клиентская библиотека для "
        "взаимодействия с Desktop Window Manager (DWM). Предоставляет "
        "программный доступ к функциям композиции рабочего стола: управление "
        "прозрачностью окон (Aero Glass), миниатюрами панели задач, Flip3D."
    ),
    "msimg32.dll": (
        "Msimg32 — GDIEXT Client DLL. Предоставляет расширенные функции "
        "графического вывода поверх стандартного GDI: GradientFill для создания "
        "градиентных заливок и AlphaBlend для полупрозрачного наложения "
        "изображений с альфа-каналом."
    ),
    "gdiplus.dll": (
        "GDI+ — библиотека двухмерной графики, преемник GDI. Поддерживает "
        "работу со сложными векторными формами, градиентными кистями, путями, "
        "альфа-каналами и множеством форматов изображений (JPEG, PNG, BMP, "
        "GIF, TIFF)."
    ),
    "oleacc.dll": (
        "OLEACC — Microsoft Active Accessibility (MSAA) Core Component. "
        "Предоставляет инфраструктуру accessibility для стандартных элементов "
        "управления Windows."
    ),
    "propsys.dll": (
        "Propsys — Microsoft Property System. Реализует систему метаданных "
        "Windows Vista и новее, позволяющую приложениям регистрировать "
        "и запрашивать расширенные свойства файлов."
    ),
    "windows.storage.dll": (
        "Windows.Storage — Windows Storage API. Предоставляет функции для "
        "работы с файловой системой, библиотеками и виртуальными папками "
        "в стиле Windows Runtime."
    ),
    "comdlg32.ocx": (
        "ComDlg32.ocx — ActiveX-версия библиотеки общих диалоговых окон "
        "для использования в средах разработки, таких как Visual Basic."
    ),
    "stobject.dll": (
        "STObject — System Tray Object. Библиотека для управления значками "
        "в системном трее (notification area), включая часы, громкость, "
        "состояние сети, индикатор батареи."
    ),
    "batmeter.dll": (
        "BatMeter — Battery Meter. Библиотека для отображения состояния "
        "батареи ноутбука/планшета в системном трее и диалоговых окнах."
    ),
    "wlanapi.dll": (
        "WlanApi — Windows Wireless LAN API. Предоставляет функции для "
        "управления беспроводными сетевыми подключениями: сканирование "
        "сетей, подключение, отключение, управление профилями."
    ),
    "wlanui.dll": (
        "WlanUI — Wireless LAN UI. Библиотека пользовательского интерфейса "
        "для управления Wi-Fi-подключениями: выбор сети, ввод пароля, "
        "отображение статуса соединения."
    ),
    "pnidui.dll": (
        "PniDui — Network List Manager UI. Предоставляет интерфейсы для "
        "отображения списка доступных сетей и управления сетевыми "
        "подключениями из области уведомлений."
    ),
    "msctf.dll": (
        "MSCTF — Text Services Framework. Базовая библиотека для поддержки "
        "ввода текста, включая IME (Input Method Editor), проверку орфографии, "
        "автозамену, распознавание речи и рукописного ввода."
    ),
    "ctfmon.exe": (
        "CTF Loader — ctfmon.exe. Процесс, управляющий Text Services "
        "Framework (MSCTF), обеспечивающий работу IME, клавиатурных "
        "раскладок и других текстовых служб."
    ),
    "input.dll": (
        "Input — библиотека управления вводом. Обрабатывает события "
        "от клавиатуры, мыши, сенсорного экрана, пера и других "
        "устройств ввода в Windows 8+."
    ),
    "inputswitch.dll": (
        "InputSwitch — библиотека переключения методов ввода. "
        "Управляет переключением между раскладками клавиатуры "
        "и IME в Windows 8+."
    ),
    "credui.dll": (
        "CredUI — Credential User Interface. Диалоговое окно для ввода, "
        "сохранения и управления учётными данными пользователя "
        "(пароли, PIN-коды, сертификаты)."
    ),
    "printui.dll": (
        "PrintUI — Print UI Library. Предоставляет пользовательский "
        "интерфейс для управления принтерами: установка, настройка, "
        "управление очередями печати."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 5. КРИПТОГРАФИЯ И БЕЗОПАСНОСТЬ
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_SECURITY_CRYPTO = {
    "advapi32.dll": (
        "Advapi32 — Advanced API: службы безопасности (управление ACL, "
        "токенами, привилегиями), реестр (RegCreateKey, RegQueryValue), "
        "сервисы Windows (Service Control Manager), криптография."
    ),
    "crypt32.dll": (
        "Crypt32 — CryptoAPI: управление сертификатами (X.509), "
        "хранилищами сертификатов, кодирование/декодирование ASN.1, "
        "проверка цифровых подписей, работа с цепочками сертификатов."
    ),
    "wintrust.dll": (
        "WinTrust — Microsoft Trust Verification: проверка подлинности "
        "исполняемых файлов (Authenticode), проверка цифровых подписей "
        "ActiveX-компонентов, управление поставщиками доверия."
    ),
    "ncrypt.dll": (
        "Ncrypt — Cryptography API Next Generation (CNG): современный "
        "криптографический API. Поддержка алгоритмов AES, RSA, ECDSA, "
        "SHA-2/3, управление ключами (Key Storage)."
    ),
    "bcrypt.dll": (
        "Bcrypt — Cryptographic Primitives: низкоуровневые криптографические "
        "примитивы, включая хеширование (SHA, MD5), симметричное шифрование "
        "(AES, 3DES), генерация случайных чисел."
    ),
    "bcryptprimitives.dll": (
        "BCryptPrimitives — высокопроизводительные криптографические примитивы "
        "Windows: симметричное шифрование, хеширование, генерация случайных "
        "чисел. Фундамент для bcrypt.dll."
    ),
    "dpapi.dll": (
        "DPAPI — Data Protection API: шифрование и расшифровка данных "
        "с привязкой к учётной записи пользователя или компьютеру."
    ),
    "secur32.dll": (
        "Secur32 — Security Support Provider Interface (SSPI): аутентификация "
        "(NTLM, Kerberos, Negotiate), управление учётными данными, "
        "контексты безопасности."
    ),
    "sspicli.dll": (
        "SspiCli — SSPI Client: клиентская часть Security Support Provider "
        "Interface. Используется приложениями для аутентификации и установки "
        "защищённых соединений."
    ),
    "msasn1.dll": (
        "Msasn1 — ASN.1 Runtime: кодирование/декодирование данных в формате "
        "ASN.1 для криптографических операций, сертификатов, Kerberos."
    ),
    "samlib.dll": (
        "Samlib — Security Account Manager Library: API для управления "
        "локальной базой учётных записей (SAM), включая пользователей, "
        "группы, пароли."
    ),
    "cryptsp.dll": (
        "CryptSP — Cryptographic Service Provider API: библиотека, "
        "обеспечивающая взаимодействие между CryptoAPI и криптографическими "
        "провайдерами (CSP)."
    ),
    "cryptdll.dll": (
        "CryptDll — Cryptography Helper DLL: вспомогательная библиотека "
        "для CryptoAPI. Предоставляет дополнительные криптографические "
        "функции и управление цифровыми сертификатами."
    ),
    "cryptnet.dll": (
        "CryptNet — Cryptographic Network Services: обеспечивает сетевую "
        "поддержку для CryptoAPI, включая проверку сертификатов по сети, "
        "работу со списками отзыва сертификатов (CRL)."
    ),
    "cryptui.dll": (
        "CryptUI — Cryptographic User Interface: предоставляет стандартные "
        "диалоговые окна для работы с сертификатами."
    ),
    "cryptngc.dll": (
        "CryptNgc — Cryptographic Next Generation API: расширение CNG "
        "с поддержкой PIN-кодов и биометрических данных для Windows Hello, "
        "взаимодействие с Trusted Platform Module (TPM)."
    ),
    "msv1_0.dll": (
        "MSV1_0 — Microsoft Authentication Package v1.0: реализует протокол "
        "аутентификации NTLM (NT LAN Manager)."
    ),
    "kerberos.dll": (
        "Kerberos Security Package: реализует протокол аутентификации "
        "Kerberos для доменов Active Directory с использованием билетов "
        "(tickets). С Windows Vista добавлена поддержка шифрования AES."
    ),
    "schannel.dll": (
        "Schannel — Secure Channel: реализует протоколы аутентификации "
        "TLS/SSL. Обеспечивает шифрование и целостность сетевых соединений, "
        "включая проверку сертификатов X.509."
    ),
    "wdigest.dll": (
        "WDigest — Digest Authentication SSP: реализует Digest-аутентификацию "
        "по протоколам HTTP и SASL."
    ),
    "tspkg.dll": (
        "TSPkg — Terminal Services Security Package: обеспечивает "
        "аутентификацию для служб терминалов (Remote Desktop Services)."
    ),
    "pku2u.dll": (
        "PKU2U — Public Key Cryptography User-to-User: реализует "
        "аутентификацию на основе сертификатов для одноранговых сетей."
    ),
    "cloudap.dll": (
        "CloudAP — Cloud Authentication Provider: современный SSP, "
        "обеспечивающий аутентификацию с использованием облачных учётных "
        "записей Microsoft (Microsoft Account, Azure AD/Entra ID)."
    ),
    "negoexts.dll": (
        "NegoExts — Negotiate Extensions: расширения для протокола Negotiate, "
        "обеспечивающие согласование между различными поставщиками "
        "безопасности (SSP)."
    ),
    "credssp.dll": (
        "CredSSP — Credential Security Support Provider: реализует "
        "делегирование учётных данных для сценариев PowerShell Remoting, "
        "WinRM."
    ),
    "lsasrv.dll": (
        "Lsasrv — Local Security Authority Server DLL: основной модуль "
        "подсистемы локальной безопасности (LSASS). Реализует большинство "
        "функций безопасности Windows."
    ),
    "samsrv.dll": (
        "Samsrv — Security Accounts Manager Server DLL: управляет "
        "локальной базой учётных записей (SAM)."
    ),
    "netlogon.dll": (
        "NetLogon — Net Logon Service: поддерживает безопасный канал "
        "между компьютером и контроллером домена."
    ),
    "keyiso.dll": (
        "KeyIso — Key Isolation Service. Обеспечивает изоляцию "
        "криптографических ключей в изолированном процессе (LSA), "
        "предотвращая доступ к ключам со стороны непривилегированных "
        "процессов даже при компрометации."
    ),
    "cngaudit.dll": (
        "CNG Audit — Cryptographic Next Generation Audit. Реализует "
        "аудит криптографических операций CNG для соответствия "
        "требованиям безопасности (PCI DSS, FIPS 140-2)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 6. СЕТЬ И КОММУНИКАЦИИ
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_NETWORK = {
    "ws2_32.dll": (
        "Ws2_32 — Windows Sockets 2 (Winsock): реализация Berkeley Sockets "
        "API для Windows. Создание и управление сокетами TCP/UDP, асинхронные "
        "операции, поддержка IPv4/IPv6."
    ),
    "winhttp.dll": (
        "WinHTTP — Windows HTTP Services: клиентская библиотека для отправки "
        "HTTP/HTTPS-запросов. Предназначена для серверных приложений и служб."
    ),
    "wininet.dll": (
        "WinINet — Windows Internet: реализация протоколов HTTP, FTP, Gopher "
        "для интерактивных приложений. Поддерживает кэширование, автонастройку "
        "прокси, обработку cookie."
    ),
    "urlmon.dll": (
        "Urlmon — URL Moniker: связывание URL с объектами, асинхронная "
        "загрузка данных, поддержка MIME-типов, security zones."
    ),
    "iertutil.dll": (
        "Iertutil — Internet Explorer Runtime Utility: вспомогательные "
        "функции для WinINet и UrlMon, включая работу со строками, "
        "памятью и кэшем."
    ),
    "dnsapi.dll": (
        "Dnsapi — DNS Client API: преобразование имён хостов в IP-адреса "
        "(DNS resolution), управление локальным кэшем DNS, асинхронные запросы."
    ),
    "iphlpapi.dll": (
        "IpHlpApi — IP Helper API: информация о сетевых интерфейсах, "
        "таблице маршрутизации, ARP-таблице, статистика TCP/UDP, "
        "управление адаптерами."
    ),
    "mpr.dll": (
        "Mpr — Multiple Provider Router: маршрутизация вызовов к сетевым "
        "провайдерам (LAN Manager, NetWare)."
    ),
    "netapi32.dll": (
        "Netapi32 — Network Management API: управление общими ресурсами, "
        "пользователями и группами домена, сетевыми соединениями."
    ),
    "wtsapi32.dll": (
        "Wtsapi32 — Windows Terminal Services API: управление сеансами "
        "удалённого рабочего стола (RDP), отправка сообщений между сессиями."
    ),
    "httpapi.dll": (
        "Httpapi — HTTP Server API: реализация серверного HTTP-стека Windows. "
        "Предоставляет интерфейс для создания высокопроизводительных "
        "веб-серверов и обработки HTTP-запросов без участия IIS."
    ),
    "webio.dll": (
        "Webio — Windows Web IO Library: низкоуровневая библиотека "
        "ввода-вывода для веб-протоколов. Обеспечивает асинхронную "
        "передачу данных по HTTP и HTTPS."
    ),
    "mswsock.dll": (
        "MSWSock — Microsoft Winsock Service Provider: реализация "
        "поставщика услуг Winsock от Microsoft. Предоставляет "
        "AcceptEx, ConnectEx и другие расширения Winsock 2."
    ),
    "wsock32.dll": (
        "Wsock32 — Windows Sockets 1.1 API: оригинальная реализация "
        "Winsock для 16/32-битных приложений. В современных системах "
        "является оболочкой над ws2_32.dll для обратной совместимости."
    ),
    "rpcrt4.dll": (
        "Rpcrt4 — Remote Procedure Call Runtime: реализация клиентской "
        "и серверной частей RPC в Windows. Является фундаментом для "
        "множества системных служб."
    ),
    "authz.dll": (
        "Authz — Authorization Framework: библиотека авторизации на основе "
        "ролей и политик для проверки прав доступа к ресурсам "
        "в распределённых системах."
    ),
    "mgmtapi.dll": (
        "Mgmtapi — SNMP Management API: реализация протокола SNMP "
        "(Simple Network Management Protocol) для управления сетевыми "
        "устройствами."
    ),
    "snmpapi.dll": (
        "Snmpapi — SNMP Utility API: дополнительные функции для работы "
        "с протоколом SNMP."
    ),
    "traffic.dll": (
        "Traffic — Quality of Service Traffic Control: библиотека "
        "управления качеством обслуживания (QoS) сетевого трафика."
    ),
    "mprapi.dll": (
        "Mprapi — Multi-Protocol Routing API: интерфейс для "
        "администрирования служб маршрутизации и удалённого доступа "
        "(RRAS): VPN-подключения, маршрутизация между сетями, NAT."
    ),
    "rtutils.dll": (
        "Rtutils — Routing Utilities: вспомогательная библиотека "
        "для служб маршрутизации и удалённого доступа."
    ),
    "security.dll": (
        "Security — RAS Security Library: библиотека безопасности "
        "для служб удалённого доступа."
    ),
    "clusapi.dll": (
        "Clusapi — Cluster API: интерфейс для управления "
        "отказоустойчивыми кластерами Windows."
    ),
    "resutils.dll": (
        "Resutils — Cluster Resource Utilities: вспомогательная "
        "библиотека ресурсов кластера."
    ),
    "netshell.dll": (
        "Netshell — Network Shell: библиотека поддержки утилиты "
        "netsh (Network Shell) для скриптового управления сетевыми "
        "конфигурациями."
    ),
    "fwpuclnt.dll": (
        "Fwpuclnt — Windows Filtering Platform (WFP) User Mode Client: "
        "клиентская библиотека для взаимодействия с подсистемой "
        "фильтрации сетевых пакетов Windows."
    ),
    "dhcpsvc.dll": (
        "Dhcpsvc — DHCP Server Service: реализация сервера DHCP "
        "(Dynamic Host Configuration Protocol). Отвечает за автоматическое "
        "назначение IP-адресов клиентам."
    ),
    "dhcpclient.dll": (
        "DHCP Client — библиотека DHCP-клиента для автоматического "
        "получения конфигурации сети через протокол DHCP."
    ),
    "winrnr.dll": (
        "WinRNR — Windows Resolution Name Service Provider. Обеспечивает "
        "разрешение имён NetBIOS и DNS через стандартный Winsock API."
    ),
    "svchost.exe": (
        "Service Host — svchost.exe. Универсальный процесс-хост для "
        "Windows-служб. Одна из ключевых исполняемых систем Windows, "
        "используется для запуска разнообразных служб (DHCP, DNS, "
        "Windows Update, BFE и др.)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 7. ГРАФИКА (DirectX, OpenGL, GDI extended)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_GRAPHICS = {
    "dxgi.dll": (
        "DXGI — DirectX Graphics Infrastructure: управление адаптерами "
        "дисплея, цепочками переключения (swap chains), перечисление "
        "видеорежимов. Фундамент для Direct3D."
    ),
    "d3d11.dll": (
        "D3D11 — Direct3D 11: трёхмерная графика и GPGPU-вычисления "
        "с использованием шейдерной модели 5.0. Поддержка тесселяции, "
        "compute-шейдеров, многопоточного рендеринга."
    ),
    "d3d12.dll": (
        "D3D12 — Direct3D 12: низкоуровневый API трёхмерной графики "
        "с явным управлением ресурсами и меньшими накладными расходами "
        "(ближе к «metal»). Поддержка шейдерной модели 6.x, ray-tracing, "
        "Variable Rate Shading, Mesh Shaders."
    ),
    "d3d12core.dll": (
        "D3D12Core — Direct3D 12 Core: базовая реализация Direct3D 12, "
        "содержащая функциональность для всех устройств Windows 10+."
    ),
    "d3d9.dll": (
        "D3D9 — Direct3D 9: трёхмерная графика предыдущего поколения. "
        "Поддерживает шейдерную модель 3.0. Всё ещё широко используется "
        "для совместимости со старыми приложениями и играми."
    ),
    "d2d1.dll": (
        "D2D1 — Direct2D: аппаратно-ускоренная двухмерная графика. "
        "Рендеринг векторной графики, текста, растровых изображений "
        "через GPU. Современная замена GDI/GDI+."
    ),
    "dwrite.dll": (
        "DWrite — DirectWrite: высококачественный рендеринг текста "
        "с поддержкой ClearType, OpenType-шрифтов, сложных скриптов."
    ),
    "dcomp.dll": (
        "DComp — DirectComposition: библиотека композиции визуального "
        "контента с аппаратным ускорением. Анимации, трансформации, "
        "прозрачность окон. Используется DWM."
    ),
    "opengl32.dll": (
        "OpenGL32 — реализация OpenGL API для Windows. Обеспечивает "
        "доступ к аппаратно-ускоренной 2D/3D-графике через "
        "стандартизированный кроссплатформенный интерфейс."
    ),
    "glu32.dll": (
        "GLU32 — OpenGL Utility Library: вспомогательные функции "
        "для OpenGL: построение квадратичных поверхностей (сферы, "
        "цилиндры), NURBS-кривые, матричные преобразования."
    ),
    "dxva2.dll": (
        "DXVA2 — DirectX Video Acceleration 2.0. Предоставляет "
        "аппаратное ускорение декодирования видео (H.264, VC-1, "
        "MPEG-2) через DirectX."
    ),
    "dxdiagn.dll": (
        "DXDiag — DirectX Diagnostic Tool: библиотека сбора "
        "информации о системе DirectX для диагностики и "
        "отчётов (dxdiag.exe)."
    ),
    "uiautomationcore.dll": (
        "UIAutomationCore — UI Automation Core: инфраструктура "
        "для accessibility-инструментов (экранные дикторы, "
        "программы для людей с ограниченными возможностями)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 8. МУЛЬТИМЕДИА (WinMM, Media Foundation, Core Audio)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_MULTIMEDIA = {
    "winmm.dll": (
        "WinMM — Windows Multimedia: аудио (waveOut, midiOut), "
        "таймеры высокого разрешения (timeGetTime), управление "
        "джойстиком. Устаревший API, заменён DirectX / Media Foundation."
    ),
    "mf.dll": (
        "MF — Media Foundation: базовая библиотека мультимедийного "
        "фреймворка Windows. Управление сессиями воспроизведения, "
        "топологией медиа-графов, синхронизацией потоков."
    ),
    "mfplat.dll": (
        "MFPlat — Media Foundation Platform: платформенная "
        "библиотека Media Foundation. Предоставляет базовые типы, "
        "интерфейсы (IMFMediaBuffer, IMFMediaSample, IMFAttributes) "
        "и вспомогательные функции."
    ),
    "mfreadwrite.dll": (
        "MFReadWrite — Media Foundation Reader/Writer: высокоуровневый "
        "API для чтения и записи медиа-файлов (Sink Writer, "
        "Source Reader)."
    ),
    "mfsrcsnk.dll": (
        "MFSrcSnk — Media Foundation Sources and Sinks: содержит "
        "стандартные источники (файлы, устройства захвата) "
        "и приёмники мультимедийных данных."
    ),
    "mfmpeg2srcsnk.dll": (
        "MFMPEG2SrcSnk — Media Foundation MPEG-2 Source/Sink: "
        "источники и приёмники для MPEG-2 контейнеров (TS, PS)."
    ),
    "mfh264enc.dll": (
        "MFH264Enc — Media Foundation H.264 Video Encoder: "
        "программный кодировщик H.264/AVC для Media Foundation."
    ),
    "mfh264dec.dll": (
        "MFH264Dec — Media Foundation H.264 Video Decoder: "
        "программный декодировщик H.264/AVC для Media Foundation."
    ),
    "mfperfhelper.dll": (
        "MFPerfHelper — Media Foundation Performance Helper: "
        "вспомогательная библиотека для сбора данных "
        "о производительности Media Foundation."
    ),
    "wmcodecdsp.dll": (
        "WMCodecDSP — Windows Media Codec DSP: набор кодеков "
        "Windows Media Video/Audio в виде DSP-модулей (MFT). "
        "Содержит WMV9, WMA, VC-1 кодеки."
    ),
    "msmpeg2vdec.dll": (
        "MSMPEG2VDec — Microsoft MPEG-2 Video Decoder: программный "
        "декодировщик MPEG-2 видео, используемый Media Foundation "
        "и DShow."
    ),
    "msmpeg2enc.dll": (
        "MSMPEG2Enc — Microsoft MPEG-2 Encoder: программный "
        "кодировщик MPEG-2 видео."
    ),
    "evr.dll": (
        "EVR — Enhanced Video Renderer: улучшенный видео-рендерер "
        "на базе Direct3D. Замена старого VMR (Video Mixing Renderer). "
        "Поддерживает аппаратное ускорение и deinterlacing."
    ),
    "colorcnv.dll": (
        "ColorCNV — Color Converter DSP: преобразование цветовых "
        "пространств (RGB ↔ YUV, Y′CbCr ↔ Y′PbPr и др.) "
        "для мультимедийных pipeline."
    ),
    "resampledmo.dll": (
        "ResampleDMO — Audio Resampler DMO: преобразование частоты "
        "дискретизации аудио (sample rate conversion) для Media "
        "Foundation и DirectShow."
    ),
    "avrt.dll": (
        "AVRT — Multimedia Class Scheduler Service: библиотека "
        "для управления приоритетами аудио/видео потоков "
        "(MMCSS). Обеспечивает плавное воспроизведение без "
        "прерываний."
    ),
    "audioses.dll": (
        "AudioSes — Audio Session API: библиотека управления "
        "аудиосессиями Windows. Предоставляет программам доступ "
        "к управлению громкостью и маршрутизацией звука."
    ),
    "mmdevapi.dll": (
        "MMDevApi — Multimedia Device API: библиотека перечисления "
        "и управления аудиоустройствами (динамики, наушники, "
        "микрофоны). Фундамент для Core Audio API."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 9. БИБЛИОТЕКИ ВРЕМЕНИ ВЫПОЛНЕНИЯ (MSVC, ATL, MFC)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_RUNTIME = {
    "msvcrt.dll": (
        "MSVCRT — Microsoft Visual C Runtime: стандартная библиотека "
        "C (printf, malloc, fopen, memcpy) для приложений, "
        "скомпилированных с Visual C++. Системная версия."
    ),
    "vcruntime140.dll": (
        "VCRuntime140 — Visual C++ 2015-2022 Runtime: базовые функции "
        "времени выполнения (инициализация/завершение потока, "
        "проброс исключений, проверки безопасности)."
    ),
    "vcruntime140_1.dll": (
        "VCRuntime140_1 — Microsoft C Runtime Library: расширенная "
        "версия vcruntime140.dll с дополнительными функциями "
        "поддержки компилятора."
    ),
    "msvcp140.dll": (
        "MSVCP140 — Microsoft Visual C++ 2015-2022 Standard Library: "
        "реализация STL (std::string, std::vector, std::map), "
        "ввод/вывод (iostream), работа с файлами."
    ),
    "msvcp140_1.dll": (
        "MSVCP140_1 — Microsoft C++ Standard Library Extension: "
        "дополнительная библиотека STL, введённая в Visual Studio "
        "2017 версии 15.6."
    ),
    "msvcp140_2.dll": (
        "MSVCP140_2 — Microsoft C++ Standard Library Extension 2: "
        "второй уровень расширения STL для более поздних обновлений "
        "Visual Studio 2017/2019."
    ),
    "msvcp140_atomic_wait.dll": (
        "MSVCP140_Atomic_Wait — Microsoft C++ Atomic Wait Library: "
        "специализированная библиотека для поддержки атомарных "
        "операций ожидания в C++20."
    ),
    "msvcp140_codecvt_ids.dll": (
        "MSVCP140_Codecvt_IDs — Microsoft C Runtime Library codecvt_ids: "
        "поддержка идентификации кодировок символов (codecvt facets) "
        "в стандартной библиотеке C++."
    ),
    "ucrtbase.dll": (
        "UCRTBase — Universal CRT: универсальная библиотека времени "
        "выполнения C для Windows 10+. Включает стандартные функции "
        "C99, математические функции, locale-поддержку."
    ),
    "concrt140.dll": (
        "ConcRT140 — Concurrency Runtime: поддержка параллельных "
        "вычислений (PPL — Parallel Patterns Library), асинхронных "
        "операций, агентов. Часть Visual C++ Runtime."
    ),
    "vccorlib140.dll": (
        "VCCorLib140 — Microsoft VC WinRT Core Library: библиотека "
        "времени выполнения для управляемого кода C++/CX и C++/CLI, "
        "обеспечивающая поддержку Windows Runtime (WinRT)."
    ),
    "vcomp140.dll": (
        "VCOMP140 — Microsoft C/C++ OpenMP Runtime: библиотека "
        "поддержки параллельных вычислений по стандарту OpenMP."
    ),
    "vcamp140.dll": (
        "VCAMP140 — Microsoft C++ AMP Runtime: библиотека поддержки "
        "технологии C++ Accelerated Massive Parallelism (C++ AMP) "
        "для параллельных вычислений на GPU."
    ),
    "atl.dll": (
        "ATL — Active Template Library: набор шаблонных классов C++ "
        "для COM-разработки. Упрощает создание COM-объектов, "
        "ActiveX-компонентов."
    ),
    "atl100.dll": (
        "ATL100 — Visual C++ ATL 10.0: версия ATL для Visual Studio 2010."
    ),
    "mfc140.dll": (
        "MFC140 — Microsoft Foundation Classes Library: основная "
        "библиотека MFC для Visual Studio 2015-2022. Предоставляет "
        "объектно-ориентированную обёртку над Win32 API."
    ),
    "mfc140u.dll": (
        "MFC140U — Microsoft Foundation Classes Library (Unicode): "
        "Unicode-версия библиотеки MFC140."
    ),
    "mfcm140.dll": (
        "MFCM140 — MFC Managed Library: управляемая библиотека MFC "
        "для приложений, использующих Windows Forms Controls."
    ),
    "mfcmifc140.dll": (
        "MFCMifc140 — MFC Managed Interfaces Library: библиотека "
        "управляемых интерфейсов для MFC."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 10. .NET FRAMEWORK и .NET Core
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_DOTNET = {
    "mscoree.dll": (
        "MSCoree — .NET Runtime Execution Engine: точка входа "
        "для запуска управляемого кода .NET Framework (CLR). "
        "Загрузчик среды выполнения .NET."
    ),
    "mscorlib.dll": (
        "MSCorLib — Multilanguage Standard Common Object Runtime "
        "Library: основная библиотека классов .NET Framework. "
        "Содержит базовые типы (System.Object, System.String, "
        "System.Int32) и фундаментальные классы."
    ),
    "clr.dll": (
        "CLR — Common Language Runtime: исполняющая среда .NET "
        "Framework. Реализует JIT-компиляцию, сборку мусора, "
        "безопасность типов, управление потоками."
    ),
    "clrjit.dll": (
        "CLRJIT — CLR Just-In-Time Compiler: компилятор MSIL "
        "(CIL) в машинный код во время выполнения. Отвечает "
        "за оптимизацию и генерацию нативного кода."
    ),
    "dfdll.dll": (
        "DFDLL — .NET Framework Delegation: библиотека для "
        "поддержки делегирования вызовов и маршалинга "
        "в .NET Framework."
    ),
    "mscordacwks.dll": (
        "MSCordacWks — .NET Data Access Component (Workstation): "
        "библиотека отладки управляемого кода, используемая "
        "отладчиками (WinDbg, Visual Studio) для доступа "
        "к внутренним структурам CLR."
    ),
    "sos.dll": (
        "SOS — Son of Strike: расширение отладчика для CLR "
        "(Debugging Extension). Предоставляет команды !dumpobj, "
        "!clrstack, !gcroot для анализа управляемой памяти."
    ),
    "hostfxr.dll": (
        "HostFxr — .NET Host Framework Resolver: библиотека "
        "для определения версии .NET Runtime и загрузки "
        "соответствующей среды выполнения."
    ),
    "hostpolicy.dll": (
        "HostPolicy — .NET Host Policy: библиотека управления "
        "политиками загрузки .NET Core / .NET 5+. Определяет "
        "какую версию фреймворка использовать."
    ),
    "coreclr.dll": (
        "CoreCLR — .NET Core / .NET 5+ Common Language Runtime: "
        "современная кроссплатформенная исполняющая среда .NET. "
        "Реализует JIT (RyuJIT), сборку мусора, метаданные."
    ),
    "msquic.dll": (
        "MsQuic — Microsoft QUIC Library: реализация протокола "
        "QUIC (RFC 9000) от Microsoft. Используется .NET для "
        "HTTP/3 и ASP.NET Core для современных сетевых соединений."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 11. СИСТЕМНЫЕ СЛУЖБЫ (WMI, WER, Update, Installer, SFC, WMI, EventLog и др.)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_SYSTEM_SERVICES = {
    # --- Process / Debug ---
    "psapi.dll": (
        "PSAPI — Process Status API: получение информации "
        "о процессах и потоках, включая список загруженных "
        "модулей, использование памяти, количество handles."
    ),
    "dbghelp.dll": (
        "DbgHelp — Debug Help Library: функции для работы "
        "с отладочной информацией (символы, формат PDB), "
        "анализ стека вызовов, создание минидампов."
    ),
    # --- Power ---
    "powrprof.dll": (
        "PowrProf — Power Profile: управление схемами "
        "электропитания, запрос состояния батареи, "
        "управление спящим режимом."
    ),
    # --- Setup / Devices ---
    "setupapi.dll": (
        "SetupAPI — Setup API: установка и удаление устройств "
        "Plug and Play, драйверов, классов устройств."
    ),
    "newdev.dll": (
        "NewDev — Device Installation DLL: библиотека для "
        "установки и обновления драйверов устройств "
        "(часть SetupAPI)."
    ),
    # --- Printing ---
    "winspool.drv": (
        "Winspool.drv — Windows Print Spooler Driver: управление "
        "принтерами, очередями печати и заданиями печати."
    ),
    # --- Performance ---
    "pdh.dll": (
        "PDH — Performance Data Helper: сбор данных "
        "о производительности системы (счётчики CPU, "
        "памяти, дисков, сети)."
    ),
    "perfos.dll": (
        "PerfOS — Performance Counter DLL for OS: поставщик "
        "данных производительности для ОС (системные счётчики)."
    ),
    # --- SFC ---
    "sfc.dll": (
        "SFC — System File Checker: проверка целостности "
        "системных файлов Windows."
    ),
    "sfc_os.dll": (
        "SFC_OS — System File Checker OS Support: низкоуровневый "
        "доступ к защищённым системным файлам."
    ),
    # --- Compatibility ---
    "apphelp.dll": (
        "AppHelp — Application Compatibility: реализация механизма "
        "совместимости приложений (shim engine). Позволяет старым "
        "приложениям работать на новых версиях Windows."
    ),
    "acgenral.dll": (
        "ACGenral — Application Compatibility General: общая "
        "библиотека совместимости приложений, содержащая "
        "часть базы данных shim-исправлений."
    ),
    "aclayers.dll": (
        "ACLayers — Application Compatibility Layers: библиотека, "
        "реализующая отдельные слои совместимости приложений."
    ),
    # --- Profiles ---
    "profapi.dll": (
        "ProfApi — Profile API: управление пользовательскими "
        "профилями: загрузка/выгрузка, управление реестром "
        "профиля, уведомления об изменениях."
    ),
    # --- Win32 User Mode Kernel Interface ---
    "win32u.dll": (
        "Win32U — Windows 32-bit User-mode: содержит реализацию "
        "части user32 и gdi32 для поддержки UWP-приложений "
        "и изоляции syscall-интерфейса."
    ),
    # --- WDF ---
    "wdfldr.sys": (
        "WDF Loader (Windows Driver Framework Loader): загрузчик "
        "сред выполнения драйверов (KMDF/UMDF). Обеспечивает "
        "динамическую привязку и управление драйверами режима ядра."
    ),
    # --- WMI (Windows Management Instrumentation) ---
    "wbemprox.dll": (
        "WBEMProx — WMI Provider Proxy: прокси-библиотека WMI, "
        "обеспечивающая межпроцессное взаимодействие между "
        "WMI-клиентами и провайдерами."
    ),
    "wbemcomn.dll": (
        "WBEMComn — WMI Common: общая библиотека WMI, содержащая "
        "базовые утилиты, менеджер контекстов и общие интерфейсы "
        "(IWbemContext, IWbemClassObject)."
    ),
    "wbemsvc.dll": (
        "WBEMSvc — WMI Service: библиотека-загрузчик WMI-"
        "провайдеров. Отвечает за обнаружение и активацию "
        "провайдеров WMI."
    ),
    "fastprox.dll": (
        "FastProx — Fast WMI Provider: оптимизированный "
        "WMI-провайдер для работы с реестром, процессами "
        "и системной информацией."
    ),
    "wmi.dll": (
        "WMI — Windows Management Instrumentation: основная "
        "библиотека WMI, содержащая реализацию CIM Object "
        "Manager и репозитория WMI."
    ),
    # --- Windows Event Log / Tracing (ETW) ---
    "wevtapi.dll": (
        "WEvtAPI — Windows Event Log API: библиотека для "
        "чтения, записи и управления журналами событий "
        "Windows (Event Log)."
    ),
    "es.dll": (
        "ES — Event Tracing for Windows (ETW): библиотека "
        "системного трассирования событий. Используется "
        "для профилирования и диагностики системы."
    ),
    "tdh.dll": (
        "TDH — Trace Data Helper: библиотека для декодирования "
        "и анализа данных ETW-трассировки. Предоставляет "
        "доступ к метаданным событий (провайдеры, манифесты)."
    ),
    # --- Windows Error Reporting (WER) ---
    "wer.dll": (
        "WER — Windows Error Reporting: библиотека сбора "
        "и отправки отчётов об ошибках (crash dumps) "
        "в Microsoft."
    ),
    "faultrep.dll": (
        "FaultRep — Fault Reporting: библиотека генерации "
        "отчётов об ошибках (Watson). Создаёт минидампы "
        "и контекстные данные для WER."
    ),
    "wermgr.exe": (
        "WER Manager — werMgr.exe: диспетчер Windows Error "
        "Reporting. Обрабатывает очередь отчётов об ошибках, "
        "управляет отправкой и хранением минидампов."
    ),
    # --- Windows Update ---
    "wuapi.dll": (
        "WUAPI — Windows Update Agent API: библиотека для "
        "программного управления обновлениями Windows: "
        "поиск, загрузка, установка обновлений."
    ),
    "wuaueng.dll": (
        "WUAUEng — Windows Update Agent Engine: движок "
        "Windows Update, реализующий синхронизацию "
        "с серверами Microsoft Update и применение обновлений."
    ),
    "wucltux.dll": (
        "WUCLTUX — Windows Update Client UI: библиотека "
        "пользовательского интерфейса для Windows Update "
        "(Параметры → Центр обновлений)."
    ),
    "wuweb.dll": (
        "WUWeb — Windows Update Web: библиотека для "
        "интеграции веб-интерфейса Windows Update."
    ),
    "cbsapi.dll": (
        "CBSApi — Component Based Servicing API: библиотека "
        "API для обслуживания компонентов Windows, используемая "
        "DISM и Windows Update."
    ),
    # --- Windows Installer ---
    "msi.dll": (
        "MSI — Windows Installer: библиотека установки "
        "приложений в формате MSI (Microsoft Installer "
        "Package). Реализует транзакционную установку, "
        "откат, рекламу."
    ),
    "msiexec.exe": (
        "MSIExec — Windows Installer Engine: исполняемый "
        "файл установщика Windows (Windows Installer). "
        "Обрабатывает .msi и .msp пакеты."
    ),
    "msihnd.dll": (
        "MSI Hand — Windows Installer Handler: библиотека-"
        "обработчик файлов .msi для shell-контекстных меню."
    ),
    "msimsg.dll": (
        "MSI Msg — Windows Installer Message: библиотека "
        "строковых сообщений и локализации для Windows "
        "Installer."
    ),
    # --- WIC (Windows Imaging Component) ---
    "windowscodecs.dll": (
        "WindowsCodecs — Windows Imaging Component (WIC): "
        "фреймворк для работы с изображениями. Предоставляет "
        "единый API для кодирования/декодирования JPEG, PNG, "
        "TIFF, GIF, BMP, HD Photo и др."
    ),
    "windowscodecsext.dll": (
        "WindowsCodecsExt — Windows Imaging Component Extensions: "
        "расширения WIC для дополнительных форматов "
        "изображений, включая метаданные EXIF и IPTC."
    ),
    # --- Windows Search / Indexing ---
    "tquery.dll": (
        "TQuery — Indexing Query: библиотека выполнения "
        "запросов к индексу Windows Search. Обрабатывает "
        "поисковые запросы и возвращает результаты."
    ),
    "msscntrs.dll": (
        "MSSCntrs — Microsoft Search Counters: поставщик "
        "счётчиков производительности для Windows Search."
    ),
    "mssrch.dll": (
        "MSSrch — Microsoft Search: основная библиотека "
        "движка индексации Windows Search."
    ),
    "searchfolder.dll": (
        "SearchFolder — Search Folder: библиотека для "
        "виртуальных папок поиска (Saved Search Files .search-ms)."
    ),
    # --- Thumbnails ---
    "thumbcache.dll": (
        "ThumbCache — Thumbnail Cache: библиотека кэширования "
        "миниатюр (thumbnails) файлов и изображений для "
        "Проводника Windows."
    ),
    # --- Firewall API ---
    "firewallapi.dll": (
        "FirewallAPI — Windows Firewall API: библиотека "
        "программного управления брандмауэром Windows "
        "(Windows Defender Firewall with Advanced Security)."
    ),
    "netfw.dll": (
        "NetFw — Network Firewall: библиотека для "
        "управления правилами брандмауэра Windows "
        "через COM-интерфейс (HNetCfg)."
    ),
    # --- Time / NTP ---
    "w32time.dll": (
        "W32Time — Windows Time Service: библиотека службы "
        "точного времени Windows. Реализует протокол NTP "
        "для синхронизации системного времени."
    ),
    # --- Volume Shadow Copy ---
    "vssapi.dll": (
        "VssApi — Volume Shadow Copy Service API: библиотека "
        "для создания теневых копий томов (Volume Shadow "
        "Copy), используемая для резервного копирования."
    ),
    # --- Data Deduplication ---
    "ddpapi.dll": (
        "DDPApi — Data Deduplication API: библиотека для "
        "дедупликации данных на томе, используемая "
        "в Windows Server."
    ),
    # --- Disk Management ---
    "diskdyn.dll": (
        "DiskDyn — Dynamic Disk Library: библиотека для "
        "управления динамическими дисками и томами "
        "Windows (RAID-0, RAID-1, RAID-5)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 12. USB, HID И УСТРОЙСТВА ВВОДА
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_USB_DEVICE = {
    "winusb.dll": (
        "WinUSB — Windows USB Driver API: предоставляет "
        "приложениям прямой доступ к USB-устройствам "
        "без написания пользовательского драйвера."
    ),
    "hid.dll": (
        "HID — Human Interface Device API: взаимодействие "
        "с HID-устройствами (клавиатуры, мыши, джойстики, "
        "сенсорные панели) через протокол USB HID."
    ),
    "usbd.sys": (
        "USBD — USB Bus Driver: драйвер шины USB в режиме "
        "ядра. Управляет USB-контроллером и устройствами "
        "на шине."
    ),
    "usbhub.sys": (
        "USBHub — USB Hub Driver: драйвер USB-концентратора. "
        "Управляет подключением и отключением USB-устройств, "
        "распределением питания по портам."
    ),
    "usbccgp.sys": (
        "USBCCGP — USB Composite Device Generic Parent Driver: "
        "родительский драйвер для составных USB-устройств "
        "(например, веб-камера + микрофон)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 13. API SETS (расширенные контракты)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_API_SETS = {
    "api-ms-win-core-ums-l1-1-0": (
        "Windows API Set: User-Mode Scheduling (UMS). "
        "Обеспечивает планирование потоков в пользовательском "
        "режиме без переключения в режим ядра."
    ),
    "ext-ms-win-com-ole32-l1-1-5": (
        "Windows API Set: COM OLE32 расширения. Дополнительные "
        "функции Component Object Model для специфических "
        "платформ."
    ),
    "ext-ms-win-ntuser-window-l1-1-0": (
        "Windows API Set: NTUser Window расширения. Функции "
        "оконного интерфейса, доступные не на всех редакциях "
        "Windows."
    ),
    "api-ms-win-core-console-l1-1-0": (
        "API Set: Core Console — виртуальная DLL для функций "
        "управления консолью (AllocConsole, WriteConsole, "
        "ReadConsole, GetStdHandle)."
    ),
    "api-ms-win-core-string-l1-1-0": (
        "API Set: Core String — виртуальная DLL для функций "
        "работы со строками (lstrcmp, lstrcpy, wcslen, "
        "MultiByteToWideChar)."
    ),
    "api-ms-win-core-errorhandling-l1-1-0": (
        "API Set: Core Error Handling — виртуальная DLL для "
        "функций обработки ошибок (GetLastError, SetLastError, "
        "SetUnhandledExceptionFilter)."
    ),
    "api-ms-win-core-timezone-l1-1-0": (
        "API Set: Core TimeZone — виртуальная DLL для функций "
        "работы с часовыми поясами (GetTimeZoneInformation, "
        "SystemTimeToTzSpecificLocalTime)."
    ),
    "api-ms-win-core-fibers-l1-1-0": (
        "API Set: Core Fibers — виртуальная DLL для функций "
        "управления файберами (легковесные потоки в "
        "пользовательском режиме: CreateFiber, SwitchToFiber)."
    ),
    "api-ms-win-core-comm-l1-1-0": (
        "API Set: Core Communications — виртуальная DLL для "
        "функций работы с последовательными портами (COM-порты: "
        "CreateFile для COM, SetCommState, WaitCommEvent)."
    ),
    "api-ms-win-core-debug-l1-1-0": (
        "API Set: Core Debug — виртуальная DLL для функций "
        "отладки (DebugBreak, IsDebuggerPresent, "
        "WaitForDebugEvent)."
    ),
    "api-ms-win-core-namedpipe-l1-1-0": (
        "API Set: Core Named Pipe — виртуальная DLL для функций "
        "именованных каналов (CreateNamedPipe, ConnectNamedPipe, "
        "CallNamedPipe)."
    ),
    "api-ms-win-core-atoms-l1-1-0": (
        "API Set: Core Atoms — виртуальная DLL для функций "
        "работы с атомарными таблицами (GlobalAddAtom, "
        "GlobalGetAtomName, AddAtom)."
    ),
    "api-ms-win-core-delayload-l1-1-0": (
        "API Set: Core Delay Load — виртуальная DLL для "
        "поддержки отложенной загрузки DLL (DelayLoadHelper, "
        "__delayLoadHelper2)."
    ),
    "api-ms-win-core-localization-l1-2-0": (
        "API Set: Core Localization — виртуальная DLL для "
        "функций локализации и поддержки языковых стандартов "
        "(EnumSystemLocalesEx, GetUserDefaultLocaleName, "
        "GetLocaleInfoEx)."
    ),
    "api-ms-win-core-interlocked-l1-1-0": (
        "API Set: Core Interlocked — виртуальная DLL для "
        "функций атомарных операций Interlocked (InterlockedIncrement, "
        "InterlockedCompareExchange, InterlockedExchange)."
    ),
    "api-ms-win-core-rtlsupport-l1-1-0": (
        "API Set: Core RTL Support — виртуальная DLL для "
        "функций поддержки библиотеки времени выполнения "
        "(RtlCaptureStackBackTrace, RtlLookupFunctionEntry, "
        "RtlUnwindEx)."
    ),
    "api-ms-win-core-datetime-l1-1-1": (
        "API Set: Core DateTime — виртуальная DLL для функций "
        "работы с датой и временем (GetSystemTime, "
        "GetLocalTime, SetSystemTime, FileTimeToSystemTime)."
    ),
    "api-ms-win-core-misc-l1-1-0": (
        "API Set: Core Miscellaneous — виртуальная DLL для "
        "различных базовых функций (lstrlen, OutputDebugString, "
        "GetModuleFileName, GetTickCount)."
    ),
    "api-ms-win-core-registry-l1-1-0": (
        "API Set: Core Registry — виртуальная DLL для функций "
        "работы с реестром (RegOpenKeyEx, RegQueryValueEx, "
        "RegSetValueEx, RegEnumKeyEx)."
    ),
    "api-ms-win-core-threadpool-l1-2-0": (
        "API Set: Core Thread Pool — виртуальная DLL для "
        "функций работы с пулом потоков (QueueUserWorkItem, "
        "CreateTimerQueue, TrySubmitThreadpoolCallback)."
    ),
    "api-ms-win-core-wow64-l1-1-0": (
        "API Set: Core WOW64 — виртуальная DLL для функций "
        "поддержки WOW64 (Wow64DisableWow64FsRedirection, "
        "Wow64RevertWow64FsRedirection, IsWow64Process)."
    ),
    "api-ms-win-core-io-l1-1-0": (
        "API Set: Core I/O — виртуальная DLL для функций "
        "управления портами завершения ввода-вывода "
        "(CreateIoCompletionPort, GetQueuedCompletionStatus, "
        "PostQueuedCompletionStatus)."
    ),
    "api-ms-win-core-job-l1-1-0": (
        "API Set: Core Job — виртуальная DLL для функций "
        "управления объектами задания (CreateJobObject, "
        "AssignProcessToJobObject, SetInformationJobObject, "
        "QueryInformationJobObject)."
    ),
    "api-ms-win-core-shlwapi-l1-1-0": (
        "API Set: Core Shell Lightweight — виртуальная DLL "
        "для функций Shell Lightweight API (PathFindFileName, "
        "PathAppend, StrCmpLogicalW, SHGetValue)."
    ),
    "api-ms-win-core-com-l1-1-0": (
        "API Set: Core COM — виртуальная DLL для базовых "
        "функций COM (CoInitializeEx, CoCreateInstance, "
        "CoUninitialize, CoTaskMemAlloc)."
    ),
    "api-ms-win-core-kernel32-legacy-l1-1-0": (
        "API Set: Kernel32 Legacy — виртуальная DLL для "
        "устаревших функций kernel32, сохранённых для "
        "обратной совместимости."
    ),
    "api-ms-win-core-process-l1-1-1": (
        "API Set: Core Process — расширенная виртуальная "
        "DLL для функций управления процессами (IsProcessCritical, "
        "PowerCreateRequest, PowerMessage)."
    ),
    "api-ms-win-core-namedpipe-anonymous-l1-1-0": (
        "API Set: Core Anonymous Pipe — виртуальная DLL для "
        "функций анонимных каналов (CreatePipe, "
        "GetStdHandle для pipes)."
    ),
    "api-ms-win-eventing-l1-1-0": (
        "API Set: Eventing — виртуальная DLL для функций "
        "Event Tracing (EventRegister, EventWrite, "
        "EventEnabled)."
    ),
    "api-ms-win-eventing-provider-l1-1-0": (
        "API Set: Eventing Provider — виртуальная DLL для "
        "поставщиков событий ETW (EventRegister, "
        "EventUnregister, EventWriteString)."
    ),
    "api-ms-win-security-base-l1-1-0": (
        "API Set: Security Base — виртуальная DLL для "
        "базовых функций безопасности (GetTokenInformation, "
        "CheckTokenMembership, AdjustTokenPrivileges, "
        "AllocateAndInitializeSid)."
    ),
    "api-ms-win-security-attributes-l1-1-0": (
        "API Set: Security Attributes — виртуальная DLL "
        "для функций управления атрибутами безопасности "
        "(ConvertSecurityDescriptorToStringSecurityDescriptor)."
    ),
    "api-ms-win-crt-runtime-l1-1-0": (
        "API Set: CRT Runtime — виртуальная DLL для функций "
        "универсальной CRT (memcpy, strcmp, sprintf, malloc, "
        "free) в составе Universal CRT."
    ),
    "api-ms-win-crt-heap-l1-1-0": (
        "API Set: CRT Heap — виртуальная DLL для функций "
        "работы с кучей из Universal CRT (calloc, realloc "
        "в терминах Win32 Heap)."
    ),
    "api-ms-win-crt-string-l1-1-0": (
        "API Set: CRT String — виртуальная DLL для строковых "
        "функций Universal CRT (strcat, strcpy, wcscmp, "
        "mbstowcs)."
    ),
    "api-ms-win-crt-stdio-l1-1-0": (
        "API Set: CRT Stdio — виртуальная DLL для функций "
        "стандартного ввода/вывода Universal CRT (fopen, "
        "fread, fprintf, printf, scanf)."
    ),
    "api-ms-win-crt-convert-l1-1-0": (
        "API Set: CRT Convert — виртуальная DLL для функций "
        "преобразования данных Universal CRT (atof, atoi, "
        "strtod, wcstombs, itoa)."
    ),
    "api-ms-win-crt-environment-l1-1-0": (
        "API Set: CRT Environment — виртуальная DLL для "
        "функций окружения Universal CRT (getenv, "
        "_putenv, _environ)."
    ),
    "api-ms-win-crt-time-l1-1-0": (
        "API Set: CRT Time — виртуальная DLL для функций "
        "работы с датой/временем Universal CRT (time, "
        "localtime, strftime, mktime, gmtime)."
    ),
    "api-ms-win-crt-multibyte-l1-1-0": (
        "API Set: CRT Multibyte — виртуальная DLL для функций "
        "преобразования многобайтовых кодировок Universal CRT "
        "(_mbstowcs_l, _wcstombs_l, _mbslen)."
    ),
    "api-ms-win-crt-math-l1-1-0": (
        "API Set: CRT Math — виртуальная DLL для математических "
        "функций Universal CRT (sin, cos, sqrt, pow, exp, "
        "ceil, floor)."
    ),
    "api-ms-win-crt-filesystem-l1-1-0": (
        "API Set: CRT Filesystem — виртуальная DLL для функций "
        "файловой системы Universal CRT (_access, _chmod, "
        "_mkdir, _findfirst, _fullpath)."
    ),
    "api-ms-win-crt-utility-l1-1-0": (
        "API Set: CRT Utility — виртуальная DLL для "
        "вспомогательных функций Universal CRT (abs, "
        "labs, rand, srand, bsearch, qsort)."
    ),
    "api-ms-win-crt-process-l1-1-0": (
        "API Set: CRT Process — виртуальная DLL для функций "
        "управления процессами Universal CRT (_beginthread, "
        "_beginthreadex, _endthread, _wexecl)."
    ),
    "api-ms-win-crt-conio-l1-1-0": (
        "API Set: CRT ConIO — виртуальная DLL для функций "
        "консольного ввода/вывода Universal CRT (_cgets, "
        "_cputs, _getch, _kbhit, _putch)."
    ),
    "api-ms-win-crt-locale-l1-1-0": (
        "API Set: CRT Locale — виртуальная DLL для функций "
        "локализации Universal CRT (setlocale, _wsetlocale, "
        "_create_locale, _free_locale)."
    ),
    "api-ms-win-core-window-l1-1-0": (
        "API Set: Core Window — виртуальная DLL для функций "
        "оконного API (RegisterClass, CreateWindowEx, "
        "DefWindowProc, SendMessage)."
    ),
    "api-ms-win-core-cursor-l1-1-0": (
        "API Set: Core Cursor — виртуальная DLL для функций "
        "управления курсорами (SetCursor, GetCursor, "
        "LoadCursor, CreateCursor)."
    ),
    "api-ms-win-core-message-l1-1-0": (
        "API Set: Core Message — виртуальная DLL для функций "
        "диспетчеризации сообщений (GetMessage, PeekMessage, "
        "DispatchMessage, PostMessage, SendMessage)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 14. УДАЛЁННЫЙ ДОСТУП И ВИРТУАЛИЗАЦИЯ (RDP, Hyper-V)
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_REMOTE = {
    "mstscax.dll": (
        "MSTSCAX — Microsoft Terminal Server Control ActiveX: "
        "элемент управления для встраивания RDP-клиента "
        "(Remote Desktop Protocol) в приложения."
    ),
    "mstsc.exe": (
        "MSTSC — Remote Desktop Client: исполняемый файл "
        "клиента подключения к удалённому рабочему столу "
        "(mstsc.exe)."
    ),
    "rdpcore.dll": (
        "RDPCore — Remote Desktop Protocol Core: реализация "
        "протокола удалённого рабочего стола Windows (RDP)."
    ),
    "rdpcorets.dll": (
        "RDPCoreTS — Remote Desktop Protocol Core Terminal "
        "Services: расширения RDP для терминальных служб."
    ),
    "rdpshareroom.dll": (
        "RDShareRoom — Remote Desktop Sharing: библиотека "
        "для совместного доступа к сеансу удалённого "
        "рабочего стола."
    ),
    "vmcompute.dll": (
        "VMCompute — Hyper-V Compute: библиотека для "
        "управления виртуальными машинами Hyper-V "
        "(создание, запуск, остановка)."
    ),
    "vmsvc.dll": (
        "VMSvc — Hyper-V Management Service: библиотека "
        "службы управления Hyper-V. Координирует работу "
        "с host-системой."
    ),
    "vmms.exe": (
        "VMMS — Hyper-V Virtual Machine Management Service: "
        "исполняемый файл службы управления виртуальными "
        "машинами Hyper-V."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# 15. ODBC, ADSI, ДИРЕКТОРИИ
# ═══════════════════════════════════════════════════════════════════════════

_WINDOWS_DATA_SERVICES = {
    # --- ODBC ---
    "odbc32.dll": (
        "ODBC32 — ODBC Driver Manager: диспетчер драйверов "
        "ODBC (Open Database Connectivity). Управляет загрузкой "
        "драйверов баз данных и маршрутизацией вызовов."
    ),
    "odbcbcp.dll": (
        "ODBCBCP — ODBC Bulk Copy: библиотека для массового "
        "копирования данных через ODBC (BCP — Bulk Copy "
        "Protocol), используемая с SQL Server."
    ),
    "odbcint.dll": (
        "ODBCInt — ODBC Integrity: библиотека поддержки "
        "целостности данных ODBC."
    ),
    "odbccp32.dll": (
        "ODBCCP32 — ODBC Control Panel: библиотека для "
        "настройки ODBC через панель управления (администрирование "
        "DSN, драйверов)."
    ),
    "odbcjt32.dll": (
        "ODBCJT32 — ODBC Jet: драйвер ODBC для баз данных "
        "Access (Jet Database Engine)."
    ),
    # --- ADSI / Active Directory ---
    "ntdsapi.dll": (
        "NTDSApi — NT Directory Services API: библиотека "
        "для взаимодействия со службами каталогов Active "
        "Directory (доменные операции, репликация)."
    ),
    "adsi.dll": (
        "ADSI — Active Directory Service Interfaces: библиотека "
        "для программного доступа к Active Directory через "
        "COM-интерфейсы (IADs, IADsContainer)."
    ),
    "adsldp.dll": (
        "ADSLDP — ADSI LDAP Provider: провайдер LDAP для "
        "ADSI, обеспечивающий доступ к каталогам через "
        "протокол LDAP."
    ),
    "adsnt.dll": (
        "ADSNT — ADSI Windows NT Provider: провайдер ADSI "
        "для Windows NT 4.0 Directory Services (обратная "
        "совместимость)."
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
# ОБЪЕДИНЕНИЕ ВСЕХ WINDOWS-СЛОВАРЕЙ
# ═══════════════════════════════════════════════════════════════════════════

WINDOWS_MODULES = {}
WINDOWS_MODULES.update(_WINDOWS_HAL)
WINDOWS_MODULES.update(_WINDOWS_NATIVE_API)
WINDOWS_MODULES.update(_WINDOWS_KERNEL_SUBSYSTEM)
WINDOWS_MODULES.update(_WINDOWS_USER_SUBSYSTEM)
WINDOWS_MODULES.update(_WINDOWS_SECURITY_CRYPTO)
WINDOWS_MODULES.update(_WINDOWS_NETWORK)
WINDOWS_MODULES.update(_WINDOWS_GRAPHICS)
WINDOWS_MODULES.update(_WINDOWS_MULTIMEDIA)
WINDOWS_MODULES.update(_WINDOWS_RUNTIME)
WINDOWS_MODULES.update(_WINDOWS_DOTNET)
WINDOWS_MODULES.update(_WINDOWS_SYSTEM_SERVICES)
WINDOWS_MODULES.update(_WINDOWS_USB_DEVICE)
WINDOWS_MODULES.update(_WINDOWS_API_SETS)
WINDOWS_MODULES.update(_WINDOWS_REMOTE)
WINDOWS_MODULES.update(_WINDOWS_DATA_SERVICES)