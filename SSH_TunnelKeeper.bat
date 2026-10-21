@echo off
chcp 65001 >nul
rem =============================================================
rem  SSH_TunnelKeeper - single file: menu + reverse SSH tunnel
rem =============================================================
setlocal
set "FINAL_TUNNEL_SELF=%~f0"

rem Run the embedded PowerShell section of this file (marker is
rem built from [char]95 below so it appears on this line only once)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$u=[string][char]95; $m=$u+$u+'FINAL_TUNNEL_PS_START'+$u+$u; $s=$env:FINAL_TUNNEL_SELF; $c=[IO.File]::ReadAllText($s,[Text.Encoding]::UTF8); $i=$c.IndexOf($m); if($i -lt 0){Write-Host 'marker not found' ; Read-Host 'Enter'} ; if($i -ge 0){[ScriptBlock]::Create($c.Substring($i+$m.Length)).Invoke()}"
exit /b
__FINAL_TUNNEL_PS_START__
# ============================================================================
#  SSH_TunnelKeeper — менеджер обратных SSH-туннелей
#  (проброс локальных портов наружу через удалённый SSH-сервер, RemoteForward).
#
#  ЕДИНЫЙ файл: bat-заголовок извлекает эту PowerShell-секцию и выполняет её.
#  Запуск: двойной клик по SSH_TunnelKeeper.bat (требуются права администратора).
#  Техническое описание: specification.md (в комплекте).
#
#  Файлы (в %USERPROFILE%\.ssh):
#    ssh_tunnelkeeper_config.txt          настройки (скрытый файл)
#    ssh_tunnelkeeper.log                 лог работы туннеля (при >1 МБ откатывается в .old)
#    ssh_tunnelkeeper_known_hosts         known_hosts (постоянный, для TOFU)
#    (StrictHostKeyChecking=accept-new; fallback 'yes' — fail-closed, не 'no')
#    id_ed25519 / id_ed25519.pub          ssh-ключ (комментарий нейтральный: ssh-tunnelkeeper)
#    SSH_TunnelKeeper.bat                 копия самого скрипта
#  Задача планировщика: SSH_TunnelKeeper
#
#  На сервере в sshd_config должны быть: AllowTcpForwarding yes,
#  GatewayPorts yes, ClientAliveInterval 15, ClientAliveCountMax 6.
# ============================================================================

# --- UTF-8 в консоли (кириллица) ---
Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public class ConCP { [DllImport("kernel32.dll")] public static extern bool SetConsoleOutputCP(uint id); [DllImport("kernel32.dll")] public static extern bool SetConsoleCP(uint id); }'
try { [ConCP]::SetConsoleOutputCP(65001) | Out-Null; [ConCP]::SetConsoleCP(65001) | Out-Null } catch { }
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8

# --- Пути и константы ---
$script:SshDir         = Join-Path $env:USERPROFILE '.ssh'
$script:KeyPath        = Join-Path $script:SshDir 'id_ed25519'
$script:ConfigPath     = Join-Path $script:SshDir 'ssh_tunnelkeeper_config.txt'
$script:LogPath        = Join-Path $script:SshDir 'ssh_tunnelkeeper.log'
$script:KnownHosts     = Join-Path $script:SshDir 'ssh_tunnelkeeper_known_hosts'
$script:LegacyKnownHosts = Join-Path $env:TEMP 'ssh_tunnelkeeper_known_hosts'
$script:KeyComment     = 'ssh-tunnelkeeper'
$script:TaskName       = 'SSH_TunnelKeeper'
$script:TaskDesc       = 'SSH_TunnelKeeper: обратный SSH-туннель (проброс портов)'
$script:LiveName       = 'SSH_TunnelKeeper.bat'
$script:LivePath       = Join-Path $script:SshDir $script:LiveName

# --- путь к самому файлу (задаётся bat-заголовком) ---
$script:SelfPath = $env:FINAL_TUNNEL_SELF
if (-not $script:SelfPath) { $script:SelfPath = $PSCommandPath }

# --- права администратора: задача в планировщике создаётся только админом ---
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $script:IsAdmin) {
    Write-Host ''
    Write-Host 'Для управления задачей планировщика нужны права администратора.'
    Read-Host 'Нажмите Enter — откроется окно с запросом подтверждения (UAC)'
    Start-Process -FilePath $script:SelfPath -Verb RunAs
    exit
}

New-Item -ItemType Directory -Path $script:SshDir -Force | Out-Null

# миграция: убираем старый known_hosts из %TEMP% (после очистки temp
# сервер принимался бы заново без проверки — риск MITM)
Remove-Item -LiteralPath $script:LegacyKnownHosts -Force -ErrorAction SilentlyContinue

# --- Оформление (цвет и стиль) ---
# Включаем VT/ANSI в консоли. Если не удалось — цвета отключаются (fallback).
$script:UseAnsi = $true
try {
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class ConVT { [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetStdHandle(int n); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetConsoleMode(IntPtr h, out uint m); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleMode(IntPtr h, uint m); }' -ErrorAction Stop
    $h = [ConVT]::GetStdHandle(-11)
    $m = 0
    if ([ConVT]::GetConsoleMode($h, [ref]$m)) { [ConVT]::SetConsoleMode($h, ($m -bor 0x0004)) | Out-Null }
} catch { $script:UseAnsi = $false }

# --- Управление окном консоли: один класс P/Invoke ConWin ---
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class ConWin { [StructLayout(LayoutKind.Sequential)] public struct COORD { public short X; public short Y; } [StructLayout(LayoutKind.Sequential)] public struct SMALL_RECT { public short Left; public short Top; public short Right; public short Bottom; } [StructLayout(LayoutKind.Sequential)] public struct CONSOLE_SCREEN_BUFFER_INFO { public COORD dwSize; public COORD dwCursorPosition; public ushort wAttributes; public SMALL_RECT srWindow; public COORD dwMaximumWindowSize; } [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetStdHandle(int n); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleScreenBufferSize(IntPtr h, COORD size); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleWindowInfo(IntPtr h, bool absolute, ref SMALL_RECT r); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetConsoleScreenBufferInfo(IntPtr h, out CONSOLE_SCREEN_BUFFER_INFO i); }' -ErrorAction SilentlyContinue

# Размер окна при старте: 90x40 символов, высокий буфер (для динамической высоты).
# Ресайз пользователем не блокируем. При неудаче — тихо пропускаем.
try {
    $hw = [ConWin]::GetStdHandle(-11)
    $cols = 90; $rows = 40
    $buf = New-Object ConWin+COORD
    $buf.X = $cols; $buf.Y = 600
    [ConWin]::SetConsoleScreenBufferSize($hw, $buf) | Out-Null
    $rect = New-Object ConWin+SMALL_RECT
    $rect.Left = 0; $rect.Top = 0; $rect.Right = $cols - 1; $rect.Bottom = $rows - 1
    [ConWin]::SetConsoleWindowInfo($hw, $true, [ref]$rect) | Out-Null
} catch { }

# Динамическая высота окна: подгоняем под уже выведенный контент.
# Не меньше базовой (40). Тихий fallback.
function Set-WindowHeight {
    try {
        $h = [ConWin]::GetStdHandle(-11)
        $info = New-Object ConWin+CONSOLE_SCREEN_BUFFER_INFO
        if (-not [ConWin]::GetConsoleScreenBufferInfo($h, [ref]$info)) { return }
        $curY = [int]$info.dwCursorPosition.Y
        $cols = [int]$info.dwSize.X
        if ($cols -lt 40) { $cols = 90 }
        # нужная высота: под контент (курсор + запас), не меньше базовой (40)
        $need = $curY + 3
        if ($need -lt 40) { $need = 40 }
        if ($need -eq [int]($info.srWindow.Bottom - $info.srWindow.Top + 1)) { return }
        # расширяем буфер, если контент выше буфера
        if ($need -gt [int]$info.dwSize.Y) {
            $b = New-Object ConWin+COORD; $b.X = $cols; $b.Y = $need
            [ConWin]::SetConsoleScreenBufferSize($h, $b) | Out-Null
        }
        # окно высотой $need от верха, чтобы был виден весь вывод
        $r = New-Object ConWin+SMALL_RECT
        $r.Left = $info.srWindow.Left; $r.Top = 0
        $r.Right = $info.srWindow.Right; $r.Bottom = $need - 1
        [ConWin]::SetConsoleWindowInfo($h, $true, [ref]$r) | Out-Null
    } catch { }
}

# ANSI-хелперы (24-bit). При отсутствии поддержки возвращают пустую строку.
function Esc([string]$c) { if ($script:UseAnsi) { return "$([char]27)[$c" } else { return '' } }
function C([string]$color) {
    switch ($color) {
        'title'  { return (Esc '38;5;45m') }   # голубой
        'accent' { return (Esc '38;5;214m') }  # янтарный
        'ok'     { return (Esc '38;5;46m') }   # зелёный
        'warn'   { return (Esc '38;5;220m') }  # жёлтый
        'err'    { return (Esc '38;5;203m') }  # красный
        'dim'    { return (Esc '38;5;244m') }  # серый
        'bold'   { return (Esc '1m') }
        default  { return '' }
    }
}
$script:Reset = Esc '0m'

# Заголовок раздела: цветная строка-полоса с названием по центру
function Write-Header([string]$text, [string]$color) {
    if (-not $color) { $color = 'title' }
    $w = 51
    $line = [string]([char]0x2550) * $w   # ═
    $pad = [Math]::Max(0, [int](($w - $text.Length) / 2))
    Write-Host ''
    Write-Host ("$(C $color)$line$script:Reset")
    Write-Host ("$(C $color)$(' ' * $pad)$text$script:Reset")
    Write-Host ("$(C $color)$line$script:Reset")
}

# Строка со статусной меткой: [OK]/[!]/[X]/[i]
function Write-Tag([string]$kind, [string]$text) {
    switch ($kind) {
        'ok'   { Write-Host ("$(C 'ok')[ OK ]$script:Reset $text") }
        'warn' { Write-Host ("$(C 'warn')[ !! ]$script:Reset $text") }
        'err'  { Write-Host ("$(C 'err')[ XX ]$script:Reset $text") }
        default { Write-Host ("$(C 'dim')[ .. ]$script:Reset $text") }
    }
}

# Обычное сообщение с цветом (обёртка над Write-Host)
function Write-Msg([string]$text, [string]$color) {
    if ($color) { Write-Host ("$(C $color)$text$script:Reset") } else { Write-Host $text }
}

# Пункт меню: номер в цвете, текст обычный
function Write-MenuItem([string]$key, [string]$text) {
    Write-Host ("  $(C 'accent')$key$script:Reset) $text")
}

# Подсказка-приглашение для ввода (цветной prompt + Read-Host)
function Read-Prompt([string]$prompt) {
    Set-WindowHeight
    Write-Host ("$(C 'title')$prompt$script:Reset") -NoNewline
    Write-Host ("$(C 'accent') > $script:Reset") -NoNewline
    return (Read-Host)
}

# --- Вспомогательные функции ---

function Pause {
    Set-WindowHeight
    Read-Host 'Нажмите Enter, чтобы продолжить'
}

function Get-PromptValue([string]$Label, [string]$Default) {
    if ([string]::IsNullOrEmpty($Default)) { $v = Read-Host $Label }
    else { $v = Read-Host ('{0} [по умолчанию: {1}]' -f $Label, $Default) }
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

function Get-PortValue([string]$Label, [string]$Default) {
    while ($true) {
        $v = Get-PromptValue $Label $Default
        if ($v -match '^\d+$') {
            $n = [long]$v
            if ($n -ge 1 -and $n -le 65535) { return [int]$n }
        }
        Write-Host 'Порт должен быть целым числом от 1 до 65535. Попробуйте ещё раз.'
    }
}

function Get-ServerValue([string]$Default) {
    while ($true) {
        $s = Get-PromptValue 'Удалённый сервер' $Default
        if ([string]::IsNullOrWhiteSpace($s)) { return $s }
        # запрет ведущего '-': иначе ssh примет хост за опцию (argument injection)
        if ($s -match '^[0-9A-Za-z.][0-9A-Za-z.\-_]*$') { return $s }
        Write-Host "Предупреждение: в адресе '$s' есть недопустимые символы (например запятая вместо точки), либо он начинается с '-'. Проверьте ввод."
    }
}

function Get-OpenSshExe([string]$Name) {
    $cands = @(
        (Join-Path $env:windir ('System32\OpenSSH\' + $Name)),
        (Join-Path $env:ProgramFiles ('OpenSSH\bin\' + $Name))
    )
    if (${env:ProgramFiles(x86)}) {
        $cands += (Join-Path ${env:ProgramFiles(x86)} ('OpenSSH\bin\' + $Name))
    }
    foreach ($p in $cands) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    return $Name
}

function Get-SshExe() { return (Get-OpenSshExe 'ssh.exe') }

function Get-SshKeygenExe() { return (Get-OpenSshExe 'ssh-keygen.exe') }

# SecureString -> открытая строка (единая точка расшифровки паролей/фраз)
function ConvertFrom-Secure([Security.SecureString]$sec) {
    if (-not $sec -or $sec.Length -eq 0) { return $null }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-UserValue([string]$Default) {
    while ($true) {
        $s = Get-PromptValue 'Пользователь SSH' $Default
        if ([string]::IsNullOrWhiteSpace($s)) { return $s }
        if ($s -match '^[0-9A-Za-z._\\][0-9A-Za-z._\\-]*$') { return $s }
        Write-Host "Предупреждение: в логине '$s' недопустимые символы. Допустимы буквы, цифры, точка, _ , - и обратный слэш (домен: DOMAIN\user). Без пробелов, кавычек и @. Проверьте ввод."
    }
}

function ConvertTo-PortPairs([string]$Raw) {
    $pairs = @()
    foreach ($part in ($Raw -split ',')) {
        $part = $part.Trim()
        if (-not $part) { continue }
        if ($part -notmatch '^(\d+):(\d+)$') { return @() }
        $pairs += $part
    }
    return $pairs
}

function Show-PortPairs([string[]]$pairs) {
    if (-not $pairs -or $pairs.Count -eq 0) {
        Write-Host '  (пробросов нет)'
        return
    }
    for ($k = 0; $k -lt $pairs.Count; $k++) {
        $rp, $lp = $pairs[$k].Split(':')
        Write-Host ('  {0}) {1} -> localhost:{2}' -f ($k + 1), $rp, $lp)
    }
}

# --- чтение и запись конфигурации (скрытый файл) ---
function Read-Cfg {
    $cfg = @{}
    if (Test-Path -LiteralPath $script:ConfigPath) {
        foreach ($line in Get-Content -LiteralPath $script:ConfigPath) {
            $line = $line.TrimStart([char]0xFEFF)
            if ($line -match '^([^=]+)=(.*)$') { $cfg[$matches[1].Trim()] = $matches[2].Trim() }
        }
    }
    # Валидация при ЧТЕНИИ конфига, а не только при интерактивном вводе:
    # файл лежит в user-writable каталоге, а его значения исполняются от админа
    # в команде задачи. Недоверенные значения отбрасываются.
    if ($cfg['server']   -and $cfg['server']   -notmatch '^[0-9A-Za-z.][0-9A-Za-z.\-_]*$') { $cfg['server'] = '' }
    if ($cfg['user']     -and $cfg['user']     -notmatch '^[0-9A-Za-z._\\][0-9A-Za-z._\\-]*$') { $cfg['user'] = '' }
    if ($cfg['ssh_port'] -notmatch '^\d+$' -or [long]$cfg['ssh_port'] -lt 1 -or [long]$cfg['ssh_port'] -gt 65535) { $cfg['ssh_port'] = '22' }
    if ($cfg['ports']    -and @(ConvertTo-PortPairs $cfg['ports']).Count -eq 0) { $cfg['ports'] = '' }
    if (-not $cfg['ssh_port']) { $cfg['ssh_port'] = '22' }
    return $cfg
}

function Save-Cfg {
    $lines = @(
        ('server={0}'   -f $script:Config.server),
        ('user={0}'     -f $script:Config.user),
        ('ssh_port={0}' -f $script:Config.ssh_port),
        ('ports={0}'    -f $script:Config.ports)
    )
    if (Test-Path -LiteralPath $script:ConfigPath) {
        [IO.File]::SetAttributes($script:ConfigPath, [IO.FileAttributes]::Normal)
    }
    [IO.File]::WriteAllLines($script:ConfigPath, $lines, (New-Object Text.UTF8Encoding($false)))
    [IO.File]::SetAttributes($script:ConfigPath, [IO.FileAttributes]::Hidden)
}

# --- ssh-ключ (ed25519); публичный ключ: .pub (приоритет) или ssh-keygen -y ---
function New-SshKey {
    $sshKeygen = Get-SshKeygenExe
    $comment = $script:KeyComment
    Write-Host ''
    Write-Host 'Создание SSH-ключа (ed25519)'
    Write-Host '--- ВНИМАНИЕ ПО БЕЗОПАСНОСТИ ---'
    Write-Host 'Ключ БЕЗ парольной фразы позволяет автозапускать туннель ДО входа в Windows.'
    Write-Host 'Ключ С парольной фразой безопаснее при краже профиля/диска, НО НЕ позволит автозапускать туннель до входа без ssh-agent/Pageant.'
    Write-Host 'По умолчанию создаётся КЛЮЧ БЕЗ ПАРОЛЬНОЙ ФРАЗЫ (для сохранения автозапуска).'
    $usePass = Read-Host 'Защитить ключ парольной фразой? (д/н) [по умолчанию: н]'
    $passArg = '""'          # без парольной фразы
    $withPass = $false
    if ($usePass -match '^(д|Д|y|Y)$') {
        $sec = Read-Host 'Парольная фраза SSH-ключа' -AsSecureString
        $passPhrase = ConvertFrom-Secure $sec
        if (-not [string]::IsNullOrEmpty($passPhrase)) {
            $passArg = $passPhrase
            $withPass = $true
        }
    }
    if ($withPass) { Write-Host 'Генерирую ssh-ключ (ed25519, С парольной фразой)...' }
    else           { Write-Host 'Генерирую ssh-ключ (ed25519, БЕЗ парольной фразы)...' }
    for ($try = 1; $try -le 2; $try++) {
        & $sshKeygen -t ed25519 -f $script:KeyPath -N $passArg -q -C $comment
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $script:KeyPath) -and (Get-PubKeyString)) {
            Write-Host 'Ключ создан.'
            $passArg = $null; $passPhrase = $null; [GC]::Collect()
            return $true
        }
        Write-Host 'Не удалось создать ключ — пробую ещё раз...'
        Remove-Item -LiteralPath $script:KeyPath, ($script:KeyPath + '.pub') -Force -ErrorAction SilentlyContinue
    }
    # best-effort: снимаем ссылку на парольную фразу
    $passArg = $null; $passPhrase = $null; [GC]::Collect()
    Write-Host 'Ошибка: ключ не сгенерировался.'
    return $false
}

function Get-PubKeyString {
    if (-not (Test-Path -LiteralPath $script:KeyPath)) { return $null }
    $pubFile = $script:KeyPath + '.pub'
    if (Test-Path -LiteralPath $pubFile) {
        $line = Get-Content -LiteralPath $pubFile -TotalCount 1 -ErrorAction SilentlyContinue
        if ($line) { return $line.Trim() }
    }
    $sshKeygen = Get-SshKeygenExe
    $pub = & $sshKeygen -y -f $script:KeyPath 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $pub) { return $null }
    $parts = $pub -split ' '
    if ($parts.Count -ge 2) {
        $keyPart = $parts[0..($parts.Count - 2)] -join ' '
        return $keyPart + ' ' + $script:KeyComment
    }
    return $pub
}

# --- поддержка StrictHostKeyChecking=accept-new (OpenSSH >= 7.6) ---
# accept-new: новые ключи принимаются автоматически, при смене ключа сервера — отклоняет (защита от MITM).
# Детект через ssh -G: убеждаемся, что ssh реально распознал 'accept-new'
# (в выводе эффективной конфигурации есть stricthostkeychecking accept-new).
# Fallback 'yes' (fail-closed): при любом сбое детекта проверка НЕ отключается.
# 'yes' безопасен — известные хосты проверяются, смена ключа отклоняется.
function Get-HostKeyCheckingOption {
    $sshExe = Get-SshExe
    try {
        $out = & $sshExe -G -o 'StrictHostKeyChecking=accept-new' -o 'BatchMode=yes' localhost 2>$null
        if ($LASTEXITCODE -eq 0 -and ($out -join "`n") -match '(?im)^\s*stricthostkeychecking\s+accept-new\s*$') {
            return 'accept-new'
        }
    } catch { }
    return 'yes'
}

# --- проверка соединения по ключу (без запроса пароля) ---
function Test-SshConnection([string]$User, [string]$Server, [string]$Port, [string]$Key) {
    $hk = Get-HostKeyCheckingOption
    $sshExe = Get-SshExe
    & $sshExe -i $Key -p $Port -o 'BatchMode=yes' -o 'ConnectTimeout=8' `
         -o "StrictHostKeyChecking=$hk" -o "UserKnownHostsFile=$script:KnownHosts" `
         -- "$User@$Server" 'exit 0' 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# Показывает открытый ключ в рамке (для вставки в authorized_keys на сервере).
# Ширина рамки — по окну; длинный ключ и путь переносятся по строкам.
# -Cancelable: Esc = отмена (возвращает $false), иначе Enter.
function Show-PubKeyBox {
    param([switch]$Cancelable)
    Write-Host ''
    $pub = Get-PubKeyString
    $t = C 'title'; $a = C 'accent'; $d = C 'dim'; $r = $script:Reset
    $v = [char]0x2551
    $tl = [char]0x2554; $tr = [char]0x2557; $bl = [char]0x255A; $br = [char]0x255D
    if (-not $pub) {
        Write-Tag 'warn' 'SSH-ключ не найден — сгенерируйте его (пункт 4 «Изменить» -> ssh-ключ).'
        return $true
    }
    # ширина окна (в символах) с запасом; ограничиваем разумным максимумом
    $winW = 90
    try { $w = $Host.UI.RawUI.WindowSize.Width; if ($w -ge 40) { $winW = [int]$w } } catch { }
    $inner = $winW - 3 - 2 - 2            # отступ 3 + рамка 2 + поля 2
    if ($inner -lt 30) { $inner = 30 }
    if ($inner -gt 110) { $inner = 110 }
    $wrapW = $inner - 2                   # полезная ширина текста (с левым полем 2)
    # перенос текста по словам (при необходимости — по символам)
    function Split-Wrap([string]$s, [int]$w) {
        $out = @()
        while ($s.Length -gt $w) {
            $cut = $s.LastIndexOf(' ', [Math]::Min($w, $s.Length - 1))
            if ($cut -le 0) { $cut = $w }
            $out += $s.Substring(0, $cut)
            $s = $s.Substring($cut).TrimStart(' ')
        }
        $out += $s
        return ,$out
    }
    $items = @()   # элементы: @{ text=...; color=... }
    foreach ($l in (Split-Wrap ('Путь: {0}' -f $script:KeyPath) $wrapW)) { $items += ,@{ text = $l; color = $d } }
    $items += ,@{ text = ''; color = $t }
    foreach ($l in (Split-Wrap 'Добавьте ключ на сервер в ~/.ssh/authorized_keys:' $wrapW)) { $items += ,@{ text = $l; color = $t } }
    $items += ,@{ text = ''; color = $t }
    foreach ($l in (Split-Wrap $pub $wrapW)) { $items += ,@{ text = $l; color = $a } }

    $h = [string]([char]0x2550) * $inner
    $ind = '   '
    Write-Host ("$ind$t$tl$h$tr$r")
    foreach ($it in $items) {
        $txt = $it.text
        $right = $inner - 2 - $txt.Length
        if ($right -lt 0) { $right = 0 }
        Write-Host ("$ind$t$v$r  $($it.color)$txt$r$(' ' * $right)$t$v$r")
    }
    Write-Host ("$ind$t$bl$h$br$r")
    Write-Host ''
    if ($Cancelable) {
        Write-Host 'Добавили ключ на сервер? Нажмите любую клавишу (Esc — отмена)...'
        $key = $null
        try { $key = [Console]::ReadKey($true) } catch { $null = Read-Host }
        Write-Host ''
        if ($key -and $key.Key -eq [ConsoleKey]::Esc) { return $false }
        return $true
    }
    try { $null = [Console]::ReadKey($true) } catch { $null = Read-Host }
    Write-Host ''
    return $true
}

# Порядок работы с ключом:
#  1) ключа НЕТ  -> создаём новый, показываем ключ и ждём клавишу (Esc — отмена);
#  2) ключ ЕСТЬ  -> пробуем подключиться в фоновом режиме (без пароля);
#                   успех  -> продолжаем работу;
#                   неудача -> показываем ключ и ждём клавишу, затем пытаемся снова
#                   (Esc на любом показе — отмена установки).
function Ensure-Connection {
    if (-not (Test-Path -LiteralPath $script:KeyPath)) {
        Write-Host ('SSH-ключ не найден ({0}). Генерирую новый...' -f $script:KeyPath)
        if (-not (New-SshKey)) { return $false }
        if (-not (Show-PubKeyBox -Cancelable)) { Write-Host 'Отменено.'; return $false }
        if (Test-SshConnection $script:Config.user $script:Config.server $script:Config.ssh_port $script:KeyPath) {
            Write-Host 'Соединение по ключу подтверждено. Продолжаем...'
        } else {
            Write-Host 'Подключение пока не выполняется — туннель будет пробовать сам (см. лог). Продолжаем.'
        }
        return $true
    }

    Write-Host ('SSH-ключ найден: {0}' -f $script:KeyPath)
    while ($true) {
        Write-Host ('Пробую подключиться (фоновый режим): {0}@{1}:{2} ...' -f $script:Config.user, $script:Config.server, $script:Config.ssh_port)
        if (Test-SshConnection $script:Config.user $script:Config.server $script:Config.ssh_port $script:KeyPath) {
            Write-Host 'Вход по ключу выполнен. Продолжаем...'
            return $true
        }
        Write-Host 'Ключ не принят сервером — показываю его, чтобы вы его добавили.'
        Write-Host ('Если сервер менял свой ключ — удалите файл {0} и повторите установку.' -f $script:KnownHosts)
        if (-not (Show-PubKeyBox -Cancelable)) { Write-Host 'Отменено.'; return $false }
    }
}

# --- команда-цикл туннеля (для задачи планировщика, в Base64) ---
function Get-TunnelLoopCommand {
    # defense-in-depth: перепроверяем значения перед запеканием в команду
    # (config-файл user-writable, а команда исполняется от админа)
    if ($script:Config.server -notmatch '^[0-9A-Za-z.][0-9A-Za-z.\-_]*$') { throw 'Недопустимый адрес сервера в настройках.' }
    if ($script:Config.user -notmatch '^[0-9A-Za-z._\\][0-9A-Za-z._\\-]*$') { throw 'Недопустимый пользователь SSH в настройках.' }
    if ($script:Config.ssh_port -notmatch '^\d+$' -or [long]$script:Config.ssh_port -lt 1 -or [long]$script:Config.ssh_port -gt 65535) { throw 'Недопустимый SSH-порт в настройках.' }
    $pairs = @(ConvertTo-PortPairs $script:Config.ports)
    if ($pairs.Count -eq 0) { throw 'Пробросы не заданы или имеют недопустимый формат.' }
    $forward = ''
    foreach ($p in $pairs) {
        $rp, $lp = $p.Split(':')
        $forward += '-NR {0}:localhost:{1} ' -f $rp, $lp
    }
    $exe    = (Get-SshExe).Replace('"', '""')
    $hk     = Get-HostKeyCheckingOption
    $key    = $script:KeyPath.Replace('"', '""')
    $log    = $script:LogPath.Replace("'", "''")
    $kh     = $script:KnownHosts.Replace('"', '""')
    $target = '{0}@{1}' -f $script:Config.user, $script:Config.server
    $target = $target.Replace('"', '""')
    $port   = $script:Config.ssh_port

    $lines = @(
        '$ErrorActionPreference = ''SilentlyContinue'''
        'while ($true) {'
        "    `$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"
        "    `$li = Get-Item -LiteralPath '$log' -ErrorAction SilentlyContinue"
        "    if (`$li -and `$li.Length -gt 1048576) { Move-Item -LiteralPath '$log' -Destination '$log.old' -Force -ErrorAction SilentlyContinue }"
        "    Add-Content -LiteralPath '$log' -Value `"`$ts | Проброс [$($script:Config.ports)] -> $target (ssh-порт $port) ...`" -Encoding UTF8"
        "    & `"$exe`" -N -i `"$key`" -p $port -o ServerAliveInterval=15 -o ServerAliveCountMax=6 -o ExitOnForwardFailure=yes -o `"StrictHostKeyChecking=$hk`" -o `"UserKnownHostsFile=$kh`" $($forward.Trim()) -- `"$target`""
        "    `$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"
        "    Add-Content -LiteralPath '$log' -Value `"`$ts | Соединение потеряно или порт занят — повтор через 15 сек.`" -Encoding UTF8"
        '    Start-Sleep -Seconds 15'
        '}'
    )
    return ($lines -join "`n")
}

# завершает ТОЛЬКО ssh-процессы этого туннеля (по known_hosts и флагу -NR),
# не трогая чужие ssh-сессии
function Stop-OwnSshProcesses {
    foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name = 'ssh.exe'" -ErrorAction SilentlyContinue)) {
        $cl = $p.CommandLine
        if ($cl -and
            $cl.IndexOf('ssh_tunnelkeeper_known_hosts', [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $cl.IndexOf('-NR', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
}

# включает (после Disable) и запускает задачу туннеля
function Start-TunnelTask {
    Enable-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue | Out-Null
    Start-ScheduledTask -TaskName $script:TaskName -ErrorAction Stop
}

# --- установка задачи в планировщике Windows ---
function Register-SshTask {
    Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Stop-OwnSshProcesses

    $loop = Get-TunnelLoopCommand
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($loop))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand ' + $encoded)
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

    $triggerBoot = New-ScheduledTaskTrigger -AtStartup
    $triggerBoot.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)).Repetition
    $triggerLogon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

    # копия скрипта в .ssh — туннель переживёт удаление/перемещение установщика
    if ($script:SelfPath -and (Test-Path -LiteralPath $script:SelfPath) -and
        -not $script:SelfPath.Equals($script:LivePath, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $script:SelfPath -Destination $script:LivePath -Force
    }

    # пароль Windows: до 3 попыток ввода (неверный пароль -> переспрос)
    Write-Host ''
    Write-Host 'Запуск ДО входа в систему требует сохранённый пароль Windows.'
    $maxAttempts = 3
    $runBeforeLogon = $false
    for ($attempt = 1; $attempt -le $maxAttempts -and -not $runBeforeLogon; $attempt++) {
        $label = 'Пароль Windows (Enter — запускать только после входа)'
        if ($attempt -gt 1) {
            $left = $maxAttempts - $attempt + 1
            $label = "Пароль неверный — попытка $attempt из $maxAttempts. Пароль Windows (осталось попыток: $left)"
        }
        $sec = Read-Host $label -AsSecureString
        $plain = ConvertFrom-Secure $sec

        if (-not $plain) { break }   # Enter -> режим по умолчанию

        # пароль задан: LogonType=Password (хранится пароль) — запуск ДО входа
        try {
            Register-ScheduledTask -TaskName $script:TaskName -Action $action `
                -Trigger @($triggerBoot, $triggerLogon) -User "$env:USERDOMAIN\$env:USERNAME" -Password $plain `
                -RunLevel Highest -Settings $settings -Description $script:TaskDesc `
                -Force -ErrorAction Stop | Out-Null
            $runBeforeLogon = $true
        } catch {
            # НЕ выводим текст исключения: он может содержать фрагмент пароля
            Write-Host 'Не получилось создать задачу с этим паролем (неверный пароль или недостаточно прав).'
            if ($attempt -lt $maxAttempts) { Write-Host 'Попробуйте ввести пароль заново...' }
        } finally {
            # best-effort: убираем ссылку на открытую строку пароля
            $plain = $null
            [GC]::Collect()
        }
    }

    if (-not $runBeforeLogon) {
        # пароль не применён (3 неудачи или Enter) — задача по умолчанию: при входе
        Write-Host ''
        Write-Host 'Пароль не сохранён — задача создаётся по умолчанию: запуск при входе в систему.'
        Register-ScheduledTask -TaskName $script:TaskName -Action $action `
            -Trigger @($triggerBoot, $triggerLogon) -User $env:USERNAME `
            -RunLevel Highest -Settings $settings -Description $script:TaskDesc `
            -Force -ErrorAction Stop | Out-Null
    }

    Write-Host ''
    Write-Host ('Задача "{0}" создана в планировщике.' -f $script:TaskName)
    if ($runBeforeLogon) {
        Write-Host 'Режим: запуск при включении компьютера (до входа) и при входе.'
    } else {
        Write-Host 'Режим: запуск при входе в систему и каждую минуту (сторож).'
    }
}

function Unregister-SshTask {
    Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Stop-OwnSshProcesses
    if (Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host ('Задача "{0}" удалена из планировщика.' -f $script:TaskName)
    } else {
        Write-Host ('Задачи "{0}" в планировщике не было.' -f $script:TaskName)
    }
}

function Remove-CreatedFiles([bool]$includeKey) {
    $paths = @($script:ConfigPath, $script:LogPath, ($script:LogPath + '.old'))
    if ($script:SelfPath -and
        -not $script:SelfPath.Equals($script:LivePath, [StringComparison]::OrdinalIgnoreCase)) {
        $paths += $script:LivePath
    }
    if ($includeKey) {
        $paths += $script:KeyPath
        $paths += $script:KeyPath + '.pub'
        $paths += $script:KnownHosts
    }
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) {
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            Write-Host "Удалено: $p"
        }
    }
}

# --- меню: Установить ---
function Invoke-Setup([hashtable]$defaults) {
    Write-Host ''
    Write-Header 'НАСТРОЙКА ТУННЕЛЯ'
    $script:Config = @{
        server   = Get-ServerValue $defaults['server']
        user     = Get-UserValue   $defaults['user']
        ssh_port = Get-PortValue   'SSH-порт сервера'  $defaults['ssh_port']
    }
    if ([string]::IsNullOrWhiteSpace($script:Config.server) -or
        [string]::IsNullOrWhiteSpace($script:Config.user)) {
        Write-Host 'Сервер и пользователь SSH должны быть заполнены.'
        Pause
        return
    }
    if (-not (Test-Path -LiteralPath (Get-SshExe))) {
        Write-Host 'ssh не найден. Установите "Клиент OpenSSH": Параметры -> Приложения -> Необязательные компоненты.'
        Pause
        return
    }

    # ключ и подключение: проверка -> вход по ключу / показ ключа + ожидание
    if (-not (Ensure-Connection)) {
        Write-Host 'Установка прервана.'
        Pause
        return
    }
    Write-Host 'Продолжаем настройку...'

    # первый проброс: значения по умолчанию из текущего конфига (если есть)
    $dfltRemote = $defaults['remote_port']
    $dfltLocal  = $defaults['local_port']
    if (-not $dfltRemote -and $defaults['ports']) {
        $first = @(ConvertTo-PortPairs $defaults['ports'])
        if ($first.Count -gt 0) {
            $rp, $lp = $first[0].Split(':')
            $dfltRemote = $rp
            $dfltLocal  = $lp
        }
    }
    $remote = Get-PortValue 'Порт на удалённом сервере (для внешних подключений)' $dfltRemote
    $local  = Get-PortValue 'Локальный порт, который пробрасываем'            $dfltLocal
    $script:Config.ports = ('{0}:{1}' -f $remote, $local)

    Save-Cfg
    try { Register-SshTask } catch {
        Write-Tag 'err' 'Не удалось создать задачу в планировщике:'
        Write-Msg $_.Exception.Message 'err'
        Pause
        return
    }
    Write-Tag 'ok' ('Задача "{0}" установлена.' -f $script:TaskName)
    $start = Read-Prompt 'Запустить туннель сейчас? (д/н)'
    if ($start -match '^(д|y)') {
        try { Start-TunnelTask | Out-Null; Write-Tag 'ok' 'Туннель запущен.' }
        catch { Write-Tag 'err' ('Ошибка запуска: {0}' -f $_.Exception.Message) }
    } else {
        Write-Msg 'Туннель запустится автоматически (по расписанию планировщика).' 'dim'
    }
    Write-Host ''
    $openHelp = Read-Prompt 'Настроить firewall/sshd на сервере? Открыть «Помощь» (д/н)'
    if ($openHelp -match '^(д|y)') { Show-Help } else { Pause }
}

# --- меню: Удалить ---
function Invoke-Uninstall {
    Write-Host ''
    Write-Header 'УДАЛЕНИЕ'
    Write-MenuItem '1' 'Только задача в планировщике (ключ и файлы останутся)'
    Write-MenuItem '2' 'Задача + настройки, лог и копия скрипта (ssh-ключ останется)'
    Write-MenuItem '3' 'Полностью: задача + настройки + лог + ssh-ключ'
    Write-MenuItem '0' 'Отмена'
    $ans = Read-Prompt 'Ваш выбор (1/2/3/0)'
    switch ($ans) {
        '1' { Unregister-SshTask; Write-Tag 'ok' 'Конфигурация и ssh-ключ не тронуты.' }
        '2' { Unregister-SshTask; Remove-CreatedFiles $false }
        '3' { Unregister-SshTask; Remove-CreatedFiles $true }
        default { Write-Msg 'Отмена.' 'dim' }
    }
    Pause
}

# --- меню: Статус ---
function Show-Status {
    Write-Header 'СТАТУС'
    $task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $cfg = Read-Cfg
        Write-Msg ('Задача в планировщике: ДА  (состояние: {0})' -f $task.State) 'title'
        $info = Get-ScheduledTaskInfo -TaskName $script:TaskName -ErrorAction SilentlyContinue
        if ($info) {
            Write-Msg ('Последний запуск: {0}  |  Результат: {1}' -f $info.LastRunTime, $info.LastTaskResult) 'dim'
        }
        if ($task.State -eq 'Running') { Write-Tag 'ok' 'Туннель сейчас: РАБОТАЕТ' }
        else                           { Write-Tag 'warn' 'Туннель сейчас: не работает' }

        if ($cfg['server']) {
            Write-Msg '--- Параметры соединения ---' 'dim'
            Write-Msg ('  Сервер:           {0}' -f $cfg['server'])
            Write-Msg ('  Пользователь ssh: {0}' -f $cfg['user'])
            Write-Msg ('  SSH-порт:         {0}' -f $cfg['ssh_port'])
            $pairs = @(ConvertTo-PortPairs $cfg['ports'])
            if ($pairs.Count -gt 0) {
                Write-Msg '  Пробросы:'
                Show-PortPairs $pairs
            } else {
                Write-Msg '  Пробросы не заданы.' 'dim'
            }
        } else {
            Write-Tag 'warn' 'Параметры соединения не найдены (нет файла настроек).'
        }
    } else {
        Write-Tag 'warn' ('Задачи "{0}" в планировщике НЕТ. Установите через пункт 1.' -f $script:TaskName)
    }

    $keyOk = Test-Path -LiteralPath $script:KeyPath
    if ($keyOk) { Write-Tag 'ok' ('SSH-ключ: есть ({0})' -f $script:KeyPath) }
    else        { Write-Tag 'warn' 'SSH-ключ: ОТСУТСТВУЕТ' }
    $sshProc = @(Get-Process ssh -ErrorAction SilentlyContinue)
    Write-Msg ('Процессы ssh.exe: {0}' -f $sshProc.Count) 'dim'

    if ($keyOk) {
        Write-Host ''
        Write-Host ("$(C 'accent')[ К ]$script:Reset Посмотреть ssh-ключ (для вставки на сервер)") -NoNewline
        Write-Host ("   $(C 'dim')(Enter — далее, K — показать ключ)$script:Reset")
        $act = Read-Prompt 'Действие'
        if ($act -match '^(k|к|9)$') { Show-PubKeyBox }
    }

    if (Test-Path -LiteralPath $script:LogPath) {
        Write-Host ''
        Write-Msg 'Последние строки лога:' 'dim'
        Get-Content -LiteralPath $script:LogPath -Tail 6 | ForEach-Object { Write-Host ("  $(C 'dim')$_$script:Reset") }
    }

    if ($task -and $task.State -ne 'Running') {
        Write-Host ''
        $restart = Read-Prompt 'Туннель сейчас не работает. Перезапустить? (д/н)'
        if ($restart -match '^(д|y)') {
            try {
                Start-TunnelTask | Out-Null
                Write-Tag 'ok' 'Туннель запущен.'
            } catch {
                Write-Tag 'err' ('Ошибка запуска: {0}' -f $_.Exception.Message)
            }
        }
    } elseif ($task -and $task.State -eq 'Running') {
        Write-Host ''
        Write-Tag 'ok' 'Всё работает — задача выполняется.'
    }
    Pause
}

# --- меню: Остановить туннель ---
# важно: Disable, иначе «сторож» (повтор триггера каждую минуту) снова
# запустит задачу максимум через минуту
function Stop-Tunnel {
    Disable-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    Stop-OwnSshProcesses
    Write-Tag 'ok' 'Туннель остановлен: задача остановлена и отключена, ssh-процессы туннеля завершены.'
    Write-Msg 'Включить снова: пункт 3 «Статус» -> перезапуск, или пункт 1 «Установить».' 'dim'
    Pause
}

# --- работа со списком пробросов ---
function Add-PortPair([string]$CurrentPorts) {
    $pairs = @(ConvertTo-PortPairs $CurrentPorts)
    Write-Host 'Текущие пробросы:'
    Show-PortPairs $pairs
    while ($true) {
        $raw = Get-PromptValue 'Новый проброс (удалённый:локальный, Enter — отмена)' ''
        if ([string]::IsNullOrWhiteSpace($raw)) { Write-Host 'Отменено.'; return $null }
        $one = @(ConvertTo-PortPairs $raw)
        if (-not $one -or $one.Count -eq 0) {
            Write-Host 'Формат: удалённый_порт:локальный_порт, например 23389:3389'
            continue
        }
        if ($one.Count -ge 2) { Write-Host 'Вводите одну пару за раз.'; continue }
        if ($pairs -contains $one[0]) { Write-Host 'Такой проброс уже есть.'; continue }
        $pairs += $one[0]
        Write-Host ('Добавлен проброс: {0}' -f $one[0])
        return ($pairs -join ',')
    }
}

function Remove-PortPair([string]$CurrentPorts) {
    $pairs = @(ConvertTo-PortPairs $CurrentPorts)
    if ($pairs.Count -le 1) {
        Write-Host 'Нельзя удалить последний проброс — должен остаться хотя бы один.'
        return $null
    }
    Write-Host 'Какой проброс удалить?'
    Show-PortPairs $pairs
    $raw = Read-Host ('Введите номер (1-{0}), 0 — отмена' -f $pairs.Count)
    if ($raw -notmatch '^\d+$') { Write-Host 'Отменено.'; return $null }
    $idx = [int]$raw
    if ($idx -eq 0)               { Write-Host 'Отменено.'; return $null }
    if ($idx -gt $pairs.Count)    { Write-Host 'Неверный номер.'; return $null }
    $removed = $pairs[$idx - 1]
    $newPairs = @()
    for ($k = 0; $k -lt $pairs.Count; $k++) {
        if ($k -ne ($idx - 1)) { $newPairs += $pairs[$k] }
    }
    Write-Host ('Проброс {0} удалён.' -f $removed)
    return ($newPairs -join ',')
}

function Set-PortPair([string]$CurrentPorts) {
    $pairs = @(ConvertTo-PortPairs $CurrentPorts)
    if ($pairs.Count -eq 0) { Write-Host 'Пробросов нет.'; return $null }
    Write-Host 'Какой проброс изменить?'
    Show-PortPairs $pairs
    $raw = Read-Host ('Введите номер (1-{0}), 0 — отмена' -f $pairs.Count)
    if ($raw -notmatch '^\d+$') { Write-Host 'Отменено.'; return $null }
    $idx = [int]$raw
    if ($idx -eq 0)            { Write-Host 'Отменено.'; return $null }
    if ($idx -gt $pairs.Count) { Write-Host 'Неверный номер.'; return $null }
    $cur = $pairs[$idx - 1]
    $curR, $curL = $cur.Split(':')
    $newR = Get-PortValue 'Удалённый порт' $curR
    $newL = Get-PortValue 'Локальный порт' $curL
    $newPair = ('{0}:{1}' -f $newR, $newL)
    if ($newPair -ne $cur -and ($pairs -contains $newPair)) {
        Write-Host 'Такой проброс уже есть — изменение не применено.'
        return $null
    }
    $newPairs = @()
    for ($k = 0; $k -lt $pairs.Count; $k++) {
        if ($k -eq ($idx - 1)) { $newPairs += $newPair } else { $newPairs += $pairs[$k] }
    }
    Write-Host ('Проброс изменён: {0} -> {1}' -f $cur, $newPair)
    return ($newPairs -join ',')
}

# применить конфигурацию: сохранить + пересоздать задачу + запустить
function Apply-CfgAndTask([hashtable]$cfg) {
    $script:Config = $cfg
    Save-Cfg
    try { Register-SshTask } catch {
        Write-Host 'Не удалось пересоздать задачу:'
        Write-Host $_.Exception.Message
        Pause
        return
    }
    try {
        Start-TunnelTask | Out-Null
        Write-Host 'Настройки сохранены, туннель перезапущен.'
    } catch {
        Write-Host 'Настройки сохранены. Туннель запустится сам по расписанию.'
    }
    Pause
}

function Invoke-Change {
    $task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host ''
        Write-Host ('Задача "{0}" ещё не установлена. Сейчас откроется установка.' -f $script:TaskName)
        Pause
        Invoke-Setup @{}
        return
    }

    while ($true) {
        Clear-Host
        Write-Header 'ЧТО ИЗМЕНИТЬ'
        Write-MenuItem '1' 'Добавить проброс'
        Write-MenuItem '2' 'Удалить проброс'
        Write-MenuItem '3' 'Изменить проброс'
        Write-MenuItem '4' 'Сервер / пользователь / ssh-порт'
        Write-MenuItem '5' 'Показать ssh-ключ'
        Write-MenuItem '6' 'Создать новый ssh-ключ'
        Write-MenuItem '7' 'Назад (в главное меню)'
        Write-Host ''
        $what = Read-Prompt 'Выберите пункт'
        $cfg = Read-Cfg

        switch ($what) {
            '1' {
                $np = Add-PortPair $cfg['ports']
                if ($np) { $cfg['ports'] = $np; Apply-CfgAndTask $cfg }
            }
            '2' {
                $np = Remove-PortPair $cfg['ports']
                if ($np) { $cfg['ports'] = $np; Apply-CfgAndTask $cfg }
            }
            '3' {
                $np = Set-PortPair $cfg['ports']
                if ($np) { $cfg['ports'] = $np; Apply-CfgAndTask $cfg }
            }
            '4' {
                $cfg['server']   = Get-ServerValue $cfg['server']
                $cfg['user']     = Get-UserValue   $cfg['user']
                $cfg['ssh_port'] = Get-PortValue   'Новый SSH-порт сервера'  $cfg['ssh_port']
                if ([string]::IsNullOrWhiteSpace($cfg['server'])) {
                    Write-Host 'Сервер должен быть заполнен.'
                } else {
                    $script:Config = $cfg
                    if (Ensure-Connection) { Apply-CfgAndTask $cfg }
                    else { Write-Host 'Изменение отменено.'; Pause }
                }
            }
            '5' {
                Show-PubKeyBox
            }
            '6' {
                Remove-Item -LiteralPath $script:KeyPath, ($script:KeyPath + '.pub') -Force -ErrorAction SilentlyContinue
                Write-Host 'Старый ключ удалён. Готовлю новый...'
                $script:Config = $cfg
                if (Ensure-Connection) { Write-Host 'Ключ готов — если ещё не добавили его на сервер, сделайте это.' }
                else { Write-Host 'Изменение отменено.' }
                Pause
            }
            '7' { return }
            default { Write-Host 'Неверный пункт, попробуйте ещё раз.' }
        }
    }
}

# --- "Завершить все ssh-туннели": зачистка любых ssh-процессов и задач ---
function Resolve-Selection {
    param($actionText)
    Write-Host "  [1] - $actionText все"
    Write-Host '  [2] - Выбрать номера'
    Write-Host '  [3] - Ничего не делать'
    $ans = Read-Host 'Ваш выбор (1/2/3)'
    switch ($ans) {
        '1' { return @(0) }
        '2' {
            $nums = Read-Host 'Введите номера через запятую (например: 1,2,5)'
            $ids = @()
            foreach ($part in ($nums -split '[,\s;]+')) {
                if ($part -match '^\d+$') { $ids += [int]$part }
            }
            return @($ids | Select-Object -Unique)
        }
        default { return @() }
    }
}

# разворачивает выбор номеров в элементы (0 = все), с проверкой границ
function Expand-Selection($choices, $items) {
    $out = @()
    foreach ($idx in $choices) {
        if ($idx -eq 0) { $out += $items }
        elseif ($idx -ge 1 -and $idx -le $items.Count) { $out += $items[$idx - 1] }
    }
    return @($out)
}

function Stop-AllSshTunnels {
    Write-Header 'ЗАВЕРШЕНИЕ ВСЕХ SSH-ТУННЕЛЕЙ' 'err'

    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $byId = @{}
    foreach ($pr in $procs) { $byId[$pr.ProcessId] = $pr }

    # шаг 1: все ssh-процессы (с подтверждением — действие деструктивное)
    $sshProcs = @($procs | Where-Object { $_.Name -ieq 'ssh.exe' })
    if ($sshProcs.Count -gt 0) {
        foreach ($s in $sshProcs) { Write-Host ("  PID $($s.ProcessId): $($s.CommandLine)") }
        $ok = Read-Host "Завершить ВСЕ ssh-процессы ($($sshProcs.Count) шт.)? (д/н)"
        if ($ok -match '^(д|Д|y|Y)$') {
            foreach ($s in $sshProcs) { Stop-Process -Id $s.ProcessId -Force -ErrorAction SilentlyContinue }
            Write-Host "Завершено ssh-процессов: $($sshProcs.Count)."
        } else {
            Write-Host 'ssh-процессы не завершались.'
        }
    } else {
        Write-Host 'Активных ssh-процессов не найдено.'
    }

    # шаг 2: процессы-"запускатели" туннелей
    $suspects = @($procs | Where-Object {
        if ($_.ProcessId -eq $PID) { return $false }
        if ($_.Name -ieq 'ssh.exe') { return $false }
        if ($_.Name -inotmatch 'powershell|pwsh|cmd|bash|wsl') { return $false }
        $cl = $_.CommandLine
        if (-not $cl) { return $false }
        $l = $cl.ToLower()
        return ($l -match 'ssh(\.exe)?|-tunnel|-nr\b|\.ssh\\|tunnelkeeper|ssh_rdp')
    })

    if ($suspects.Count -gt 0) {
        Write-Host ''
        Write-Host "Найдены процессы, запускающие ssh-туннели: $($suspects.Count)"
        $i = 0
        foreach ($s in $suspects) {
            $i++
            $parent = $byId[$s.ParentProcessId]
            $pp = if ($parent) { $parent.Name } else { '?' }
            Write-Host "  $i) PID $($s.ProcessId) | $($s.Name) | запущен из: $pp"
            Write-Host "      КОМАНДА: $($s.CommandLine)"
            Write-Host ''
        }
        Write-Host 'Что сделать с найденными процессами?'
        $choices = Resolve-Selection -actionText 'Завершить'
        if ($choices.Count -gt 0) {
            $killed = 0
            foreach ($s in (Expand-Selection $choices $suspects)) {
                Stop-Process -Id $s.ProcessId -Force -ErrorAction SilentlyContinue
                $killed++
            }
            Write-Host "Завершено процессов-запускателей: $killed."
        } else {
            Write-Host 'Процессы не завершались.'
        }
    } else {
        Write-Host 'Процессов, явно запускающих ssh-туннели, не найдено.'
    }

    # шаг 3: задачи планировщика, связанные с ssh-туннелями
    Write-Host ''
    Write-Host 'Ищу задачи планировщика, связанные с ssh-туннелями...'
    $suspectTasks = @()
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $actionLines = @($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" })
        $joined = (($actionLines -join ' ') + ' ' + $task.TaskName).ToLower()
        # более строгая эвристика: ssh в команде как отдельный токен/путь,
        # либо явные маркеры туннеля — снижаем ложные срабатывания
        if ($joined -match '(^|[\s\\/])(ssh|ssh\.exe)\b' -or $joined -match 'tunnelkeeper|ssh_rdp|-tunnel|remote forward|remote-forward') {
            $suspectTasks += [pscustomobject]@{
                TaskName = $task.TaskName
                Path     = $task.TaskPath
                Command  = ($actionLines -join ' | ')
            }
        }
    }

    if ($suspectTasks.Count -gt 0) {
        Write-Host "Найдены задачи планировщика, связанные с ssh: $($suspectTasks.Count)"
        $i = 0
        foreach ($t in $suspectTasks) {
            $i++
            Write-Host "  $i) $($t.Path)$($t.TaskName)"
            Write-Host "      Команда: $($t.Command)"
            Write-Host ''
        }
        Write-Host 'Что сделать с найденными задачами?'
        $choices = Resolve-Selection -actionText 'Удалить'
        if ($choices.Count -gt 0) {
            $deleted = 0
            foreach ($t in (Expand-Selection $choices $suspectTasks)) {
                try {
                    Stop-ScheduledTask -TaskName $t.TaskName -TaskPath $t.Path -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.Path -Confirm:$false -ErrorAction Stop
                    Write-Host "Удалена задача: $($t.Path)$($t.TaskName)"
                    $deleted++
                } catch {
                    Write-Host "Не удалось удалить задачу '$($t.TaskName)': $($_.Exception.Message)"
                }
            }
            Write-Host "Удалено задач: $deleted."
        } else {
            Write-Host 'Задачи не удалялись.'
        }
    } else {
        Write-Host 'Задач планировщика, связанных с ssh, не найдено.'
    }

    Write-Host ''
    Write-Host 'Проверка завершена. Если ssh снова появится — проверьте автозагрузку (другие скрипты/задачи).'
    Pause
}

# --- Помощь: настройка сервера (firewall / sshd) ---

# известные "чувствительные" локальные порты: их публикация наружу опасна
$script:SensitivePorts = @{
    '3389' = 'RDP'; '445' = 'SMB'; '139' = 'NetBIOS'; '135' = 'RPC'
    '21' = 'FTP'; '23' = 'Telnet'; '1433' = 'MSSQL'; '3306' = 'MySQL'
    '5432' = 'PostgreSQL'; '5900' = 'VNC'; '5985' = 'WinRM'
}

# возвращает "23389 (RDP)" если локальный порт чувствительный, иначе "23389"
function Format-RemotePort([string]$RemotePort, [string]$LocalPort) {
    $name = $script:SensitivePorts[$LocalPort]
    if ($name) { return ('{0} ({1})' -f $RemotePort, $name) }
    return $RemotePort
}

# определяет публичный IP клиента через ipify; при неудаче возвращает $null
function Get-PublicIp {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 'https://api.ipify.org'
        $ip = ($r.Content).Trim()
        if ($ip -match '^[0-9A-Fa-f:.]{3,45}$') { return $ip }
    } catch { }
    return $null
}

# спрашивает у пользователя IP-адрес для разрешения в firewall
function Get-AllowedIp {
    Write-Host ''
    Write-Msg 'IP, которому разрешён доступ к опубликованным портам:' 'dim'
    Write-MenuItem '1' 'Определить автоматически (через api.ipify.org)'
    Write-MenuItem '2' 'Ввести вручную'
    Write-MenuItem '3' 'Оставить плейсхолдер <ваш_IP>'
    $ans = Read-Prompt 'Ваш выбор (1/2/3)'
    switch ($ans) {
        '1' {
            Write-Host 'Определяю публичный IP...'
            $ip = Get-PublicIp
            if ($ip) {
                Write-Msg ('Публичный IP: {0}' -f $ip) 'ok'
                Write-Msg 'Если вы работаете через VPN — укажите адрес, с которого реально подключаетесь (вариант 2).' 'warn'
                return $ip
            }
            Write-Tag 'warn' 'Не удалось определить IP (нет сети или сервис недоступен) — введите вручную.'
            $manual = Read-Prompt 'Разрешённый IP (Enter — плейсхолдер)'
            if ([string]::IsNullOrWhiteSpace($manual)) { return '<ваш_IP>' }
            return $manual.Trim()
        }
        '2' {
            $manual = Read-Prompt 'Разрешённый IP (можно несколько через запятую)'
            if ([string]::IsNullOrWhiteSpace($manual)) { return '<ваш_IP>' }
            return $manual.Trim()
        }
        default { return '<ваш_IP>' }
    }
}

# печатает команды firewall/sshd для одного удалённого порта
function Write-PortSetup([string]$RemotePort, [string]$Label, [string]$Ip, [string]$Kind) {
    if ($Kind -eq 'ufw') {
        Write-Host ('  # ufw ({0})' -f $Label)
        Write-Host ('  sudo ufw allow from {0} to any port {1} proto tcp' -f $Ip, $RemotePort)
        Write-Host ('  sudo ufw deny {0}/tcp' -f $RemotePort)
    } elseif ($Kind -eq 'iptables') {
        Write-Host ('  # iptables ({0})' -f $Label)
        Write-Host ('  sudo iptables -A INPUT -p tcp --dport {0} -s {1} -j ACCEPT' -f $RemotePort, $Ip)
        Write-Host ('  sudo iptables -A INPUT -p tcp --dport {0} -j DROP' -f $RemotePort)
        Write-Host '  sudo netfilter-persistent save'
    } elseif ($Kind -eq 'windows') {
        Write-Host ('  # Windows Server ({0})' -f $Label)
        Write-Host ('  New-NetFirewallRule -DisplayName "Tunnel {0}" -Direction Inbound -Protocol TCP -LocalPort {0} -RemoteAddress {1} -Action Allow' -f $RemotePort, $Ip)
    }
}

# показывает готовые команды настройки сервера (firewall и/или sshd)
function Show-ServerSetup([string]$Mode, [string]$RemotePorts, [string]$LocalPorts) {
    $pairs = @(ConvertTo-PortPairs $RemotePorts)
    if ($pairs.Count -eq 0) {
        Write-Tag 'warn' 'Пробросы не заданы — показываю плейсхолдер <PORT>.'
        $pairs = @('')
    }
    $withFirewall = ($Mode -ne 'sshd')
    $withSshd     = ($Mode -ne 'ufw' -and $Mode -ne 'iptables' -and $Mode -ne 'windows')

    if ($withFirewall) {
        $kind = $Mode
        if ($kind -notin @('ufw','iptables','windows')) {
            Write-Host ''
            Write-Msg 'Система на сервере:' 'dim'
            Write-MenuItem '1' 'ufw (Ubuntu/Debian)'
            Write-MenuItem '2' 'iptables (прочие Linux)'
            Write-MenuItem '3' 'Windows Server (редко)'
            $k = Read-Prompt 'Ваш выбор (1/2/3)'
            switch ($k) {
                '1' { $kind = 'ufw' }
                '2' { $kind = 'iptables' }
                '3' { $kind = 'windows' }
                default { $kind = 'ufw' }
            }
        }
        $ip = Get-AllowedIp

        Write-Host ''
        Write-Host ("$(C 'title')FIREWALL НА СЕРВЕРЕ (выполнить на сервере)$script:Reset")
        foreach ($p in $pairs) {
            if ($p) {
                $rp, $lp = $p.Split(':')
                $label = Format-RemotePort $rp $lp
                Write-Host ''
                Write-Host ("# --- Порт {0} ---" -f $label)
                Write-PortSetup $rp $label $ip $kind
            } else {
                Write-Host ''
                Write-Host "# --- Порт <PORT> ---"
                Write-PortSetup '<PORT>' '<PORT>' $ip $kind
            }
        }
        Write-Host ''
        Write-Msg ('Замените {0} на реальный адрес. По умолчанию остальные источники должны быть запрещены.' -f $ip) 'dim'
    }

    if ($withSshd) {
        Write-Host ''
        Write-Host ("$(C 'title')SSHD НА СЕРВЕРЕ (файл /etc/ssh/sshd_config)$script:Reset")
        Write-Host '# Публикация проброшенных портов на интерфейсах сервера:'
        Write-Host 'GatewayPorts yes'
        Write-Host '# затем перезапустить: sudo systemctl restart sshd'
    }
}

# --- Помощь: меню ---
function Show-Help {
    $cfg = Read-Cfg
    $remotePorts = $cfg['ports']
    Write-Host ''
    Write-Header 'ПОМОЩЬ: НАСТРОЙКА СЕРВЕРА'

    if ($cfg['server']) {
        $plist = @(ConvertTo-PortPairs $remotePorts)
        if ($plist.Count -gt 0) {
            $shown = @()
            foreach ($p in $plist) { $rp, $lp = $p.Split(':'); $shown += (Format-RemotePort $rp $lp) }
            Write-Msg ('Сервер: {0}  |  Пробросы: {1}' -f $cfg['server'], ($shown -join ', '))
        } else {
            Write-Msg ('Сервер: {0}  |  Пробросы не заданы' -f $cfg['server'])
        }
        # мягкое предупреждение о чувствительных портах
        $sens = @()
        foreach ($p in $plist) {
            $rp, $lp = $p.Split(':')
            if ($script:SensitivePorts[$lp]) { $sens += (Format-RemotePort $rp $lp) }
        }
        if ($sens.Count -gt 0) {
            Write-Host ''
            Write-Msg ('Внимание: публикуются чувствительные службы ({0}).' -f ($sens -join ', ')) 'warn'
            Write-Msg 'Их стоит ограничить firewall — разрешить только ваши IP и запретить остальное.' 'dim'
        }
    } else {
        Write-Tag 'warn' 'Настройки ещё не заданы. Команды будут с плейсхолдером <PORT>.'
    }

    while ($true) {
        Write-Host ''
        Write-Msg 'Что показать?' 'dim'
        Write-MenuItem '1' 'Firewall (ufw / iptables)'
        Write-MenuItem '2' 'sshd (GatewayPorts)'
        Write-MenuItem '3' 'Всё сразу'
        Write-MenuItem '4' 'Windows Server (редко)'
        Write-MenuItem '0' 'Назад'
        $what = Read-Prompt 'Ваш выбор (1/2/3/4/0)'
        switch ($what) {
            '1' { Show-ServerSetup 'firewall' $remotePorts $cfg['ports']; Pause }
            '2' { Show-ServerSetup 'sshd' $remotePorts $cfg['ports']; Pause }
            '3' { Show-ServerSetup 'all' $remotePorts $cfg['ports']; Pause }
            '4' { Show-ServerSetup 'windows' $remotePorts $cfg['ports']; Pause }
            '0' { return }
            default { Write-Tag 'err' 'Неверный пункт.' }
        }
    }
}

# --- Главное меню ---
function Show-Menu {
    while ($true) {
        Clear-Host
        Show-Banner
        Write-Host ''
        Write-MenuItem '1' 'Установить'
        Write-MenuItem '2' 'Удалить'
        Write-MenuItem '3' 'Статус'
        Write-MenuItem '4' 'Изменить'
        Write-MenuItem '5' 'Остановить туннель'
        Write-MenuItem '6' 'Завершить все ssh-туннели'
        Write-MenuItem '7' 'Помощь (настройка сервера)'
        Write-MenuItem '8' 'Выход'
        Write-Host ''
        Write-Host ("$(C 'dim')$([string]([char]0x2500) * 55)$script:Reset")
        $choice = Read-Prompt 'Выберите пункт меню'

        switch ($choice) {
            '1' { Clear-Host; try { $cfg = Read-Cfg; if (-not $cfg['server']) { $cfg = @{} }; Invoke-Setup $cfg } catch { Show-Error $_ } }
            '2' { Clear-Host; try { Invoke-Uninstall } catch { Show-Error $_ } }
            '3' { Clear-Host; try { Show-Status } catch { Show-Error $_ } }
            '4' { Clear-Host; try { Invoke-Change } catch { Show-Error $_ } }
            '5' { Clear-Host; try { Stop-Tunnel } catch { Show-Error $_ } }
            '6' { Clear-Host; try { Stop-AllSshTunnels } catch { Show-Error $_ } }
            '7' { Clear-Host; try { Show-Help } catch { Show-Error $_ } }
            '8' { Write-Host ("$(C 'title')До свидания!$script:Reset"); exit }
            default { Write-Tag 'err' 'Неверный пункт меню, попробуйте ещё раз.'; Pause }
        }
    }
}

# ASCII-логотип в шапке. Все строки логотипа одной ширины (ровный блок);
# ширина рамки = ширина логотипа + поля по бокам.
function Show-Banner {
    $t = C 'title'
    $a = C 'accent'
    $r = $script:Reset
    $d = C 'dim'
    $v = [char]0x2551

    # логотип "SSH / TUNNEL / KEEPER" (figlet standard, 42 символа в ширину)
    $logo = @(
        ' ____   ____   _   _                      '
        '/ ___| / ___| | | | |                     '
        '\___ \ \___ \ | |_| |                     '
        ' ___) | ___) ||  _  |                     '
        '|____/ |____/ |_| |_|                     '
        '                                          '
        ' _____  _   _  _   _  _   _  _____  _     '
        '|_   _|| | | || \ | || \ | || ____|| |    '
        '  | |  | |_| ||  \| ||  \| ||  _|  | |    '
        '  | |  |  _  || |\  || |\  || |___ | |___ '
        '  |_|  |_| |_||_| |_||_| |_||_____||_____|'
        ' _  __ _____  _____  ____   _____  ____   '
        '| |/ /| ____|| ____||  _ \ | ____||  _ \  '
        '| '' / |  _|  |  _|  | |_) ||  _|  | |_) | '
        '| . \ | |___ | |___ |  __/ | |___ |  _ <  '
        '|_|\_\|_____||_____||_|    |_____||_| \_\ '
    )
    $logoW = ($logo | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $side  = 3
    $inner = $logoW + ($side * 2)
    $h  = [string]([char]0x2550) * $inner
    $tl = [char]0x2554; $tr = [char]0x2557; $bl = [char]0x255A; $br = [char]0x255D
    $ind = '   '

    Write-Host ("$ind$d$tl$h$tr$r")
    for ($i = 0; $i -lt $logo.Count; $i++) {
        $txt = $logo[$i]
        # строки "KEEPER" (индексы 11-15) — янтарные, остальные голубые
        if ($i -ge 11) { $col = $a } else { $col = $t }
        $right = $inner - $side - $txt.Length
        if ($right -lt 0) { $right = 0 }
        Write-Host ("$ind$d$v$r$(' ' * $side)$col$txt$r$(' ' * $right)$d$v$r")
    }
    # подпись по центру
    $sub = 'обратный SSH-туннель'
    $leftSub = [int][Math]::Floor(($inner - $sub.Length) / 2)
    $rightSub = $inner - $leftSub - $sub.Length
    Write-Host ("$ind$d$v$r$(' ' * $leftSub)$d$sub$r$(' ' * $rightSub)$d$v$r")
    # автор
    $tag = 'by FogRock'
    $leftTag = [int][Math]::Floor(($inner - $tag.Length) / 2)
    $rightTag = $inner - $leftTag - $tag.Length
    Write-Host ("$ind$d$v$r$(' ' * $leftTag)$a$tag$r$(' ' * $rightTag)$d$v$r")
    Write-Host ("$ind$d$bl$h$br$r")
}


function Show-Error {
    param($err)
    Write-Host ''
    Write-Tag 'err' "Произошла ошибка: $($err.Exception.Message)"
    Pause
}

# --- Точка входа ---
Show-Menu