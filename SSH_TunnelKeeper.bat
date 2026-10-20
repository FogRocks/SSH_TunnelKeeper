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

# --- Вспомогательные функции ---

function Pause {
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
        if ($s -match '^[0-9A-Za-z.\-_]+$') { return $s }
        Write-Host "Предупреждение: в адресе '$s' есть недопустимые символы (например запятая вместо точки). Проверьте ввод."
    }
}

function Get-SshExe() {
    $cands = @(
        (Join-Path $env:windir 'System32\OpenSSH\ssh.exe'),
        (Join-Path $env:ProgramFiles 'OpenSSH\bin\ssh.exe')
    )
    if ($env:ProgramFilesx86) {
        $cands += (Join-Path $env:ProgramFilesx86 'OpenSSH\bin\ssh.exe')
    }
    foreach ($p in $cands) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $cmd = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    return 'ssh.exe'
}

function Get-SshKeygenExe() {
    $cands = @(
        (Join-Path $env:windir 'System32\OpenSSH\ssh-keygen.exe'),
        (Join-Path $env:ProgramFiles 'OpenSSH\bin\ssh-keygen.exe')
    )
    if ($env:ProgramFilesx86) {
        $cands += (Join-Path $env:ProgramFilesx86 'OpenSSH\bin\ssh-keygen.exe')
    }
    foreach ($p in $cands) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $cmd = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    return 'ssh-keygen.exe'
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
    if ($usePass -match '^(д|Д|y|Y)$') {
        $sec = Read-Host 'Парольная фраза SSH-ключа' -AsSecureString
        $passPhrase = ''
        if ($sec -and $sec.Length -gt 0) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try { $passPhrase = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        if (-not [string]::IsNullOrEmpty($passPhrase)) {
            Write-Host 'Генерирую ssh-ключ (ed25519, С парольной фразой)...'
            for ($try = 1; $try -le 2; $try++) {
                & $sshKeygen -t ed25519 -f $script:KeyPath -N $passPhrase -q -C $comment
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $script:KeyPath) -and (Get-PubKeyString)) {
                    Write-Host 'Ключ создан.'
                    $passPhrase = $null
                    return $true
                }
                Write-Host 'Не удалось создать ключ — пробую ещё раз...'
                Remove-Item -LiteralPath $script:KeyPath, ($script:KeyPath + '.pub') -Force -ErrorAction SilentlyContinue
            }
            $passPhrase = $null
            Write-Host 'Ошибка: ключ не сгенерировался.'
            return $false
        }
    }
    Write-Host 'Генерирую ssh-ключ (ed25519, БЕЗ парольной фразы)...'
    for ($try = 1; $try -le 2; $try++) {
        & $sshKeygen -t ed25519 -f $script:KeyPath -N '""' -q -C $comment
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $script:KeyPath) -and (Get-PubKeyString)) {
            Write-Host 'Ключ создан.'
            return $true
        }
        Write-Host 'Не удалось создать ключ — пробую ещё раз...'
        Remove-Item -LiteralPath $script:KeyPath, ($script:KeyPath + '.pub') -Force -ErrorAction SilentlyContinue
    }
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
# Детект через ssh -G. Fallback 'no': на старых ssh (<7.6) 'yes' сделал бы
# невозможным первое подключение (BatchMode, нет TTY для подтверждения).
function Get-HostKeyCheckingOption {
    $sshExe = Get-SshExe
    try {
        & $sshExe -G -o 'StrictHostKeyChecking=accept-new' -o 'BatchMode=yes' localhost 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { return 'accept-new' }
    } catch { }
    return 'no'
}

# --- проверка соединения по ключу (без запроса пароля) ---
function Test-SshConnection([string]$User, [string]$Server, [string]$Port, [string]$Key) {
    $hk = Get-HostKeyCheckingOption
    $sshExe = Get-SshExe
    & $sshExe -i $Key -p $Port -o 'BatchMode=yes' -o 'ConnectTimeout=8' `
         -o "StrictHostKeyChecking=$hk" -o "UserKnownHostsFile=$script:KnownHosts" `
         "$User@$Server" 'exit 0' 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# Показывает открытый ключ и ждёт клавишу; Esc = отмена (возврат $false).
function Show-PubKeyAndWait {
    Write-Host ''
    Write-Host ('Путь к ключу: {0}' -f $script:KeyPath)
    Write-Host 'Открытый ключ — добавьте эту строку на сервер в ~/.ssh/authorized_keys:'
    Write-Host '------------------------- КЛЮЧ -------------------------'
    $pub = Get-PubKeyString
    if ($pub) { Write-Host $pub } else { Write-Host 'Не удалось прочитать ключ.' }
    Write-Host '--------------------------------------------------------'
    Write-Host ''
    Write-Host 'Добавили ключ на сервер? Нажмите любую клавишу (Esc — отмена)...'
    $key = [Console]::ReadKey($true)
    Write-Host ''
    if ($key.Key -eq [ConsoleKey]::Esc) { return $false }
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
        if (-not (Show-PubKeyAndWait)) { Write-Host 'Отменено.'; return $false }
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
        if (-not (Show-PubKeyAndWait)) { Write-Host 'Отменено.'; return $false }
    }
}

# --- команда-цикл туннеля (для задачи планировщика, в Base64) ---
function Get-TunnelLoopCommand {
    $pairs = @(ConvertTo-PortPairs $script:Config.ports)
    $forward = ''
    foreach ($p in $pairs) {
        $rp, $lp = $p.Split(':')
        $forward += '-NR {0}:localhost:{1} ' -f $rp, $lp
    }
    $exe    = Get-SshExe
    $hk     = Get-HostKeyCheckingOption
    $key    = $script:KeyPath.Replace('"', '""')
    $log    = $script:LogPath.Replace("'", "''")
    $kh     = $script:KnownHosts.Replace('"', '""')
    $target = '{0}@{1}' -f $script:Config.user, $script:Config.server
    $port   = $script:Config.ssh_port

    $lines = @(
        '$ErrorActionPreference = ''SilentlyContinue'''
        'while ($true) {'
        "    `$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"
        "    `$li = Get-Item -LiteralPath '$log' -ErrorAction SilentlyContinue"
        "    if (`$li -and `$li.Length -gt 1048576) { Move-Item -LiteralPath '$log' -Destination '$log.old' -Force -ErrorAction SilentlyContinue }"
        "    Add-Content -LiteralPath '$log' -Value `"`$ts | Проброс [$($script:Config.ports)] -> $target (ssh-порт $port) ...`" -Encoding UTF8"
        "    & `"$exe`" -N -i `"$key`" -p $port -o ServerAliveInterval=15 -o ServerAliveCountMax=6 -o ExitOnForwardFailure=yes -o `"StrictHostKeyChecking=$hk`" -o `"UserKnownHostsFile=$kh`" $($forward.Trim()) $target"
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
        $plain = $null
        if ($sec -and $sec.Length -gt 0) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
            try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }

        if (-not $plain) { break }   # Enter -> режим по умолчанию

        # пароль задан: LogonType=Password (хранится пароль) — запуск ДО входа
        try {
            Register-ScheduledTask -TaskName $script:TaskName -Action $action `
                -Trigger @($triggerBoot, $triggerLogon) -User "$env:USERDOMAIN\$env:USERNAME" -Password $plain `
                -RunLevel Highest -Settings $settings -Description $script:TaskDesc `
                -Force -ErrorAction Stop | Out-Null
            $runBeforeLogon = $true
        } catch {
            Write-Host ("Не получилось создать задачу с этим паролем: {0}" -f $_.Exception.Message)
            if ($attempt -lt $maxAttempts) { Write-Host 'Попробуйте ввести пароль заново...' }
        }
        $plain = $null
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
    Write-Host '---------------- НАСТРОЙКА ТУННЕЛЯ ----------------'
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
        Write-Host 'Не удалось создать задачу в планировщике:'
        Write-Host $_.Exception.Message
        Pause
        return
    }
    Write-Host ('Задача "{0}" установлена.' -f $script:TaskName)
    $start = Read-Host 'Запустить туннель сейчас? (д/н)'
    if ($start -match '^(д|y)') {
        try { Start-TunnelTask | Out-Null; Write-Host 'Туннель запущен.' }
        catch { Write-Host ('Ошибка запуска: {0}' -f $_.Exception.Message) }
    } else {
        Write-Host 'Туннель запустится автоматически (по расписанию планировщика).'
    }
    Pause
}

# --- меню: Удалить ---
function Invoke-Uninstall {
    Write-Host ''
    Write-Host '============== УДАЛЕНИЕ =============='
    Write-Host '  1 - Только задача в планировщике (ключ и файлы останутся)'
    Write-Host '  2 - Задача + настройки, лог и копия скрипта (ssh-ключ останется)'
    Write-Host '  3 - Полностью: задача + настройки + лог + ssh-ключ'
    Write-Host '  0 - Отмена'
    $ans = Read-Host 'Ваш выбор (1/2/3/0)'
    switch ($ans) {
        '1' { Unregister-SshTask; Write-Host 'Конфигурация и ssh-ключ не тронуты.' }
        '2' { Unregister-SshTask; Remove-CreatedFiles $false }
        '3' { Unregister-SshTask; Remove-CreatedFiles $true }
        default { Write-Host 'Отмена.' }
    }
    Pause
}

# --- меню: Статус ---
function Show-Status {
    Write-Host ''
    Write-Host '================ СТАТУС ================'
    $task = Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $cfg = Read-Cfg
        Write-Host ('Задача в планировщике: ДА  (состояние: {0})' -f $task.State)
        $info = Get-ScheduledTaskInfo -TaskName $script:TaskName -ErrorAction SilentlyContinue
        if ($info) {
            Write-Host ('Последний запуск: {0}  |  Результат: {1}' -f $info.LastRunTime, $info.LastTaskResult)
        }
        if ($task.State -eq 'Running') { Write-Host 'Туннель сейчас: РАБОТАЕТ' }
        else                           { Write-Host 'Туннель сейчас: не работает' }

        if ($cfg['server']) {
            Write-Host '--- Параметры соединения ---'
            Write-Host ('Сервер:           {0}' -f $cfg['server'])
            Write-Host ('Пользователь ssh: {0}' -f $cfg['user'])
            Write-Host ('SSH-порт:         {0}' -f $cfg['ssh_port'])
            $pairs = @(ConvertTo-PortPairs $cfg['ports'])
            if ($pairs.Count -gt 0) {
                Write-Host 'Пробросы:'
                Show-PortPairs $pairs
            } else {
                Write-Host 'Пробросы не заданы.'
            }
        } else {
            Write-Host 'Параметры соединения не найдены (нет файла настроек).'
        }
    } else {
        Write-Host ('Задачи "{0}" в планировщике НЕТ. Установите через пункт 1.' -f $script:TaskName)
    }

    $keyOk = Test-Path -LiteralPath $script:KeyPath
    Write-Host ('SSH-ключ: {0}' -f $(if ($keyOk) { 'есть (' + $script:KeyPath + ')' } else { 'ОТСУТСТВУЕТ' }))
    $sshProc = @(Get-Process ssh -ErrorAction SilentlyContinue)
    Write-Host ('Процессы ssh.exe: {0}' -f $sshProc.Count)

    if (Test-Path -LiteralPath $script:LogPath) {
        Write-Host ''
        Write-Host 'Последние строки лога:'
        Get-Content -LiteralPath $script:LogPath -Tail 6 | ForEach-Object { Write-Host "  $_" }
    }

    if ($task -and $task.State -ne 'Running') {
        Write-Host ''
        $restart = Read-Host 'Туннель сейчас не работает. Перезапустить? (д/н)'
        if ($restart -match '^(д|y)') {
            try {
                Start-TunnelTask | Out-Null
                Write-Host 'Туннель запущен.'
            } catch {
                Write-Host ('Ошибка запуска: {0}' -f $_.Exception.Message)
            }
        }
    } elseif ($task -and $task.State -eq 'Running') {
        Write-Host ''
        Write-Host 'Всё работает — задача выполняется.'
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
    Write-Host 'Туннель остановлен: задача остановлена и отключена, ssh-процессы туннеля завершены.'
    Write-Host 'Включить снова: пункт 3 «Статус» -> перезапуск, или пункт 1 «Установить».'
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
        Write-Host ''
        Write-Host '--------------- ЧТО ИЗМЕНИТЬ? ---------------'
        Write-Host '  1) Добавить проброс'
        Write-Host '  2) Удалить проброс'
        Write-Host '  3) Изменить проброс'
        Write-Host '  4) Сервер / пользователь / ssh-порт'
        Write-Host '  5) Показать ssh-ключ'
        Write-Host '  6) Создать новый ssh-ключ'
        Write-Host '  7) Назад (в главное меню)'
        Write-Host '---------------------------------------------'
        $what = Read-Host 'Выберите пункт'
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
                Show-PubKeyAndWait
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

function Stop-AllSshTunnels {
    Write-Host ''
    Write-Host '========== ЗАВЕРШЕНИЕ ВСЕХ SSH-ТУННЕЛЕЙ =========='

    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $byId = @{}
    foreach ($pr in $procs) { $byId[$pr.ProcessId] = $pr }

    # шаг 1: все ssh-процессы
    $sshProcs = @($procs | Where-Object { $_.Name -ieq 'ssh.exe' })
    if ($sshProcs.Count -gt 0) {
        foreach ($s in $sshProcs) { Stop-Process -Id $s.ProcessId -Force -ErrorAction SilentlyContinue }
        Write-Host "Завершено ssh-процессов: $($sshProcs.Count)."
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
            foreach ($idx in $choices) {
                $targets = @()
                if ($idx -eq 0) { $targets = @($suspects) }
                elseif ($idx -ge 1 -and $idx -le $suspects.Count) { $targets = @($suspects[$idx - 1]) }
                foreach ($s in $targets) {
                    Stop-Process -Id $s.ProcessId -Force -ErrorAction SilentlyContinue
                    $killed++
                }
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
        if ($joined -match 'ssh|tunnel|tunnelkeeper|ssh_rdp') {
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
            foreach ($idx in $choices) {
                $targets = @()
                if ($idx -eq 0) { $targets = @($suspectTasks) }
                elseif ($idx -ge 1 -and $idx -le $suspectTasks.Count) { $targets = @($suspectTasks[$idx - 1]) }
                foreach ($t in $targets) {
                    try {
                        Stop-ScheduledTask -TaskName $t.TaskName -TaskPath $t.Path -ErrorAction SilentlyContinue
                        Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.Path -Confirm:$false -ErrorAction Stop
                        Write-Host "Удалена задача: $($t.Path)$($t.TaskName)"
                        $deleted++
                    } catch {
                        Write-Host "Не удалось удалить задачу '$($t.TaskName)': $($_.Exception.Message)"
                    }
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

# --- Главное меню ---
function Show-Menu {
    while ($true) {
        Clear-Host
        Write-Host '============================================='
        Write-Host '      SSH TunnelKeeper'
        Write-Host '   обратный SSH-туннель (проброс портов)'
        Write-Host '============================================='
        Write-Host '  1) Установить'
        Write-Host '  2) Удалить'
        Write-Host '  3) Статус'
        Write-Host '  4) Изменить'
        Write-Host '  5) Остановить туннель'
        Write-Host '  6) Завершить все ssh-туннели'
        Write-Host '  7) Выход'
        Write-Host '============================================='
        $choice = Read-Host 'Выберите пункт меню'

        switch ($choice) {
            '1' { Clear-Host; try { $cfg = Read-Cfg; if (-not $cfg['server']) { $cfg = @{} }; Invoke-Setup $cfg } catch { Show-Error $_ } }
            '2' { Clear-Host; try { Invoke-Uninstall } catch { Show-Error $_ } }
            '3' { Clear-Host; try { Show-Status } catch { Show-Error $_ } }
            '4' { Clear-Host; try { Invoke-Change } catch { Show-Error $_ } }
            '5' { Clear-Host; try { Stop-Tunnel } catch { Show-Error $_ } }
            '6' { Clear-Host; try { Stop-AllSshTunnels } catch { Show-Error $_ } }
            '7' { Write-Host 'До свидания!'; exit }
            default { Write-Host 'Неверный пункт меню, попробуйте ещё раз.'; Pause }
        }
    }
}

function Show-Error {
    param($err)
    Write-Host ''
    Write-Host "Произошла ошибка: $($err.Exception.Message)"
    Pause
}

# --- Точка входа ---
Show-Menu