#Requires -Version 5.1
<#
  vpn-killswitch.ps1 — VPN kill switch для Windows на базе Windows Defender Firewall.

  Когда kill switch включён, на физических сетевых адаптерах (Wi-Fi, Ethernet)
  блокируется весь трафик, кроме:
    - трафика к IP-адресу(ам) VPN-сервера (чтобы туннель мог подняться);
    - DHCP (чтобы не терять адрес в Wi-Fi/Ethernet);
    - локальной сети — только с флагом --allow-lan.
  Виртуальные адаптеры VPN (TAP, Wintun, WireGuard, встроенный VPN Windows)
  правила не затрагивают, поэтому всё, что идёт через туннель, работает.
  Loopback (localhost) брандмауэр Windows не фильтрует вообще.

  Используются правила БЛОКИРОВКИ: в брандмауэре Windows они всегда сильнее
  разрешающих, поэтому никакое другое правило не откроет дыру мимо VPN.

  Использование (в терминале администратора, либо через vpn-killswitch.cmd):
    .\vpn-killswitch.ps1 --start <VPN_SERVER_IP> [IP2 ...] [--allow-lan]
    .\vpn-killswitch.ps1 --stop
    .\vpn-killswitch.ps1 --status
    .\vpn-killswitch.ps1 --install     # установить как команду vpn-killswitch
    vpn-killswitch --uninstall         # удалить команду
#>

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Numerics

# Все правила создаются в этой группе — по ней их легко найти и удалить.
$Group     = 'VPN Killswitch'
$StateDir  = Join-Path $env:ProgramData 'vpn-killswitch'
$StateFile = Join-Path $StateDir 'state.json'

# Куда ставится команда: папка bin добавляется в системный PATH.
$InstallDir = Join-Path $env:ProgramFiles 'vpn-killswitch'
$BinDir     = Join-Path $InstallDir 'bin'
$EnvKey     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

$LanNets = @(
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
    '224.0.0.0/4', '255.255.255.255/32', 'fe80::/10', 'ff00::/8'
)

# Адаптеры с такими описаниями — VPN-туннели, их никогда не блокируем,
# даже если Windows считает их «физическими».
$VpnAdapterPattern = 'TAP|Wintun|WireGuard|OpenVPN|VPN|Tunnel|Miniport'

$script:Pause = $false

function Show-Usage {
    Write-Host @"
Использование:
  vpn-killswitch --start <VPN_SERVER_IP> [IP2 ...] [--allow-lan]
  vpn-killswitch --stop
  vpn-killswitch --status
  vpn-killswitch --install | --uninstall

  --start      включить kill switch: трафик только через VPN или к IP сервера
  --stop       выключить kill switch и вернуть всё как было
  --status     показать, включён ли kill switch и какие правила действуют
  --allow-lan  (с --start) разрешить локальную сеть: роутер, принтеры, NAS
  --install    установить как команду: дальше запускать как «vpn-killswitch ...»
               из любой папки (ставится в $InstallDir)
  --uninstall  удалить установленную команду
  -h, --help   эта справка

IP можно перечислить через пробел или через запятую.
Нужны права администратора (скрипт сам запросит их через UAC).
"@
}

function Exit-Script([int]$Code) {
    if ($script:Pause) { [void](Read-Host 'Нажмите Enter, чтобы закрыть окно') }
    exit $Code
}

function Stop-WithError([string]$Message) {
    Write-Host "Ошибка: $Message" -ForegroundColor Red
    Exit-Script 1
}

function Test-IpAddress([string]$Text) {
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Text, [ref]$ip)) { return $false }
    # TryParse принимает и «1.2.3», поэтому для IPv4 требуем ровно 4 числа.
    if ($ip.AddressFamily -eq 'InterNetwork') { return $Text -match '^\d{1,3}(\.\d{1,3}){3}$' }
    return $Text.Contains(':')
}

function Test-Admin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- арифметика IP-диапазонов ---
# Брандмауэр не умеет «всё, кроме X», поэтому вычисляем дополнение:
# список диапазонов, покрывающих все адреса, кроме разрешённых.

function ConvertTo-BigInt([System.Net.IPAddress]$Ip) {
    $bytes = $Ip.GetAddressBytes()
    [array]::Reverse($bytes)
    # Лишний нулевой байт, чтобы число не стало отрицательным.
    return [System.Numerics.BigInteger]::new([byte[]]($bytes + [byte]0))
}

function ConvertFrom-BigInt([System.Numerics.BigInteger]$Number, [int]$Length) {
    $le = $Number.ToByteArray()
    $bytes = New-Object byte[] $Length
    for ($i = 0; $i -lt [Math]::Min($Length, $le.Length); $i++) {
        $bytes[$Length - 1 - $i] = $le[$i]
    }
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-IpRange([string]$Cidr) {
    $parts = $Cidr.Split('/')
    $ip = [System.Net.IPAddress]::Parse($parts[0])
    $bits = if ($ip.AddressFamily -eq 'InterNetwork') { 32 } else { 128 }
    $prefix = if ($parts.Count -gt 1) { [int]$parts[1] } else { $bits }
    $size = [System.Numerics.BigInteger]::Pow(2, $bits - $prefix)
    $start = [System.Numerics.BigInteger]::Divide((ConvertTo-BigInt $ip), $size) * $size
    return [pscustomobject]@{ Bits = $bits; Start = $start; End = $start + $size - 1 }
}

function Format-IpRange([System.Numerics.BigInteger]$Start, [System.Numerics.BigInteger]$End, [int]$Length) {
    $a = ConvertFrom-BigInt $Start $Length
    if ($Start -eq $End) { return $a }
    return "$a-$(ConvertFrom-BigInt $End $Length)"
}

function Get-Complement($Ranges, [int]$Bits) {
    $max = [System.Numerics.BigInteger]::Pow(2, $Bits) - 1
    $length = $Bits / 8
    $result = @()
    $cur = [System.Numerics.BigInteger]::Zero
    foreach ($r in @($Ranges | Where-Object { $_.Bits -eq $Bits } | Sort-Object Start)) {
        if ($r.Start -gt $cur) { $result += Format-IpRange $cur ($r.Start - 1) $length }
        if ($r.End + 1 -gt $cur) { $cur = $r.End + 1 }
    }
    if ($cur -le $max) { $result += Format-IpRange $cur $max $length }
    return $result
}

# --- состояние ---

function Read-State {
    if (Test-Path $StateFile) { return Get-Content $StateFile -Raw | ConvertFrom-Json }
    return $null
}

function Get-KillswitchRules {
    return @(Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue)
}

function Remove-KillswitchRules {
    $rules = @(Get-KillswitchRules)
    if ($rules.Count -gt 0) { $rules | Remove-NetFirewallRule }
}

function Get-TargetAdapters {
    return @(Get-NetAdapter -Physical |
        Where-Object { $_.InterfaceDescription -notmatch $VpnAdapterPattern } |
        Select-Object -ExpandProperty Name)
}

# --- действия ---

function Start-Killswitch([string[]]$Ips, [bool]$AllowLan) {
    if ((Get-Service mpssvc).Status -ne 'Running') {
        Stop-WithError 'служба брандмауэра Windows (mpssvc) не запущена. Возможно, её отключил сторонний антивирус/файрвол.'
    }

    $adapters = Get-TargetAdapters
    if ($adapters.Count -eq 0) { Stop-WithError 'не найдено ни одного физического сетевого адаптера' }

    $excluded = @($Ips | ForEach-Object { Get-IpRange $_ })
    if ($AllowLan) { $excluded += @($LanNets | ForEach-Object { Get-IpRange $_ }) }
    $blocked4 = @(Get-Complement $excluded 32)
    $blocked6 = @(Get-Complement $excluded 128)
    $blockedAll = $blocked4 + $blocked6

    $old = Read-State
    # Профили брандмауэра, которые включили мы (чтобы при --stop выключить обратно).
    $enabledByUs = @()
    if ($old) { $enabledByUs = @($old.EnabledProfiles) }

    # Повторный --start просто пересоздаёт правила с новыми параметрами.
    Remove-KillswitchRules

    $common = @{
        Group          = $Group
        Action         = 'Block'
        Profile        = 'Any'
        Enabled        = 'True'
        InterfaceAlias = $adapters
        Description    = "Создано vpn-killswitch.ps1. Разрешены: $($Ips -join ', ')$(if ($AllowLan) { ' + LAN' })"
    }
    # DHCP (сервер — порт 67) исключаем из блокировки UDP, остальные порты блокируем.
    $notDhcp = @('1-66', '68-65535')

    try {
        foreach ($dir in 'Outbound', 'Inbound') {
            $tag = if ($dir -eq 'Outbound') { 'out' } else { 'in' }
            [void](New-NetFirewallRule @common -Direction $dir -DisplayName "$Group - $tag TCP" `
                -Protocol TCP -RemoteAddress $blockedAll)
            [void](New-NetFirewallRule @common -Direction $dir -DisplayName "$Group - $tag UDP" `
                -Protocol UDP -RemotePort $notDhcp -RemoteAddress $blockedAll)
            if ($blocked4.Count -gt 0) {
                [void](New-NetFirewallRule @common -Direction $dir -DisplayName "$Group - $tag ICMPv4" `
                    -Protocol ICMPv4 -RemoteAddress $blocked4)
            }
            if ($blocked6.Count -gt 0) {
                [void](New-NetFirewallRule @common -Direction $dir -DisplayName "$Group - $tag ICMPv6" `
                    -Protocol ICMPv6 -RemoteAddress $blocked6)
            }
        }

        # Если брандмауэр выключен в каком-то профиле, правила там не работают.
        $disabled = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' } |
            Select-Object -ExpandProperty Name)
        if ($disabled.Count -gt 0) {
            Set-NetFirewallProfile -Name $disabled -Enabled True
            Write-Host "Брандмауэр Windows был выключен в профилях: $($disabled -join ', ') — включён." -ForegroundColor Yellow
            $enabledByUs = @($enabledByUs + $disabled | Select-Object -Unique)
        }
    } catch {
        # Не оставляем систему в полусостоянии.
        Remove-KillswitchRules
        Stop-WithError "не удалось создать правила: $($_.Exception.Message)"
    }

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    [pscustomobject]@{
        Ips             = @($Ips)
        AllowLan        = $AllowLan
        Adapters        = @($adapters)
        EnabledProfiles = @($enabledByUs)
    } | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8

    Write-Host "Kill switch ВКЛЮЧЁН. Разрешён трафик через VPN-туннель и к: $($Ips -join ', ')" -ForegroundColor Green
    if ($AllowLan) { Write-Host 'Локальная сеть разрешена.' }
    Write-Host "Заблокированы адаптеры: $($adapters -join ', ')"
    Write-Host 'Выключить: vpn-killswitch --stop'
}

function Stop-Killswitch {
    $rules = @(Get-KillswitchRules)
    $state = Read-State

    Remove-KillswitchRules

    if ($state -and @($state.EnabledProfiles).Count -gt 0) {
        $profiles = @($state.EnabledProfiles)
        Set-NetFirewallProfile -Name $profiles -Enabled False
        Write-Host "Брандмауэр Windows снова выключен в профилях: $($profiles -join ', ') (как было до --start)."
    }
    if (Test-Path $StateDir) { Remove-Item -Recurse -Force $StateDir }

    if ($rules.Count -gt 0) {
        Write-Host 'Kill switch ВЫКЛЮЧЕН. Трафик снова идёт как обычно.' -ForegroundColor Green
    } else {
        Write-Host 'Kill switch и так не был включён.'
    }
}

function Show-Status {
    $rules = @(Get-KillswitchRules)
    $state = Read-State
    if ($rules.Count -gt 0) {
        Write-Host 'Kill switch: ВКЛЮЧЁН' -ForegroundColor Green
        if ($state) {
            Write-Host "Разрешённые IP:        $(@($state.Ips) -join ', ')"
            Write-Host "Локальная сеть:        $(if ($state.AllowLan) { 'разрешена' } else { 'заблокирована' })"
            Write-Host "Блокируемые адаптеры:  $(@($state.Adapters) -join ', ')"
        }
        Write-Host ''
        Write-Host "Правила (группа «$Group»):"
        $rules | Format-Table DisplayName, Direction, Action, Enabled -AutoSize | Out-String | Write-Host
    } else {
        Write-Host 'Kill switch: выключен'
    }
    Write-Host 'Брандмауэр Windows по профилям:'
    Get-NetFirewallProfile | Format-Table Name, Enabled -AutoSize | Out-String | Write-Host
}

# --- установка ---

function Get-MachinePath {
    # Читаем PATH «как есть», не раскрывая %SystemRoot% и подобное.
    return (Get-Item $EnvKey).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
}

function Set-MachinePath([string]$Value) {
    Set-ItemProperty -Path $EnvKey -Name Path -Value $Value -Type ExpandString
    # Оповещаем систему, что переменные среды изменились: изменение
    # переменной через .NET рассылает сообщение WM_SETTINGCHANGE.
    [Environment]::SetEnvironmentVariable('VPN_KILLSWITCH_REFRESH', '1', 'User')
    [Environment]::SetEnvironmentVariable('VPN_KILLSWITCH_REFRESH', $null, 'User')
}

function Install-Self {
    $target = Join-Path $InstallDir 'vpn-killswitch.ps1'
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

    if ($PSCommandPath -ieq $target) {
        Write-Host "Это уже установленная копия ($target)."
    } else {
        # Program Files доступна для записи только администраторам, поэтому
        # подменить скрипт, который запускается с правами администратора, нельзя.
        Copy-Item -Path $PSCommandPath -Destination $target -Force
    }

    # В PATH кладём только .cmd: если там окажется .ps1, PowerShell попробует
    # запустить его напрямую и упрётся в политику выполнения скриптов.
    Set-Content -Path (Join-Path $BinDir 'vpn-killswitch.cmd') -Encoding ASCII -Value @(
        '@echo off',
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\vpn-killswitch.ps1" %*',
        'exit /b %ERRORLEVEL%'
    )

    $parts = @((Get-MachinePath) -split ';' | Where-Object { $_ })
    if ($parts -notcontains $BinDir) {
        Set-MachinePath (($parts + $BinDir) -join ';')
    }

    Write-Host "Установлено в $InstallDir" -ForegroundColor Green
    Write-Host 'Откройте НОВОЕ окно терминала и запускайте из любой папки:'
    Write-Host '  vpn-killswitch --start <IP> | --stop | --status'
    Write-Host 'После изменения скрипта запустите --install ещё раз, чтобы обновить копию.'
}

function Uninstall-Self {
    if (@(Get-KillswitchRules).Count -gt 0) {
        Stop-WithError 'kill switch сейчас включён — сначала выполните: vpn-killswitch --stop'
    }

    $parts = @((Get-MachinePath) -split ';' | Where-Object { $_ })
    if ($parts -contains $BinDir) {
        Set-MachinePath (@($parts | Where-Object { $_ -ne $BinDir }) -join ';')
    }

    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Host "Удалено: $InstallDir" -ForegroundColor Green
    } else {
        Write-Host "Команда не установлена ($InstallDir не найдена)."
    }
}

# --- разбор аргументов ---

$action   = $null
$allowLan = $false
$ips      = @()
$rawArgs  = @()

foreach ($arg in $args) {
    # «1.2.3.4,5.6.7.8», набранное прямо в PowerShell, приходит массивом.
    $text = @($arg) -join ','
    $rawArgs += $text
    $key = $text.ToLower()

    if ($key -match '^(--?|/)(start|stop|status|install|uninstall)$') {
        if ($action) { Stop-WithError 'укажите только одно действие (--start, --stop, --status, --install, --uninstall)' }
        $action = $Matches[2]
    } elseif ($key -match '^(--?|/)allow-?lan$') {
        $allowLan = $true
    } elseif ($key -match '^(--?|/)pause$') {
        # служебный флаг: держать окно открытым после перезапуска через UAC
        $script:Pause = $true
    } elseif ($key -match '^(--?|/)(h|help|\?)$') {
        Show-Usage
        exit 0
    } elseif ($key.StartsWith('-')) {
        Stop-WithError "неизвестный флаг: $text (см. --help)"
    } else {
        foreach ($ip in $text.Split(',')) {
            $ip = $ip.Trim()
            if (-not $ip) { continue }
            if (-not (Test-IpAddress $ip)) { Stop-WithError "некорректный IP-адрес: $ip" }
            $ips += $ip
        }
    }
}

if (-not $action) {
    Show-Usage
    Exit-Script 1
}
if ($action -eq 'start' -and $ips.Count -eq 0) { Stop-WithError 'для --start укажите IP-адрес VPN-сервера' }
if ($action -ne 'start' -and ($ips.Count -gt 0 -or $allowLan)) {
    Stop-WithError 'IP-адреса и --allow-lan используются только с --start'
}

# Нет прав администратора — перезапускаемся через UAC в новом окне.
if (-not (Test-Admin)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"") +
        @($rawArgs | Where-Object { $_ -notmatch '^(--?|/)pause$' } | ForEach-Object { "`"$_`"" }) +
        @('--pause')
    try {
        Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $argList
    } catch {
        Stop-WithError 'нужны права администратора (запрос UAC был отклонён)'
    }
    exit 0
}

switch ($action) {
    'start'     { Start-Killswitch $ips $allowLan }
    'stop'      { Stop-Killswitch }
    'status'    { Show-Status }
    'install'   { Install-Self }
    'uninstall' { Uninstall-Self }
}
Exit-Script 0
