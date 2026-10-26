<#
Instala o fgt-gateway no servidor Windows (executar como Administrador, PowerShell 5.1+).
Cria: conta local svc_fgtgw (sem logon interativo/RDP), C:\ProgramData\fgt-gateway com ACLs,
chave SSH própria sem frase (só svc_fgtgw lê), known_hosts fixado, CA + certificados mTLS,
regra de firewall restrita e tarefa agendada que inicia o serviço no boot.
Não exibe nem grava senhas no console. Reexecutar com -Reissue recria certificados e senha da conta.
-SelfTestOnly: depois de cadastrar a chave no FortiGate, roda "get system status" com BatchMode=yes
como svc_fgtgw (tarefa temporária) e mostra só o resultado.

Exemplos:
  powershell -ExecutionPolicy Bypass -File .\install-server.ps1 -ClientName acalixto -SshPath 'C:\Program Files\Git\usr\bin\ssh.exe'
  powershell -ExecutionPolicy Bypass -File .\install-server.ps1 -SelfTestOnly
#>
param(
  [string]$ClientName = $env:USERNAME,
  [string]$ServerIp = '172.16.159.140',
  [int]$ListenPort = 8443,
  [string[]]$AllowedRemote = @('172.19.12.0/22'),
  [string]$FortiGateHost = '172.16.0.1',
  [int]$FortiGatePort = 40022,
  [string]$FortiGateUser = 'claude',
  [string]$TrustedKnownHosts = 'C:\Users\administrator\.ssh\known_hosts',
  [string]$SshPath = '',
  [switch]$Reissue,
  [switch]$SelfTestOnly
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Execute como Administrador.'
}
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = 'C:\Program Files\nodejs\node.exe' }
if (-not (Test-Path $node)) { throw 'Node.js não encontrado. Instale o Node.js LTS (nodejs.org) e rode de novo.' }
# OpenSSH: embutido no Windows Server 2019+; no 2016 vem do pacote Win32-OpenSSH.
function Find-Tool([string]$name, [string[]]$candidates) {
  foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return (Resolve-Path $c).Path } }
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}
if ($SshPath) {
  if (-not (Test-Path $SshPath)) { throw "SshPath inexistente: $SshPath" }
  $ssh = (Resolve-Path $SshPath).Path
} else {
  $ssh = Find-Tool 'ssh.exe' @((Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'), 'C:\Program Files\OpenSSH\ssh.exe',
    'C:\Program Files\OpenSSH-Win64\ssh.exe', 'C:\Program Files\Git\usr\bin\ssh.exe')
}
if (-not $ssh) { throw 'ssh.exe não encontrado (informe -SshPath).' }
$keygen = Join-Path (Split-Path $ssh) 'ssh-keygen.exe'
if (-not (Test-Path $keygen)) { throw "ssh-keygen.exe não encontrado ao lado de $ssh." }
# OpenSSL: o do Git for Windows basta; gera os certificados em PEM, sem depender do cofre do Windows.
$openssl = Find-Tool 'openssl.exe' @('C:\Program Files\Git\usr\bin\openssl.exe', 'C:\Program Files\Git\mingw64\bin\openssl.exe', 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe')
if (-not $openssl) { throw 'openssl.exe não encontrado (instale o Git for Windows ou o OpenSSL).' }
Write-Host "Node: $node | ssh: $ssh | openssl: $openssl"

$svc = 'svc_fgtgw'
$root = 'C:\ProgramData\fgt-gateway'
$dirs = @{ bin = "$root\bin"; conf = "$root\conf"; keys = "$root\keys"; pki = "$root\pki"; logs = "$root\logs"; bundle = "$root\client-bundle" }
function New-RandomSecret([int]$bytes = 32) {
  $b = New-Object byte[] $bytes; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', 'A').Replace('/', 'B')
}

$task = 'fgt-gateway'
$selfTask = 'fgt-gateway-selftest'
function Register-Service([string]$password) {
  $action = New-ScheduledTaskAction -Execute $node -Argument "`"$($dirs.bin)\server.mjs`" `"$($dirs.conf)\gateway.json`"" -WorkingDirectory $dirs.bin
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
  Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings -User "$env:COMPUTERNAME\$svc" -Password $password -RunLevel Limited -Force | Out-Null
}
# Executa "get system status" com BatchMode=yes como svc_fgtgw e mostra só o resumo (sem a saída do FortiGate).
function Invoke-SelfTest([string]$password) {
  $log = "$($dirs.logs)\selftest.jsonl"
  $before = if (Test-Path $log) { (Get-Content $log).Count } else { 0 }
  $action = New-ScheduledTaskAction -Execute $node -Argument "`"$($dirs.bin)\server.mjs`" --selftest `"$($dirs.conf)\gateway.json`"" -WorkingDirectory $dirs.bin
  Register-ScheduledTask -TaskName $selfTask -Action $action -User "$env:COMPUTERNAME\$svc" -Password $password -RunLevel Limited -Force | Out-Null
  Start-ScheduledTask -TaskName $selfTask
  $deadline = (Get-Date).AddSeconds(90)
  do { Start-Sleep -Seconds 2; $lines = if (Test-Path $log) { @(Get-Content $log) } else { @() } } while ($lines.Count -le $before -and (Get-Date) -lt $deadline)
  Unregister-ScheduledTask -TaskName $selfTask -Confirm:$false
  if ($lines.Count -le $before) { Write-Host '   Autoteste sem resultado em 90 s (veja o Visualizador de Eventos > Agendador de Tarefas).'; return $false }
  $r = $lines[-1] | ConvertFrom-Json
  Write-Host "   Conta: $env:COMPUTERNAME\$svc | ok=$($r.ok) | exit=$($r.exitCode) | hostname=$($r.hostname) | versão=$($r.version) | erro=$($r.error)"
  return [bool]$r.ok
}

if ($SelfTestOnly) {
  if (-not (Test-Path "$($dirs.conf)\gateway.json")) { throw 'Instalação não encontrada; rode sem -SelfTestOnly primeiro.' }
  # A senha da conta não é guardada: gera outra e reaplica na tarefa principal antes do autoteste.
  $pw = New-RandomSecret 32
  Set-LocalUser -Name $svc -Password (ConvertTo-SecureString $pw -AsPlainText -Force)
  Register-Service $pw
  Write-Host 'Autoteste SSH (BatchMode=yes) como svc_fgtgw:'
  $ok = Invoke-SelfTest $pw
  $pw = $null
  Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
  Start-ScheduledTask -TaskName $task
  if (-not $ok) { exit 1 }
  exit 0
}

Write-Host '1/8 Conta de serviço'
$pw = New-RandomSecret 32
$secure = ConvertTo-SecureString $pw -AsPlainText -Force
if (-not (Get-LocalUser -Name $svc -ErrorAction SilentlyContinue)) {
  New-LocalUser -Name $svc -Password $secure -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires `
    -Description 'fgt-gateway: consultas somente leitura ao FortiGate' | Out-Null
} else {
  Set-LocalUser -Name $svc -Password $secure
}
$sid = (Get-LocalUser -Name $svc).SID.Value
# Nega logon interativo e por RDP; logon em lote (tarefa agendada) é concedido no registro da tarefa.
$inf = Join-Path $env:TEMP 'fgtgw-secpol.inf'; $db = Join-Path $env:TEMP 'fgtgw-secpol.sdb'
secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
$lines = Get-Content $inf
foreach ($right in 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeBatchLogonRight') {
  $idx = [Array]::FindIndex([string[]]$lines, [Predicate[string]]{ param($l) $l -like "$right*" })
  if ($idx -ge 0) { if ($lines[$idx] -notmatch [regex]::Escape("*$sid")) { $lines[$idx] = "$($lines[$idx]),*$sid" } }
  else {
    # Direito ainda sem titulares: entra dentro da seção [Privilege Rights].
    $sec = [Array]::IndexOf([string[]]$lines, '[Privilege Rights]')
    if ($sec -lt 0) { $lines += '[Privilege Rights]'; $sec = $lines.Count - 1 }
    $lines = @($lines[0..$sec]) + "$right = *$sid" + @($lines[($sec + 1)..($lines.Count - 1)] | Where-Object { $_ -ne $null })
  }
}
$lines | Set-Content $inf -Encoding Unicode
secedit /configure /db $db /cfg $inf /areas USER_RIGHTS | Out-Null
Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue

Write-Host '2/8 Pastas e permissões'
foreach ($d in $dirs.Values) { New-Item -ItemType Directory -Force $d | Out-Null }
icacls $root /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null
foreach ($d in 'bin', 'conf', 'keys', 'pki') { icacls $dirs[$d] /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "${svc}:(OI)(CI)RX" | Out-Null }
icacls $dirs.logs /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' "${svc}:(OI)(CI)M" | Out-Null
icacls $dirs.bundle /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'server.mjs') $dirs.bin -Force
New-Item -ItemType Directory -Force "$($dirs.bin)\lib" | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'lib\commands.mjs') "$($dirs.bin)\lib" -Force

Write-Host '3/8 Chave SSH do serviço (sem frase; só svc_fgtgw lê)'
$key = "$($dirs.keys)\fortigate_ed25519"
if (-not (Test-Path $key)) {
  & $keygen -q -t ed25519 -N '""' -C "fgt-gateway@$env:COMPUTERNAME" -f $key | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen falhou' }
}
# O OpenSSH do Windows só aceita a chave se o dono for a própria conta que a usa.
icacls $key /setowner $svc | Out-Null
icacls $key /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' "${svc}:R" | Out-Null

Write-Host '4/8 Identidade SSH do FortiGate (known_hosts fixado)'
$kh = "$($dirs.keys)\known_hosts"
$hostPattern = "[$FortiGateHost]:$FortiGatePort"
$trusted = @()
if (Test-Path $TrustedKnownHosts) { $trusted = Get-Content $TrustedKnownHosts | Where-Object { $_.StartsWith("$hostPattern ") } }
if ($trusted.Count -gt 0) {
  $trusted | Set-Content $kh -Encoding ascii
  Write-Host "   Copiado do known_hosts já validado ($TrustedKnownHosts)."
} elseif (-not (Test-Path $kh)) {
  throw "Nenhuma entrada $hostPattern em $TrustedKnownHosts. Conecte uma vez manualmente para validar a identidade e rode de novo."
}
& $keygen -l -f $kh | ForEach-Object { Write-Host "   $_" }

Write-Host '5/8 Certificados mTLS em PEM (CA própria, servidor e cliente)'
$serverKey = "$($dirs.pki)\server.key"
if ($Reissue -or -not (Test-Path $serverKey)) {
  $work = Join-Path $env:TEMP ("fgtgw-pki-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory $work | Out-Null
  icacls $work /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null
  # O OpenSSL escreve progresso no stderr; no PowerShell 5.1 isso não pode virar erro fatal.
  function Invoke-OpenSsl { $ErrorActionPreference = 'Continue'; & $openssl @args 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "openssl falhou: $($args[0])" } }
  Get-ChildItem $dirs.bundle -File -ErrorAction SilentlyContinue | Remove-Item -Force
  Push-Location $work
  try {
    # CA própria (não é instalada como confiável no Windows); a chave da CA é apagada no fim.
    Invoke-OpenSsl req -x509 -newkey rsa:3072 -nodes -keyout ca.key -out ca.pem -days 1095 -subj '/CN=fgt-gateway CA' `
      -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign,cRLSign'
    "subjectAltName=IP:$ServerIp,DNS:$env:COMPUTERNAME`nkeyUsage=critical,digitalSignature,keyEncipherment`nextendedKeyUsage=serverAuth`n" |
      Set-Content server.ext -Encoding ascii
    "keyUsage=critical,digitalSignature,keyEncipherment`nextendedKeyUsage=clientAuth`n" | Set-Content client.ext -Encoding ascii
    Invoke-OpenSsl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj '/CN=fgt-gateway'
    Invoke-OpenSsl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 730 -out server.pem -extfile server.ext
    Invoke-OpenSsl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=fgt-client-$ClientName"
    Invoke-OpenSsl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 -out client.pem -extfile client.ext
    Copy-Item ca.pem, server.pem, server.key $dirs.pki -Force
    Copy-Item ca.pem, client.pem, client.key $dirs.bundle -Force
  } finally {
    Pop-Location
    Remove-Item $work -Recurse -Force
  }
  @{ url = "https://${ServerIp}:$ListenPort"; caFile = 'ca.pem'; certFile = 'client.pem'; keyFile = 'client.key' } |
    ConvertTo-Json | Set-Content "$($dirs.bundle)\client.json" -Encoding ascii
}
icacls $serverKey /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' "${svc}:R" | Out-Null
icacls "$($dirs.bundle)\client.key" /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' 2>$null | Out-Null

Write-Host '6/8 Configuração do serviço'
@{
  listenHost = '0.0.0.0'; listenPort = $ListenPort; caFile = "$($dirs.pki)\ca.pem"; serverCertFile = "$($dirs.pki)\server.pem"; serverKeyFile = $serverKey
  allowedClients = @("fgt-client-$ClientName"); sshPath = $ssh; sshKeyFile = $key; knownHostsFile = $kh
  fortigateHost = $FortiGateHost; fortigatePort = $FortiGatePort; fortigateUser = $FortiGateUser; auditDir = $dirs.logs
  timeoutMs = 60000; maxOutputBytes = 4194304
} | ConvertTo-Json | Set-Content "$($dirs.conf)\gateway.json" -Encoding ascii

Write-Host '7/8 Firewall do Windows'
Get-NetFirewallRule -DisplayName 'fgt-gateway (mTLS)' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'fgt-gateway (mTLS)' -Direction Inbound -Protocol TCP -LocalPort $ListenPort -RemoteAddress $AllowedRemote `
  -Action Allow -Profile Any | Out-Null

Write-Host '8/8 Tarefa agendada (inicia no boot como svc_fgtgw)'
Register-Service $pw
$pw = $null; $secure = $null
Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName $task

Write-Host ''
Write-Host '=== Pronto ==='
Write-Host 'A) Cadastre esta chave pública numa posição LIVRE (ssh-public-key1..3) do usuário claude no FortiGate,'
Write-Host '   sem substituir a chave atual:'
Write-Host "   $(Get-Content "$key.pub")"
Write-Host "   Confirme que $ServerIp está num trusthost do usuário claude."
Write-Host 'B) Depois rode: install-server.ps1 -SelfTestOnly  (SSH com BatchMode=yes como svc_fgtgw).'
Write-Host "C) Copie a pasta $($dirs.bundle) para o notebook (install-client.ps1) e depois apague-a deste servidor."
