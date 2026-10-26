<#
Instala o fgt-gateway no servidor Windows (executar como Administrador, PowerShell 5.1+).
Cria: conta local svc_fgtgw (sem logon interativo/RDP), C:\ProgramData\fgt-gateway com ACLs,
chave SSH própria sem frase (só svc_fgtgw lê), known_hosts fixado, CA + certificados mTLS,
regra de firewall restrita e tarefa agendada que inicia o serviço no boot.
Não exibe nem grava senhas no console. Reexecutar com -Reissue recria certificados e senha da conta.

Exemplo:
  powershell -ExecutionPolicy Bypass -File .\install-server.ps1 -ClientName acalixto
#>
param(
  [string]$ClientName = $env:USERNAME,
  [string]$ServerIp = '172.16.159.196',
  [int]$ListenPort = 8443,
  [string[]]$AllowedRemote = @('172.19.12.0/22'),
  [string]$FortiGateHost = '172.16.0.1',
  [int]$FortiGatePort = 40022,
  [string]$FortiGateUser = 'claude',
  [string]$TrustedKnownHosts = 'C:\Users\administrator\.ssh\known_hosts',
  [switch]$Reissue
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Execute como Administrador.'
}
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = 'C:\Program Files\nodejs\node.exe' }
if (-not (Test-Path $node)) { throw 'Node.js não encontrado. Instale o Node.js LTS (nodejs.org) e rode de novo.' }
$ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
$keygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
$keyscan = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keyscan.exe'
if (-not (Test-Path $ssh)) { throw 'Cliente OpenSSH do Windows ausente (Recurso opcional "OpenSSH Client").' }

$svc = 'svc_fgtgw'
$root = 'C:\ProgramData\fgt-gateway'
$dirs = @{ bin = "$root\bin"; conf = "$root\conf"; keys = "$root\keys"; pki = "$root\pki"; logs = "$root\logs"; bundle = "$root\client-bundle" }
function New-RandomSecret([int]$bytes = 32) {
  $b = New-Object byte[] $bytes; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  return [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', 'A').Replace('/', 'B')
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

Write-Host '5/8 Certificados (CA própria, servidor e cliente)'
$passFile = "$($dirs.pki)\server.pass"
if ($Reissue -or -not (Test-Path "$($dirs.pki)\server.pfx")) {
  $store = 'Cert:\LocalMachine\My'
  $ca = New-SelfSignedCertificate -Subject 'CN=fgt-gateway CA' -KeyUsage CertSign, CRLSign, DigitalSignature -KeyExportPolicy Exportable `
    -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=0') -NotAfter (Get-Date).AddYears(3) -CertStoreLocation $store -KeyAlgorithm RSA -KeyLength 3072
  $srv = New-SelfSignedCertificate -Subject 'CN=fgt-gateway' -Signer $ca -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(2) -CertStoreLocation $store `
    -TextExtension @("2.5.29.17={text}IPAddress=$ServerIp&DNS=$env:COMPUTERNAME", '2.5.29.37={text}1.3.6.1.5.5.7.3.1') -KeyAlgorithm RSA -KeyLength 2048
  $cli = New-SelfSignedCertificate -Subject "CN=fgt-client-$ClientName" -Signer $ca -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(1) -CertStoreLocation $store `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') -KeyAlgorithm RSA -KeyLength 2048
  $pem = "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($ca.RawData, 'InsertLineBreaks'))`n-----END CERTIFICATE-----`n"
  [IO.File]::WriteAllText("$($dirs.pki)\ca.pem", $pem); [IO.File]::WriteAllText("$($dirs.bundle)\ca.pem", $pem)
  $sp = New-RandomSecret 24; $cp = New-RandomSecret 24
  # AES-256: o Node 24 (OpenSSL 3) não lê PFX com a cifra antiga padrão (3DES/RC2).
  $pfxOpt = @{ ChainOption = 'EndEntityCertOnly' }
  if ((Get-Command Export-PfxCertificate).Parameters.ContainsKey('CryptoAlgorithmOption')) { $pfxOpt.CryptoAlgorithmOption = 'AES256_SHA256' }
  else { throw 'Este Windows não exporta PFX com AES-256 (requer Windows Server 2019 ou posterior).' }
  Export-PfxCertificate -Cert $srv -FilePath "$($dirs.pki)\server.pfx" -Password (ConvertTo-SecureString $sp -AsPlainText -Force) @pfxOpt | Out-Null
  Export-PfxCertificate -Cert $cli -FilePath "$($dirs.bundle)\client.pfx" -Password (ConvertTo-SecureString $cp -AsPlainText -Force) @pfxOpt | Out-Null
  [IO.File]::WriteAllText($passFile, $sp); [IO.File]::WriteAllText("$($dirs.bundle)\client.pass", $cp)
  # Chaves privadas só ficam nos arquivos com ACL: a CA não fica no repositório de certificados.
  foreach ($c in $ca, $srv, $cli) { Remove-Item "$store\$($c.Thumbprint)" -DeleteKey -Force }
  $sp = $null; $cp = $null
  @{ url = "https://${ServerIp}:$ListenPort"; caFile = 'ca.pem'; pfxFile = 'client.pfx'; passFile = 'client.pass' } |
    ConvertTo-Json | Set-Content "$($dirs.bundle)\client.json" -Encoding ascii
}
icacls "$($dirs.pki)\server.pfx" /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' "${svc}:R" | Out-Null
icacls $passFile /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' "${svc}:R" | Out-Null

Write-Host '6/8 Configuração do serviço'
@{
  listenHost = '0.0.0.0'; listenPort = $ListenPort; caFile = "$($dirs.pki)\ca.pem"; serverPfxFile = "$($dirs.pki)\server.pfx"; serverPassFile = $passFile
  allowedClients = @("fgt-client-$ClientName"); sshPath = $ssh; sshKeyFile = $key; knownHostsFile = $kh
  fortigateHost = $FortiGateHost; fortigatePort = $FortiGatePort; fortigateUser = $FortiGateUser; auditDir = $dirs.logs
  timeoutMs = 60000; maxOutputBytes = 4194304
} | ConvertTo-Json | Set-Content "$($dirs.conf)\gateway.json" -Encoding ascii

Write-Host '7/8 Firewall do Windows'
Get-NetFirewallRule -DisplayName 'fgt-gateway (mTLS)' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'fgt-gateway (mTLS)' -Direction Inbound -Protocol TCP -LocalPort $ListenPort -RemoteAddress $AllowedRemote `
  -Action Allow -Profile Domain, Private | Out-Null

Write-Host '8/8 Tarefa agendada (inicia no boot como svc_fgtgw)'
$action = New-ScheduledTaskAction -Execute $node -Argument "`"$($dirs.bin)\server.mjs`" `"$($dirs.conf)\gateway.json`"" -WorkingDirectory $dirs.bin
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName 'fgt-gateway' -Action $action -Trigger $trigger -Settings $settings -User "$env:COMPUTERNAME\$svc" -Password $pw -RunLevel Limited -Force | Out-Null
$pw = $null; $secure = $null
Stop-ScheduledTask -TaskName 'fgt-gateway' -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName 'fgt-gateway'

Write-Host ''
Write-Host '=== Pronto ==='
Write-Host 'A) Cadastre esta chave pública no usuário claude do FortiGate (ssh-public-key2):'
Write-Host "   $(Get-Content "$key.pub")"
Write-Host "   e inclua $ServerIp nos trusted hosts do usuário claude (ex.: trusthost2)."
Write-Host "B) Copie a pasta $($dirs.bundle) para o notebook (install-client.ps1) e depois apague-a deste servidor."
