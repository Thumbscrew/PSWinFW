Import-Module .\PSWinFW.psm1 -Force

$path = Get-PSFirewallLogPath -LogProfile Public -ComputerName stb603970 -Verbose

Write-Host $path