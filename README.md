# **PSWinFW (beta)**

**Note: Module is WIP. Testing is done in a domain environment (not sure how it will fair on standalone machines). Pull Requests welcome.**

## **Description**
A powershell module for retrieving Windows Firewall logs and displaying them in a nicer, more useful format.

## **Installation**
```
git clone https://github.com/Thumbscrew/PSWinFW.git
Import-Module PSWinFW\PSWinFW.psm1
```
## **Example Usage**
Get last 1000 Windows Firewall log lines at a specific path:
```powershell
Get-PSFirewallLog -Path C:\Windows\system32\logfiles\firewall\pfirewall.log -Tail 1000
```
Get Windows Firewall log by specifying the log directory and filename separately:
```powershell
Get-PSFirewallLog -LogDirectory C:\Windows\system32\logfiles\firewall\ -LogFileName domainfw.log
```
Get Windows Firewall log by retrieving the path automatically from the registry on the local machine:
```powershell
Get-PSFirewallLog -LogProfile Domain
```
Get Windows Firewall log on a remote computer using the Remote Registry service to get the log path:
```powershell
Get-PSFirewallLog -LogProfile Public -ComputerName MyRemoteComputer -Verbose
```