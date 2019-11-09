function Get-PSFirewallLog {
    [CmdletBinding(DefaultParameterSetName = 'direct')]
    param (
        # Path to firewall log. Defaults to $ENV:SystemRoot\system32\LogFiles\Firewall\pfirewall.log if parameter not supplied.
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline, ParameterSetName = 'direct')]
        [string]
        $Path = "$ENV:SystemRoot\system32\LogFiles\Firewall\pfirewall.log",

        # Path to firewall log directory. Defaults to $ENV:SystemRoot\system32\LogFiles\Firewall\ if parameter not supplied.
        [Parameter(Mandatory = $false, ParameterSetName = 'indirect')]
        [string]
        $LogDirectory = "$ENV:SystemRoot\system32\LogFiles\Firewall\",

        # Log file name.
        [Parameter(Mandatory = $true, ParameterSetName = 'indirect')]
        [string]
        $LogFileName,

        # Retrieve a profile's log using registry settings of the local or remote machine
        [Parameter(Mandatory = $true, ParameterSetName = 'auto')]
        [Parameter(Mandatory = $true, ParameterSetName = 'remote')]
        [ValidateSet('Public','Private','Domain')]
        [string]
        $LogProfile,

        # Number of firewall events to retrieve. Defaults to 0 (All events).
        [Parameter(Mandatory = $false)]
        [int]
        $Tail = 0,

        # ComputerName to retrieve log from
        [Parameter(Mandatory = $true, ParameterSetName = 'remote')]
        [string]
        $ComputerName
    )
    
    begin {
        if($PSCmdlet.ParameterSetName -eq 'auto') {
            # $Path = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -Path ("HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\{0}Profile\Logging" -f $LogProfile) -Name "LogFilePath").LogFilePath)
            $Path = Get-PSFirewallLogPath -LogProfile $LogProfile -Verbose:$VerbosePreference
        }
        elseif($PSCmdlet.ParameterSetName -eq 'remote') {
            $Path = Get-PSFirewallLogPath -LogProfile $LogProfile -ComputerName $ComputerName -Verbose:$VerbosePreference
        }
    }
    
    process {

        if($PSCmdlet.ParameterSetName -eq 'indirect') {
            # Check for trailing slash and add if necessary
            if(!$LogDirectory.EndsWith('\')) {
                $LogDirectory += '\'
            }

            $logPath = $LogDirectory + $LogFileName
        }
        else {
            $logPath = $Path
        }

        if(Test-Path $logPath) {
            $log = Get-Content $logPath

            if($log.Length -gt 0) {
                # Remove header lines
                $log = $log[5..($log.Length - 1)]

                if($Tail -gt 0) {
                    $startIndex = if($Tail -lt $log.Length) { $log.Length - $Tail } else { 0 }
                    
                    $log = $log[$startIndex..($log.Length - 1)]
                }

                $members = @{
                    "Date" = 0
                    "Time" = 1
                    "Action" = 2
                    "Protocol" = 3
                    "SourceIP" = 4
                    "DestinationIP" = 5
                    "SourcePort" = 6
                    "DestinationPort" = 7
                    "Size" = 8
                    "TcpFlags" = 9
                    "TcpSyn" = 10
                    "TcpAck" = 11
                    "TcpWin" = 12
                    "IcmpType" = 13
                    "IcmpCode" = 14
                    "Info" = 15
                    "Path" = 16
                }

                $log | ForEach-Object {
                    $line = $_
                    $split = $line -split ('\s')

                    $fwEvent = New-Object PSCustomObject

                    foreach($member in $members.GetEnumerator() | Sort-Object Value) {
                        $fwEvent | Add-Member NoteProperty -Name $member.Name -Value $split[$member.Value]
                    }

                    $fwEvent.pstypenames.insert(0, 'PSWinFW.Log.Event')

                    $fwEvent
                }
            }
            else {
                Write-Error "File $logPath has zero length."
            }
        }
        else {
            Write-Error "Failed to retrieve log at $logPath."
        }
    }
}