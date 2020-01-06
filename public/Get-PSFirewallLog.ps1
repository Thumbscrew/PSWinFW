function Get-PSFirewallLog {
    <#
    .SYNOPSIS

    Retrieves Windows Firewall log events and returns them as a table.

    .DESCRIPTION

    Retrieves Windows Firewall log events and returns them as a table. Log path can be directly specified or automatically determined based on local or remote registry settings.

    .EXAMPLE

    Get-PSFirewallLog -Path C:\Windows\system32\logfiles\firewall\pfirewall.log -Tail 1000

    Get last 1000 Windows Firewall log lines at a specific path.

    .EXAMPLE

    Get-PSFirewallLog -LogDirectory C:\Windows\system32\logfiles\firewall\ -LogFileName domainfw.log

    Get Windows Firewall log by specifying the log directory and filename separately.

    .EXAMPLE

    Get-PSFirewallLog -LogProfile Domain

    Get Windows Firewall log by retrieving the path automatically from the registry on the local machine.

    .EXAMPLE

    Get-PSFirewallLog -LogProfile Public -ComputerName MyRemoteComputer -Verbose

    Get Windows Firewall log on a remote computer using the Remote Registry service to get the log path.

    .EXAMPLE

    Get-PSFirewallLog -LogProfile Public -ComputerName MyRemoteComputer -InferPath

    Get Windows Firewall log on a remote computer using the path configured in the local machine's registry (converted to a UNC path).
    
    #>

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

        # Number of firewall events to retrieve. Defaults to -1 (All events).
        [Parameter(Mandatory = $false)]
        [int]
        $Tail = -1,

        # ComputerName to retrieve log from
        [Parameter(Mandatory = $true, ParameterSetName = 'remote')]
        [string]
        $ComputerName,

        # Follow the log
        [Parameter(Mandatory = $false)]
        [switch]
        $Wait,

        # Use local machine's registry setting to infer remote machine's log path
        [Parameter(Mandatory = $false, ParameterSetName = 'remote')]
        [switch]
        $InferPath
    )
    
    begin {
        if($PSCmdlet.ParameterSetName -eq 'auto') {
            $Path = Get-PSFirewallLogPath -LogProfile $LogProfile -Verbose:$VerbosePreference
        }
        elseif($PSCmdlet.ParameterSetName -eq 'remote') {
            $lpc = "Get-PSFirewallLogPath -LogProfile $LogProfile -ComputerName $ComputerName"

            if($InferPath) {
                $lpc += " -InferPath"
            }

            $Path = Invoke-Expression $lpc -Verbose:$VerbosePreference
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

            $count = (Get-Content -Path $logPath).Count

            # Check if outputting all events from the log and cut the first 5 lines that aren't events.
            if(($Tail -lt 0) -or ($Tail -gt $count)) {
                $Tail = $count - 5
            }

            Write-Verbose "Log has $count lines. Retrieving $Tail lines."

            $c = "Get-Content -Path $logPath -Tail $Tail"

            if($Wait) {
                $c = "$c -Wait"
            }

            Invoke-Expression $c | ForEach-Object {
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
            Write-Error "Failed to retrieve log at $logPath."
        }
    }
}