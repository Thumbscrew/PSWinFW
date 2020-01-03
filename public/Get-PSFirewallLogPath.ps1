function Get-PSFirewallLogPath {
    param(
        # Log Profile to retrieve path for
        [Parameter(Mandatory = $true)]
        [ValidateSet('Public','Private','Domain')]
        [string]
        $LogProfile,

        # Remote Host to retrieve from
        [Parameter(Mandatory = $false, ParameterSetName = 'remote')]
        [string]
        $ComputerName,

        # Use local machine's registry setting to infer remote machine's log path
        [Parameter(Mandatory = $false, ParameterSetName = 'remote')]
        [switch]
        $InferPath
    )

    process {
        if($PSCmdlet.ParameterSetName -eq 'remote') {

            if($InferPath) {
                # Get local registry key entry
                $localPath = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -Path ("HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\{0}Profile\Logging" -f $LogProfile) -Name "LogFilePath").LogFilePath)

                if($null -eq $localPath) {
                    $defaultPath = "$ENV:SystemRoot\system32\LogFiles\Firewall\pfirewall.log"
                    Write-Warning "Path for $LogProfile firewall log not defined in registry. Assuming default path of $defaultPath"
                    $localPath = $defaultPath
                }
            }
            else {
                $serviceName = "RemoteRegistry"
                $startTypeChanged = $false
                $statusChanged = $false

                Write-Verbose "Retrieving path from registry on host $ComputerName."
                $remoteRegistry = Get-Service -ComputerName $ComputerName -Name $serviceName
                
                if($remoteRegistry.StartType -eq "Disabled") {
                    Write-Verbose "$serviceName service is Disabled. Attempting to change to Manual startup."
                    Set-Service -StartupType "Manual" -Name $serviceName -ComputerName $ComputerName
                    $modifiedRemoteRegistry = Get-Service -Name $serviceName -ComputerName $ComputerName

                    if($modifiedRemoteRegistry.StartType -ne "Manual") {
                        Write-Warning "Unable to change startup of $serviceName on host $ComputerName."
                        return $null
                    }
                    else {
                        Write-Verbose "$serviceName startup changed to Manual."
                        $startTypeChanged = $true
                    }
                }

                if($remoteRegistry.Status -ne "Running") {
                    Write-Verbose "$serviceName service is not running. Attempting to start."
                    Set-Service -Status "Running" -Name $serviceName -ComputerName $ComputerName
                    $modifiedRemoteRegistry = Get-Service -Name $serviceName -ComputerName $ComputerName

                    if($modifiedRemoteRegistry.Status -eq "Stopped") {
                        Write-Warning "Unable to start $serviceName service on host $ComputerName."
                        return $null
                    }
                    else {
                        Write-Verbose "$serviceName service started OK."
                        $statusChanged = $true
                    }
                }

                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $regKey = $reg.OpenSubKey("SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\{0}Profile\Logging" -f $LogProfile)
                $localPath = [Environment]::ExpandEnvironmentVariables($RegKey.GetValue("LogFilePath"))

                # Set Remote Registry back the way we found it if we had to change it

                if($statusChanged) {
                    Write-Verbose ("Reverting status of $serviceName Service to {0}." -f $remoteRegistry.Status)
                    # Set-Service -Name $serviceName -ComputerName $ComputerName -Status $remoteRegistry.Status
                    # Need to use Invoke-Command as Set-Service won't stop a service that has dependencies
                    Invoke-Command -ComputerName $ComputerName -ScriptBlock { Stop-Service -Name "RemoteRegistry" }
                    
                    # Verify that service has been restored to its original state.
                    $revertedRemoteRegistry = Get-Service -Name $serviceName -ComputerName $ComputerName
                    if($remoteRegistry.Status -ne $revertedRemoteRegistry.Status) {
                        Write-Warning "Failed to revert $serviceName status to $($remoteRegistry.Status)!"
                    }
                }

                if($startTypeChanged) {
                    Write-Verbose ("Reverting Startup of $serviceName Service to {0}." -f $remoteRegistry.StartType)
                    Set-Service -Name $serviceName -ComputerName $ComputerName -StartupType $remoteRegistry.StartType
                    
                    # Verify that service has been restored to its original state.
                    if($remoteRegistry.StartType -ne $revertedRemoteRegistry.StartType) {
                        Write-Warning "Failed to revert startup type of $serviceName to $($remoteRegistry.StartType)!"
                    }
                }
            }

            # Do the conversion to UNC path
            $path = "\\$ComputerName\" + $localPath.replace(':', '$')

            return $path
        }
        else {
            # Get local registry key entry
            $path = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -Path ("HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\{0}Profile\Logging" -f $LogProfile) -Name "LogFilePath").LogFilePath)

            if($null -eq $path) {
                $defaultPath = "$ENV:SystemRoot\system32\LogFiles\Firewall\pfirewall.log"
                Write-Warning "Path for $LogProfile firewall log not defined in registry. Assuming default path of $defaultPath"
                $path = $defaultPath
            }

            return $path
        }
    }
}