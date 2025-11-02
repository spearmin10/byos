Param(
    [parameter(mandatory=$true)][string]$ComputerIP,
    [parameter(mandatory=$true)][string]$ComputerName,
    [parameter(mandatory=$true)][string[]]$ComputerDnsServers,
    [parameter(mandatory=$true)][string]$LocalUserID,
    [parameter(mandatory=$true)][string]$LocalPassword,
    [parameter(mandatory=$true)][string]$DomainUserID,
    [parameter(mandatory=$true)][string]$DomainPassword,
    [parameter(mandatory=$true)][string]$DomainDnsName
)

function SleepForever() {
    while ($true) { Start-Sleep -Seconds 1000 }
}

function ResetAutoLogon () {
    $wl_path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Remove-ItemProperty -Path $wl_path -Name "DefaultUserName" -Force
    Remove-ItemProperty -Path $wl_path -Name "DefaultPassword" -Force
    Remove-ItemProperty -Path $wl_path -Name "DefaultDomainName" -Force
    Remove-ItemProperty -Path $wl_path -Name "AutoAdminLogon" -Force
}

function SetAutoLogon (
    [string]$logon_userid,
    [string]$logon_password,
    [string]$logon_domain
) {
    $wl_path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty -Path $wl_path -Name "DefaultUserName" -Type String -Value "$logon_userid"
    Set-ItemProperty -Path $wl_path -Name "DefaultPassword" -Type String -Value "$logon_password"
    Set-ItemProperty -Path $wl_path -Name "DefaultDomainName" -Type String -Value "$logon_domain"
    Set-ItemProperty -Path $wl_path -Name "AutoAdminLogon" -Type String -Value "1"
}

function BuildCommandLineArgs (
    [System.Collections.Hashtable]$cmdline_args
) {
    $arg_list = @()
    foreach ($key in $cmdline_args.Keys) {
        $value = $cmdline_args[$key]
        if ($value -is [string] -and ($value -match '\s' -or $value -match '"')) {
            $escaped_value = '"' + $value.Replace('"', '`"') + '"'
        } elseif ($value -is [System.Collections.ICollection]) {
            $escaped_value = '"' + ($value -join ',') + '"'
        } else {
            $escaped_value = $value
        }
        $arg_list += "-$key $escaped_value"
    }
    return $arg_list -join ' '
}

class Main {
    static [string]$TASK_NAME = "byos-setup"

    [Management.Automation.InvocationInfo]$invocation_info
    [System.Collections.Hashtable]$cmdline_args
    [string]$computer_ip
    [string]$computer_name
    [string[]]$computer_dns_servers
    [string]$local_userid
    [string]$local_password
    [string]$domain_userid
    [string]$domain_password
    [string]$domain_dns_name

    Main(
        [Management.Automation.InvocationInfo]$invocation_info,
        [System.Collections.Hashtable]$cmdline_args
    ) {
        $this.invocation_info = $invocation_info
        $this.cmdline_args = $cmdline_args
        $this.computer_ip = $cmdline_args["ComputerIP"]
        $this.computer_name = $cmdline_args["ComputerName"]
        $this.computer_dns_servers = $cmdline_args["ComputerDnsServers"]
        $this.local_userid = $cmdline_args["LocalUserID"]
        $this.local_password = $cmdline_args["LocalPassword"]
        $this.domain_userid = $cmdline_args["DomainUserID"]
        $this.domain_password = $cmdline_args["DomainPassword"]
        $this.domain_dns_name = $cmdline_args["DomainDnsName"]
    }

    hidden [void] _RegisterAutoSetupTask () {
        # Set the task to auto-run the script
        $shed_service = New-Object -comobject 'Schedule.Service'
        $shed_service.Connect($null, $null, $null, $null)

        $task = $shed_service.NewTask(0)
        $task.Settings.Enabled = $true
        $task.Settings.AllowDemandStart = $true
        $task.Principal.RunLevel = 1

        $trigger = $task.triggers.Create(9)
        $trigger.Enabled = $true
        $trigger.Delay = "PT1S"

        $action = $task.Actions.Create(0)
        $action.Path = "powershell.exe"
        $action.Arguments = "-NoProfile -ExecutionPolicy Bypass " `
          + "`"$($this.invocation_info.MyCommand.Path)`" " `
          + $(BuildCommandLineArgs $this.cmdline_args)

        $taskFolder = $shed_service.GetFolder("\")
        $taskFolder.RegisterTaskDefinition([Main]::TASK_NAME, $task, 6, "Administrators", $null, 4)
    }

    hidden [void] _ConfigureHostName () {
        if ($env:COMPUTERNAME.ToUpper() -ne $this.computer_name.ToUpper()) {
            SetAutoLogon $this.local_userid $this.local_password ""
            $this._RegisterAutoSetupTask()
            Rename-Computer -NewName $this.computer_name -Restart
            SleepForever
        }
    }

    hidden [void] _ConfigureIpAddress () {
        $adapter_name = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -ExpandProperty Name -First 1
        $current_ip = $(Get-NetIPAddress -InterfaceAlias $adapter_name -AddressFamily IPv4).IPAddress
        if ($current_ip -ne $this.computer_ip) {
            $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $adapter_name | Select-Object -First 1
            Get-NetIPAddress -InterfaceAlias $adapter_name -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false
            
            if ($route -ne $null) {
                Remove-NetRoute -InputObject $route -Confirm:$false
                New-NetIPAddress `
                    -InterfaceAlias $adapter_name `
                    -IPAddress $this.computer_ip `
                    -PrefixLength 24 `
                    -DefaultGateway $route.NextHop
            } else {
                New-NetIPAddress `
                    -InterfaceAlias $adapter_name `
                    -IPAddress $this.computer_ip `
                    -PrefixLength 24
            }
            Set-DnsClientServerAddress `
                -InterfaceAlias $adapter_name `
                -ServerAddresses $this.computer_dns_servers
        }
    }

    hidden [void] _JoinToAD () {
        if (!$(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
            SetAutoLogon $this.local_userid $this.local_password ""
            $this._RegisterAutoSetupTask()

            $credential = New-Object system.Management.Automation.PSCredential `
                $this.domain_userid, `
                $(ConvertTo-SecureString -AsPlainText $this.domain_password -Force)

            do {
                Add-Computer -Force -Restart -DomainName $this.domain_dns_name -Credential $credential
                if ($?) {
                    SleepForever
                }
                Start-Sleep -Seconds 10
            } while ($true);
        }
    }

    hidden [void] _ConfigureUserAccess () {
        $short_domain = $this.domain_dns_name.Split(".")[0]
        $u_ok = (Get-LocalGroupMember -Name "Administrators" | Where-Object {
            $_.Name.ToLower() -like "${short_domain}\$($this.domain_userid)".ToLower()
        }).Count -gt 0
        $r_ok = (Get-LocalGroupMember -Name "Remote Desktop Users" | Where-Object {
            $_.Name.ToLower() -like "Domain Users".ToLower() -or $_.Name.ToLower() -like "*\Domain Users".ToLower()
        }).Count -gt 0
        if (!$u_ok -or !$r_ok) {
            Add-LocalGroupMember -Group "Administrators" -Member "${short_domain}\$($this.domain_userid)".ToLower()
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Domain Users"

            SetAutoLogon $this.domain_userid $this.domain_password $this.domain_dns_name
            $this._RegisterAutoSetupTask()
            Restart-Computer -Force
        }
    }

    [void] Run () {
        $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (!$current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Host "This script must be run as an administrator."
            SleepForever
        }
        Unregister-ScheduledTask -TaskName [Main]::TASK_NAME -Confirm:$false -ErrorAction Ignore
        
        $this._ConfigureHostName()
        $this._ConfigureIpAddress()
        $this._JoinToAD()
        $this._ConfigureUserAccess()

        Unregister-ScheduledTask -TaskName [Main]::TASK_NAME -Confirm:$false -ErrorAction Ignore
    }
}


[Main]::New($MyInvocation, $PSBoundParameters).Run()
