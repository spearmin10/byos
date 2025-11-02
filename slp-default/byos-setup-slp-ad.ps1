Param(
    [parameter(mandatory=$true)][string]$ComputerIP,
    [parameter(mandatory=$true)][string]$ComputerName,
    [parameter(mandatory=$true)][string[]]$ComputerDnsServers,
    [parameter(mandatory=$true)][string]$LocalUserID,
    [parameter(mandatory=$true)][string]$LocalPassword,
    [parameter(mandatory=$true)][string]$DomainDnsName,
    [parameter(mandatory=$true)][string]$DomainOU
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
    [string]$domain_dns_name
    [string]$domain_ou

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
        $this.domain_dns_name = $cmdline_args["DomainDnsName"]
        $this.domain_ou = $cmdline_args["DomainOU"]
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

    hidden [void] _PromoteToDC () {
        if ([string]::IsNullOrEmpty($env:USERDNSDOMAIN)) {
            SetAutoLogon $this.local_userid $this.local_password $this.domain_dns_name
            $this._RegisterAutoSetupTask()

            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            Import-Module ADDSDeployment
            
            $short_domain = $this.domain_dns_name.Split(".")[0].ToUpper()
            
            Install-ADDSForest -Force `
                -DomainNetbiosName $short_domain `
                -DomainName $this.domain_dns_name `
                -SafeModeAdministratorPassword (ConvertTo-SecureString $this.local_password-AsPlainText -Force)
            SleepForever
        }
    }

    hidden [void] _AddOUAndUsers () {
        $dn_suffix = (($this.domain_dns_name.Split(".")) | ForEach-Object { "DC=$_" }) -join ','
        $user_names = @(
            "leroy sears",
            "francisco mayo",
            "marcus dunlap",
            "micheal hayden",
            "theodore wilder",
            "clifford mckay",
            "miguel coffey",
            "oscar mccarty",
            "jay ewing",
            "jim cooley",
            "tom vaughan",
            "calvin bonner",
            "alex cotton",
            "jon holder",
            "ronnie stark",
            "bill ferrell",
            "lloyd cantrell",
            "tommy fulton",
            "leon lynn",
            "derek lott",
            "warren calderon",
            "darrell rosa",
            "jerome pollard",
            "floyd hooper",
            "leo burch",
            "alvin mullen",
            "tim fry",
            "wesley riddle",
            "gordon levy",
            "dean david",
            "greg duke",
            "jorge odonnell",
            "dustin guy",
            "pedro michael",
            "derrick britt",
            "dan frederick",
            "lewis daugherty",
            "zachary berger",
            "corey dillard",
            "herman alston",
            "maurice jarvis",
            "vernon frye",
            "roberto riggs",
            "clyde chaney",
            "glen odom",
            "hector duffy",
            "shane fitzpatrick",
            "ricardo valenzuela",
            "sam merrill",
            "rick mayer",
            "lester alford",
            "brent mcpherson",
            "ramon acevedo",
            "charlie donovan",
            "tyler barrera",
            "gilbert albert",
            "gene cote",
            "marc reilly",
            "reginald compton",
            "ruben raymond",
            "brett mooney",
            "angel mcgowan",
            "nathaniel craft",
            "rafael cleveland",
            "leslie clemons",
            "edgar wynn",
            "milton nielsen",
            "raul baird",
            "ben stanton",
            "chester snider",
            "cecil rosales",
            "duane bright",
            "franklin witt",
            "andre stuart",
            "elmer hays",
            "brad holden",
            "gabriel rutledge",
            "ron kinney",
            "mitchell clements",
            "roland castaneda",
            "arnold slater",
            "harvey hahn",
            "jared emerson",
            "adrian conrad",
            "karl burks",
            "cory delaney",
            "claude pate",
            "erik lancaster",
            "darryl sweet",
            "jamie justice",
            "neil tyson",
            "jessie sharpe",
            "christian whitfield",
            "javier talley",
            "fernando macias",
            "clinton irwin",
            "ted burris",
            "mathew ratliff",
            "tyrone mccray",
            "darren madden"
        )

        New-ADOrganizationalUnit -Name $this.domain_ou -Path $dn_suffix

        $culture = [System.Globalization.CultureInfo]::GetCultureInfo("en-US")
        foreach ($full_name in $user_names) {
            $full_name = $culture.TextInfo.ToTitleCase($full_name)
            $given_name, $family_name = $full_name -split " "
            $user_id = ($given_name.Substring(0, 1) + $family_name).ToLower()

            New-ADUser -Name $full_name `
                -DisplayName $full_name `
                -SamAccountName $user_id `
                -GivenName $given_name `
                -Surname $family_name `
                -UserPrincipalName "${user_id}@$($this.domain_dns_name)".ToLower() `
                -EmailAddress "${user_id}@cortex.lan" `
                -Path "OU=$($this.domain_ou),${dn_suffix}" `
                -Department "CORTEX" `
                -AccountPassword (ConvertTo-SecureString $this.local_password -AsPlainText -Force) `
                -PasswordNeverExpires $true `
                -Enabled $true
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
        $this._PromoteToDC()
        $this._AddOUAndUsers()

        Unregister-ScheduledTask -TaskName [Main]::TASK_NAME -Confirm:$false -ErrorAction Ignore
        ResetAutoLogon
    }
}


[Main]::New($MyInvocation, $PSBoundParameters).Run()
