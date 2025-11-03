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
    static [System.Collections.Hashtable[]]$USERS = @(
        @{ given_name = "leroy"; family_name = "sears" },
        @{ given_name = "francisco"; family_name = "mayo" },
        @{ given_name = "marcus"; family_name = "dunlap" },
        @{ given_name = "micheal"; family_name = "hayden" },
        @{ given_name = "theodore"; family_name = "wilder" },
        @{ given_name = "clifford"; family_name = "mckay" },
        @{ given_name = "miguel"; family_name = "coffey" },
        @{ given_name = "oscar"; family_name = "mccarty" },
        @{ given_name = "jay"; family_name = "ewing" },
        @{ given_name = "jim"; family_name = "cooley" },
        @{ given_name = "tom"; family_name = "vaughan" },
        @{ given_name = "calvin"; family_name = "bonner" },
        @{ given_name = "alex"; family_name = "cotton" },
        @{ given_name = "jon"; family_name = "holder" },
        @{ given_name = "ronnie"; family_name = "stark" },
        @{ given_name = "bill"; family_name = "ferrell" },
        @{ given_name = "lloyd"; family_name = "cantrell" },
        @{ given_name = "tommy"; family_name = "fulton" },
        @{ given_name = "leon"; family_name = "lynn" },
        @{ given_name = "derek"; family_name = "lott" },
        @{ given_name = "warren"; family_name = "calderon" },
        @{ given_name = "darrell"; family_name = "rosa" },
        @{ given_name = "jerome"; family_name = "pollard" },
        @{ given_name = "floyd"; family_name = "hooper" },
        @{ given_name = "leo"; family_name = "burch" },
        @{ given_name = "alvin"; family_name = "mullen" },
        @{ given_name = "tim"; family_name = "fry" },
        @{ given_name = "wesley"; family_name = "riddle" },
        @{ given_name = "gordon"; family_name = "levy" },
        @{ given_name = "dean"; family_name = "david" },
        @{ given_name = "greg"; family_name = "duke" },
        @{ given_name = "jorge"; family_name = "odonnell" },
        @{ given_name = "dustin"; family_name = "guy" },
        @{ given_name = "pedro"; family_name = "michael" },
        @{ given_name = "derrick"; family_name = "britt" },
        @{ given_name = "dan"; family_name = "frederick" },
        @{ given_name = "lewis"; family_name = "daugherty" },
        @{ given_name = "zachary"; family_name = "berger" },
        @{ given_name = "corey"; family_name = "dillard" },
        @{ given_name = "herman"; family_name = "alston" },
        @{ given_name = "maurice"; family_name = "jarvis" },
        @{ given_name = "vernon"; family_name = "frye" },
        @{ given_name = "roberto"; family_name = "riggs" },
        @{ given_name = "clyde"; family_name = "chaney" },
        @{ given_name = "glen"; family_name = "odom" },
        @{ given_name = "hector"; family_name = "duffy" },
        @{ given_name = "shane"; family_name = "fitzpatrick" },
        @{ given_name = "ricardo"; family_name = "valenzuela" },
        @{ given_name = "sam"; family_name = "merrill" },
        @{ given_name = "rick"; family_name = "mayer" },
        @{ given_name = "lester"; family_name = "alford" },
        @{ given_name = "brent"; family_name = "mcpherson" },
        @{ given_name = "ramon"; family_name = "acevedo" },
        @{ given_name = "charlie"; family_name = "donovan" },
        @{ given_name = "tyler"; family_name = "barrera" },
        @{ given_name = "gilbert"; family_name = "albert" },
        @{ given_name = "gene"; family_name = "cote" },
        @{ given_name = "marc"; family_name = "reilly" },
        @{ given_name = "reginald"; family_name = "compton" },
        @{ given_name = "ruben"; family_name = "raymond" },
        @{ given_name = "brett"; family_name = "mooney" },
        @{ given_name = "angel"; family_name = "mcgowan" },
        @{ given_name = "nathaniel"; family_name = "craft" },
        @{ given_name = "rafael"; family_name = "cleveland" },
        @{ given_name = "leslie"; family_name = "clemons" },
        @{ given_name = "edgar"; family_name = "wynn" },
        @{ given_name = "milton"; family_name = "nielsen" },
        @{ given_name = "raul"; family_name = "baird" },
        @{ given_name = "ben"; family_name = "stanton" },
        @{ given_name = "chester"; family_name = "snider" },
        @{ given_name = "cecil"; family_name = "rosales" },
        @{ given_name = "duane"; family_name = "bright" },
        @{ given_name = "franklin"; family_name = "witt" },
        @{ given_name = "andre"; family_name = "stuart" },
        @{ given_name = "elmer"; family_name = "hays" },
        @{ given_name = "brad"; family_name = "holden" },
        @{ given_name = "gabriel"; family_name = "rutledge" },
        @{ given_name = "ron"; family_name = "kinney" },
        @{ given_name = "mitchell"; family_name = "clements" },
        @{ given_name = "roland"; family_name = "castaneda" },
        @{ given_name = "arnold"; family_name = "slater" },
        @{ given_name = "harvey"; family_name = "hahn" },
        @{ given_name = "jared"; family_name = "emerson" },
        @{ given_name = "adrian"; family_name = "conrad" },
        @{ given_name = "karl"; family_name = "burks" },
        @{ given_name = "cory"; family_name = "delaney" },
        @{ given_name = "claude"; family_name = "pate" },
        @{ given_name = "erik"; family_name = "lancaster" },
        @{ given_name = "darryl"; family_name = "sweet" },
        @{ given_name = "jamie"; family_name = "justice" },
        @{ given_name = "neil"; family_name = "tyson" },
        @{ given_name = "jessie"; family_name = "sharpe" },
        @{ given_name = "christian"; family_name = "whitfield" },
        @{ given_name = "javier"; family_name = "talley" },
        @{ given_name = "fernando"; family_name = "macias" },
        @{ given_name = "clinton"; family_name = "irwin" },
        @{ given_name = "ted"; family_name = "burris" },
        @{ given_name = "mathew"; family_name = "ratliff" },
        @{ given_name = "tyrone"; family_name = "mccray" },
        @{ given_name = "darren"; family_name = "madden" }
    )

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

        New-ADOrganizationalUnit -Name $this.domain_ou -Path $dn_suffix

        $culture = [System.Globalization.CultureInfo]::GetCultureInfo("en-US")
        foreach ($user in [Main]::USERS) {
            $given_name = $culture.TextInfo.ToTitleCase($user.given_name)
            $family_name = $culture.TextInfo.ToTitleCase($user.family_name)
            $full_name = "${given_name} ${family_name}"
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
