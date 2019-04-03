# Make commands zone aware

function Get-FirewalldLogs ($LogFile) {
<#
 .Synopsis
  Converts firewalld output log format to POSH object.

 .Description
  Firewalld will capture traffic connection detail strings in a flat log file format when configured.
  This cmdlet finds and parses those lines from that log file and converts them to a powershell object.

 .Link
  https://firewalld.org/
  https://docs.microsoft.com/en-us/powershell

 .EXAMPLE
  Get-FirewalldLogs .\messages | where {$_.DST -notlike "*.255"}

 .INPUTS
  Does not accept pipeline input; specify logfile as parameter

 .OUTPUTS
  Returns TCP/UDP connection information in object format
#>
    $content = gc $logfile | where {$_ -like "*kernel:*SRC*DST*PROTO*DPT*"}
    if ($content) {
        [array]$csv = $null
        foreach ($line in $content) {
            [string]$header = $null
            [string]$values = $null
            $traffic = "IN=" + ($line -split "IN=")[1]
            $columns = $traffic -split " " | where {$_ -like "*=*" -and $_ -notlike "*LEN*"}
            foreach ($column in $columns) {
                $header += ($column -split "=")[0] + ","
                $values += ($column -split "=")[1] + ","
            }
            if (-not $csv) {$csv += $header}
            $csv += $values
        }
        $csv | convertfrom-csv | select IN,SRC,DST,@{l="PROTO";e={$_.PROTO.tolower()}},DPT -Unique | where {$_.SRC -and $_.SRC -ne "0.0.0.0"}
    } else {
        Write-Error "No firewall traffic found in $logfile."   
    }
}

function New-FirewalldRule {
<#
 .Synopsis
  Adds firewall-cmd accept rule for single source IP, protocol, and destination port

 .Description
  Cmdlet wrapper to pass Source, Protocol, Port and variables to firewall-cmd to create an accept rule

 .Link
  https://firewalld.org/
  https://docs.microsoft.com/en-us/powershell

 .EXAMPLE
  New-FirewalldRule -SRC 192.168.1.123 -PROTO TCP -DPT 80

 .EXAMPLE
  Get-FirewalldLogs .\messages | New-FirewalldRule

 .INPUTS
  Accets pipeline input from objects containing SRC, PROTO, and DPT properties.

 .OUTPUTS
  Command parameter strings
#>
    [cmdletbinding()]
    param(  
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String]$SRC,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][INT]$CIDR=32,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String]$PROTO,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][INT]$DPT
    )
    process {
        "ADD source=$SRC/$CIDR protocol=$PROTO port=$DPT"
        $running = $null; $running = /bin/systemctl status firewalld | /bin/grep running
        if ($running) {
            /bin/firewall-cmd --zone=public --add-rich-rule="rule family="ipv4" source address="$SRC/$CIDR" port protocol="$PROTO" port="$DPT" accept"
            /bin/firewall-cmd --zone=public --permanent --add-rich-rule="rule family="ipv4" source address="$SRC/$CIDR" port protocol="$PROTO" port="$DPT" accept"
        } else {
            /bin/firewall-offline-cmd --zone=public --add-rich-rule="rule family="ipv4" source address="$SRC/$CIDR" port protocol="$PROTO" port="$DPT" accept"
        }
    }
}

function Remove-FirewalldRule {
<#
 .Synopsis
  Removes firewall-cmd accept rule for single source IP, protocol, and destination port

 .Description
  Cmdlet wrapper to pass Source, Protocol, Port and variables to firewall-cmd to remove an accept rule created by New-FirewalldRule

 .Link
  https://firewalld.org/
  https://docs.microsoft.com/en-us/powershell

 .EXAMPLE
  Remove-FirewalldRule -SRC 192.168.1.123 -PROTO TCP -DPT 80

 .EXAMPLE
  import-csv rulestoremove.csv | Remove-FirewalldRule  

 .INPUTS
  Accets pipeline input from objects containing SRC, PROTO, and DPT properties.

 .OUTPUTS
  Command parameter strings
#>
    [cmdletbinding()]
    param(  
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String]$SRC,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][INT]$CIDR=32,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String]$PROTO,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][INT]$DPT
    )
    process {
        "REMOVE source=$SRC/$CIDR protocol=$PROTO port=$DPT"
        $running = $null; $running = /bin/systemctl status firewalld | /bin/grep running
        if ($running) {
            /bin/firewall-cmd --zone=public --remove-rich-rule="rule family="ipv4" source address="$SRC/$CIDR" port protocol="$PROTO" port="$DPT" accept"
            /bin/firewall-cmd --zone=public --permanent --remove-rich-rule="rule family="ipv4" source address="$SRC/$CIDR" port protocol="$PROTO" port="$DPT" accept"
        } else {
            /bin/firewall-offline-cmd --zone=public --remove-rich-rule="rule family="ipv4" source address="$SRC/$CIDR" port protocol="$PROTO" port="$DPT" accept"
        }
    }
}

function Start-FirewalldLogging {
<#
 .Synopsis
  Configure firewalld to log and allow all traffic

 .Description
  Runs firewall-cmd to configure firewalld rule allowing any traffic from any destination and saving connection summary to message log

 .Link
  https://firewalld.org/
  https://docs.microsoft.com/en-us/powershell

 .EXAMPLE
  Start-FirewalldLogging

 .INPUTS
  Does not accept pipeline input

 .OUTPUTS
  Command parameter strings
#>
 # logic to check for running firewall and use non-offline cmd if necessary
    $running = $null; $running = /bin/systemctl status firewalld | /bin/grep running
    if ($running) {
        "Adding running firewalld rule that allows any traffic (firewalld is currently running)"
        firewall-cmd --zone=public --add-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="tcp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
        firewall-cmd --zone=public --add-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="udp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
    } else {
        "Adding offline firewalld rule that allows any traffic (firewalld is not currently running, please start firewalld to enable the log)"
        firewall-offline-cmd --zone=public --add-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="tcp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
        firewall-offline-cmd --zone=public --add-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="udp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
    }
}

function Stop-FirewalldLogging {
<#
 .Synopsis
  Configure firewalld to disable traffic logging

 .Description
  Runs firewall-cmd to remove firewalld rule and undo Start-FirewalldLogging configuration

 .Link
  https://firewalld.org/
  https://docs.microsoft.com/en-us/powershell

 .EXAMPLE
  Stop-FirewalldLogging

 .INPUTS
  Does not accept pipeline input

 .OUTPUTS
  Command parameter strings
#>
 # logic to check for running firewall and use non-offline cmd if necessary
    $running = $null; $running = /bin/systemctl status firewalld | /bin/grep running
    if ($running) {
        "Removing running firewalld rule that allows any traffic (firewalld is currently running)"
        firewall-cmd --zone=public --remove-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="tcp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
        firewall-cmd --zone=public --remove-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="udp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
    } else {
        "Removing offline firewalld rule that allows any traffic (firewalld is not currently running)"
        firewall-offline-cmd --zone=public --remove-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="tcp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
        firewall-offline-cmd --zone=public --remove-rich-rule="rule family="ipv4" source address="0.0.0.0/0" port protocol="udp" port="1-65535" log prefix="POSHfirewalld_" level="info" accept"
    } 
}

function Get-FirewalldRules {
<#
 .Synopsis
  View the firewalld active config

 .Description
  Runs firewall-cmd to list everything added or enabled for default zone

 .Link
  https://firewalld.org/
  https://docs.microsoft.com/en-us/powershell

 .EXAMPLE
  Get-FirewalldRules

 .INPUTS
  Does not accept pipeline input

 .OUTPUTS
  Command parameter strings
#>
    $running = $null; $running = /bin/systemctl status firewalld | grep running
    if ($running) {
        /bin/firewall-cmd --list-all
    } else {
        /bin/firewall-offline-cmd --list-all
    }
}
