
<#
	.Synopsis
		 Install and enable SSH server with Public Key Authentization
    .Description
		This script automates installation and configuration
		of the OpenSSH server which is a integral part of the 
		Windows 10 since 1809 build.
		The script configures the 'administrators_authorized_keys'
		mechanism for authentication. 
		The SSH Server service start is changed to automatic
		then SSH server is accessible after each computer reboot.
		
	.Parameter SSHKey    
        The SSH Key (as string) to be used for authentication
	
	.Parameter Port
	    Port where the SSH server will listen for connections. 
		This port will be also enabled at the Windows Firewall
		Previously used port will be blocked by the Firewall.
	    	
	.Example
        enable-ssh-server.ps1 "<place key string here>" -Port 2345
		
    .Notes
        NAME:      enable-ssh-server.ps1
        AUTHOR:    Zdenek Polach
		WEBSITE:   https://polach.me
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param (
	[Parameter(Mandatory)][string]$SSHKey,
    [ValidateRange(1,65535)][Int]$Port
)

function CheckIfLIneExistsInFile {
    param (
		[string]$file_path,
		[string]$line_content
	)
    #at first, get whole line content
    $line = Get-Content $file_path | Select-String -Pattern $line_content -SimpleMatch | Select-Object -ExpandProperty Line
    if ( $line -eq $null ) {
        return $False
    } else {
        return $True
    }

}
function AddLineToFileIfNotExist {
	param (
		[string]$file_path,
		[string]$line_content
	)

    #at first, get whole line content
    $content = Get-Content $file_path
    if ( $content -eq $null ) {
        #empty file, just append
        Add-Content $file_path "$line_content"
    } else {
        $line = $content | Select-String -Pattern $line_content -SimpleMatch | Select-Object -ExpandProperty Line
        if ( $line -eq $null ) {
            #Add-Content $file_path "`n$line_content"
            Add-Content $file_path "$line_content"
        }else{
            Write-Host "AddLine to file $file_path skipped, because line already exists" -ForegroundColor Yellow
        }
    }
        
}

function ReplaceLineWithPattern {
	param (
		[string]$file_path,
		[string]$line_pattern,
        [string]$new_line_content
	)

    #at first, get whole line content
    $line = Get-Content $file_path | Select-String $line_pattern | Select-Object -ExpandProperty Line
    #now replace
    if ( $line -eq $null ) {

        Write-Host "The pattern '$line_pattern' not found in the file!!" -ForegroundColor Red
    }
    if ( $line -eq $new_line_content ) {
        Write-Host "The line '$new_line_content' already exists in the file. Skipping" -ForegroundColor Yellow
    }
    $content = Get-Content $file_path
    $new_content = $content | ForEach-Object { $_ -replace $line, $new_line_content } 
    $new_content | Set-Content $file_path
}

$OpenSSHServer = Get-WindowsCapability -Online | ? Name -like ‘OpenSSH.Server*’
Add-WindowsCapability -Online -Name $OpenSSHServer.Name > $null

$SSHDaemonSvc = Get-Service -Name ‘sshd’
Start-Service -Name $SSHDaemonSvc.Name
Stop-Service -Name $SSHDaemonSvc.Name

$config_file = "$env:PROGRAMDATA\ssh\sshd_config"

ReplaceLineWithPattern $config_file '\bPubkeyAuthentication\b' 'PubkeyAuthentication yes'
ReplaceLineWithPattern $config_file '\bPasswordAuthentication\b' 'PasswordAuthentication no'
ReplaceLineWithPattern $config_file '\bPermitEmptyPasswords\b' 'PermitEmptyPasswords no'

if ( $PSBoundParameters.ContainsKey('Port') ){
    $port_line = 'Port ' + $Port.ToString()
    $line_exists = CheckIfLIneExistsInFile $config_file $port_line
    if ($line_exists -eq $False){
        Write-Host "Moving SSH Port to $Port"
        ReplaceLineWithPattern $config_file '\bPort\b' "$port_line"
        $fw_rule = Get-NetFirewallRule -DisplayName "OpenSSH SSH Server (sshd)" -ErrorAction SilentlyContinue
        if($fw_rule -eq $null){
            Write-Host "Unable to modify FW rule for SSH. Please check this and do it manually" -ForegroundColor Red
        }else{
            $fw_rule | Set-NetFirewallRule -LocalPort $Port
        }
    }
}

$authorizedKeyFilePath = “$env:ProgramData\ssh\administrators_authorized_keys”
$file_exists = Test-Path -Path $authorizedKeyFilePath -PathType Leaf 
if ($file_exists -eq $False ){
    New-Item $authorizedKeyFilePath > $null

    icacls.exe $authorizedKeyFilePath /remove “NT AUTHORITY\Authenticated Users” > $null
    icacls.exe $authorizedKeyFilePath /inheritance:r > $null
    Get-Acl “$env:ProgramData\ssh\ssh_host_dsa_key” | Set-Acl $authorizedKeyFilePath
}

AddLineToFileIfNotExist $authorizedKeyFilePath $SSHKey


New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force > $null


$SSHDaemonSvc = Get-Service -Name ‘sshd’
Set-Service -Name $SSHDaemonSvc.Name -StartupType Automatic
Start-Service -Name $SSHDaemonSvc.Name

Write-Host "`r`nThe OpenSSH server is successfully installed and configured" -ForegroundColor Green

