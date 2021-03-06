# PowerShellScripts

Some useful PS Scripts to make life easier:

* **enable-ssh-server.ps1** -- _Installs and enable SSH server with Public Key Authentization on Windows host_

##### Hint:
To bypass Power Shell policy, you can use this trick from PowerShell console:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_PowerShell.exe -ExecutionPolicy Bypass -File script_to_run.ps1_


-------------------------------------------------
**enable-ssh-server**

This script automates installation and configuration of the OpenSSH server on Windows host The OpenSSH Server an integral part of the Windows 10 since 1809 build.\
The script configures the **'administrators_authorized_keys'** mechanism for authentication.\
The SSH Server service start is changed to automatic then SSH server is accessible after each computer reboot.

##### Usage:

enable-ssh-server.ps1 "&lt;place SSH Key string here&gt;" -Port 2345

##### Parameters:

* **SSHKey** (Mandatory) - The SSH Key (as string) to be used for authentication
* **Port** - Port where the SSH server will listen for connections. This port will be also enabled at the Windows Firewall and previously used port will be blocked by the Firewall.

##### Hint:

To remove ssh key from known hosts to allow connect after VM redeploy or SSH server reinstall:

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;_ssh-keygen -R example.com_
