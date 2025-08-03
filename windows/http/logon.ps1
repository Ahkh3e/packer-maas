<#
# Upstream Author:
#
#     Canonical Ltd.
#
# Copyright:
#
#     (c) 2014-2023 Canonical Ltd.
#
# Licence:
#
# If you have an executed agreement with a Canonical group company which
# includes a licence to this software, your use of this software is governed
# by that agreement.  Otherwise, the following applies:
#
# Canonical Ltd. hereby grants to you a world-wide, non-exclusive,
# non-transferable, revocable, perpetual (unless revoked) licence, to (i) use
# this software in connection with Canonical's MAAS software to install Windows
# in non-production environments and (ii) to make a reasonable number of copies
# of this software for backup and installation purposes.  You may not: use,
# copy, modify, disassemble, decompile, reverse engineer, or distribute the
# software except as expressly permitted in this licence; permit access to the
# software to any third party other than those acting on your behalf; or use
# this software in connection with a production environment.
#
# CANONICAL LTD. MAKES THIS SOFTWARE AVAILABLE "AS-IS".  CANONICAL  LTD. MAKES
# NO REPRESENTATIONS OR WARRANTIES OF ANY KIND, WHETHER ORAL OR WRITTEN,
# WHETHER EXPRESS, IMPLIED, OR ARISING BY STATUTE, CUSTOM, COURSE OF DEALING
# OR TRADE USAGE, WITH RESPECT TO THIS SOFTWARE.  CANONICAL LTD. SPECIFICALLY
# DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OR CONDITIONS OF TITLE, SATISFACTORY
# QUALITY, MERCHANTABILITY, SATISFACTORINESS, FITNESS FOR A PARTICULAR PURPOSE
# AND NON-INFRINGEMENT.
#
# IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL
# CANONICAL LTD. OR ANY OF ITS AFFILIATES, BE LIABLE TO YOU FOR DAMAGES,
# INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
# OUT OF THE USE OR INABILITY TO USE THIS SOFTWARE (INCLUDING BUT NOT LIMITED
# TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU
# OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
# PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGES.
#>

param(
    [Parameter()]
    [switch]$RunPowershell,
    [bool]$DoGeneralize
)

$ErrorActionPreference = "Stop"

# Use build ID from environment or generate fallback
$global:BuildId = if ($env:BUILD_ID) { $env:BUILD_ID } else { "build-$(Get-Date -Format 'yyyyMMdd-HHmmss')" }
$global:LogServerUrl = "http://10.0.2.2:8080/api/logs"

# Enhanced logging function with remote logging
function Write-LogMessage {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Local logging (always works)
    Write-Host $logMessage
    $logMessage | Out-File -FilePath "c:\setup_log.txt" -Append
    
    # Remote logging (graceful fallback)
    try {
        $logEntry = @{
            buildId = $global:BuildId
            timestamp = $timestamp
            level = $Level
            message = $Message
            hostname = $env:COMPUTERNAME
        }
        $jsonBody = $logEntry | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri $global:LogServerUrl -Method POST -Body $jsonBody -ContentType "application/json" -TimeoutSec 3 -ErrorAction Stop
    } catch {
        # Silently continue if remote logging fails
    }
}

try
{
    Write-LogMessage "=== Starting Windows setup process ===" "INFO"
    Write-LogMessage "RunPowershell: $RunPowershell, DoGeneralize: $DoGeneralize" "INFO"
    
    # Need to have network connection to continue, wait 30 seconds for the network to be active.
    Write-LogMessage "Waiting 30 seconds for network connectivity..." "INFO"
    start-sleep -s 30
    Write-LogMessage "Network wait completed" "INFO"

    # Inject extra drivers if the infs directory is present on the attached iso
    if (Test-Path -Path "E:\infs")
    {
        Write-LogMessage "Extra drivers directory found, starting driver injection process" "INFO"
        
        # Copy the WDK installer from downloads.
        $Host.UI.RawUI.WindowTitle = "Copying Windows Driver Kit..."
        Write-LogMessage "Copying Windows Driver Kit installer..." "INFO"
        Copy-Item "F:\wdksetup.exe" "c:\wdksetup.exe"
        Write-LogMessage "WDK installer copied successfully" "INFO"

        # Run the installer.
        $Host.UI.RawUI.WindowTitle = "Installing Windows Driver Kit..."
        Write-LogMessage "Installing Windows Driver Kit..." "INFO"
        $p = Start-Process -PassThru -Wait -WindowStyle Hidden -FilePath cmd -ArgumentList "/c `"c:\wdksetup.exe`" /features OptionId.WindowsDriverKitComplete /quiet /norestart /ceip off"
        if ($p.ExitCode -ne 0)
        {
            Write-LogMessage "WDK installation failed with exit code: $($p.ExitCode)" "ERROR"
            throw "Installing wdksetup.exe failed."
        }
        Write-LogMessage "WDK installation completed successfully" "INFO"

        # Run dpinst.exe with the path to the drivers.
        $Host.UI.RawUI.WindowTitle = "Injecting Windows drivers..."
        Write-LogMessage "Injecting Windows drivers using dpinst..." "INFO"
        $dpinst = "$ENV:ProgramFiles (x86)\Windows Kits\8.1\redist\DIFx\dpinst\EngMui\x64\dpinst.exe"
        Start-Process -Wait -FilePath "$dpinst" -ArgumentList "/S /C /F /SA /Path E:\infs"
        Write-LogMessage "Driver injection completed" "INFO"

        # Uninstall the WDK
        $Host.UI.RawUI.WindowTitle = "Uninstalling Windows Driver Kit..."
        Write-LogMessage "Uninstalling Windows Driver Kit..." "INFO"
        Start-Process -Wait -WindowStyle Hidden -FilePath cmd -ArgumentList "/c `"c:\wdksetup.exe`" /features + /q /uninstall /norestart"
        Write-LogMessage "WDK uninstallation completed" "INFO"

        # Clean-up
        Write-LogMessage "Starting WDK installer cleanup..." "INFO"
        Remove-Item -Path c:\wdksetup.exe -Force
        Write-LogMessage "WDK installer cleanup completed" "INFO"
    } else {
        Write-LogMessage "No extra drivers directory found, skipping driver injection" "INFO"
    }

    $Host.UI.RawUI.WindowTitle = "Installing Cloudbase-Init..."
    Write-LogMessage "Starting Cloudbase-Init installation..." "INFO"
    Copy-Item "F:\CloudbaseInitSetup_Stable_x64.msi" "c:\cloudbase.msi"
    Write-LogMessage "Cloudbase-Init installer copied" "INFO"
    
    $cloudbaseInitLog = "$ENV:Temp\cloudbase_init.log"
    $serialPortName = @(Get-WmiObject Win32_SerialPort)[0].DeviceId
    Write-LogMessage "Using serial port: $serialPortName" "INFO"
    
    $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/i c:\cloudbase.msi /qn /norestart /l*v $cloudbaseInitLog LOGGINGSERIALPORTNAME=$serialPortName"
    if ($p.ExitCode -ne 0)
    {
        Write-LogMessage "Cloudbase-Init installation failed with exit code: $($p.ExitCode)" "ERROR"
        throw "Installing cloudbase.msi failed. Log: $cloudbaseInitLog"
    }
    Write-LogMessage "Cloudbase-Init installation completed successfully" "INFO"

    # Install virtio drivers
    $Host.UI.RawUI.WindowTitle = "Installing Virtio Drivers..."
    Write-LogMessage "Starting Virtio drivers installation..." "INFO"
    
    Write-LogMessage "Adding Red Hat certificate to trusted publishers..." "INFO"
    certutil -f -addstore -enterprise "TrustedPublisher" A:\rh.cer
    Write-LogMessage "Certificate added successfully" "INFO"
    
    Copy-Item "F:\virtio-win-gt-x64.msi" "c:\virtio.msi"
    Copy-Item "F:\virtio-win-guest-tools.exe" "c:\virtio.exe"
    Write-LogMessage "Virtio installers copied" "INFO"
    
    $virtioLog = "$ENV:Temp\virtio.log"
    Write-LogMessage "Installing Virtio MSI package..." "INFO"
    $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/i c:\virtio.msi /qn /norestart /l*v $virtioLog"
    Write-LogMessage "Virtio MSI installation exit code: $($p.ExitCode)" "INFO"
    
    Write-LogMessage "Installing Virtio guest tools..." "INFO"
    $p = Start-Process -Wait -PassThru -FilePath c:\virtio.exe -ArgumentList "/S /v/qn"
    Write-LogMessage "Virtio guest tools installation exit code: $($p.ExitCode)" "INFO"
    Write-LogMessage "Virtio drivers installation completed" "INFO"

    # We're done, remove LogonScript, disable AutoLogon
    Write-LogMessage "Cleaning up registry entries..." "INFO"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Unattend*
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount
    Write-LogMessage "Registry cleanup completed" "INFO"

    $Host.UI.RawUI.WindowTitle = "Running SetSetupComplete..."
    Write-LogMessage "Running SetSetupComplete..." "INFO"
    Start-Process -Wait -WindowStyle Hidden -FilePath cmd -ArgumentList "/c `"$ENV:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\bin\SetSetupComplete.cmd`""
    Write-LogMessage "SetSetupComplete completed" "INFO"

    if ($RunPowershell) {
        $Host.UI.RawUI.WindowTitle = "RunPowershell flag detected - skipping for automated execution"
        Write-LogMessage "RunPowershell flag detected but skipped for automated execution" "INFO"
        Write-LogMessage "If manual intervention is needed, disable this flag and run interactively" "WARN"
    }

    # Clean-up
    Write-LogMessage "Starting file cleanup..." "INFO"
    Remove-Item -Path c:\cloudbase.msi -Force
    Remove-Item -Path c:\virtio.msi -Force
    Remove-Item -Path c:\virtio.exe -Force
    Write-LogMessage "File cleanup completed" "INFO"

    # Write success, this is used to check that this process made it this far
    New-Item -Path c:\success.tch -Type file -Force
    Write-LogMessage "Success marker created" "INFO"

    # Prepare system for Sysprep - suspend BitLocker and remove problematic UWP apps
    $Host.UI.RawUI.WindowTitle = "Preparing system for Sysprep..."
    Write-LogMessage "=== Preparing system for Sysprep ===" "INFO"

    # Fully decrypt and verify BitLocker is fully disabled
    try {
        $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:"
        Write-LogMessage "Current BitLocker status: $($bitlockerStatus.ProtectionStatus)" "INFO"

        if ($bitlockerStatus.ProtectionStatus -eq "On" -or $bitlockerStatus.EncryptionPercentage -gt 0) {
            Write-LogMessage "BitLocker is enabled, initiating full decryption..." "INFO"
            Disable-BitLocker -MountPoint "C:"

            # Poll until BitLocker is fully decrypted
            $maxWaitSeconds = 1800  # 30 minutes max
            $pollInterval = 10      # Check every 10 seconds
            $elapsedTime = 0

            Write-LogMessage "Polling for BitLocker decryption completion..." "INFO"
            do {
                Start-Sleep -Seconds $pollInterval
                $elapsedTime += $pollInterval
                $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:"
                Write-LogMessage "BitLocker encryption: $($bitlockerStatus.EncryptionPercentage)% (${elapsedTime}s elapsed)" "INFO"
            } while ($bitlockerStatus.EncryptionPercentage -gt 0 -and $elapsedTime -lt $maxWaitSeconds)

            if ($bitlockerStatus.EncryptionPercentage -eq 0) {
                Write-LogMessage "BitLocker successfully decrypted - EncryptionPercentage: 0" "INFO"
            } else {
                Write-LogMessage "BitLocker still shows $($bitlockerStatus.EncryptionPercentage)% after ${maxWaitSeconds}s - proceeding anyway" "WARN"
            }
        } else {
            Write-LogMessage "BitLocker already decrypted or protection off - no action needed" "INFO"
        }
    } catch {
        Write-LogMessage "BitLocker check/decryption failed or not present: $_" "WARN"
    }


    # Remove problematic UWP apps
    Write-LogMessage "Removing problematic UWP applications..." "INFO"
    try {
        $widgetPackages = Get-AppxPackage -Name Microsoft.WidgetsPlatformRuntime*
        if ($widgetPackages) {
            Write-LogMessage "Found $($widgetPackages.Count) Widget Platform packages to remove" "INFO"
            $widgetPackages | Remove-AppxPackage
            Write-LogMessage "Widget Platform packages removed from current user" "INFO"
        } else {
            Write-LogMessage "No Widget Platform packages found for current user" "INFO"
        }
        
        $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "Microsoft.WidgetsPlatf*"}
        if ($provisionedPackages) {
            Write-LogMessage "Found $($provisionedPackages.Count) provisioned Widget Platform packages to remove" "INFO"
            $provisionedPackages | Remove-AppxProvisionedPackage -Online
            Write-LogMessage "Provisioned Widget Platform packages removed" "INFO"
        } else {
            Write-LogMessage "No provisioned Widget Platform packages found" "INFO"
        }
        
        Write-LogMessage "UWP app removal completed successfully" "INFO"
    } catch {
        Write-LogMessage "UWP app removal failed: $_" "WARN"
    }

    $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
    Write-LogMessage "=== Starting Sysprep process ===" "INFO"
    Write-LogMessage "DoGeneralize parameter: $DoGeneralize" "INFO"
    
    if ($DoGeneralize) {
        $unattendedXmlPath = "$ENV:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"
        Write-LogMessage "Running Sysprep with generalize option using: $unattendedXmlPath" "INFO"
        & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
    } else {
        $unattendedXmlPath = "$ENV:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"
        Write-LogMessage "Running Sysprep without generalize using: $unattendedXmlPath" "INFO"
        & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
    }
    Write-LogMessage "Sysprep command executed - system should shutdown soon" "INFO"
}
catch
{
    Write-LogMessage "FATAL ERROR: $_" "ERROR"
    $_ | Out-File c:\error_log.txt
    Write-LogMessage "Error details written to c:\error_log.txt" "ERROR"
}
