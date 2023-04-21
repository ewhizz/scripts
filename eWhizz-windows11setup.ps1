<#
.Synopsis
   Setup a Windows Machine with basic defaults
.DESCRIPTION

  Enables System Protection and sets the maximum disk space used for restore points to 25%.
  Sets the desktop background to a solid blue color.
  Sets the display language and system culture to English (Australia).
  Renames the computer to a new name specified by the user.
  Sets the default region and user language to Australia.
  Removes the UK keyboard layout and sets the US keyboard layout.
  Installs the PSWindowsUpdate module (if not already installed), runs Windows updates, and does not reboot
  Removes any McAfee products installed on the computer.
  Removed any Xbox related products installed on the computer.
  Sets the taskbar alignment to the left and turns off the chat taskbar item.
  Removes all desktop icons and shows the "This PC" icon on the desktop.
  Saves the computer's name, model, manufacture serial number and main specifications (cpu, RAM, Storage size) in a text file on the desktop.
  Ceate Restore Point
  
.EXAMPLE
   Open Powershell (as Administrator) and drag in this script. Press up arrow then return.

.NOTES
   General notes
#>

# Turn on System Protection and set maximum disk space used for restore points to 25%
Enable-ComputerRestore -Drive "C:\"
$vols = Get-Volume | Where-Object {$_.FileSystemLabel -eq 'OS'}
foreach ($vol in $vols) {
    $maxsize = [math]::Round($vol.Size * 0.25) # Set maximum disk space used for restore points to 25%
    Write-Host "Setting maximum disk space used for restore points on $($vol.DriveLetter) to $maxsize bytes."
    Disable-ComputerRestore -Drive $($vol.DriveLetter)
    Enable-ComputerRestore -Drive $($vol.DriveLetter) -MaxSize $maxsize
}

Write-Host "System Protection has been turned on for Local Disk with maximum disk space used for restore points set to 25%."



# Create Restore Point
Checkpoint-Computer -Description "Before changes made by script"
Write-Host "A restore point has been created."





# Set desktop pattern to solid blue
Set-ItemProperty -path 'HKCU:\Control Panel\Desktop' -name WallPaper -value ''
Set-ItemProperty -path 'HKCU:\Control Panel\Colors' -name Background -value '0 0 255'
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters

# Rename computer
$NewName = Read-Host -Prompt 'Enter new computer name'
Rename-Computer -NewName $NewName -Force

# Set region and language to Australia
Set-WinSystemLocale en-AU
Set-WinUserLanguageList en-AU -Force
Set-Culture en-AU

#Set time in taskbar to 24hr
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortTime -Value "HH:mm";

# Remove UK keyboard layout and set US keyboard layout
$InputLanguages = Get-WinUserLanguageList
$NewInputLanguages = @()
foreach ($InputLanguage in $InputLanguages) {
    if ($InputLanguage.LanguageTag -ne 'en-GB') {
        $NewInputLanguages += $InputLanguage
    }
}
$NewInputLanguages += 'en-US'
Set-WinUserLanguageList -LanguageList $NewInputLanguages -Force

# Install PSWindowsUpdate module (if not installed)
if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
    Write-Host "Installing PSWindowsUpdate module..."
    Install-Module -Name PSWindowsUpdate -Force
}

# Run Windows updates
Import-Module PSWindowsUpdate
Get-WindowsUpdate -Install -AcceptAll -AutoReboot

# Remove McAfee products
$mcAfeeProducts = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*McAfee*"}

if ($mcAfeeProducts.Count -gt 0) {
    Write-Host "McAfee products found. Removing..."
    foreach ($product in $mcAfeeProducts) {
        $product.Uninstall()
    }
    Write-Host "McAfee products have been removed."
} else {
    Write-Host "No McAfee products found."
}

# Uninstall Xbox programs
$XboxPackages = @(
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
)

ForEach ($package in $XboxPackages) {
    $packageFullName = (Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $package }).PackageFullName
    if ($packageFullName) {
        Write-Host "Uninstalling package: $packageFullName"
        Remove-AppxPackage -AllUsers -Package $packageFullName -ErrorAction SilentlyContinue
    } else {
        Write-Host "Package not found: $package"
    }
}


# Set Visual Effects to Performance
[System.Environment]::SetEnvironmentVariable("COMPLUS_EnableBMGraphics", 0, "Machine")
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f



# Remove icons from Desktop
Get-ChildItem -Path "$env:userprofile\desktop" -Include "Computer.lnk", "Control Panel.lnk", "Network.lnk", "Recycle Bin.lnk" -Recurse | Remove-Item -Force

# Show PC on desktop
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0

# Set taskbar alignment to the left 
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Force

#Turn off chat taskbar item
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$regValueName = "TaskBarMn"
Set-ItemProperty -Path $regPath -Name $regValueName -Value 0


# Get computer name
$ComputerName = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Name

# Get computer model and manufacturer
$ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
$Manufacturer = $ComputerSystem.Manufacturer
$Model = $ComputerSystem.Model

# Get serial number
$Bios = Get-WmiObject -Class Win32_BIOS
$SerialNumber = $Bios.SerialNumber

# Get system information
$System = Get-CimInstance -ClassName CIM_ComputerSystem
$Processor = Get-CimInstance -ClassName CIM_Processor
$Memory = Get-CimInstance -ClassName CIM_PhysicalMemory
$Disk = Get-CimInstance -ClassName CIM_DiskDrive | Where-Object {$_.MediaType -eq 'Fixed hard disk media'}

# Format system information for output
$SystemInfo = "Computer Name: $ComputerName`r`n" +
              "Manufacturer: $Manufacturer`r`n" +
              "Model: $Model`r`n" +
              "Serial Number: $SerialNumber`r`n" +
              "CPU: $($Processor.Name)`r`n" +
              "RAM: $([math]::Round(($Memory.Capacity | Measure-Object -Sum).Sum / 1GB)) GB`r`n" +
              "Storage: $($Disk.Size / 1GB) GB"

# Save system information to text file on desktop
$FilePath = "$env:UserProfile\Desktop\SystemInfo.txt"
$SystemInfo | Out-File -FilePath $FilePath
