# PowerShell-GetInventory
A PowerShell module for creating an inventory of Windows hardware and software

Main use is to enumerate registry hives of offline Windows installations from something like Windows PE or another copy of Windows to gather a list of installed software, to gather a list of hardware information, and to export the information to HTML/CSV.

This module hasn't been looked at for a while so treat as entirely untested

# Original README from private repo
The Client Tools Module contains all the underlying functionality of the Client Tools project. This functionality inclues things like information gathering from an offline OS, backing up customer files, and reinstallation of the OS with the correct OS version.

This module is written in PowerShell and will eventually be used with a GUI front-end to simplify troubleshooting and working on customer machines.

## Utility Functions

### Get-WindowsInstallation

This function scans all local volumes with a type of `fixed` for the folder at `\Windows\System32\Drivers` and the file at `\Windows\System32\config\SOFTWARE`. If both of these are detected, the volume is assumed to contain a Windows installation.

#### Example

```powershell
Get-WindowsInstallation
C
D
```

## Inventory Functions

### Get-Inventory

This function retrieves information about the customer machine, combining both hardware and software inventories from `Get-HardwareInventory` and `Get-SoftwareInventory`.

### Get-HardwareInventory

The Get-HardwareInventory function uses WMI queries to determine the specifications of the machine it is being run on.

### Get-SoftwareInventory

The Get-SoftwareInventory function loads an offline SYSTEM registry hive and read the entries from `Microsoft\Windows\CurrentVersion\Uninstall` (x86, x64), `Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (x64).

#### Parameters

The `-OSDrive <LETTER>` and `-Online` parameters are mutually exclusive.

* `-OSDrive <LETTER>`
 * Inventory the Windows installation on `<LETTER>`, where `<LETTER>` is a single character representing the drive letter (eg. `-OSDrive C`)
* `-Online`
 * Do not load an offline registry hive, and use the booted OSes registry instead.
 
#### Outputs

The Get-SoftwareInventory function outputs an object with two arrays, one containing the `Raw` software inventory and one containing a `Filtered` list. The elements within these arrays have the properties `Publisher`, `DisplayName`, `DisplayVersion`, `Architecture`.

```powershell
$Software
    .Raw[]
        .Publisher
        .DisplayName
        .DisplayVersion
        .Architecture
    .Filtered[]
        .Publisher
        .DisplayName
        .DisplayVersion
        .Architecture
```

Filtered list is a list of regular expressions that are ignored for software listings. Example contained in [ApplicationFilter.csv](https://github.com/DanDonoghue/PowerShell-GetInventory/files/11185821/ApplicationFilter.csv)
