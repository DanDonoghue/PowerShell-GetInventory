<#
    CT-Module

    Client Tools functions for the Client Tools project

    (C) Dan Donoghue, 2016

    Author: Dan Donoghue <dan@mentula.co.uk>

#>

<#
    Utility Functions
#>

$ErrorActionPreference = "Stop"

Function Get-RegistryHive{
	<#
		Get-RegistryHive

		.SYNOPSIS
			Loads an offline registry hive into a random key in the current OSes HKLM. Returns the location where the registry was mounted.
		.EXAMPLE
			Load the SOFTWARE hive from the Windows installation on C:

			$MountPath = Get-RegistryHive -Hive C:\Windows\System32\Config\SOFTWARE
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True)]
		[String]$Hive
	)

	Write-Verbose "Hive: $Hive"

	If( -Not (Test-Path -PathType Leaf -Path $Hive) ){
		Throw [System.IO.FileNotFoundException]
	}

	$MountPath = "RegHive$(Get-Random)"
	reg load "HKLM\$MountPath" "$($Hive)" > $null
	If( Test-Path "HKLM:\$MountPath" ){
		$MountPath
	}Else{
		Throw [System.IO.InvalidDataException]
	}
}

Function Remove-RegistryHive{
	<#
		Remove-RegistryHive

		.SYNOPSIS
			Unload a registry hive by mount point
		.EXAMPLE
			Remove the hive "RegHive123456789"

			Remove-RegistryHive -MountPath "RegHive123456789"
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$True)]
		[String]$MountPath
	)

	If( Test-Path "HKLM:\$MountPath" ){
		[gc]::Collect()
		reg unload "HKLM\$MountPath" > $null
	}Else{
		Throw [System.IO.FileNotFoundException]
	}
}

Function Get-WindowsInstallations{
    <#
        Get-WindowsInstallations

        .SYNOPSIS
            Finds Windows installations on fixed local disks and returns a list of drive letters

        .DESCRIPTION
            Finds Windows installations by looking for \Windows\System32\drivers and \Windows\System32\config on any local fixed volumes that were found
		.EXAMPLE
			Get exactly ONE Windows installation

			Get-WindowsInstallations
		.EXAMPLE
			Get any number of Windows installations (useful for prompts where manual selection is needed, ie. multiboot)

			Get-WindowsInstallations -NoLimit
    #>
    [CmdletBinding()]
    Param(
		[switch]$NoLimit=$false
	)

	$Count=0

    ForEach( $Letter in ( Get-Volume | Where-Object {$_.DriveType -eq "Fixed"} ).DriveLetter ){
	    If( 
            ( Test-Path $Letter":\Windows\System32\drivers" ) -and 
            ( Test-Path $Letter":\Windows\System32\config" ) 
        ){
			If( $NoLimit ){
				"$($Letter):"
			}Else{
				$Count++
				$Letters+="$($Letter):"
			}
	    }
    }

	If( -Not $NoLimit -and $Count -le 1 ){
		$Letters
	}ElseIf( -Not $NoLimit -and $Count -gt 1 ){
		Throw "Multiple Windows Installations Found"
	}
}

Function Get-WindowsVersion{
	<#
		Get-WindowsVersion

		.SYNOPSIS
			Gets the Windows Version and Edition from a Windows installation
		.EXAMPLE
			Get the version of the Windows installation on C:

			Get-WindowsVersion -OSDrive C:
		.EXAMPLE
			Get the version of the currently booted Windows installation

			Get-WindowsVersion -Online
		.EXAMPLE
			Get the version of Windows using an already mounted SOFTWARE registry hive

			Get-WindowsVersion -MountPath "RegHive123456789"
		.EXAMPLE
			Get the version of Windows from the offline installation specified on the pipeline

			C:,D: | Get-WindowsVersion
		.EXAMPLE
			Get the version of Windows from the Get-WindowsInstallations output

			Get-WindowsInstallations | Get-WindowsVersion
	#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = "Online" )]
        [Switch]$Online,
        [Parameter(Mandatory = $True, ParameterSetName = "Mounted" )]
        [String]$MountPath,
        [Parameter(Mandatory = $True, ParameterSetName = "NonMounted", ValueFromPipeline = $True, Position = 0 )]
		[ValidatePattern("^[a-z]{1}\:$")]
        [String[]]$OSDrive
    )

    Begin{
        Function GetOSVersion{
            Param(
                [String]$MountPath
            )
            $WindowsVersion = New-Object -TypeName PSObject

            If( Test-Path "HKLM:\$MountPath\Wow6432Node" ){
                $WindowsVersion | Add-Member -MemberType NoteProperty -Name Architecture -Value "amd64"
            }Else{
                $WindowsVersion| Add-Member -MemberType NoteProperty -Name Architecture -Value "i386"
            }

            $WindowsVersion = Get-ItemProperty "HKLM:\$MountPath\Microsoft\Windows NT\CurrentVersion" | Select-Object EditionID, ProductName

            # Figure out what version and edition are installed to match to the ImageName's specified in the WIMs
            If( $WindowsVersion.ProductName -match "Windows 7" ){
                Write-Verbose "Detected Windows 7"
                $WindowsVersion | Add-Member -MemberType NoteProperty -Name ImageName -Value "Windows 7 $($WindowsVersion.EditionID)"
                $WindowsVersion | Add-Member -MemberType NoteProperty -Name ImageVersion -Value "Windows 7"
            }ElseIf( $WindowsVersion.ProductName -match "^Windows 8|^Windows 10" ){
                Write-Verbose "Detected Windows 8/10"
                $WindowsVersion | Add-Member -MemberType NoteProperty -Name ImageName -Value $WindowsVersion.ProductName
                If( $WindowsVersion.ProductName -match "^Windows 8" ){
                    $WindowsVersion | Add-Member -MemberType NoteProperty -Name ImageVersion -Value "Windows 8.1"
                }ElseIf( $WindowsVersion.ProductName -match "^Windows 10" ){
                    $WindowsVersion | Add-Member -MemberType NoteProperty -Name ImageVersion -Value "Windows 10"
                }
            }Else{
                Throw "Could not detect OS version"
            }
            $WindowsVersion
        }
    }

    Process{
        If( $PSCmdlet.ParameterSetName -eq "NonMounted" ){
            ForEach( $Drive in $OSDrive ){
                Write-Verbose "Using Registry Hive"
                Try{
					$MountPath = Get-RegistryHive -Hive "$($Drive)\Windows\System32\Config\SOFTWARE"
                    $WindowsVersion = GetOSVersion -MountPath $MountPath
					$WindowsVersion | Add-Member -MemberType NoteProperty -Name OSDrive -Value $Drive
					$WindowsVersion
                    Write-Verbose "Unloading Registry Hive"
                }Catch{
                    Throw
                }Finally{
					Remove-RegistryHive -MountPath $MountPath
                }
            }
        }ElseIf( $PSCmdlet.ParameterSetName -eq "Online" ){
            $MountPath = "SOFTWARE"
        }
        If( $PSCmdlet.ParameterSetName -ne "NonMounted" ){
            $WindowsVersion = GetOSVersion -MountPath $MountPath
			$WindowsVersion | Add-Member -MemberType NoteProperty -Name OSDrive -Value $Drive
			$WindowsVersion
        }
    }
}

<#
    Inventory Functions
#>

Function Get-Inventory{
    <#
        Get-Inventory

		.SYNOPSIS
			Get an inventory of hardware/software/OS from a locally installed copy of Windows.
		.EXAMPLE
			Get an inventory from an offline Windows installation on C:

			Get-Inventory -OSDrive C:
		.EXAMPLE
			Get an inventory from a booted Windows installation

			Get-Inventory -Online
		.EXAMPLE
			Get an inventory from the Windows installation specified by pipeline

			C: | Get-Inventory
		.EXAMPLE
			Get an inventory from the Windows installations detected by Get-WindowsInstallations

			Get-WindowsInstallations | Get-Inventory
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true, ParameterSetName="Offline", Position=0, ValueFromPipeline=$true)]
        [ValidatePattern("^[a-z]{1}\:$")]
        [String]$OSDrive,
        [Parameter(ParameterSetName="Online", Position=0)]
        [Switch]$Online = $false
    )
	Process{
		$Inventory = New-Object -TypeName PSObject

		$Inventory | Add-Member -MemberType NoteProperty -Name Hardware -Value (Get-HardwareInventory)

		If( $PSCmdlet.ParameterSetName -eq "Online" ){
			$Inventory | Add-Member -MemberType NoteProperty -Name Users -Value (Get-Users -Online)
			$Inventory | Add-Member -MemberType NoteProperty -Name Software -Value (
				Get-SoftwareInventory -Online
			)
		}Else{
			$Inventory | Add-Member -MemberType NoteProperty -Name Users -Value (Get-Users -OSDrive $OSDrive)
			$Inventory | Add-Member -MemberType NoteProperty -Name Software -Value (
				Get-SoftwareInventory -OSDrive $OSDrive
			)
		}

		$Inventory
	}
}

Function Get-SoftwareInventory {
    <#
        Get-SoftwareInventory

        .SYNOPSIS
            Reads the currently installed applications from a Windows installation
		.Description
			This function will get the list of installed applications, and store the filtered list in the Filtered property and raw list in Raw. This function also gets information about the current operating system, such as the version/edition, architecture, and product key. OS related information is stored in the OS property.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true, ParameterSetName="Offline", Position=0)]
        [ValidatePattern("^[a-z]{1}\:$")]
        [String]$OSDrive,
        [Parameter(Mandatory=$true, ParameterSetName="Online", Position=0)]
        [Switch]$Online = $false
    )

    $Filter = Import-Csv "$(Split-Path -Parent $PSCommandPath)\ApplicationFilter.csv"

	$Software = New-Object -TypeName PSObject
    $Software | Add-Member -MemberType NoteProperty -Name Raw -Value $null
    $Software | Add-Member -MemberType NoteProperty -Name Filtered -Value $null
	$Software | Add-Member -MemberType NoteProperty -Name OS -Value (New-Object -TypeName PSObject)

    If( $PSCmdlet.ShouldProcess( $env:COMPUTERNAME ) ){
        Switch ( $PSCmdlet.ParameterSetName ){
            "Online" {
                Write-Verbose "Using Online Registry Hive"
                $MountPoint = "SOFTWARE"
				Write-Verbose "Querying OS Version"
				$Software.OS | Add-Member -MemberType NoteProperty -Name Version -Value (Get-WindowsVersion -Online).ProductName
				$Software.OS | Add-Member -MemberType NoteProperty -Name ProductKey -Value (Get-WindowsProductKey -Online)
            }
            "Offline" {
                Write-Verbose "Using Registry Hive"
                $MountPoint = Get-RegistryHive -Hive "$($OSDrive)\Windows\System32\Config\SOFTWARE"
				Write-Verbose "Querying OS Version"
				$Software.OS | Add-Member -MemberType NoteProperty -Name Version -Value (Get-WindowsVersion -MountPath $MountPoint).ProductName
				$Software.OS | Add-Member -MemberType NoteProperty -Name ProductKey -Value (Get-WindowsProductKey -MountPath $MountPoint)
            }
        }

		$OSArch = "x86"

        If( Test-Path "HKLM:\$MountPoint\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*\" ){
			$Software.OS | Add-Member -MemberType NoteProperty -Name Architecture -Value "x64"
			$OSArch = "x64"
            $Software.Raw = Get-ItemProperty "HKLM:\$MountPoint\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*\" |
                Add-Member -PassThru -MemberType NoteProperty -Name Architecture -Value "x86" |
                Select-Object Publisher,DisplayName,DisplayVersion,Architecture | 
                Where-Object {
                    ($_.DisplayName -ne $null -and $_.DisplayName -ne "")
                }
        }Else{
			$Software.OS | Add-Member -MemberType NoteProperty -Name Architecture -Value "x86"
		}

        $Software.Raw += Get-ItemProperty "HKLM:\$MountPoint\Microsoft\Windows\CurrentVersion\Uninstall\*\" | 
            Add-Member -PassThru -MemberType NoteProperty -Name Architecture -Value "$OSArch" |
            Select-Object Publisher,DisplayName,DisplayVersion,Architecture |
            Where-Object {
                ($_.DisplayName -ne $null -and $_.DisplayName -ne "")
            }

        $Software.Raw = $Software.Raw | Sort-Object {$_.Publisher,$_.DisplayName} -Unique
        $Software.Filtered = $Software.Raw | Where-Object {
            ($_.DisplayName -notmatch ($Filter.Value -join "|"))
        }

        $Software

        If( $PSCmdlet.ParameterSetName -eq "Offline" ){
            Write-Verbose "Unloading Registry"
            Remove-RegistryHive $MountPoint
        }
    }
}

Function Get-HardwareInventory {
    <#
        Get-HardwareInventory

        .SYNOPSIS
            Reads the current systems hardware information using WMI
        
        .DESCRIPTION
            Reads information on the current systems processor, memory, disks. This command is fairly simple as detecting the hardware is no different between a booted Windows installation and WinPE.
		.EXAMPLE
			Get the hardware inventory

			Get-HardwareInventory
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    
    )
    If( $PSCmdlet.ShouldProcess( $env:COMPUTERNAME ) ){
        $ComputerHardware = New-Object -TypeName PSObject
        Write-Verbose "Querying System"
        $ComputerHardware | Add-Member -MemberType NoteProperty -Name System -Value (
            Get-WmiObject Win32_ComputerSystem | 
            Select-Object Manufacturer, Model
        )

        Write-Verbose "Querying Processor"
        $ComputerHardware | Add-Member -MemberType NoteProperty -Name Processor -Value (
            Get-WmiObject Win32_Processor | 
            Select-Object Name, @{Name="Frequency";Expression={"$($_.MaxClockSpeed / 1000) GHz"}}
        )

        Write-Verbose "Querying Memory"
        $ComputerHardware | Add-Member -MemberType NoteProperty -Name Memory -Value (
            Get-WmiObject Win32_PhysicalMemory | 
            Select-Object Manufacturer, PartNumber, DeviceLocator, @{Name="Capacity";Expression={"$($_.Capacity / 1GB) GB"}}
        )

        Write-Verbose "Querying Disks"
        $ComputerHardware | Add-Member -MemberType NoteProperty -Name Disks -Value (
            Get-WmiObject Win32_DiskDrive | 
            Where-Object {$_.MediaType -eq "Fixed hard disk media"} |
            Select-Object Model, @{Name="Size";Expression={"$([Math]::Round($_.Size / 1GB)) GB"}}
        )
        $ComputerHardware
    }
}

Function Get-WindowsProductKey{
	<#
		Get-WindowsProductKey

		.SYNOPSIS
			Gets the Product Key from a Windows installation
		.EXAMPLE
			Get the product key from an offline Windows installation

			Get-WindowsProductKey -OSDrive C:
		.EXAMPLE
			Get the product key from an offline Windows installation and use an already-mounted registry hive

			Get-WindowsProductKey -MountPath "RegHive123456789"
		.EXAMPLE
			Get the product key from a booted Windows installation

			Get-WindowsProductKey -Online
	#>
	[CmdletBinding()]
	Param(
        [Parameter(Mandatory=$true, ParameterSetName="Offline", Position=0)]
        [ValidatePattern("^[a-z]{1}\:$")]
        [String]$OSDrive,
		[Parameter(Mandatory=$true, ParameterSetName="Mounted", Position=0)]
		[String]$MountPath,
        [Parameter(Mandatory=$true, ParameterSetName="Online", Position=0)]
        [Switch]$Online = $false
    )

	Function ConvertToKey($Key){
		"Not Implemented"
	}

	If( $PSCmdlet.ParameterSetName -eq "Online" ){
		$MountPath = "SOFTWARE"
	}ElseIf($PSCmdlet.ParameterSetName -eq "Offline" ){
		$MountPath = Get-RegistryHive -Hive "$($OSDrive)\Windows\System32\Config\SOFTWARE"
	}

	$DigitalProductId = (Get-ItemProperty -Path "HKLM:\$MountPath\Microsoft\Windows NT\CurrentVersion" -Name "DigitalProductId").DigitalProductId
	ConvertToKey $DigitalProductId

	If( $PSCmdlet.ParameterSetName -eq "Offline" ){
		Remove-RegistryHive -MountPath $MountPath
	}
}

Function Write-InventoryHtml{
    <#
        Write-InventoryHtml

        .SYNOPSIS
            Writes the inventory data to a HTML file
        
        .DESCRIPTION
            Writes the inventory data to a HTML file for easier viewing of machine information

		.EXAMPLE
			Get-Inventory -Online | Write-InventoryHtml | Out-File R:\Clients\Test\Inventory.html
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [object]$Object
    )

    Begin{
        Function Write-HtmlTable{
            <#
                Write-HtmlTable

                .SYNOPSIS
                    Helper function for Write-InventoryHtml that converts objects to tables with headings
            #>
            Param(
                [string]$Title,
                [object]$Object,
				[String]$Class
            )
			Write-Output "<section class=`"$Class`">"
            Write-Output "<h2>$($Title)</h2>$($Object | ConvertTo-Html -As Table -Fragment)"
			Write-Output "</section>"
        }
    }

    Process{
        ForEach ($Input in $Object){
            Write-Output @"
<DOCTYPE html>
<html>
<head>
    <title>Inventory</title>
    <style>
        body{font-family:sans-serif}
        td{padding:0 1em 0 1em;}
        td{padding:.5em;}
        th{padding:.5em;text-align:center;}
        tr:nth-child(even){background-color:#ccc;}
        tr:not(:first-child):hover{background-color:#aaa;}
		table{width:100%;}
		.Float{float:left;padding:1em;}
		section:not(.Float){clear:both;padding-top:2em;}
		section h2{text-align:center;}
    </style>
</head>
<body>
"@
            Write-HtmlTable -Title System -Class Float -Object $Input.Hardware.System
			Write-HtmlTable -Title OS -Class Float -Object $Input.Software.OS
			Write-HtmlTable -Title Users -Class Float -Object $Input.Users
            Write-HtmlTable -Title Processor -Class Float -Object $Input.Hardware.Processor
            Write-HtmlTable -Title Memory -Class Float -Object $Input.Hardware.Memory
            Write-HtmlTable -Title Disks -Class Float -Object $Input.Hardware.Disks
            Write-HtmlTable -Title Software -Object $Input.Software.Filtered
            Write-Output @"
</body>
</html>
"@
        }
    }
}

Function Get-Users{
	<#
		Get-Users

		.SYNOPSIS
			Gets the list of usernames from a Windows installation
		.EXAMPLE
			WinPE only. Get the users from an offline Windows installation.

			Get-Users -OSDrive C:
		.EXAMPLE
			Get the users from the currently booted Windows installation

			Get-Users -Online
	#>
	[CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true, ParameterSetName="Offline", Position=0)]
        [ValidatePattern("^[a-z]{1}\:$")]
        [String]$OSDrive,
		[Parameter(Mandatory=$true, ParameterSetName="Online", Position=0)]
		[Switch]$Online
    )

	$BlackList = "Guest","HomeGroupUser$","Administrator","DefaultAccount"

	If( $PSCmdlet.ParameterSetName -eq "Offline" ){
		$MountPath = Get-RegistryHive -Hive "$($OSDrive)\Windows\System32\config\SAM"
		Get-ItemProperty HKLM:\$MountPath\SAM\Domains\Account\Users\Names\*\ |
			Select-Object @{Name='Username'; Expression={$_.PSChildName}} | 
			Where-Object{$_.Username -notin $BlackList}
		Remove-RegistryHive -MountPath $MountPath
	}Else{
		Get-WmiObject Win32_UserAccount |
			Where-Object{ $_.LocalAccount -and $_.Name -notin $BlackList } |
			Select-Object @{Name='Username'; Expression={$_.Name}}
	}
}

<#
	Backup Functions
#>

Function Start-Backup{
	<#
		Start-Backup

		.SYNOPSIS
			Creates WIM images of multiple volumes with a common naming style to a backup directory.
		.EXAMPLE
			Capture a single volume

			Start-Backup -BackupDirectory Z:\Backups\MachineID\ -Volume C:
		.EXAMPLE
			Capture multiple volumes

			Start-Backup -BackupDirectory Z:\Backups\MachineID\ -Volume C:,D:,E:
		.EXAMPLE
			Capture all detected volumes (fixed and assigned, typically what the user sees in My Computer)

			Start-Backup -BackupDirectory Z:\Backups\MachineID\
		.EXAMPLE
			Use the volumes specified in the pipeline

			C:,D:,E: | Start-Backup -BackupDirectory Z:\Backups\MachineID\
		.EXAMPLE
			Use the volumes specified in the pipeline (from command output). This will backup only windows installations.

			Get-WindowsInstallations | Start-Backup -BackupDirectory Z:\Backups\MachineID\
	#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$BackupDirectory,
		[Parameter(ValueFromPipeline=$true,ParameterSetName="VolumeSpecified")]
		[ValidatePattern("^[a-z]{1}\:$")]
		[AllowEmptyString()]
		[Alias("OSDrive")]
		[string[]]$Volume
	)
	Begin{
		If( $PSCmdlet.ParameterSetName -ne "VolumeSpecified" ){
			$Volume = (Get-Volume | Where-Object {$_.DriveType -eq "Fixed" -and $_.DriveLetter} | Select-Object @{Name="DriveLetter";Expression={"$($_.DriveLetter):"}}).DriveLetter
		}
		If( -Not (Test-Path $BackupDirectory) ){
			New-Item -ItemType Directory -Path $BackupDirectory | Out-Null
		}
	}
	Process{
		ForEach ($CurrentVolume in $Volume){
			If( $PSCmdlet.ShouldProcess( $CurrentVolume ) ){
				$PrintableDriveLetter = $CurrentVolume.Substring(0,1)
				$Label = (Get-Volume -DriveLetter $PrintableDriveLetter).FileSystemLabel
				If( -Not $Label ){
					$Label = "NOLABEL"
				}
				#### Should be capturing to C_NOLABEL_YYYYMMDD.wim ####
				$ImagePath = "$BackupDirectory\$($PrintableDriveLetter)_$($Label).wim"
				Write-Verbose "Capturing $CurrentVolume to $ImagePath"
				New-WindowsImage -ImagePath $ImagePath -CapturePath $CurrentVolume -CheckIntegrity -Name "Capture of $Volume - DATE" -Verbose:$false | Out-Null
			}
		}
	}
	End{}
}

Function Restore-Backup{
	<#
		Restore-Backup

		.SYNOPSIS
			Restores WIM files to a computer

		.EXAMPLE
			Restore all volumes (may be lengthy)

			Restore-Backup -BackupDirectory R:\Clients\Test\
		.EXAMPLE
			Restore multipel volumes

			Restore-Backup -BackupDirectory R:\Clients\Test\ -Volume C:,D:,E:
		.EXAMPLE
			Restore a specific volume from a specific image

			Restore-Backup -ImageFile R:\Clients\Test\C_Windows.wim -Volume C:
		.EXAMPLE
			Use the pipeline

			C:,D:,E: | Restore-Backup -BackupDirectory R:\Clients\Test\
		.EXAMPLE
			Use the pipeline (command)

			Get-WindowsInstallations | Restore-Backup -BackupDirectory R:\Clients\Test\
		.EXAMPLE
			Use the pipeline (command)

			Get-WindowsInstallations | Restore-Backup -ImageFile R:\Clients\Test\C_Windows.wim
		
	#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param(
		[Parameter(Mandatory=$true,ParameterSetName="BackupFromDirectory")]
		[string]$BackupDirectory,
		[Parameter(Mandatory=$true,ParameterSetName="BackupFromFile")]
		[string]$ImageFile,
		[ValidatePattern("^[a-z]{1}\:$")]
		[Alias("OSDrive")]
		[string[]]$Volume,
		[int]$Index
	)
	Begin{
		If( -Not (Test-Path -Path $BackupDirectory -PathType Container) ){
			Throw [System.IO.DirectoryNotFoundException]
		}
		If( $PSCmdlet.ParameterSetName -eq "BackupFromFile" -and $Volume.Count -gt 1 ){
			Throw [System.IO.InvalidDataException]
		}
		If( -Not $Volume ){
			$Volume = (Get-Volume | Where-Object {$_.DriveType -eq "Fixed" -and $_.DriveLetter} | Select-Object @{Name="DriveLetter";Expression={"$($_.DriveLetter):"}}).DriveLetter
		}
	}
	Process{
		ForEach( $CurrentVolume in $Volume ){
			$PrintableDriveLetter = $CurrentVolume.Substring(0,1)
			$Label = (Get-Volume -DriveLetter $PrintableDriveLetter).FileSystemLabel
			If( $PSCmdlet.ParameterSetName -eq "BackupFromDirectory" ){
				If( -Not ($ImageFile = (Get-ChildItem $BackupDirectory | Sort-Object Name -Descending | Where-Object {$_.Name -match "^$PrintableDriveLetter"} | Select-Object -First 1).Name)){
					Throw [System.IO.FileNotFoundException]
				}
			}
			If( $PSCmdlet.ShouldProcess( $CurrentVolume, "Restoring $ImageFile" )){
				Format-Volume -DriveLetter $PrintableDriveLetter -Confirm:$false -NewFileSystemLabel $Label | Out-Null
				Expand-WindowsImage -ImagePath "$BackupDirectory\$ImageFile" -Index 1 -ApplyPath $CurrentVolume -CheckIntegrity -Verbose:$false | Out-Null
			}
		}
	}
	End{}
}

Function Restore-UserData{
	<#
		Restore-UserData

		.SYNOPSIS
			Restores user data from a WIM file

		.EXAMPLE
			Restore the files for "Dan"

			Restore-UserData -ImageFile R:\Clients\Test\C_Windows.wim -User Dan
		.EXAMPLE
			Restore the files for "Dan" and "Test"

			Restore-UserData -ImageFile R:\Clients\Test\C_Windows.wim -User Dan,Test
		.EXAMPLE
			Restore the files with users from the pipeline

			"Dan","Test" | Restore-UserData -ImageFile R:\Clients\Test\C_Windows.wim
		.EXAMPLE
			Restore the files for "Dan" to the Windows installation on F:

			Restore-UserData -ImageFile R:\Clients\Test\C_Windows.wim -Volume F: -User Dan
	#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param(
		[Parameter(Mandatory=$true)]
		[string]$ImageFile,
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[string[]]$User,
		[ValidatePattern("^[a-z]{1}\:$")]
		[Alias("OSDrive")]
		[string]$Volume,
		[int]$Index=1
	)
	
	Begin{
		# What profile directories should be restored. Root is %USERPROFILE%
		$Directories = "Documents","Desktop","Downloads","Favorites","Pictures","Videos","Music","APPDATA\Roaming\Mozilla\Firefox","APPDATA\Local\Google\Chrome"
		If( -Not $Volume ){
			$Volume = Get-WindowsInstallations
		}
		If( $PSCmdlet.ShouldProcess( $ImageFile, "Mounting Backup" )){
			New-Item -ItemType Directory "$Volume\RestoreMount" | Out-Null
			Mount-WindowsImage -ImagePath $ImageFile -Path "$Volume\RestoreMount" -Index $Index -Verbose:$false | Out-Null
		}
	}
	
	Process{
		ForEach( $CurrentUser in $User ){
			ForEach( $CurrentDirectory in $Directories ){
				If( $PSCmdlet.ShouldProcess( $CurrentUser, "Restoring $CurrentDirectory" ) ){
					# Copy files from the temporary mount directory (\Users\$CurrentUser\Documents, etc.)
					robocopy /E "$Volume\RestoreMount\Users\$CurrentUser\$CurrentDirectory" "$Volume\Users\$CurrentUser\$CurrentDirectory" > $null
				}
			}
		}
	}
	
	End{
		If( $PSCmdlet.ShouldProcess( $ImageFile, "Dismounting Backup" )){
			Dismount-WindowsImage -Path "$Volume\RestoreMount" -Discard -Verbose:$false | Out-Null
			Remove-Item -Confirm:$false "$Volume\RestoreMount" | Out-Null
		}
	}

}

Function Update-Unattend{
	<#
		Update-Unattend

		.SYNOPSIS
			Updates an Unattend.xml template file with specific data relating to the current machine.
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true,ParameterSetName="FromInventory")]
		$Inventory,
		[string]$UnattendTemplate = "$PSScriptRoot\ReferenceUnattend.xml",
		[Parameter(Mandatory=$true)]
		[ValidatePattern("^[a-z]{1}\:$")]
		[Alias("OSDrive")]
		[string]$Volume
	)
	Begin{}
	Process{
		[xml]$Unattend = Get-Content $UnattendTemplate
		$NameSpace = New-Object System.Xml.XmlNamespaceManager( $Unattend.NameTable )
		$NameSpace.AddNamespace( "ns", $Unattend.DocumentElement.NamespaceURI )
		
		ForEach( $CurrentUser in $Inventory.Users ){
			$Unattend.SelectNodes( "//ns:unattend /ns:settings[@pass='oobeSystem'] /ns:component[@name='Microsoft-Windows-Shell-Setup'] /ns:UserAccounts /ns:LocalAccounts",$NameSpace ) | ForEach-Object {
				$User = $Unattend.CreateElement( "LocalAccount" )
				$User.SetAttribute( "wcm:action", "add" )
				$Password = $Unattend.CreateElement( "Password" )
                $Value = $Unattend.CreateElement( "Value" )
                $Value.InnerText = "UABhAHMAcwB3AG8AcgBkAA=="
                $Password.AppendChild( $Value )
                $PlainText = $Unattend.CreateElement( "PlainText" )
                $PlainText.InnerText = "false"
                $Password.AppendChild( $PlainText )
                $User.AppendChild( $Password )
				$Description = $Unattend.CreateElement( "Description" )
                $Description.InnerText = $Username
                $User.AppendChild( $Description )
				$DisplayName = $Unattend.CreateElement( "DisplayName" )
                $DisplayName.InnerText = $Username
                $User.AppendChild( $DisplayName )
				$Group = $Unattend.CreateElement( "Group" )
                $Group.InnerText = "Administrators"
                $User.AppendChild( $Group )
				$Name = $Unattend.CreateElement( "Name" )
                $Name.InnerText = $Username
                $User.AppendChild( $Name )
				$_.AppendChild( $User )
			}
		}

		$Unattend.Save( "$Volume\Unattend.xml" )
	}
	End{}
}

#Export-ModuleMember -Function Get-Inventory, Get-SoftwareInventory, Get-HardwareInventory, Write-InventoryHtml, Get-WindowsVersion, DriveTest, Get-RegistryHive, Remove-RegistryHive, Get-Users, Get-WindowsProductKey, Get-WindowsInstallations, Start-Backup, Restore-UserData, Restore-Backup