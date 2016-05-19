#requires -version 2
Set-StrictMode -Version 2

#### start common functions ####

Function Get-ErrorMessage() {
<#
   .SYNOPSIS  
   Gets a formatted error message from an error record.
   
   .DESCRIPTION
   Gets a formatted error message from an error record.
  
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [string]

   .PARAMETER ErrorRecord
   A PowerShell ErrorRecord object.
   
   .EXAMPLE
   Get-ErrorMessage -ErrorRecord $_
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The PowerShell error record object to get information from.")]
      [ValidateNotNullOrEmpty()]
      [System.Management.Automation.ErrorRecord]$ErrorRecord
   )
   Process {
      $msg = [System.Environment]::NewLine,"Exception Message: ",$ErrorRecord.Exception.Message -join ""
      
      if($ErrorRecord.Exception.StackTrace -ne $null) {
         $msg = $msg,[System.Environment]::NewLine,"Exception Stacktrace: ",$ErrorRecord.Exception.StackTrace -join ""
      }
      
      if (($ErrorRecord.Exception | gm | Where-Object { $_.Name -eq "WasThrownFromThrowStatement"}) -ne $null) {
         $msg = $msg,[System.Environment]::NewLine,"Explicitly Thrown: ",$ErrorRecord.Exception.WasThrownFromThrowStatement -join ""
      }

      if ($ErrorRecord.Exception.InnerException -ne $null) {
         if ($ErrorRecord.Exception.InnerException.Message -ne $ErrorRecord.Exception.Message) {
            $msg = $msg,[System.Environment]::NewLine,"Inner Exception: ",$ErrorRecord.Exception.InnerException.Message -join ""
         }
      }

      $msg = $msg,[System.Environment]::NewLine,"Call Site: ",$ErrorRecord.InvocationInfo.PositionMessage -join ""
   
      if (($ErrorRecord | gm | Where-Object { $_.Name -eq "ScriptStackTrace"}) -ne $null) {
         $msg = $msg,[System.Environment]::NewLine,"Script Stacktrace: ",$ErrorRecord.ScriptStackTrace -join ""
      }
   
      return $msg
   }
}   

# global exception handler
# note that this does not execute when a script is dot sourced so the file must be run with powershell.exe -File 

trap {
   Set-Content -Path "error.txt" -Value (Get-ErrorMessage -ErrorRecord $_)
   exit -1
}

#### end common functions ####

Function Test-RegistryKey() {
<#
   .SYNOPSIS  
   Tests if a registry key exists.
   
   .DESCRIPTION
   Tests if a registry key exists in the specified hive at the specified path.
   
   .PARAMETER Hive
   The registry hive to check.
   
   .PARAMETER Path
   The path of the registry key to check, not including the hive.
     
   .INPUTS
   None
   
   .OUTPUTS
   [bool]

   .EXAMPLE
   Test-RegistryKey -Hive "hklm" -Path "Software\Microsoft\Windows\CurrentVersion\ProgramFilesDir"

   .EXAMPLE
   Test-RegistryKey "hklm" "Software\Microsoft\Windows\CurrentVersion\ProgramFilesDir"
   #>
   [CmdletBinding()]
   [OutputType([System.Boolean])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The registry hive to check.")]
      [ValidateNotNullOrEmpty()]
      [string]$Hive,
      
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The path of the registry key, not including the hive.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process {
      return (Test-Path -Path ("{0}:\{1}" -f $Hive,$Path) -EA SilentlyContinue)
   }
}

Function Test-RegistryValue() {
<#
   .SYNOPSIS  
   Tests if a registry value exists.
   
   .DESCRIPTION
   Tests if a registry value exists in the specified hive at the specified path.
   
   .PARAMETER Hive
   The registry hive to check.
   
   .PARAMETER Path
   The path of the registry key to check, not including the hive.
   
   .PARAMETER Name
   The name of the registry value to check.
     
   .INPUTS
   None
   
   .OUTPUTS
   [bool]

   .EXAMPLE
   Test-RegistryValue -Hive "hklm" -Path "Software\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir"

   .EXAMPLE
   Test-RegistryValue "hklm" "Software\Microsoft\Windows\CurrentVersion" "ProgramFilesDir"
   #>
   [CmdletBinding()]
   [OutputType([System.Boolean])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The registry hive to check.")]
      [ValidateNotNullOrEmpty()]
      [string]$Hive,
      
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The path of the registry key, not including the hive.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path,
      
      [Parameter(Position=2, Mandatory=$true, HelpMessage="The name of the registry value to check.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name
   )
   Process {
      $exists = $false

      try {
         Get-ItemProperty -Path ("{0}:\{1}" -f $Hive,$Path) -ErrorAction stop | Select-Object -ExpandProperty $Name -ErrorAction stop | Out-Null
         $exists = $true
      } catch [System.Management.Automation.PSArgumentException],[System.Management.Automation.ItemNotFoundException],[System.Management.Automation.ActionPreferenceStopException] {
         $exists = $false
      }

      return $exists
   }
}

Function Get-RegistryValue() {
<#
   .SYNOPSIS  
   Gets a registry value.
   
   .DESCRIPTION
   Gets a registry value in the specified hive at the specified path. Returns null when not found.
   
   .PARAMETER Hive
   The registry hive to get data from.
   
   .PARAMETER Path
   The path of the registry key to get data from, not including the hive.
   
   .PARAMETER Name
   The name of the registry value to to get data from.
     
   .INPUTS
   None
   
   .OUTPUTS
   A dynamic type based on the registry value data type.

   .EXAMPLE
   Get-RegistryValue -Hive "hklm" -Path "Software\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir"

   .EXAMPLE
   Get-RegistryValue "hklm" "Software\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir"
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The registry hive to get data from.")]
      [ValidateNotNullOrEmpty()]
      [string]$Hive,
      
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The path of the registry key to get data from, not including the hive.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path,
      
      [Parameter(Position=2, Mandatory=$true, HelpMessage="The name of the registry value to to get data from.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name
   )
   Process {
      return Get-ItemProperty -Path ("{0}:\{1}" -f $Hive,$Path) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
   }
}

Function New-PatchDefinition() {
<#
   .SYNOPSIS  
   Creates a new patch definition.
   
   .DESCRIPTION
   Creates a new patch definition.
  
   .INPUTS
   None
   
   .OUTPUTS
   [PSObject]
   
   .EXAMPLE
   New-PatchDefinition -ID "ID_NAME" -Name "Penalty name" -Value 1 -Reason "You are getting a small penalty" -Remediation (New-RemediationDefinition -Description "Here is how you fix it"),(New-RemediationDefinition -Description "Here is another way you can fix it")

   .EXAMPLE
   New-PatchDefinition -ID "ID_NAME" -Name "Penalty name" -Value 100 -Reason "You are getting a big penalty" -Remediation (New-RemediationDefinition -Description "This is the only way you can fix it")
   #>
   [CmdletBinding()]
   [OutputType([object])]
   Param(    
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The patch category name.")]
      [AllowEmptyString()]
      [string]$Category = "",
      
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The patch identifier.")]
      [ValidateNotNullOrEmpty()]
      [string]$ID,
      
      [Parameter(Position=2, Mandatory=$true, HelpMessage="The date the patch was installed.")]
      [ValidateNotNullOrEmpty()]
      [DateTime]$InstallDate
   )  
   Process {
      $p = @{}
   
      $p.Category = $Category
      $p.ID = $ID
      $p.InstallDate = $InstallDate

      $patch = New-Object -TypeName PSObject -Prop $p
      return $patch
   }
}

Function Get-InstallDate() {
   [CmdletBinding()]
   [OutputType([System.DateTime])]
   Param()
   Process {
      $installDate = [System.DateTime]::MaxValue

      $hive = "HKLM"
      $keyName = "Software\Microsoft\Windows NT\CurrentVersion"
      $valueName = "InstallDate"

      if(Test-RegistryKey -Hive $hive -Path $keyName) {
         if(Test-RegistryValue -Hive $hive -Path $keyName -Name $valueName) {
            $unixSeconds = Get-RegistryValue -Hive $hive -Path $keyName -Name $valueName

            $unixDate = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0

            $installDate = $unixDate.AddSeconds($unixSeconds).ToLocalTime()
         }
      }
      return $installDate
   }
}

Function Get-Patches() {
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[psobject]])]
   Param()
   Process {
      $culture = New-Object System.Globalization.CultureInfo "en-US"

      $patches = New-Object System.Collections.Generic.List[psobject]

      $fixes = Get-WmiObject -Class "Win32_QuickFixEngineering"

      $fixes| ForEach {
         $date = [DateTime]::MaxValue

         $value = [string]($_.PSBase.Properties["InstalledOn"].Value)

         if($value.Contains("/")) { # Windows 7 and later
            $date = [DateTime]::ParseExact($value, "M/d/yyyy", $culture)
         } else {
            if($value.Length -eq 8) { # Windows Vista has some of these but this is more common on XP and Server 2003. The HotfixId property will be a GUID
               $date = [System.DateTime]::ParseExact($value, "yyyyMMdd", $culture)
            } elseif($value.Length -gt 8) { # Windows Vista and earlier
               $value = ("0x{0}" -f $value)
               $date = [DateTime]::FromFileTimeUTC([System.Int64]$value)
            }
         }
         
         $category = "Unknown"
         
         if(-not([string]::IsNullOrEmpty($_.Description))) {
            $category = $_.Description
         }
         
         # some IDs that aren't GUIDs are still missing the "KB" text at the beginning
         $patch = New-PatchDefinition -Category $category -ID $_.HotFixID -InstallDate $date
         $patches.Add($patch)
      }

      # add the install date so we can use that in the analyzer to filter out a weird case
      # we saw some instances of patches being reported as being installed before the OS was

      $installDate = Get-InstallDate

      if(($installDate -ne [System.DateTime]::MaxValue)) {
         $patches.Add((New-PatchDefinition -Category "Install Date" -ID "KB12345678" -InstallDate $installDate))
      }

      return ,$patches
   }
}


Function Invoke-Survey() {
<#
   .SYNOPSIS
   Main method for running the survey.

   .DESCRIPTION
   Main method for running the survey.

   .PARAMETER Architecture
   The path of a file to write to.

   .INPUTS
   None

   .OUTPUTS
   None

   .EXAMPLE
   Invoke-Survey -Path "ll_osph.csv"
#>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of a file to write to.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process {
      if(Test-Path -Path $Path -Type Leaf) {
         Remove-Item -Path $Path -Force -ErrorAction Stop
      }

      $patches = Get-Patches

      # output has an extra line break at end
      if($patches.Count -eq 0 ) {
          "" | Add-Content -Path $Path
      } else {
         $patches | Sort-Object InstallDate | ForEach -Process { ("{0},{1},{2}" -f $_.Category,$_.ID,$_.InstallDate) | Add-Content -Path $Path}
      }
   }
}

Invoke-Survey -Path "ll_osph.csv"
#Invoke-Survey -Path (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\ll_osph.csv")