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

Function Get-ServiceState() {
<#
   .SYNOPSIS  
   Gets the run state of a Windows service.
   
   .DESCRIPTION
   Gets the run state of a Windows service for a specific Windows service name.

   .PARAMETER Name
   The Windows service name.
     
   .INPUTS
   None
   
   .OUTPUTS
   [bool]
   
   .EXAMPLE
   Get-ServiceState -Name "ServiceName"
   #>
   [CmdletBinding()]
   [OutputType([System.Boolean])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The Windows service name.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name
   )
   Process {
      $state = "Unknown"
     
      $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
      
      if($service -ne $null) {
         $state = [string]$service.Status
      }

      return $state
   }
}

Function Test-ServiceState() {
<#
   .SYNOPSIS  
   Tests the run state of a Windows service.
   
   .DESCRIPTION
   Tests the run state of a Windows service against a specific run state for a specific Windows service name.

   .PARAMETER Name
   The Windows service name.

   .PARAMETER State
   The service run state to test for.
     
   .INPUTS
   None
   
   .OUTPUTS
   [bool]
   
   .EXAMPLE
   Test-ServiceState -Name "ServiceName" -State "Running" 
   #>
   [CmdletBinding()]
   [OutputType([System.Boolean])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The Windows service name.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name,
      
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The run state to test for.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("Running","Stopped","ContinuePending","Paused","PausePending","StartPending","StopPending", IgnoreCase=$true)] # See System.ServiceProcess.ServiceControllerStatus enum
      [string]$State     
   )
   Process {
      $currentState = Get-ServiceState -Name $Name
          
      return $currentState -ieq $State
   }
}

Function Get-ServiceStart() {
<#
   .SYNOPSIS  
   Gets the start mode of a Windows service.
   
   .DESCRIPTION
   Gets the start mode of a Windows service for a specific Windows service name.

   .PARAMETER Name
   The Windows service name.
     
   .INPUTS
   None
   
   .OUTPUTS
   [bool]
   
   .EXAMPLE
   Get-ServiceStart -Name "ServiceName"
   #>
   [CmdletBinding()]
   [OutputType([System.Boolean])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The Windows service name.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name
   )
   Process {
      $start = "Unknown"

      $service = Get-WmiObject -Class "Win32_Service" -Filter ("Name='{0}'" -f $Name)

      if($service -ne $null) {
         $start = $service.StartMode
      }

      return $start
   }
}

Function Test-ServiceStart() {
<#
   .SYNOPSIS  
   Tests the start mode of a Windows service.
   
   .DESCRIPTION
   Gets the start mode of a Windows service against a specific start mode for a specific Windows service name.

   .PARAMETER Name
   The Windows service name.

   .PARAMETER Start
   The service start mode to test for.
     
   .INPUTS
   None
   
   .OUTPUTS
   [bool]
   
   .EXAMPLE
   Test-ServiceStart -Name "ServiceName" -Start "Auto" 
   #>
   [CmdletBinding()]
   [OutputType([System.Boolean])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The Windows service name.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name,
      
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The service start mode to test for.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("Auto","Manual","Disabled",IgnoreCase=$true)]
      [string]$Start     
   )
   Process {
      $currentStart = Get-ServiceStart -Name $Name
          
      return $currentStart -ieq $Start
   }
}

Function Get-Architecture() {
<#
   .SYNOPSIS  
   Gets the operating system architecture.
   
   .DESCRIPTION
   Gets the operating system architecture.
     
   .INPUTS
   None
   
   .OUTPUTS
   [UInt32]
   
   .EXAMPLE
   Get-Architecture  
   #>
   [CmdletBinding()]
   [OutputType([System.UInt32])]
   Param()
   Process {
      $arch = 32

      $os = Get-WmiObject -Class "Win32_OperatingSystem" -Filter "Primary=true" |Select-Object OSArchitecture

      if ($os.OSArchitecture -match "64") {
         $arch = 64
      }

      return $arch
   }
}

Function Get-HIPSDirectoryPath() {
<#
   .SYNOPSIS  
   Gets the path of the base folder where HIPS is installed.
   
   .DESCRIPTION
   Gets the path of the base folder where HIPS is installed.

   .PARAMETER Architecture
   The operating system architecture.
     
   .INPUTS
   None
   
   .OUTPUTS
   [string]
   
   .EXAMPLE
   Get-HIPSDirectoryPath  
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The operating system architecture.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet(32,64)]
      [UInt32]$Architecture
   )
   Process {
      $path = Join-Path -Path $env:ProgramFiles -ChildPath "McAfee\Host Intrusion Prevention"

      # turns out it isn't uncommon to find only the x86 version installed on an x64 system so only use the x86 file path
      #if ($Architecture -eq 64) {
      #   $path = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "McAfee\Host Intrusion Prevention"
      #}

      return $path
   }
}

Function Get-HIPSRegistryPath() {
<#
   .SYNOPSIS  
   Gets the path of the base registry key where HIPS has its registry information. The path does not include the hive.
   
   .DESCRIPTION
   Gets the path of the base registry key where HIPS has its registry information. The path does not include the hive.
     
   .INPUTS
   None
   
   .OUTPUTS
   [string]
   
   .EXAMPLE
   Get-HIPSRegistryPath  
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The operating system architecture.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet(32,64)]
      [UInt32]$Architecture
   )
   Process {
      $path = "Software\McAfee\HIP"

      if ($Architecture -eq 64) {
         $path = "Software\Wow6432Node\McAfee\HIP"
      }

      return $path
   }
}

Function Test-HIPSInstalled() {
<#
   .SYNOPSIS  
   Tests whether or not HIPS is installed on the system.
   
   .DESCRIPTION
   Tests whether or not HIPS is installed on the system.

   .PARAMETER Architecture
   The operating system architecture.
     
   .INPUTS
   None
   
   .OUTPUTS
   [bool]
   
   .EXAMPLE
   Test-HIPSInstalled  
   #>
   [CmdletBinding()]
   [OutputType([System.Boolean])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The operating system architecture.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet(32,64)]
      [UInt32]$Architecture
   )
   Process {
      $regPath = Get-HIPSRegistryPath -Architecture $Architecture
      $dirPath = Get-HIPSDirectoryPath -Architecture $Architecture
      $filePath = Join-Path -Path $dirPath  -ChildPath "HcApi.dll"


      if($Architecture -eq 64) {
         $regPath = Get-HIPSRegistryPath -Architecture $Architecture
         # turns out it isn't uncommon to find only the x86 version installed on an x64 system so only use the x86 file path
         #$filePath = Join-Path -Path (Get-HIPSDirectoryPath -Architecture $Architecture) -ChildPath "X64\HcApi.dll"
      }

      $fileExists = Test-Path -Path $filePath
      $registryExists = Test-RegistryValue -Hive "HKLM" -Path $regPath -Name "State"

      if($registryExists -and -not($fileExists)) {
         $fileExists = (Get-ChildItem -Path $dirPath -Filter "HcApi.dll" -Recurse -Force -ErrorAction SilentlyContinue) -ne $null
      }

      return ($fileExists -and $registryExists)   
   }  
} 

Function Get-HIPSProperties() {
<#
   .SYNOPSIS  
   Gets the HIPS information from the system that is being surveyed for potential scoring.
   
   .DESCRIPTION
   Gets the HIPS information from the system that is being surveyed for potential scoring.
     
   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Hashtable]
   
   .EXAMPLE
   Get-HIPSProperties  
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Hashtable])]
   Param()
   Process {
      $properties = @{}

      $architecture = Get-Architecture

      $isInstalled = Test-HIPSInstalled -Architecture $architecture
      $properties.Add("installed", $isInstalled) # insert the value as lower case so we don't care about case in the analyzer

      if($isInstalled) {
         $registryPath = Get-HIPSRegistryPath -Architecture $architecture

         $serviceStart = Get-ServiceStart -Name "enterceptAgent"
         $properties.Add("hipsservicestartmode", $serviceStart) # insert the value as lower case so we don't care about case in the analyzer

         $serviceState = Get-ServiceState -Name "enterceptAgent"
         $properties.Add("hipsservicerunstate", $serviceState) # insert the value as lower case so we don't care about case in the analyzer

         # key = Registry value name
         # value = Registry key **sub path** under the base HIPS registry key path
         $values = @{ "State"=$null; "LastEnabledStateHips"=$null ; "Patch"=$null; "ContentVersion"=$null; "ContentCreated"=$null; "Version"=$null; "CreatedDate"=$null; "Fixes"=$null; "PreventHigh"="CounterMeasures"; "PreventMedium"="CounterMeasures"; "PreventLow"="CounterMeasures"; "IPS_AuditModeEnabled"="Config\Settings"; "IPS_HipsEnabled"="Config\Settings"; "IPS_ReactionForHigh"="Config\Settings" ; "IPS_ReactionForMedium"="Config\Settings"; "IPS_ReactionForLow"="Config\Settings"; "IPS_ReactionForInfo"="Config\Settings"; "Client_LastPolicyEnforcementTime"="Config\Settings"}
       
         $values.GetEnumerator() | ForEach -Process {
            $valueName = $_.Key
            $registrySubPath = $_.Value

            if($registrySubPath -eq $null) {
               $fullPath = $registryPath
            } else {
               $fullPath = Join-Path -Path $registryPath -ChildPath $registrySubPath
            }

            if(Test-RegistryKey -Hive "HKLM" -Path $fullPath) {
               if(Test-RegistryValue -Hive "HKLM" -Path $fullPath -Name $valueName) {
                  $valueData = Get-RegistryValue -Hive "HKLM" -Path $fullPath -Name $valueName
                  $properties.Add($valueName.ToLower(), $valueData) # insert the value as lower case so we don't care about case in the analyzer
               } else {
                  Write-Verbose -Message ("Registry Value Name '{0}' at Path '{1}\{2}' did not exist" -f $valueName,"HKLM",$fullPath)
               }
            } else {
               Write-Verbose -Message ("Registry Path '{0}\{1}' did not exist" -f "HKLM",$fullPath)
            }
         }
      }

      return $properties
   }
}

Function Invoke-Survey() {
<#
   .SYNOPSIS  
   Main method for running the survey
   
   .DESCRIPTION
   Main method for running the survey

   .PARAMETER Architecture
   The path of a file to write to.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   Invoke-Survey -Path "ll_hbss.txt"
   #>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of a file to write to.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path   
   )
   Process {
      $properties = Get-HIPSProperties
      
      if(Test-Path -Path $Path -Type Leaf) {
         Remove-Item -Path $Path -Force -ErrorAction Stop 
      }
      
      # output has an extra line break at end
      $properties.GetEnumerator() | Sort-Object Name | ForEach -Process {  ("{0}={1}" -f $_.Key,$_.Value) | Add-Content -Path $Path}
   }
}

Invoke-Survey -Path "ll_hbss.txt"
#Invoke-Survey -Path (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\ll_hbss.txt")