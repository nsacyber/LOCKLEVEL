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

      $temp = Get-ItemProperty -Path ("{0}:\{1}" -f $Hive,$Path) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
      return $temp -ne $null
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

Function New-Configuration() {
<#
   .SYNOPSIS  
   Creates a new whitelisting policy configuration definition.
   
   .DESCRIPTION
   Creates a new whitelisting policy configuration definition.

   .PARAMETER Policy
   The type of policy the configuration represents.

   .PARAMETER Properties
   A dictionary of properties and their values associated with the configuration.

   .PARAMETER RuleSets
   The list of rulesets associated with the configuration.
  
   .INPUTS
   None
   
   .OUTPUTS
   [PSObject]
   
   .EXAMPLE
   New-Configuration -Product "SRP" -Policy "User" -Properties $properties -RuleSets $rules
   #>
   [CmdletBinding()]
   [OutputType([psobject])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The product that the configuration represents.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("SRP","AppLocker",IgnoreCase=$true)]
      [string]$Product,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The type of policy the configuration represents.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("User","Machine",IgnoreCase=$true)]
      [string]$Policy,
     
      [Parameter(Position=2, Mandatory=$true, HelpMessage="A dictionary of properties and their values associated with the configuration.")]
      [ValidateNotNullOrEmpty()]    
      [System.Collections.Hashtable]$Properties,
      
      [Parameter(Position=3, Mandatory=$true, HelpMessage="The list of rulesets associated with the configuration.")]
      [ValidateNotNullOrEmpty()]    
      [object[]]$RuleSets
   )
   Process {
      $c = @{}

      $c.Product = $Product
      $c.Policy = $Policy 
      $c.Properties = $Properties
      $c.RuleSets = $RuleSets

      $config = New-Object -TypeName PSObject -Prop $c
      return $config
   }
}

Function New-Rule() {
<#
   .SYNOPSIS  
   Creates a new whitelisting rule definition.
   
   .DESCRIPTION
   Creates a new whitelisting rule definition.

   .PARAMETER Category
   The category the rule belongs to.

   .PARAMETER Guid
   The rule GUID.

   .PARAMETER Description
   The rule description.

   .PARAMETER RawData
   The unparsed rule data.

   .PARAMETER Data
   The parsed rule data with some environment variables and SIDs resolved.

   .PARAMETER Flags
   The rule flags.

   .INPUTS
   None
   
   .OUTPUTS
   [PSObject]
   
   .EXAMPLE
   New-Rule -Category "Category" -GUID $guid -Description "Desc" -RawData "Raw" -Data "Data" -Flags 1
   #>
   [CmdletBinding()]
   [OutputType([psobject])]
   Param(   
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The category the rule belongs to.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("Appx","Dll","Exe","Msi","Script","Paths","Hashes","UrlZones",IgnoreCase=$true)]
      [string]$Category,
       
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The rule GUID.")]
      [ValidateNotNullOrEmpty()]
      [System.Guid]$GUID,
 
      [Parameter(Position=2, Mandatory=$true, HelpMessage="The rule description.")]
      [AllowEmptyString()]
      [string]$Description,
      
      [Parameter(Position=3, Mandatory=$true, HelpMessage="The unparsed rule data.")]
      [ValidateNotNullOrEmpty()]      
      [string]$RawData,
      
      [Parameter(Position=4, Mandatory=$true, HelpMessage="The parsed rule data with some environment variables and SIDs resolved.")]
      [ValidateNotNullOrEmpty()]      
      [string]$Data,
      
      [Parameter(Position=5, Mandatory=$false, HelpMessage="The rule flags.")]
      [ValidateNotNullOrEmpty()]      
      [UInt32]$Flags = 0 
   )
   Process {
      $r = @{}
   
      $r.Category = $Category
      $r.GUID = $GUID
      $r.Description = if ($Description -ieq "") { $null } else { $Description }
      $r.RawData = $RawData
      $r.Data = $Data
      $r.Flags = $Flags

      $rule = New-Object -TypeName PSObject -Prop $r
      return $rule
   }
}

Function New-RuleSet() {
<#
   .SYNOPSIS  
   Creates a new whitelisting policy ruleset definition.
   
   .DESCRIPTION
   Creates a new whitelisting policy ruleset definition.

   .PARAMETER Category
   The category the rule belongs to.

   .PARAMETER Configured
   Whether ruleset is configured.

   .PARAMETER Enforced
   Whether ruleset is enforced.

   .PARAMETER Rules
   The rules definition for the ruleset.
  
   .INPUTS
   None
   
   .OUTPUTS
   [PSObject]
   
   .EXAMPLE
   New-RuleSet -Category "RuleType" -Configured $true -Enforced $true -Rules $rules
   #>
   [CmdletBinding()]
   [OutputType([psobject])]
   Param(   
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The category the rule belongs to.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("Appx","Dll","Exe","Msi","Script","Disallowed","Unrestricted","Normal",IgnoreCase=$true)]
      [string]$Category,
      
      [Parameter(Position=1, Mandatory=$false, HelpMessage="Whether ruleset is configured.")]
      [ValidateNotNullOrEmpty()]
      [bool]$Configured = $false,
      
      [Parameter(Position=2, Mandatory=$false, HelpMessage="Whether ruleset is enforced.")]
      [ValidateNotNullOrEmpty()]
      [bool]$Enforced = $false,
      
      [Parameter(Position=3, Mandatory=$false, HelpMessage="The rules definition for the ruleset.")]
      [AllowEmptyCollection()]    
      [psobject[]]$Rules = [psobject[]]@()
   )
   Process {
      $rs = @{}

      $rs.Category = $Category
      $rs.Configured = $Configured
      $rs.Enforced = $Enforced
      $rs.Rules = $Rules
      
      $ruleSet = New-Object -TypeName PSObject -Prop $rs
      return $ruleSet
   }
}

Function Get-SrpLevelName() {
<#
   .SYNOPSIS  
   Gets a SRP level name based on its integer value.
   
   .DESCRIPTION
   Gets a SRP level name based on its integer value.

   .PARAMETER Value
   The integer value of the SRP level.
 
   .INPUTS
   None
   
   .OUTPUTS
   [string]
   
   .EXAMPLE
   Get-SrpLevelName -Value 131072
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The integer value of the SRP level.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet(0,4096,65536,131072,262144,IgnoreCase=$true)]   
      [UInt32]$Value
   )
   Process {
      $name = "Unknown"

      switch($Value) {
         262144 { $name="Unrestricted" ; break } # UI
         131072 { $name="Normal" ; break } # UI = Basic User
          65536 { $name="Constrained" ; break }
           4096 { $name="Untrusted" ; break }
              0 { $name="Disallowed" ; break } # UI
        default { $name = "Unknown" ; break}
      }

      return $Name
   }
}

Function Get-ExpandedSrpRule() {
<#
   .SYNOPSIS  
   Expands certain values in a SRP rule.
   
   .DESCRIPTION
   Expands certain values, such as environment variables, in a SRP rule.

   .PARAMETER Value
   The rule value to expand.
 
   .INPUTS
   None
   
   .OUTPUTS
   [string]
   
   .EXAMPLE
   Get-ExpandedSrpRule -Value "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir (x86)%"

   .EXAMPLE
   Get-ExpandedSrpRule -Value "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32"
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The rule value to expand.")]
      [ValidateNotNullOrEmpty()]
      [string]$Value   
   )
   Process {
      $expandedValue = $Value
             
      $firstPercent = $expandedValue.IndexOf("%")
      $lastPercent = $expandedValue.LastIndexOf("%")
               
      # check if we need to expand long form environment rules supported by SRP into their real values:
      #%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir (x86)% = %ProgramFilesDir (x86)% = C:\Program Files (x86)
      #%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot% = %SystemRoot% = C:\Windows
      #%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32 = %SystemRoot%\System32 = C:\Windows\System32\
               
      if(($firstPercent -ge 0) -and ($lastPercent -gt 0) -and ($firstPercent -ne $lastPercent)) {
         $valuePath = $expandedValue[($firstPercent+1)..($lastPercent-1)] -join ""
                  
         $valueIndex = $valuePath.LastIndexOf("\")
                 
         $valueName = $valuePath[($valueIndex+1)..($valuePath.Length-1)] -join ""
                  
         $keyPath = $valuePath[0..($valueIndex-1)] -join ""
         $keyPath = $keyPath.Replace("HKEY_LOCAL_MACHINE","")
                  
         if(Test-RegistryValue -Hive "HKLM" -Path $keyPath -Name $valueName) {
            $resolvedValue = Get-RegistryValue -Hive "HKLM" -Path $keyPath -Name $valueName
                     
            if($expandedValue.EndsWith("%")) {
               $expandedValue = $resolvedValue
            } else { 
               $expandedValue = Join-Path -Path $resolvedValue -ChildPath ($expandedValue[($lastPercent+1)..($expandedValue.Length-1)] -join "")
            }
         }
         # else { $expandedValue = "" }
      }
      
      return $expandedValue
   }
}

Function Get-SrpProperties() {
<#
   .SYNOPSIS  
   Gets SRP properties.
   
   .DESCRIPTION
   Gets SRP properties from the registry.

   .PARAMETER Path
   The registry path.
 
   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Hashtable]
   
   .EXAMPLE
   Get-SrpProperties -Path "hklm:\software\policies\microsoft\windows\safer\codeidentifiers"

   .EXAMPLE
   Get-SrpProperties -Path "hkcu:\software\policies\microsoft\windows\safer\codeidentifiers"
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Hashtable])]
   Param (
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The registry path.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path  
   )
   Process {
      $config = Get-Item $Path | Get-ItemProperty -Name "AuthenticodeEnabled","DefaultLevel","ExecutableTypes","PolicyScope","TransparentEnabled" -ErrorAction SilentlyContinue 
                          
      $properties = @{"AuthenticodeEnabled"=[UInt32]::MaxValue; "DefaultLevel"=[UInt32]::MaxValue; "ExecutableTypes"=""; "PolicyScope"=[UInt32]::MaxValue; "TransparentEnabled"=[UInt32]::MaxValue}
    
      $config | gm -MemberType "NoteProperty" | Where-Object { -not($_.Name.StartsWith("PS")) } | ForEach { # just to be safe, make sure we excluded any PowerShell default properties. PSPath,PSChildName,PSParentPath,etc
         if($properties.ContainsKey($_.Name)) {
            $properties[$_.Name] = $config.($_.Name)
         }
      }

      return $properties
   }
}

Function Get-SrpConfiguration() {
<#
   .SYNOPSIS  
   Creates a new SRP configuration.
   
   .DESCRIPTION
   Creates a new SRP configuration.

   .PARAMETER Policy
   The type of policy the configuration is part of.
 
   .INPUTS
   None
   
   .OUTPUTS
   [PSObject]
   
   .EXAMPLE
   Get-SrpConfiguration -Policy "User"
   #>
   [CmdletBinding()]
   [OutputType([psobject])]
   Param (
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The type of policy the configuration is part of.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("User","Machine",IgnoreCase=$true)]
      [string]$Policy   
   )
   Process {
      $srpPath = "hklm:\software\policies\microsoft\windows\safer\codeidentifiers"

      if($Policy -ieq "User") {
         $srpPath = "hkcu:\software\policies\microsoft\windows\safer\codeidentifiers"
      }

      $srpRuleSets = New-Object System.Collections.Generic.List[psobject]

      Get-ChildItem -Path $srpPath | ForEach { 
         $parts = $_.Name.Split("\")
         $ruleSetKey = $parts[$parts.Length-1]
         $ruleSetName = Get-SrpLevelName -Value $ruleSetKey

         $srpRules = New-Object System.Collections.Generic.List[psobject]
         
         # this filters out hash rules' additional subkey named SHA256Hashes that has an ItemData registry value. the parent level key and registry values are still captured though
         $rules = Get-ChildItem -Path (Join-Path -Path $srpPath -ChildPath $ruleSetKey) -Recurse | Where-Object { $_.PSChildName.StartsWith("{") -and $_.PSChildName.EndsWith("}") } | Get-ItemProperty -Name "Description","ItemData","SaferFlags" -ErrorAction SilentlyContinue  | ForEach {           
            $parts = $_.PSParentPath.Split("\")
            $ruleType = $parts[$parts.Length-1]
            
            if(($_ | gm -MemberType "NoteProperty" | Where-Object {$_.Name -eq "Description"}) -ne $null) { #URLZone rules don't have a Description registry value
               $desc = $_.Description 
            } else { 
               $desc = ""
            }

            if ($_.ItemData -is [string]) {
               $keyPath = $_.PSPath.Replace((([string]$_.PSProvider),"::HKEY_LOCAL_MACHINE" -join ""),"hklm:")

               # if ItemData contains an environment variable, then it is expanded by default so %USERDOMAIN% in a rule ends up being read as the real domain value
               $unexpandedValue = (Get-Item $keyPath).GetValue("ItemData", $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)

               # still need to expanded SRP rules that use SRP-style environment variables, $_.ItemData will expand to the real value by default for normal (non-SRP) environment variables
               $expandedValue = Get-ExpandedSrpRule -Value $_.ItemData 
            } elseif ($_.ItemData -is [byte[]]) {
               $unexpandedValue = $_.ItemData -join " "
               $expandedValue = @($_.ItemData | ForEach {"{0:X2}" -f $_ }) -join ""
            } else {
               $unexpandedValue = $_.ItemData
               $expandedValue = $_.ItemData             
            }

            #$isInert = ($_.SaferFlags -band 0x20000) -eq 0x20000
            #$isAudit = ($_.SaferFlags -band 0x1000) -eq 0x1000
            #$enforced = -not($isInert -or $isAudit) for every rule
            $rule = New-Rule -Category $ruleType -GUID $_.PSChildName -Description $desc -RawData $unexpandedValue -Data $expandedValue -Flags $_.SaferFlags

            $srpRules.Add($rule) 
         }
         
         #Configured - any guid keys below the path?
         #Enforced - all items have no SaferFlags of 0x1000 or 0x20000
         
         # | Where-Object { ([System.Array]::IndexOf($_.Property, "SaferFlags") -ge 0) }
         
         if($srpRules.Count -gt 0) {
            $ruleSet = New-RuleSet -Category $ruleSetName -Configured $true -Enforced $true -Rules $srpRules
         } else {
            $ruleSet = New-RuleSet -Category $ruleSetName -Configured $true -Enforced $true
         }    
         
         if($ruleSet -ne $null) {
            $srpRuleSets.Add($ruleSet)
         }      
      }
             
      $properties = Get-SrpProperties -Path $srpPath
                 
      $srpConfig = New-Configuration -Product "SRP" -Policy $Policy -Properties $properties -RuleSets $srpRuleSets 

      return $srpConfig     
   }
}
            
Function Get-ExpandedAppLockerRule() {
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The .")]
      [ValidateNotNullOrEmpty()]
      [string]$Value    
   )
   Process {
      $xml = [xml]$Value
         
      $rootName = $xml.DocumentElement.LocalName
      $sidValue = $xml.$rootName.UserOrGroupSid
         
      $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
      $sidName = ($sid.Translate([System.Security.Principal.NTAccount])).Value
      #Write-Host $rootName ($xml.$rootName.Id) ($xml.$rootName.Name) ($xml.$rootName.Description) ($xml.$rootName.Action) $sidName
      # expand SID into real user or group name
      $expandedValue = $Value.Replace($sidValue,$sidName)
       
      # expand known environment variables into real paths
      Get-ChildItem env: | ForEach { 
         $variable = "%",$_.Key.ToUpper(),"%" -join ""
          
         if ($expandedValue.ToUpper().Contains($variable)) {
            $expandedValue = [System.Text.RegularExpressions.Regex]::Replace($expandedValue,$variable,$_.Value,[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
         }
      }
       
      return $expandedValue
   }
}

Function Get-AppLockerProperties() {
<#
   .SYNOPSIS  
   Gets AppLocker properties.
   
   .DESCRIPTION
   Gets AppLocker properties from the system.

   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Hashtable]
   
   .EXAMPLE
   Get-AppLockerProperties 
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Hashtable])]
   Param()
   Process {                       
      $properties = @{}
      
      $serviceState = Get-ServiceState -Name "AppIDSvc"
      $properties.Add("ServiceState",$serviceState)

      $serviceStart = Get-ServiceStart -Name "AppIDSvc"
      $properties.Add("ServiceStart",$serviceStart)

      return $properties
   }
}

Function Get-AppLockerConfiguration() {
   [CmdletBinding()]
   [OutputType([psobject])]
   Param()
   Process {
      $appLockerRuleSets = New-Object System.Collections.Generic.List[psobject]

      $ruleSet = $null

      Get-ChildItem -Path "hklm:\Software\Policies\Microsoft\Windows\SrpV2" | ForEach { 
         $parts = $_.Name.Split("\")
         $ruleSetName = $parts[$parts.Length-1]
         $ruleSetConfigured = [System.Array]::IndexOf($_.Property,"EnforcementMode") -ge 0 # rule set doesn't do anything if EnforcementMode value doesn't exist

         $appLockerRules = New-Object System.Collections.Generic.List[psobject]          

         if($ruleSetConfigured) {
            $ruleSetEnforced = $_.GetValue("EnforcementMode") -eq 1

            $rules = Get-ChildItem -Path (Join-Path -Path "hklm:\Software\Policies\Microsoft\Windows\SrpV2" -ChildPath $ruleSetName) -Recurse | Get-ItemProperty -Name "Value" -ErrorAction SilentlyContinue | ForEach {
               $rule = New-Rule -Category $ruleSetName -GUID $_.PSChildName -Description "" -RawData $_.Value -Data (Get-ExpandedAppLockerRule -Value $_.Value)
               
               $appLockerRules.Add($rule) 
            }

            if($appLockerRules.Count -gt 0) {
               $ruleSet = New-RuleSet -Category $ruleSetName -Configured $ruleSetConfigured -Enforced $ruleSetEnforced -Rules $appLockerRules
            } else {
               $ruleSet = New-RuleSet -Category $ruleSetName -Configured $ruleSetConfigured -Enforced $ruleSetEnforced
            }            
         } else {
            $ruleSet = New-RuleSet -Category $ruleSetName -Configured $ruleSetConfigured -Enforced $false 
         }

         if($ruleSet -ne $null) {
            $appLockerRuleSets.Add($ruleSet)
         }
      }

      $properties = Get-AppLockerProperties
       
      $appLockerConfig = New-Configuration -Product "AppLocker" -Policy "Machine" -Properties $properties -RuleSets $appLockerRuleSets
      
      return $appLockerConfig
   }
}

Function New-Xml() {
<#
   .SYNOPSIS  
   Creates the XML document representating the survey data.
   
   .DESCRIPTION
   Creates the XML document representating the survey data.

   .PARAMETER Configurations 
   The whitelisting configurations.

   .PARAMETER Path 
   "The path of a file to write to.
    
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   New-Xml -Configurations @($srp,$applocker) -Path "C:\result.xml"
   #>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$false, HelpMessage="The whitelisting configurations.")]
      [AllowEmptyCollection()]
      [psobject[]]$Configurations,
     
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The path of a file to write to.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
      
   )
   Process {
      if(Test-Path -Path $Path -PathType Leaf) {
         Remove-Item -Path $Path -Force -ErrorAction Stop | Out-Null
      }

      $xmlDoc = New-Object System.Xml.XmlDocument

      [void]$xmlDoc.AppendChild($xmlDoc.CreateXmlDeclaration("1.0", "UTF-8", $null))
      
      $awElement = $xmlDoc.CreateElement("AW");
      [void]$xmlDoc.AppendChild($awElement)
      
      $accountElement = $xmlDoc.CreateElement("Account");
      $accountElement.InnerText = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
      
      [void]$xmlDoc.DocumentElement.AppendChild($accountElement)
      
      $envsElement = $xmlDoc.CreateElement("Environment");
      
      Get-ChildItem env: | ForEach { 
         $envElement = $xmlDoc.CreateElement("Variable");
         $envElement.SetAttribute("Name", $_.Key)
         $envElement.InnerText = $_.Value
         [void]$envsElement.AppendChild($envElement) 
      }

      [void]$xmlDoc.DocumentElement.AppendChild($envsElement)

      #might want to add a list of hard drives Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" (maybe "DriveType=3 or DriveType=4") 


      # might want to put the rest inside an if($Configurations.Count -gt ) block
      # right now this will write out an empy Configurations element when no supporting whitelisting product is found
      
      $confsElement = $xmlDoc.CreateElement("Configurations");
      
      $Configurations | ForEach {
         $product = $_.Product
         $confElement = $xmlDoc.CreateElement("Configuration");
         $confElement.SetAttribute("Product", $_.Product)
         $confElement.SetAttribute("PolicyType", $_.Policy)
            
         $propsElement = $xmlDoc.CreateElement("Properties");
            
         $_.Properties.GetEnumerator() | ForEach {
            $propElement = $xmlDoc.CreateElement("Property");
            $propElement.SetAttribute("Name", $_.Key)
            $propElement.InnerText = $_.Value
            [void]$propsElement.AppendChild($propElement)
         }
            
         [void]$confElement.AppendChild($propsElement)
                    
         $ruleSetsElement = $xmlDoc.CreateElement("RuleSets")
         
         $_.RuleSets | ForEach {
            $ruleSetElement = $xmlDoc.CreateElement("RuleSet")
            $ruleSetElement.SetAttribute("Name", $_.Category)

            if($product -ieq "AppLocker") {
               $ruleSetElement.SetAttribute("Configured", $_.Configured)
               $ruleSetElement.SetAttribute("Enforced", $_.Enforced)
            }
              
            $_.Rules | ForEach {
               $ruleElement = $xmlDoc.CreateElement("Rule")
               $ruleElement.SetAttribute("Type", $_.Category)
               $ruleElement.SetAttribute("Guid", $_.GUID)
               $ruleElement.SetAttribute("Description", $_.Description)
               $ruleElement.SetAttribute("RawData", $_.RawData)
               $ruleElement.SetAttribute("Data", $_.Data)

               if($product -ieq "SRP") {
                  $ruleElement.SetAttribute("Flags", $_.Flags)
               }

               [void]$ruleSetElement.AppendChild($ruleElement) 
            }

            [void]$ruleSetsElement.AppendChild($ruleSetElement) 
         } 
            
         [void]$confElement.AppendChild($ruleSetsElement)
         
         [void]$confsElement.AppendChild($confElement)
      } 

      [void]$xmlDoc.DocumentElement.AppendChild($confsElement)  

      $xmlDoc.Save($Path)
   }
}

Function Invoke-Survey() {
<#
   .SYNOPSIS  
   Main method for running the survey
   
   .DESCRIPTION
   Main method for running the survey

   .PARAMETER Path
   The path of the file to write the results to.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   Invoke-Survey -Path "ll_aw.xml"
   #>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of the file to write results to.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path   
   )
   Process {     
      if(Test-Path -Path $Path -Type Leaf) {
         Remove-Item -Path $Path -Force -ErrorAction Stop 
      }

      $configurations = New-Object System.Collections.Generic.List[psobject]

      # SRP can be configured via user or machine group policy
      # DefaultLevel registry value must exist for it to have been configured at some point but we don't care what its current configuration is yet   
      $isMachineSRPConfigured = Test-RegistryValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "DefaultLevel"
      $isUserSRPConfigured = Test-RegistryValue -Hive "HKCU" -Path "SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "DefaultLevel"
      
      $isSRPConfigured = $isMachineSRPConfigured -or $isUserSRPConfigured
               
      if($isSRPConfigured) {
         if($isMachineSRPConfigured) {                    
            $srpMachineConfig = Get-SrpConfiguration -Policy "Machine"
            $configurations.Add($srpMachineConfig)
         }
                  
         if($isUserSRPConfigured) {           
            $srpUserConfig = Get-SrpConfiguration -Policy "User"
             $configurations.Add($srpUserConfig)
         }
      } 
      
      # AppLocker is only configured via machine group policy
      # EnforcementMode registry value must exist on at least one of the rule sets (Exe, Dll, Script, Msi, Appx) but we don't care what its current configuration is yet 
      $isAppLockerConfigured = $false
      
      Get-ChildItem -Path "hklm:\Software\Policies\Microsoft\Windows\SrpV2" -ErrorAction SilentlyContinue | ForEach { $isAppLockerConfigured = $isAppLockerConfigured -or ([System.Array]::IndexOf($_.Property, "EnforcementMode") -ge 0) }
      
      if($isAppLockerConfigured) {            
         $appLockerConfig = Get-AppLockerConfiguration
         $configurations.Add($appLockerConfig)
      }

      New-Xml -Configurations $configurations -Path $Path
   }
}

Invoke-Survey -Path "ll_aw.xml"
#Invoke-Survey -Path (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\ll_aw.xml")