<#
   .SYNOPSIS
   Executes the LOCKLEVEL Application Whitelisting analyzer.
   
   .DESCRIPTION
   Executes the LOCKLEVEL Application Whitelisting analyzer.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .PARAMETER i
   The path to the input directory.

   .PARAMETER o
   The path to the output directory. It will be created if it doesn't exist. It will deleted if it already exists.

   .PARAMETER p
   The path to the penalties XML file. Optional. If not specified then, a penalties.xml file is looked for in the same location that the script is executing from.

   #>
param(
   [Parameter(Position=0, Mandatory=$true, HelpMessage="The input directory path.")]
   [ValidateNotNullOrEmpty()]
   [string]$i,

   [Parameter(Position=1, Mandatory=$true, HelpMessage="The output directory path.")]
   [ValidateNotNullOrEmpty()]
   [string]$o,

   [Parameter(Position=2, Mandatory=$false, HelpMessage="The penalty file path.")]
   [ValidateNotNullOrEmpty()]
   [string]$p
)

#requires -version 4
Set-StrictMode -Version 4

# hard dependencies for this script are PowerShell 4.0 and .Net 4.5 (for unzipping files)
# this means the script can only run on Windows 7 SP1+ and Windows Server 2008 R2 SP1+

# penalty IDs used by this script
$script:PenaltyIDs = [string[]]@("SRP_NOT_WHITELISTING", "SRP_RULE_NOT_ENFORCED", "SRP_BLACKLIST_RULE_MISSING", "SRP_SCOPE_USERS_ONLY", "SRP_BINARIES_NONE", "SRP_BINARIES_EXE_ONLY", "SRP_MISSING_EXE_TYPE", "SRP_WHITELIST_RULE_MISSING", "SRP_NO_PATH_RULES", "SRP_NO_WHITELIST_RULES", "SRP_NO_BLACKLIST_RULES", "APPLOCKER_SERVICE_NOT_AUTOMATIC", "APPLOCKER_SERVICE_NOT_RUNNING", "APPLOCKER_RULESET_NOT_ENFORCED", "APPLOCKER_RULESET_NOT_CONFIGURED", "APPLOCKER_BAD_PUBLISHER", "APPLOCKER_BLACKLIST_RULE_MISSING", "APPLOCKER_NO_BLACKLIST_RULES", "APPLOCKER_NO_USERPROFILE_RULES", "NO_WHITELISTING")

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
   Write-Error -Message (Get-ErrorMessage -ErrorRecord $_) 
   exit -1
}

Function Copy-PSObject() {
<#
   .SYNOPSIS
   Makes a deep copy of a PSObject.
   
   .DESCRIPTION
   Makes a deep copy of a PSObject.
     
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [psobject]

   .PARAMETER PSObject
   The psobject to make a deep copy of.
   
   .EXAMPLE
   Copy-PSObject -PSObject $customObject
   #>
   [CmdletBinding()]
   [OutputType([psobject])]
      Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The psobject to make a deep copy of.")]
      [ValidateNotNullOrEmpty()]
      [object]$PSObject
   )
   Process {
      if($PSObject -isnot [psobject]) {
         throw "Input was not of type [psobject]"
      }

      $stream = New-Object System.IO.MemoryStream
      $formatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
      $formatter.Serialize($stream,$PSObject)
      $stream.Position = 0
      $copy = $formatter.Deserialize($stream)
      $stream.Close()
      $stream.Dispose()
      return [psobject]$copy
   }
}

Function Get-Files() {
<#
   .SYNOPSIS  
   Retrieves the files from a given path.
   
   .DESCRIPTION
   Retrieves the files from a given path they match an optionally specified pattern.
     
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [System.IO.FileInfo[]]

   .PARAMETER Path
   The path to get files from.

   .PARAMETER Filter
   The extension(s) to filter on. Defaults to *.zip when omitted.
   
   .EXAMPLE
   Get-Files -Path "C:\some path"

   .EXAMPLE
   Get-Files -Path "C:\some path" -Filter "*.xml","*.txt"
   #>
   [CmdletBinding()]
   [OutputType([System.IO.FileInfo[]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path to get files from.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path,
           
      [Parameter(Position=1, Mandatory=$false, HelpMessage="The extension(s) to filter on.")]
      [ValidateNotNullOrEmpty()]
      [string[]]$Filter = "*.zip"
   )
   Process {
      $files = [System.IO.FileInfo[]]@(Get-ChildItem -Path $Path -Include $Filter -Recurse | Where-Object { $_.PsIsContainer -eq $false})

      return ,$files
   }
}

Function Expand-ZipFile() {
<#
   .SYNOPSIS  
   Expands a zip file's contents into a folder.
   
   .DESCRIPTION
   Expands a zip file's contents into a folder. If the folder already exists, then it is deleted before expanding the zip file and then recreated.
     
   .INPUTS
   See parameters.
   
   .OUTPUTS
   None

   .PARAMETER ZipFile
   The path of the zip file.

   .PARAMETER Path
   The path of a folder to unzip to.
   
   .EXAMPLE
   Expand-ZipFile -ZipFile "C:\test.zip" -Path "C:\testzip"
   #>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of the zip file.")]
      [ValidateNotNullOrEmpty()]
      [string]$ZipFile,
           
      [Parameter(Position=1, Mandatory=$false, HelpMessage="The path of a folder to unzip to.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Begin {
      Add-Type -AssemblyName System.IO.Compression.FileSystem
   }
   Process {
      if(-not(Test-Path -Path $ZipFile -PathType Leaf)) {
         throw "$ZipFile not found or inaccessible"
      }

      if(Test-Path -Path $Path -PathType Container) {
         Remove-Item -Path $Path -Force -Recurse -ErrorAction Stop | Out-Null
      }

      New-Item -Path $Path -ItemType Container -ErrorAction Stop | Out-Null

      [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipFile, $Path)
   }
}

Function New-RemediationDefinition() {
<#
   .SYNOPSIS  
   Creates a new remediation definition.
   
   .DESCRIPTION
   Creates a new remediation definition.
  
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [PSObject]

   .PARAMETER Description
   The remediation description.

   .PARAMETER ID
   The remediation ID which is a symbol rather than a numeric ID.
   
   .EXAMPLE
   New-RemediationDefinition -ID "ID_NAME" -Description "Description of the remediation"

   .EXAMPLE
   New-RemediationDefinition -ID "ID_NAME" -Description "Description of the remediation"
   #>
   [CmdletBinding()]
   [OutputType([psobject])]
   Param(    
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The remediation description.")]
      [ValidateNotNullOrEmpty()]
      [string]$Description,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The remediation ID which is a symbol rather than a numeric ID.")]
      [ValidateNotNullOrEmpty()]
      [string]$ID
   )  
   Process {
      $r = @{}
   
      $r.Description = $Description
      $r.ID = $ID

      $remediation = New-Object -TypeName PSObject -Prop $r
      return $remediation
   }
}

Function New-PenaltyDefinition() {
<#
   .SYNOPSIS  
   Creates a new penalty definition.
   
   .DESCRIPTION
   Creates a new penalty definition.
  
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [PSObject]

   .PARAMETER Name
   The penalty name.

   .PARAMETER Value
   The penalty value.

   .PARAMETER Reason
   The reason for the penalty.

   .PARAMETER Remediation
   The remediation(s) for the penalty of which there may be multiple.

   .PARAMETER ID
   The penalty ID which is a symbol rather than a numeric ID.
   
   .EXAMPLE
   New-PenaltyDefinition -ID "ID_NAME" -Name "Penalty name" -Value 1 -Reason "You are getting a small penalty" -Remediation (New-RemediationDefinition -Description "Here is how you fix it"),(New-RemediationDefinition -Description "Here is another way you can fix it")

   .EXAMPLE
   New-PenaltyDefinition -ID "ID_NAME" -Name "Penalty name" -Value 100 -Reason "You are getting a big penalty" -Remediation (New-RemediationDefinition -Description "This is the only way you can fix it")
   #>
   [CmdletBinding()]
   [OutputType([psobject])]
   Param(    
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty name.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name,
      
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The penalty value.")]
      [ValidateNotNullOrEmpty()]
      [ValidateRange(1,100)]
      [UInt32]$Value,
      
      [Parameter(Position=2, Mandatory=$true, HelpMessage="The reason for the penalty.")]
      [ValidateNotNullOrEmpty()]
      [string]$Reason,
           
      [Parameter(Position=3, Mandatory=$true, HelpMessage="The remediation(s) for the penalty of which there may be multiple.")]
      [ValidateNotNullOrEmpty()]
      [object[]]$Remediation,

      [Parameter(Position=4, Mandatory=$true, HelpMessage="The penalty ID which is a symbol rather than a numeric ID.")]
      [ValidateNotNullOrEmpty()]
      [string]$ID
   )  
   Process {
      $p = @{}
   
      $p.Name = $Name
      $p.Value = $Value
      $p.Reason = $Reason
      $p.Remediation = $Remediation
      $p.ID = $ID

      $penalty = New-Object -TypeName PSObject -Prop $p
      return $penalty
   }
}

Function Read-PenaltyDefinitions() {
<#
   .SYNOPSIS  
   Reads the penalty definitions from a file and returns the relevant penalty definitions for this analyzer.
   
   .DESCRIPTION
   Reads the penalty definitions from a file and returns the relevant penalty definitions for this analyzer.
     
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [OutputType([System.Collections.Hashtable])]

   .PARAMETER Path
   The path of the penalty definitions file.
   
   .EXAMPLE
   Read-PenaltyDefinitions 
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Hashtable])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of the penalty definitions file.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process {
      $penalties = @{}

      if(-not(Test-Path -Path $Path -PathType Leaf)) {
         throw "$Path not found or inaccessible"
      }

      [xml]$xml = Get-Content -Path $Path

      $xml.penalties.penalty | ForEach -Process { 
         $penalty = New-PenaltyDefinition -ID $_.ID -Name $_.Name -Value $_.Value -Reason $_.Reason -Remediation @($_.Remediation | ForEach -Process { (New-RemediationDefinition -ID ($_.ID) -Description ($_.InnerText)) }) 
         $penalties.Add($penalty.ID, $penalty)
      }

      return $penalties
   }
}

Function Test-PenaltyDefinitions() {
<#
   .SYNOPSIS  
   Tests whether the penalty definitions contain all the penalty definitions expected for this analyzer.
   
   .DESCRIPTION
   Tests whether the penalty definitions contain all the penalty definitions expected for this analyzer.
     
   .INPUTS
   See parameters.
   
   .OUTPUTS
   None

   .PARAMETER PenaltyDefinitions
   The penalty definitions.

   .PARAMETER PenaltyIDs
   The penalty IDs for the penalty definitions used by this script.
   
   .EXAMPLE
   Test-PenaltyDefinitions -PenaltyDefinitions $penalties -PenaltyIDs
   #>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty definitions.")]
      [ValidateNotNullOrEmpty()]
      [System.Collections.Hashtable]$PenaltyDefinitions,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The penalty IDs for the penalty definitions used by this script.")]
      [ValidateNotNullOrEmpty()]
      [string[]]$PenaltyIDs
   )
   Process {
      $PenaltyIDs | ForEach -Process {
         if(-not($PenaltyDefinitions.ContainsKey($_))) {
            throw "Required penalty ID $_ not found"
         }
      }
   }
}

Function Get-MultiplicativeCumulativeScore() {
<#
   .SYNOPSIS  
   Gets a multiplicative cumulative score.
   
   .DESCRIPTION
   Gets a multiplicative cumulative score given all the penalties and rounds to the nearest tenths place.
     
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [System.Decimal]

   .PARAMETER Penalties
   The penalty values to score.
   
   .EXAMPLE
   Get-MultiplicativeCumulativeScore -Penalties 10,20,30

   .EXAMPLE
   Get-MultiplicativeCumulativeScore -Penalties 10 
   #>
   [CmdletBinding()]
   [OutputType([System.Decimal])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty values to score.")]
      [ValidateNotNull()]
      [AllowEmptyCollection()]
      [UInt32[]]$Penalties
   )
   Process {
      $cumulativeScore = 9

      foreach($penalty in $Penalties) {
         $currentScore = 100 - $penalty
         $cumulativeScore = $cumulativeScore * ($currentScore/100)
      }

      $cumulativeScore = $cumulativeScore + 1
      $roundedScore = [System.Math]::Round($cumulativeScore, 1)

      return $roundedScore
   }
}

Function New-ScoreXml() {
<#
   .SYNOPSIS  
   Creates the XML that contains the system information, score, and penalties.
   
   .DESCRIPTION
   Creates the XML that contains the system information, score, and penalties.
     
   .INPUTS
   See parameters.

   .PARAMETER Name
   The name of the mitigation.

   .PARAMETER Penalties
   The applied penalties.

   .PARAMETER HostInformation
   The host information.

   .PARAMETER Path
   The path to save the XML document to

   .OUTPUTS
   None
   
   .EXAMPLE
   New-ScoreXml -Name "Name" -Penalties $penalties -HostInformation (([xml]Get-Content -Path "systeminfo.xml").SelectSingleNode("systemInfo")) -Path "C:\result.xml"
   #>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The name of the mitigation.")]
      [ValidateNotNullOrEmpty()]
      [string]$Name,
   
      [Parameter(Position=1, Mandatory=$true, HelpMessage="The applied penalties.")]
      [ValidateNotNull()]
      [AllowEmptyCollection()]
      [System.Collections.Generic.List[psobject]]$Penalties,

      [Parameter(Position=2, Mandatory=$true, HelpMessage="The host information.")]
      [ValidateNotNullOrEmpty()]
      [System.Xml.XmlNode]$HostInformation,

      [Parameter(Position=3, Mandatory=$true, HelpMessage="The path to save the XML document to.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process {
      if(Test-Path -Path $Path -PathType Leaf) {
         Remove-Item -Path $Path -Force -ErrorAction Stop | Out-Null
      }

      $xmlDoc = New-Object System.Xml.XmlDocument

      [void]$xmlDoc.AppendChild($xmlDoc.CreateXmlDeclaration("1.0", "UTF-8", $null))
      
      $mitigationElement = $xmlDoc.CreateElement("mitigation");
      $mitigationElement.SetAttribute("name", $Name);

      $hostNode = $xmlDoc.ImportNode($HostInformation, $true)
      [void]$mitigationElement.AppendChild($hostNode)

      # creates "mitigation" as the DocumentElement aka root
      [void]$xmlDoc.AppendChild($mitigationElement)

      $score = Get-MultiplicativeCumulativeScore -Penalties @($penalties | ForEach -Process { $_.Value})

      $scoreElement = $xmlDoc.CreateElement("score");
      $scoreElement.SetAttribute("cumulativeScore", $score)

      $totalPenalty = (@($penalties | ForEach -Process { $_.Value}) | Measure-Object -Sum).Sum

      if($totalPenalty -gt 0) {
         foreach($penalty in $Penalties) {
            $penaltyElement = $xmlDoc.CreateElement("penalty")
            $penaltyElement.SetAttribute("id", $penalty.ID)
            $penaltyElement.SetAttribute("name", $penalty.Name)
            $penaltyElement.SetAttribute("value", $penalty.Value)

            $reasonElement = $xmlDoc.CreateElement("reason")
            $reasonElement.InnerText = $penalty.Reason
            [void]$penaltyElement.AppendChild($reasonElement)

            foreach($remediation in $penalty.Remediation) {
               $remediationElement = $xmlDoc.CreateElement("remediation")
               $remediationElement.InnerText = $remediation.Description
               $remediationElement.SetAttribute("id", $remediation.ID)
               [void]$penaltyElement.AppendChild($remediationElement)
            }

            [void]$scoreElement.AppendChild($penaltyElement)
         }
      }

      # since we already created the Document element, then we have to append to that
      [void]$xmlDoc.DocumentElement.AppendChild($scoreElement)

      $xmlDoc.Save($Path)
   }
}

#### end common functions ####

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
         131072 { $name="Normal" ; break } # UI aka Basic User
          65536 { $name="Constrained" ; break }
           4096 { $name="Untrusted" ; break }
              0 { $name="Disallowed" ; break } # UI
        default { $name = "Unknown" ; break}
      }

      return $Name
   }
}

Function Get-SrpScopeName() {
<#
   .SYNOPSIS  
   Gets a SRP scope policy name based on its integer value.
   
   .DESCRIPTION
   Gets a SRP scope policy name based on its integer value.

   .PARAMETER Value
   The integer value of the SRP scope policy.
 
   .INPUTS
   None
   
   .OUTPUTS
   [string]
   
   .EXAMPLE
   Get-SrpScopeName -Value 0
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The integer value of the SRP scope policy.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet(0,1,IgnoreCase=$true)]   
      [UInt32]$Value
   )
   Process {
      $name = "Unknown"

      switch($Value) {
         0 { $name="All Users" ; break } # UI
         1 { $name="All Users except Administrators" ; break } # UI
         default { $name = "Unknown" ; break}
      }

      return $Name
   }
}

Function Get-SrpBinaryPolicyName() {
<#
   .SYNOPSIS  
   Gets a SRP binary policy name based on its integer value.
   
   .DESCRIPTION
   Gets a SRP binary policy name based on its integer value.

   .PARAMETER Value
   The integer value of the SRP binary policy.
 
   .INPUTS
   None
   
   .OUTPUTS
   [string]
   
   .EXAMPLE
   Get-SrpBinaryPolicyName -Value 0
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The integer value of the SRP binary policy.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet(1,2,IgnoreCase=$true)]   
      [UInt32]$Value
   )
   Process {
      $name = "Unknown"

      switch($Value) {
         0 { $name="No Software Files or Libraries" ; break }
         1 { $name="All Software Files except Libraries" ; break } # UI
         2 { $name="All Software Files" ; break } # UI
         default { $name = "Unknown" ; break}
      }

      return $Name
   }
}

Function Get-AppLockerRuleSetName() {
<#
   .SYNOPSIS  
   Gets the AppLocker rule set name based on its registry key name.
   
   .DESCRIPTION
   Gets a SRP level name based on its integer value.

   .PARAMETER Value
   The AppLocker rule set registry key name.
 
   .INPUTS
   None
   
   .OUTPUTS
   [string]
   
   .EXAMPLE
   Get-AppLockerRuleSetName -Value "msi"
   #>
   [CmdletBinding()]
   [OutputType([string])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The AppLocker rule set registry key name.")]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("APPX","DLL","EXE","MSI","SCRIPT",IgnoreCase=$true)]   
      [string]$Value
   )
   Process {
      $name = "Unknown"

      switch($Value.ToLower()) {
        "appx" { $name="Packaged App Rules" ; break } 
         "dll" { $name="DLL Rules" ; break } 
         "exe" { $name="Executable Rules" ; break }
         "msi" { $name="Windows Installer Rules" ; break }
      "script" { $name="Script Rules" ; break } 
       default { $name = "Unknown" ; break}
      }

      return $Name
   }
}


Function Get-AppliedSRPPenalties() {
<#
   .SYNOPSIS  
   Gets the penalties that are applied to a system that has SRP configured.
   
   .DESCRIPTION
   Gets the penalties that are applied to a system that has SRP configured.
     
   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Generic.List[object]]
   
   .EXAMPLE
   Get-AppliedSRPPenalties 
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[psobject]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty definitions.")]
      [ValidateNotNullOrEmpty()]
      [System.Collections.Hashtable]$PenaltyDefinitions,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The HIPS properties to check for scoring.")]
      [ValidateNotNullOrEmpty()]
      [psobject]$Configuration
   )
   Begin {
      $srpWhitelistRules = [string[]]@("%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir%","%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir (x86)%","%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%")
      $srpBlacklistRules = [string[]]@("%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\Debug", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\PCHEALTH\ERRORREP", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\Registration", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32\catroot2", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32\com\dmp", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32\FxsTmp", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32\spool\drivers\color", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32\spool\PRINTERS", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32\spool\SERVERS", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\System32\Tasks", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\SysWOW64\com\dmp", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\SysWOW64\FxsTmp", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\SysWOW64\Tasks", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\Tasks", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\Temp", "%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot%\tracing")
      $srpExtensions = [string[]]@("ADE", "ADP", "BAS", "BAT", "CHM", "CMD", "COM", "CPL", "CRT", "EXE", "HLP", "HTA", "INF", "INS", "ISP", "LNK", "MDB", "MDE", "MSC", "MSI", "MSP", "MST", "OCX", "PCD", "PIF", "REG", "SCR", "SHS", "URL", "VB", "WSC") # add PowerShell extensions?
   }
   Process {
      $penalties = New-Object System.Collections.Generic.List[psobject]

      # check critical properties

      if($Configuration.Properties.ContainsKey("DefaultLevel")) {
         $level = $Configuration.Properties["DefaultLevel"]

         if($level -ne 0) {
            $levelName = Get-SrpLevelName -Value $level
            $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_NOT_WHITELISTING"]
            $penalty.Reason = ($penalty.Reason -f $levelName)
            $penalties.Add($penalty)
         }
      }

      if($Configuration.Properties.ContainsKey("PolicyScope")) {
         $scope = $Configuration.Properties["PolicyScope"]

         if($scope -ne 0) {
            $scopeName = Get-SrpScopeName -Value $scope
            $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_SCOPE_USERS_ONLY"]
            $penalty.Reason = ($penalty.Reason -f $scopeName)
            $penalties.Add($penalty)
         }
      }

      if($Configuration.Properties.ContainsKey("TransparentEnabled")) {
         $binary = $Configuration.Properties["TransparentEnabled"]

         if($binary -ne 2) {
            $binaryName = Get-SrpBinaryPolicyName -Value $binary

            if($binary -eq 0 ) {
              $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_BINARIES_NONE"]
            } elseif($binary -eq 1) {
              $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_BINARIES_EXE_ONLY"]
            }

            $penalty.Reason = ($penalty.Reason -f $binaryName)
            $penalties.Add($penalty)
         }
      }

      if($Configuration.Properties.ContainsKey("ExecutableTypes")) {
          $exeTypes = $Configuration.Properties["ExecutableTypes"].Split(" ")
          $srpExtensions | ForEach {
             if($_ -notin $exeTypes) {
                $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_MISSING_EXE_TYPE"]
                $penalty.Reason = ($penalty.Reason -f $_) 
                $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $_)
                $penalties.Add($penalty)
             }
         }
      }

      if($Configuration.RuleSets.Count -gt 0) {
         # check for needed whitelisting rules

         $whitelist = $Configuration.RuleSets | Where { $_.Category -ieq "Unrestricted" }

         if($whitelist -ne $null) {
            if($whitelist.Rules.Count -gt 0) {
               $pathRules = @($whitelist.Rules | Where-Object {$_.Category -ieq "Paths" } | ForEach { $_.RawData} )

               if($pathRules -ne $null) {
                  if($pathRules.Count -gt 0) {
                     $srpWhitelistRules | ForEach {
                        if($_ -notin $pathRules) {
                           $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_WHITELIST_RULE_MISSING"]
                           $penalty.Reason = ($penalty.Reason -f $_)
                           $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $_)
                           $penalties.Add($penalty)
                        }
                     }
                  } else {
                     $penalty = $PenaltyDefinitions["SRP_NO_PATH_RULES"]
                     $penalties.Add($penalty)
                  }
               } else {
                  $penalty = $PenaltyDefinitions["SRP_NO_PATH_RULES"]
                  $penalties.Add($penalty)
               }
            } else {
               $penalty = $PenaltyDefinitions["SRP_NO_WHITELIST_RULES"]
               $penalties.Add($penalty)
            }
         } else {
            $penalty = $PenaltyDefinitions["SRP_NO_WHITELIST_RULES"]
            $penalties.Add($penalty)
         }

         # check for needed blacklisting rules

         $blacklist = $Configuration.RuleSets | Where { $_.Category -ieq "Disallowed" }

         if($blacklist -ne $null) {
            if($blacklist.Rules.Count -gt 0) {
               $pathRules = @($blacklist.Rules | Where-Object {$_.Category -ieq "Paths" } | ForEach { $_.RawData} )

               if($pathRules -ne $null) {
                  if($pathRules.Count -gt 0) {
                     $srpBlacklistRules | ForEach {
                        if($_ -notin $pathRules) {
                           $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_BLACKLIST_RULE_MISSING"]
                           $penalty.Reason = ($penalty.Reason -f $_)
                           $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $_) 
                           $penalties.Add($penalty)
                        }
                     }
                  } else {
                     $penalty = $PenaltyDefinitions["SRP_NO_PATH_RULES"]
                     $penalties.Add($penalty)
                  }
               } else {
                  $penalty = $PenaltyDefinitions["SRP_NO_PATH_RULES"]
                  $penalties.Add($penalty)
               }
            } else {
               $penalty = $PenaltyDefinitions["SRP_NO_BLACKLIST_RULES"]
               $penalties.Add($penalty)
            }
         } else {
            $penalty = $PenaltyDefinitions["SRP_NO_BLACKLIST_RULES"]
            $penalties.Add($penalty)
         }

         # no checks for Normal aka Basic User rules since it seems like this SRP level is broken in Windows 7+

         # check for rules that have flags specifying audit mode or sandbox_inert

         $Configuration.RuleSets | ForEach {
            $_.Rules | ForEach {
               if(($_.Flags -band 0x1000) -or ($_.Flags -band 0x20000)) {
                  $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["SRP_RULE_NOT_ENFORCED"]

                  $mode = ""

                  if(($_.Flags -band 0x1000) -and ($_.Flags -band 0x20000)) {
                     $mode = "Audit and Inert"
                  } elseif(($_.Flags -band 0x1000)) {
                     $mode = "Audit"
                  } elseif(($_.Flags -band 0x20000)) {
                     $mode ="Inert"
                  }
                  $penalty.Reason = ($penalty.Reason -f $mode) # update the reason to have more information
                  $penalties.Add($penalty)
               }
            }
         }

      } else {
         #penalty for no rulesets? no because the OS would break without any rulesets
      }

      return ,$penalties
   }
}

Function Get-AppliedAppLockerPenalties() {
<#
   .SYNOPSIS  
   Gets the penalties that are applied to a system that has AppLocker configured.
   
   .DESCRIPTION
   Gets the penalties that are applied to a system that has AppLocker configured.
     
   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Generic.List[object]]
   
   .EXAMPLE
   Get-AppliedSRPPenalties 
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[psobject]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty definitions.")]
      [ValidateNotNullOrEmpty()]
      [System.Collections.Hashtable]$PenaltyDefinitions,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The HIPS properties to check for scoring.")]
      [ValidateNotNullOrEmpty()]
      [psobject]$Configuration
   )
   Begin {
      $applockerWhitelistRules = [string[]]@("%PROGRAMFILES%\*", "%WINDIR%\*", "%WINDIR%\Installer\*")
      $applockerBlacklistRules = [string[]]@("%SYSTEM32%\catroot2\*", "%SYSTEM32%\com\dmp\*", "%SYSTEM32%\FxsTmp\*", "%SYSTEM32%\spool\drivers\color\*", "%SYSTEM32%\spool\printers\*", "%SYSTEM32%\spool\servers\*", "%SYSTEM32%\Tasks\*", "%WINDIR%\Debug\*", "%WINDIR%\PCHEALTH\ERRORREP\*", "%WINDIR%\Registration\*", "%WINDIR%\SysWOW64\com\dmp\*", "%WINDIR%\SysWOW64\FxsTmp\*", "%WINDIR%\SysWOW64\Tasks\*", "%WINDIR%\Tasks\*", "%WINDIR%\Temp\*", "%WINDIR%\tracing\*")
   }
   Process {
      $penalties = New-Object System.Collections.Generic.List[psobject]

      # check critical properties

      if($Configuration.Properties.ContainsKey("ServiceStart")) {
         $start = $Configuration.Properties["ServiceStart"]


         if(-not($start -ieq "auto")) {
            $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["APPLOCKER_SERVICE_NOT_AUTOMATIC"]
            $penalty.Reason = ($penalty.Reason -f $start,"Automatic")
            $penalties.Add($penalty)
         }
      }

      if($Configuration.Properties.ContainsKey("ServiceState")) {
         $state = $Configuration.Properties["ServiceState"]


         if(-not($state -ieq "running")) {
            $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["APPLOCKER_SERVICE_NOT_RUNNING"]
            $penalty.Reason = ($penalty.Reason -f $state,"Running")
            $penalties.Add($penalty)
         }
      }

      # check that rulesets are configured and enforced

      if($Configuration.RuleSets.Count -gt 0) {
         $Configuration.RuleSets | ForEach {
            $ruleSetUIName = Get-AppLockerRuleSetName -Value $_.Category

            if(-not($_.Enforced)) {
               $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["APPLOCKER_RULESET_NOT_ENFORCED"]
               $penalty.Reason = ($penalty.Reason -f $ruleSetUIName)
               $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $ruleSetUIName) 
               $penalties.Add($penalty) 
            }

            if(-not($_.Configured)) {
               $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["APPLOCKER_RULESET_NOT_CONFIGURED"]
               $penalty.Reason = ($penalty.Reason -f $ruleSetUIName)
               $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $ruleSetUIName) 
               $penalties.Add($penalty) 
            }
         }

         # add checks to make sure EXE, DLL, Script, and MSI rule sets exist?

         $Configuration.RuleSets  | ForEach {
            $ruleSetUIName = Get-AppLockerRuleSetName -Value $_.Category

            $_.Rules | ForEach {
               $rawRuleXml = [xml]$_.RawData
               $ruleXml = [xml]$_.Data # contains translated Path and SID values

               $ruleType = $rawRuleXml.DocumentElement.LocalName # this is the name of the root element that we need to use for PowerShell dot notation produced by the xml type accelerator
               $ruleName = $rawRuleXml.$ruleType.Name
               $action = $rawRuleXml.$ruleType.Action
               $sidName = $ruleXml.$ruleType.UserOrGroupSid
               $sid = $rawRuleXml.$ruleType.UserOrGroupSid

               if(($action -ieq "Allow") -and ($ruleType -ieq "FilePathRule") -and ($sidName -in @("Everyone","Users"))) {
                  $rulePath = $rawRuleXml.$ruleType.Conditions.FilePathCondition.Path

                  # look at default allow rules for windir and make sure they have their path exceptions
                  if($rulePath -ieq "%WINDIR%\*") {
                     $hasExceptions = (@($rawRuleXml.$ruleType | gm -MemberType "Property" | Where {$_.Name -ieq "Exceptions" })).Count -ge 1

                     if($hasExceptions) {
                        $exceptions = @($rawRuleXml.$ruleType.Exceptions.FilePathCondition.Path | ForEach { $_ })

                        if($exceptions -ne $null) {
                           if($exceptions.Count -gt 0) {
                              $appLockerBlacklistRules | ForEach {  
                                 if($_ -notin $exceptions) {
                                    $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["APPLOCKER_BLACKLIST_RULE_MISSING"]
                                    $penalty.Reason = ($penalty.Reason -f $ruleName,$ruleSetUIName,$_)
                                    $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $_,$ruleName,$ruleSetUIName)
                                    $penalties.Add($penalty)
                                 }
                              }
                           } else {
                              $penalty = Copy-PSObject $PenaltyDefinitions["APPLOCKER_NO_BLACKLIST_RULES"]
                              $penalty.Reason = ($penalty.Reason -f $ruleName,$ruleSetUIName) 
                              $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $ruleName,$ruleSetUIName)
                              $penalties.Add($penalty)
                           }
                        } else {
                           $penalty = Copy-PSObject $PenaltyDefinitions["APPLOCKER_NO_BLACKLIST_RULES"]
                           $penalty.Reason = ($penalty.Reason -f $ruleName,$ruleSetUIName) 
                           $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $ruleName,$ruleSetUIName)
                           $penalties.Add($penalty)
                        }

                     } else {
                        $penalty = Copy-PSObject $PenaltyDefinitions["APPLOCKER_NO_BLACKLIST_RULES"]
                        $penalty.Reason = ($penalty.Reason -f $ruleName,$ruleSetUIName) 
                        $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $ruleName,$ruleSetUIName)
                        $penalties.Add($penalty)
                     }
                          
                  }

                  if($rulePath.StartsWith("%OSDRIVE%\Users")) { # $rulePath -ieq "%OSDRIVE%\Users\*"
                     $penalty = Copy-PSObject $PenaltyDefinitions["APPLOCKER_NO_USERPROFILE_RULES"]
                     $penalty.Reason = ($penalty.Reason -f $ruleName,$ruleSetUIName) 
                     $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $ruleName,$ruleSetUIName)
                     $penalties.Add($penalty)
                  }
                   
                  #insert checks for required allow rules? 
                  #allow everyone execution from Program Files for EXE,DLL,Script
                  #allow everyone execution from Windir for EXE,DLL,Script
                  #allow everyone exection from the MSI installer folder
                  #not necessary because OS will break without these rules
               }

               # look for allow rules that allow any publisher
               # we don't want to allow Everyone to execute *any signed* anything though no matter what the ruleset
               # this takes care of the overly permissive default rules for MSI and APPX
               if(($action -ieq "Allow") -and ($ruleType -ieq "FilePublisherRule") -and ($sidName -in @("Everyone","Users"))) {
                  $conditions = @($ruleXml.$ruleType.Conditions | gm -MemberType "Property" | Where-Object {$_.Name -ieq "FilePublisherCondition"})

                  if($conditions.Count -ge 1) {
                     $conditions | ForEach {
                        if($ruleXml.$ruleType.Conditions.FilePublisherCondition.PublisherName -ieq "*" ) {
                           $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["APPLOCKER_BAD_PUBLISHER"]
                           $penalty.Reason = ($penalty.Reason -f $ruleName,$ruleSetUIName)
                           $penalty.Remediation[0].Description = ($penalty.Remediation[0].Description -f $ruleName,$ruleSetUIName) 
                           $penalties.Add($penalty) 
                        }
                     }
                  }
               }
            }
         } 


      } else {
         #penalty for no rulesets?
      }

      # check for necessary path rules? they sort of have to exist for AppLocker otherwise the OS will break so probably redundant to explicitly check. see comments around line 1120

      # check for blacklist rules as standalone rules? not sure if that scenario even works properly

      return ,$penalties
   }
}


Function Get-AppliedPenalties() {
<#
   .SYNOPSIS  
   Gets the penalties that are applied to a system.
   
   .DESCRIPTION
   Gets the penalties that are applied to a system. 
     
   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Generic.List[object]]
   
   .EXAMPLE
   Get-AppliedPenalties 
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[psobject]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty definitions.")]
      [ValidateNotNullOrEmpty()]
      [System.Collections.Hashtable]$PenaltyDefinitions,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The HIPS properties to check for scoring.")]
      [ValidateNotNull()]
      [AllowEmptyCollection()]
      [System.Collections.Generic.List[psobject]]$Configurations
   )
   Process {
      $penalties = New-Object System.Collections.Generic.List[psobject]

      $Configurations | Where-Object { $_.Product -ieq "SRP" } | ForEach {
         $srpPenalties = Get-AppliedSRPPenalties -PenaltyDefinitions $PenaltyDefinitions -Configuration $_

         if($srpPenalties.Count -gt 0) {
            $penalties.AddRange($srpPenalties) 
         }
      }


      $Configurations | Where-Object { $_.Product -ieq "AppLocker" } | ForEach {
         $appLockerPenalties = Get-AppliedAppLockerPenalties -PenaltyDefinitions $PenaltyDefinitions -Configuration $_

         if($appLockerPenalties.Count -gt 0) {
            $penalties.AddRange($appLockerPenalties) 
         }
      }

      if($Configurations.Count -eq 0) {
         $penalties.Add($PenaltyDefinitions['NO_WHITELISTING'])
      }

      return ,$penalties
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

Function Read-Configurations() {
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path to the XML file contains the whitelisting configuration data.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process {
      $configurations = New-Object System.Collections.Generic.List[psobject]

      if(Test-Path -Path $Path -PathType Leaf) {
         $xml = [xml](Get-Content -Path $Path)

         if((Select-Xml -Xml $xml -XPath "//AW/Configurations") -ne $null) {
            
            #$conf = @($xml.AW.Configurations | gm -MemberType Property | Where {$_.Name -ieq "Configuration"})
            #$conf = @($xml.AW.Configurations | gm -MemberType Property | Where {$_.Name -ieq "Configuration"} | ForEach { $_})

            if((Select-Xml -Xml $xml -XPath "//AW/Configurations/Configuration") -ne $null) { #if($xml.AW.Configurations -isnot [string]) {

               $xml.AW.Configurations.Configuration | ForEach {
                  $product = $_.Product

                  $properties = @{}

                  $_.Properties.Property | ForEach {
                     $properties.Add($_.Name,$_.InnerText)
                  }

                  $ruleSets = New-Object System.Collections.Generic.List[psobject]

                  $_.RuleSets.RuleSet | ForEach {

                     $rules = New-Object System.Collections.Generic.List[psobject]

                     $hasRule = ($_ | gm -MemberType "Property" | Where {$_.Name -ieq "Rule"}) -ne $null

                     if($hasRule) {
                        $_.Rule | ForEach {                     
                           if($product -ieq "AppLocker") {
                              $rule = New-Rule -Category $_.Type -GUID $_.Guid -Description $_.Description -RawData $_.RawData -Data $_.Data
                           } elseif($product -ieq "SRP") {
                              $rule = New-Rule -Category $_.Type -GUID $_.Guid -Description $_.Description -RawData $_.RawData -Data $_.Data -Flags $_.Flags
                           }
                           $rules.Add($rule)
                        }
                     }

                     if($product -ieq "AppLocker") {
                        $ruleSet = New-RuleSet -Category $_.Name -Configured ([System.Boolean]::Parse($_.Configured)) -Enforced ([System.Boolean]::Parse($_.Enforced)) -Rules $rules
                     } elseif($product -ieq "SRP") {
                        $ruleSet = New-RuleSet -Category $_.Name -Configured $true -Enforced $true -Rules $rules
                     }
                     $ruleSets.Add($ruleSet)
                  }

                  $configuration = New-Configuration -Product $_.Product -Policy $_.PolicyType -Properties $properties -RuleSets $ruleSets
                  $configurations.Add($configuration)
               }
            }
         }
      }

      return ,$configurations
   }
}

Function Invoke-Analyzer() {
<#
   .SYNOPSIS  
   Main method for running the anaylzer.
   
   .DESCRIPTION
   Main method for running the anaylzer.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   Main  
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of a folder that contains the survey data that's used for scoring.")]
      [ValidateNotNullOrEmpty()]
      [string]$DataPath,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The path of a temporary folder to use. It will be created if it doesn't exist. It will be deleted and recreated if it exists.")]
      [ValidateNotNullOrEmpty()]
      [string]$TempPath,

      [Parameter(Position=2, Mandatory=$true, HelpMessage="The path of the file that contains the penalty definitions.")]
      [ValidateNotNullOrEmpty()]
      [string]$PenaltyFile
   )
   Begin {
      $prefix = "LL_AW"
      $dataFile = "ll_aw.xml"
   }
   Process {
     if(-not(Test-Path -Path $DataPath -PathType Container)) {
        throw "$DataPath does not exist or is not accessible"
     }

     if(-not(Test-Path -Path $PenaltyFile -PathType Leaf)) {
        throw "$PenaltyFile does not exist or is not accessible"
     }

     if(Test-Path -Path $TempPath -PathType Container) {
        Remove-Item -Path $TempPath -Force -Recurse -ErrorAction Stop | Out-Null
     }

     $penaltyDefinitions = Read-PenaltyDefinitions -Path $PenaltyFile

     Test-PenaltyDefinitions -PenaltyDefinitions $penaltyDefinitions -PenaltyIDs $script:PenaltyIDs

     New-Item -Path $TempPath -ItemType Container | Out-Null

     $zips = Get-Files -Path $DataPath -Filter "*.zip"

     if($zips -ne $null) {
        if($zips.Count -ge 1) {
           foreach($zip in $zips) {
              Expand-ZipFile -ZipFile $zip.FullName -Path (Join-Path -Path $TempPath -ChildPath $zip.BaseName)
           }
        }
     }

     $validXmls = New-Object System.Collections.Generic.List[string]

     $xmls = Get-Files -Path $TempPath -Filter "ll_systeminfo.xml"

     if($xmls -ne $null) {
        if($xmls.Count -ge 1) {
           foreach($xml in $xmls) {
              $xmlDoc = New-Object System.Xml.XmlDocument

              try {
                 $xmlDoc.Load($xml.FullName)
              
                 if(-not($validXmls.Contains($xml.FullName))) {
                    $validXmls.Add($xml.FullName)
                 }
              } catch [Exception] {
                 Write-Warning -Message ("Failed loading {0} due to '{1}'" -f $xml.FullName,$_.Exception.Message)
              }
           }
        }
     }

     if($validXmls -ne $null) {
        if($validXmls.Count -ge 1) {
           foreach($validXml in $validXmls) {
              try {
                 [xml]$xml = Get-Content -Path $validXml
              
                 # shortcut syntax that reads elements as strings by default
                 $hostname = $xml.systemInfo.hostName
                 $domain = $xml.systemInfo.domainName
                 $timestamp = $xml.systemInfo.timeStamp
                 $osName =  $xml.systemInfo.osName
                 $os = $xml.systemInfo.osVersion
                 $sp = $xml.systemInfo.ServicePack

                 if( ($hostname -eq $null) -or ($domain -eq $null) -or ($timestamp -eq $null) -or($osName -eq $null) -or ($os -eq $null) -or ($sp -eq $null) ) {
                    throw "Error reading system information XML"
                 }

                 $surveyTimestamp = [System.DateTime]::ParseExact($timestamp, "yyyyMMddHHmmss", [System.Globalization.CultureInfo]::CurrentCulture)

                 $analysisTimestamp = "{0:yyyyMMddHHmmss}" -f [System.DateTime]::Now

                 $filename = ("{0}_{1}.{2}_{3}.xml") -f $prefix,$hostname,$domain,$timestamp

                 $dataFilePath = Join-Path -Path ([System.IO.FileInfo]$validXml).Directory.FullName -ChildPath $dataFile

                 if (Test-Path $dataFilePath) {
                    $configurations = Read-Configurations -Path $dataFilePath

                    $appliedPenalties = Get-AppliedPenalties -PenaltyDefinitions $penaltyDefinitions -Configurations $configurations

                    $totalPenalty = (@($appliedPenalties | ForEach -Process { $_.Value}) | Measure-Object -Sum).Sum

                    $score = Get-MultiplicativeCumulativeScore -Penalties @($appliedPenalties | ForEach -Process { $_.Value})
                                         
                    Write-Verbose -Message ("OS Version: {0} SP: {1} Penalties: {2,2} Penalty Value: {3,3} Score: {4,3} Survey DateTime: {5} Analysis DateTime: {6} File: {7} Host: {8}.{9} OS Name: {10}" -f $os,$sp,$appliedPenalties.Count,$totalPenalty,$score,$timestamp,$analysisTimestamp,$filename,$hostname,$domain,$osName)

                    $scoreXmlPath = Join-Path -Path $TempPath -ChildPath $filename

                    $hostInfo = $xml.DocumentElement.SelectSingleNode(".") # works without having hardcode for 'systemInfo' 

                    New-ScoreXml -Name "AW" -Penalties $appliedPenalties -HostInformation $hostInfo -Path $scoreXmlPath
                 } else {
                    Write-Warning -Message ("AW data file did not exist at '{0}'" -f $dataFilePath)
                 }
              } catch [Exception] {
                 Write-Error -Message (Get-ErrorMessage -ErrorRecord $_)
              }
              
           }
        }
     }

     Write-Verbose -Message ("Total XML: {0}" -f $xmls.Count)
     Write-Verbose -Message ("Valid XML: {0}" -f $validXmls.Count)
   }
}

if([Environment]::CommandLine -like "*-NonInteractive*" -or [Environment]::CommandLine -like "*-File*" ) {
   # only print out errors and warnings when the script is being invoked in an automation scenario
   $verbose = $false
} else {
   $verbose = $true
}

switch($PSBoundParameters.Count) {
   2 {
      $DataPath = $PSBoundParameters["i"]
      $TempPath = $PSBoundParameters["o"]
      $PenaltyFile = Join-Path -Path $PSScriptRoot -ChildPath penalties.xml
      break;
   }
   3 {
      $DataPath = $PSBoundParameters["i"]
      $TempPath = $PSBoundParameters["o"]
      $PenaltyFile = $PSBoundParameters["p"]
      break;
   } 
   default {
      Write-Host Get-Help $PSCommandPath
      throw "Invalid invocation"
   }
}

Invoke-Analyzer -DataPath $DataPath -TempPath $TempPath -PenaltyFile $PenaltyFile -Verbose:$verbose

#Execute from inside the PowerShell ISE as:
# .\LL_AW_Analyzer.ps1 -i (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\TestData\Raw\LL_AW") -o (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\TestData\Analyzed\LL_AW") -p (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\TestData\penalties.xml")

#Execute from command line as:
# "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%USERPROFILE%\Documents\LOCKLEVEL\LL_AW\LL_AW\LL_AW_Analyzer.ps1" -i "%USERPROFILE%\Documents\LOCKLEVEL\TestData\Raw\LL_AW" -o "%USERPROFILE%\Documents\LOCKLEVEL\TestData\Analyzed\LL_AW" -p "%USERPROFILE%\Documents\LOCKLEVEL\TestData\penalties.xml"


#Invoke-Analyzer -DataPath (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\MockAWData\Raw") -TempPath (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\MockAWData\Analyzed") -PenaltyFile (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\TestData\penalties.xml") -Verbose