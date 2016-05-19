<#
   .SYNOPSIS
   Executes the LOCKLEVEL Host Intrusion Prevention System analyzer.
   
   .DESCRIPTION
   Executes the LOCKLEVEL Host Intrusion Prevention System analyzer.
     
   .INPUTS
   See parameters.
   
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
$script:PenaltyIDs = [string[]]@("HIPS_NOT_ENABLED", "HIPS_SERVICE_NOT_RUNNING", "HIPS_NOT_INSTALLED", "UPDATE_HIPS", "UPDATE_HIPS_OLD", "HIPS_NOT_PREVENTING_HIGH", "HIPS_NOT_PREVENTING_MEDIUM", "HIPS_NOT_LOGGING_LOW", "HIPS_NOT_ENFORCING", "UPDATE_HIPS_CONTENT", "HIPS_SERVICE_NOT_AUTOMATIC")

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

Function Get-HIPSContentDate() {
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[psobject]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The date string to parse.")]
      [ValidateNotNullOrEmpty()]
      [string]$Date
   )
   Process {
      $parsedDate = [System.DateTime]::MaxValue

      # both formats (e.g. "Friday, July 05, 2013" and "Thursday, May 7, 2015") have been observed
      $formats = @("dddd, MMMM dd, yyyy", "dddd, MMMM d, yyyy")

      foreach($format in $formats) {
         try {
            # might want to hard code to en-US culture
            $parsedDate = [System.DateTime]::ParseExact($date, $format, [System.Globalization.CultureInfo]::CurrentCulture)
            break
         } catch [Exception] {

         }
      }

      return $parsedDate
   }
}

Function Get-AppliedPenalties() {
<#
   .SYNOPSIS  
   Gets the penalties that are applied to a system.
   
   .DESCRIPTION
   Gets the penalties that are applied to a system. Uses HIPS version and timestamp.
     
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [System.Collections.Generic.List[psobject]]

   .PARAMETER PenaltyDefinitions
   The penalty definitions.

   .PARAMETER Properties
   The HIPS properties to check for scoring.

   .PARAMETER Version
   The HIPS version used to compare against.

   .PARAMETER Timestamp
   The timestamp used to compare against.

   .EXAMPLE
   Get-AppliedPenalties -PenaltyDefinitions $definitions -Properties (@{"Name"="Value"}) -Version ([System.Version]"8.0.1.2345") -Timestamp [DateTime]::Now
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[psobject]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty definitions.")]
      [ValidateNotNullOrEmpty()]
      [System.Collections.Hashtable]$PenaltyDefinitions,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The HIPS properties to check for scoring.")]
      [ValidateNotNullOrEmpty()]
      [System.Collections.Hashtable]$Properties,

      [Parameter(Position=2, Mandatory=$true, HelpMessage="The recommended HIPS version.")]
      [ValidateNotNullOrEmpty()]
      [System.Version]$RecommendedVersion,
	  
	  [Parameter(Position=3, Mandatory=$true, HelpMessage="The minimum recommended HIPS version.")]
      [ValidateNotNullOrEmpty()]
      [System.Version]$MinimumVersion,

      [Parameter(Position=4, Mandatory=$true, HelpMessage="The timestamp used to compare against.")]
      [ValidateNotNullOrEmpty()]
      [System.DateTime]$Timestamp
   )
   Process {
      $penalties = New-Object System.Collections.Generic.List[psobject]

      $installedProperty = "installed"
      $installedValue = $properties.Get_Item($installedProperty)

      if($properties.ContainsKey($installedProperty)) {
         $parsedValue = $false # default to failing value

         if([System.Boolean]::TryParse($installedValue, [ref]$parsedValue)) { 
            $isInstalled = $parsedValue  
         } else {
            throw "Unable to parse $installedProperty property with value of $installedValue as a boolean value" 
         }
         
         # any penalty that uses formatting in its Reason property MUST be cloned before we update the Reason otherwise the penalty "copy" (it is the same object reference) in $PenaltyDefinitions is updated too

         if($isInstalled) {
            $properties.GetEnumerator() | ForEach -Process {
               $property = [string]$_.Key
               $value = $_.Value

               # make sure $script:ParsedProperties and the switch statement in Get-AppliedProperties are changed in unison (add from both, subtract from both, change a name in both, etc) 

               switch($property.ToLower()) { # everything was inserted as lower case but do this just to be safe
                  "version" { 
                     $foundHIPSVersion = Expand-SystemVersion -Version $value

                     if($foundHIPSVersion.CompareTo($MinimumVersion) -lt 0) {
                        $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["UPDATE_HIPS_OLD"] 
                        $penalty.Reason = ($penalty.Reason -f $foundHIPSVersion,$MinimumVersion)
                        $penalties.Add($penalty)
                     }
                     elseif($foundHIPSVersion.CompareTo($RecommendedVersion) -lt 0) { # -1 means left (found) HIPS version is older than right (latest) HIPS version, 0 means equal versions, 1 = found HIPS version is newer than passed in value for latest HIPS version
                        $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["UPDATE_HIPS"] 
                        $penalty.Reason = ($penalty.Reason -f $foundHIPSVersion,$RecommendedVersion)
                        $penalties.Add($penalty)
                     }

                     break
                  }
                  "hipsservicestartmode" {
                     if(-not($value -ieq "auto")) {
                        $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["HIPS_SERVICE_NOT_AUTOMATIC"]
                        $penalty.Reason = ($penalty.Reason -f $value,"Automatic")
                        $penalties.Add($penalty)
                     }

                     break
                  }
                  "hipsservicerunstate" {
                     if(-not($value -ieq "running")) {
                        $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["HIPS_SERVICE_NOT_RUNNING"]
                        $penalty.Reason = ($penalty.Reason -f $value,"Running")
                        $penalties.Add($penalty)
                     }

                     break
                  }
                  "contentcreated" {
                     $maxDays = 37 # McAfee releases 1-2 HIPS security content releases a month so using 37 days should be safe, but this could be changed to 45 if that is too strict

                     $contentDate = Get-HIPSContentDate -Date $value

                     if([System.DateTime]::MaxValue -eq $contentDate) {
                        Write-Warning -Message ("Unable to parse HIPS content created date string '{0}'" -f $value) 
                     }
                     else {
                        $timespan = [System.TimeSpan]($Timestamp - $contentDate) 
                        $currentDays = $timespan.Days

                        if($currentDays -gt $maxDays) {
                           $contentVersion = $Properties["contentversion"]

                           $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["UPDATE_HIPS_CONTENT"]
                           $penalty.Reason = ($penalty.Reason -f $contentVersion,$currentDays,$maxDays)
                           $penalties.Add($penalty)
                        }
                     }

                     break
                  }
                  "ips_auditmodeenabled" {
                     $parsedValue = 1 # default to failing value

                     if([UInt32]::TryParse($value, [ref]$parsedValue)) { 
                        $audit = $parsedValue 
                     } else { 
                        throw "Unable to parse $property property with value of $value as an integer value" 
                     }

                     if($audit -ne 0) {
                        $penalties.Add($PenaltyDefinitions["HIPS_NOT_ENFORCING"])
                     }

                     break
                  }
                  "ips_hipsenabled" {
                     $parsedValue = 0 # default to failing value

                     if([UInt32]::TryParse($value, [ref]$parsedValue)) { 
                        $enabled = $parsedValue 
                     } else { 
                        throw "Unable to parse $property property with value of $value as an integer value" 
                     }

                     if($enabled -ne 1) {
                        $penalties.Add($PenaltyDefinitions["HIPS_NOT_ENABLED"])
                     }

                     break
                  }
                  "ips_reactionforhigh" {
                     $parsedValue = 0 # default to failing value

                     if([UInt32]::TryParse($value, [ref]$parsedValue)) { 
                        $reaction = $parsedValue 
                     } else { 
                        throw "Unable to parse $property property with value of $value as an integer value" 
                     }

                     if($reaction -ne 3) { # 3 is Prevent
                        switch ($reaction) {
                           2 { $reactionName = "Log" ; break }
                           1 { $reactionName = "Ignore" ; break }
                           default { $reactionName = "Unknown " + $reaction ; break }
                        }

                        $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["HIPS_NOT_PREVENTING_HIGH"]
                        $penalty.Reason = ($penalty.Reason -f $reactionName)
                        $penalties.Add($penalty)
                     }

                     break
                  }
                  "ips_reactionformedium" {
                     $parsedValue = 0 # default to failing value

                     if([UInt32]::TryParse($value, [ref]$parsedValue)) { 
                        $reaction = $parsedValue 
                     } else { 
                        throw "Unable to parse $property property with value of $value as an integer value" 
                     }

                     if($reaction -ne 3) { # 3 is Prevent
                        switch ($reaction) {
                           2 { $reactionName = "Log" ; break }
                           1 { $reactionName = "Ignore" ; break }
                           default { $reactionName = "Unknown " + $reaction ; break }
                        }

                        $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["HIPS_NOT_PREVENTING_MEDIUM"]
                        $penalty.Reason = ($penalty.Reason -f $reactionName)
                        $penalties.Add($penalty)
                     }

                     break
                  }
                  "ips_reactionforlow" {
                     $parsedValue = 0 # default to failing value

                     if([UInt32]::TryParse($value, [ref]$parsedValue)) { 
                        $reaction = $parsedValue 
                     } else { 
                        throw "Unable to parse $property property with value of $value as an integer value" 
                     }

                     if($reaction -lt 2) { # STIG says must be at least be set to Log
                        switch ($reaction) {
                           2 { $reactionName = "Log" ; break }
                           1 { $reactionName = "Ignore" ; break }
                           default { $reactionName = "Unknown " + $reaction ; break }
                        }

                        $penalty = Copy-PSObject -PSObject $PenaltyDefinitions["HIPS_NOT_LOGGING_LOW"]
                        $penalty.Reason = ($penalty.Reason -f $reactionName)
                        $penalties.Add($penalty)
                     }

                     break
                  }
               }
            }
         } else {
             $penalties.Add($PenaltyDefinitions["HIPS_NOT_INSTALLED"])
         }
      } else {
         Write-Warning -Message "Survey data was missing minimally required property"
      }

      return ,$penalties
   }
}

# System.Version object "drops off" any numbers that are 0 so it makes comparisons more difficult than needed
# e.g. 1.2.3.0 would end up being 1.2.3 which doesn't compare the same as 1.2.3.0. 
# this function ensures all 4 fields have a number e.g 1.2.3 will be converted to 1.2.3.0
Function Expand-SystemVersion() {
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The version.")]
      [ValidateNotNullOrEmpty()]
      [System.Version]$Version
   )
   Process{
      if ($Version.Major -eq -1) { $versionMajor = 0 } else { $versionMajor = $Version.Major }
  
      if ($Version.Minor -eq -1) { $versionMinor = 0 } else { $versionMinor = $Version.Minor }

      if ($Version.Build -eq -1) { $versionBuild = 0 } else { $versionBuild = $Version.Build }

      if ($Version.Revision -eq -1) { $versionRevision = 0 } else { $versionRevision = $Version.Revision }
   
      $expandedVersion = [System.Version]("" + $versionMajor + "." + $versionMinor + "." + $versionBuild  + "." + $versionRevision)
      return $expandedVersion
   }
}

Function Read-HIPSProperties() {
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path to the file containing the properties.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process{
      $properties = @{}

      if(Test-Path -Path $Path -PathType Leaf) {
         $content = Get-Content -Path $Path

         $lines = $content -split [System.Environment]::NewLine

         if($lines.Count -gt 0) {
            foreach($line in $lines) {
               $parts = $line -split "=";
               $key = $parts[0]
               $value = $null
               
               if(-not($properties.ContainsKey($key))) {
                  # there will always be 1 item returned by split even if the split char does not exist in the string
                  if($parts.Count -eq 1) {
                     $value = $null
                  } elseif ($parts.Count -eq 2) {
                     $value= $parts[1]
                  } else {
                     # this is the case for SomeRegValueName=SomeValue=with=Equal=Signs
                     # need to grab all from the right of the first equal sign and treat it as one value
                     $value = ($parts[1..($parts.Length-1)] -join "=")
                  }

                  $properties.Add($key, $value)
               } else {
                  Write-Warning -Message ("Duplicate property name {0} found. Value {1} was ignored." -f $key, $value)
               }
            }
         }     
      }

      return $properties
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
      [string]$PenaltyFile,

      [Parameter(Position=3, Mandatory=$true, HelpMessage="The recommended HIPS version.")]
      [ValidateNotNullOrEmpty()]
      [string]$RecommendedVersion,
	  
	  [Parameter(Position=4, Mandatory=$true, HelpMessage="The minimum recommended HIPS version.")]
      [ValidateNotNullOrEmpty()]
      [string]$MinimumVersion
   )
   Begin {
      $prefix = "LL_HBSS"
      $dataFile = "ll_hbss.txt"
      $recommendedHIPSVersion = Expand-SystemVersion -Version $RecommendedVersion
	  $minimumHIPSVersion = Expand-SystemVersion -Version $MinimumVersion
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

      New-Item -Path $TempPath -ItemType Container -ErrorAction Stop | Out-Null

      $zips = Get-Files -Path $DataPath -Filter "*.zip"

      if($zips -ne $null) {
         if($zips.Count -ge 1) {
            foreach($zip in $zips) {
               Expand-ZipFile -ZipFile $zip.FullName -Path (Join-Path -Path $TempPath -ChildPath $zip.BaseName)
            }
         }
      }

      $validXmls = New-Object System.Collections.Generic.List[string]

      $xmls = Get-Files -Path $TempPath -Filter "ll_*.xml"

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

                  try {
                     $surveyTimestamp = [System.DateTime]::ParseExact($timestamp, "yyyyMMddHHmmss", [System.Globalization.CultureInfo]::CurrentCulture)
                  } catch [Exception] {
                     Write-Warning -Message ("Using current timestamp rather than survey timestamp. Unable to parse survey timestamp from system XML due to {0}" -f $_)
                     $surveyTimestamp = [System.DateTime]::Now
                  }

                  $analysisTimestamp = "{0:yyyyMMddHHmmss}" -f [System.DateTime]::Now

                  $filename = ("{0}_{1}.{2}_{3}.xml") -f $prefix,$hostname,$domain,$timestamp

                  $dataFilePath = Join-Path -Path ([System.IO.FileInfo]$validXml).Directory.FullName -ChildPath $dataFile

                  if (Test-Path $dataFilePath) {
                     $properties = Read-HIPSProperties -Path $dataFilePath

                     # instead of using $analysisTimestamp (DateTime.Now), pass in the analysis timestamp from the system info XML file to prevent false positives if the data is re-analyzed later
                     $appliedPenalties = Get-AppliedPenalties -PenaltyDefinitions $penaltyDefinitions -Properties $properties -RecommendedVersion $recommendedHIPSVersion -MinimumVersion $minimumHIPSVersion -Timestamp $surveyTimestamp

                     $totalPenalty = (@($appliedPenalties | ForEach -Process { $_.Value}) | Measure-Object -Sum).Sum

                     $score = Get-MultiplicativeCumulativeScore -Penalties @($appliedPenalties | ForEach -Process { $_.Value})
                                         
                     Write-Verbose -Message ("OS Version: {0} SP: {1} Penalties: {2,2} Penalty Value: {3,3} Score: {4,3} Survey DateTime: {5} Analysis DateTime: {6} File: {7} Host: {8}.{9} OS Name: {10}" -f $os,$sp,$appliedPenalties.Count,$totalPenalty,$score,$timestamp,$analysisTimestamp,$filename,$hostname,$domain,$osName)

                     $scoreXmlPath = Join-Path -Path $TempPath -ChildPath $filename

                     $hostInfo = $xml.DocumentElement.SelectSingleNode(".") # works without having hardcode for 'systemInfo' 

                     New-ScoreXml -Name "HBSS" -Penalties $appliedPenalties -HostInformation $hostInfo -Path $scoreXmlPath
                  } else {
                     Write-Warning -Message ("HBSS data file did not exist at '{0}'" -f $dataFilePath)
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



# recommended version is 8.0.0.3363 which is HIPS 8.0 Patch 6
# minimally recommended version is 8.0.0.3203 which is HIPS 8.0 Patch 5
Invoke-Analyzer -DataPath $DataPath -TempPath $TempPath -PenaltyFile $PenaltyFile -RecommendedVersion "8.0.0.3363" -MinimumVersion "8.0.0.3203" -Verbose:$verbose


#Execute from inside the PowerShell ISE as:
# .\LL_HIPS_Analyzer.ps1 -i (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\TestData\Raw\LL_HIPS") -o (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\TestData\Analyzed\LL_HIPS") -p (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\LOCKLEVEL\LL_HIPS\Analyzer\penalties.xml")

#Execute from command line as:
# "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%USERPROFILE%\Documents\LOCKLEVEL\LL_HIPS\Analyzer\LL_HIPS_Analyzer.ps1" -i "%USERPROFILE%\Documents\LOCKLEVEL\TestData\Raw\LL_HIPS" -o "%USERPROFILE%\Documents\LOCKLEVEL\TestData\Analyzed\LL_HIPS" -p "%USERPROFILE%\Documents\LOCKLEVEL\LL_HIPS\Analyzer\penalties.xml"