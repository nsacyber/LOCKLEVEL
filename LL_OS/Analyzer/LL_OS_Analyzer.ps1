<#
   .SYNOPSIS
   Executes the LOCKLEVEL Operating System analyzer.
   
   .DESCRIPTION
   Executes the LOCKLEVEL Operating System analyzer.
     
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
$script:PenaltyIDs = [string[]]@("UPGRADE_TO_WIN10", "UPGRADE_TO_WIN81","UPGRADE_TO_WIN8","UPGRADE_TO_WIN7", "UNSUPPORTED_SP_WIN7","UNSUPPORTED_SP_WINVISTA","UNSUPPORTED_OS")

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

Function Get-AppliedPenalties() {
<#
   .SYNOPSIS  
   Gets the penalties that are applied to a system.
   
   .DESCRIPTION
   Gets the penalties that are applied to a system. Uses operating system and service pack.
     
   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Generic.List[object]]
   
   .EXAMPLE
   Get-AppliedPenalties
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[object]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalty definitions.")]
      [ValidateNotNullOrEmpty()]
      [System.Collections.Hashtable]$PenaltyDefinitions,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The operating system name.")]
      [ValidateNotNull()]
      [AllowEmptyString()]
      [string]$Name,

      [Parameter(Position=2, Mandatory=$true, HelpMessage="The operating system version.")]
      [ValidateNotNullOrEmpty()]
      [decimal]$Version,
           
      [Parameter(Position=3, Mandatory=$true, HelpMessage="The operating system service pack.")]
      [ValidateNotNullOrEmpty()]
      [uint32]$ServicePack
   )
   Process {
      $penalties = New-Object System.Collections.Generic.List[psobject]

      if($Version -gt 6.3) { 

      } elseif ($Version -eq 6.3) {
         $penalties.Add($PenaltyDefinitions["UPGRADE_TO_WIN10"])
      } elseif ($Version -eq 6.2) { 
         $penalties.Add($PenaltyDefinitions["UPGRADE_TO_WIN81"])
      } elseif ($Version -eq 6.1) {
         if ($ServicePack -ge 1) {
            $penalties.Add($PenaltyDefinitions["UPGRADE_TO_WIN8"])
         } else {
            $penalties.Add($PenaltyDefinitions["UNSUPPORTED_SP_WIN7"])
         }
      } elseif ($Version -eq 6.0) {  
         if ($ServicePack -ge 2) {
            $penalties.Add($PenaltyDefinitions["UPGRADE_TO_WIN7"])
         } else {
            $penalties.Add($PenaltyDefinitions["UNSUPPORTED_SP_WINVISTA"])
         }
      } elseif ($Version -le 5.2 ) { 
         $penalties.Add($PenaltyDefinitions["UNSUPPORTED_OS"])
      }

      if($penalties.Count -gt 0) {
         # any penalty that uses formatting in its Reason property MUST be cloned before we update the Reason otherwise the penalty "copy" (it is the same object reference) in $PenaltyDefinitions is updated too
         $penalty = Copy-PSObject -PSObject $penalties[0]

         $sp = ""

         if($ServicePack -ne 0) {
            $sp = (" SP{0}" -f $ServicePack)
         }

         $penalty.Reason = ($penalty.Reason -f $Name,$sp)
         $penalties[0] = $penalty
      }

      return ,$penalties
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
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of a folder that contains the collected data that's used for scoring.")]
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
      $prefix="LL_OS"
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

                 if( ($hostname -eq $null) -or ($domain -eq $null) -or ($timestamp -eq $null) -or ($osName -eq $null) -or ($os -eq $null) -or ($sp -eq $null) ) {
                    throw "Error reading system information XML"
                 }

                 $analysisTimestamp = "{0:yyyyMMddHHmmss}" -f [System.DateTime]::Now

                 $filename = ("{0}_{1}.{2}_{3}.xml") -f $prefix,$hostname,$domain,$timestamp
              
                 # try and survive missing values as best as possible

                 if($osName -eq "") {
                    # it is ok to leave it empty
                    Write-Warning -Message "OS name was missing"
                 }

                 if($os -eq "") {
                    Write-Warning -Message "OS version was missing"
                    $osVersion = 0.0
                 } else {
                    $osVersion = [decimal](($os -split '\.')[0..1] -join ".")
                 }

                 if($sp -eq "") {
                    Write-Warning -Message "OS service pack number was missing"
                    $spNumber = 0
                 } else {
                    $spNumber = [uint32]($sp.Split(".")[0])
                 }

                 $appliedPenalties = Get-AppliedPenalties -PenaltyDefinitions $penaltyDefinitions -Name $osName -Version $osVersion -ServicePack $spNumber 

                 $totalPenalty = ( @($appliedPenalties | ForEach -Process { $_.Value}) | Measure-Object -Sum).Sum

                 $score = Get-MultiplicativeCumulativeScore -Penalties @($appliedPenalties | ForEach -Process { $_.Value})

                 Write-Verbose -Message ("OS Version: {0} SP: {1} Penalties: {2,2} Penalty Value: {3,3} Score: {4,3} Collection DateTime: {5} Analysis DateTime: {6} File: {7} Host: {8}.{9} OS Name: {10}" -f $os,$sp,$appliedPenalties.Count,$totalPenalty,$score,$timestamp,$analysisTimestamp,$filename,$hostname,$domain,$osName)

                 $scoreXmlPath = Join-Path -Path $TempPath -ChildPath $filename

                 $hostInfo = $xml.DocumentElement.SelectSingleNode(".") # works without having hardcode for 'systemInfo' 

                 New-ScoreXml -Name "OperatingSystem" -Penalties $appliedPenalties -HostInformation $hostInfo -Path $scoreXmlPath
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
# .\LL_OS_Analyzer.ps1 -i (Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\LOCKLEVEL\TestData\Raw\LL_OS") -o (Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\LOCKLEVEL\TestData\Analyzed\LL_OS") -p (Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\LOCKLEVEL\TestData\penalties.xml")

#Execute from command line as:
# "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "%USERPROFILE%\Documents\LOCKLEVEL\LL_OS\LL_OS\LL_OS_Analyzer.ps1" -i "%USERPROFILE%\Documents\LOCKLEVEL\TestData\Raw\LL_OS" -o "%USERPROFILE%\Documents\LOCKLEVEL\TestData\Analyzed\LL_OS" -p "%USERPROFILE%\Documents\LOCKLEVEL\TestData\penalties.xml"