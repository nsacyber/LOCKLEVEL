#requires -version 2
Set-StrictMode -Version 2

Function New-RemediationDefinition() {
<#
   .SYNOPSIS  
   Creates a new remediation definition.
   
   .DESCRIPTION
   Creates a new remediation definition.
  
   .INPUTS
   None
   
   .OUTPUTS
   [PSObject]
   
   .EXAMPLE
   New-RemediationDefinition -ID "ID_NAME" -Description "Description of the remediation"

   .EXAMPLE
   New-RemediationDefinition -ID "ID_NAME" -Description "Description of the remediation"
   #>
   [CmdletBinding()]
   [OutputType([object])]
   Param(    
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The remediation description.")]
      [ValidateNotNullOrEmpty()]
      [string]$Description,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The remediation ID. Think of it as a symbol rather than a numeric ID.")]
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
   None
   
   .OUTPUTS
   [PSObject]
   
   .EXAMPLE
   New-PenaltyDefinition -ID "ID_NAME" -Name "Penalty name" -Value 1 -Reason "You are getting a small penalty" -Remediation (New-RemediationDefinition -Description "Here is how you fix it"),(New-RemediationDefinition -Description "Here is another way you can fix it")

   .EXAMPLE
   New-PenaltyDefinition -ID "ID_NAME" -Name "Penalty name" -Value 100 -Reason "You are getting a big penalty" -Remediation (New-RemediationDefinition -Description "This is the only way you can fix it")
   #>
   [CmdletBinding()]
   [OutputType([object])]
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

      [Parameter(Position=4, Mandatory=$true, HelpMessage="The penalty ID. Think of it as a symbol rather than a numeric ID.")]
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

Function Get-PenaltyDefinitions() {
<#
   .SYNOPSIS  
   Gets the penalties defined for this analyzer.
   
   .DESCRIPTION
   Gets the penalties defined for this analyzer.
  
   .INPUTS
   None
   
   .OUTPUTS
   [System.Collections.Hashtable]
   
   .EXAMPLE
   Get-PenaltyDefinitions
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Hashtable])]
   Param()
   Process {   
      $penalties = @{}

      # LL_OS penalties

      $penalty = New-PenaltyDefinition -ID "UPGRADE_TO_WIN10" -Name "Not using the latest operating system version" -Value 10 -Reason "{0}{1} is installed which isn't the newest operating system." -Remediation (New-RemediationDefinition -ID "UPGRADE_TO_WINDOWS_10" -Description "Upgrade to Windows 10/Windows Server 2016 or later")
      $penalties.Add($penalty.ID, $penalty)	  
	  
      $penalty = New-PenaltyDefinition -ID "UPGRADE_TO_WIN81" -Name "Not using the latest operating system version" -Value 20 -Reason "{0}{1} is installed which isn't the newest operating system." -Remediation (New-RemediationDefinition -ID "UPGRADE_TO_WINDOWS_8_1" -Description "Upgrade to Windows 8.1/Windows Server 2012 R2 or later")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "UPGRADE_TO_WIN8" -Name "Not using the latest operating system version" -Value 30 -Reason "{0}{1} is installed which isn't the newest operating system" -Remediation (New-RemediationDefinition -ID "UPGRADE_TO_WINDOWS_8" -Description "Upgrade to Windows 8/Windows Server 2012 or later")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "UPGRADE_TO_WIN7" -Name "Not using the latest operating system version" -Value 60 -Reason "{0}{1} is installed which isn't the newest operating system" -Remediation (New-RemediationDefinition -ID "UPGRADE_TO_7_SP1" "Upgrade to Windows 7 SP1/Windows Server 2008 R2 SP1 or later")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "UNSUPPORTED_OS" -Name "Unsupported operating system version" -Value 100 -Reason "{0}{1} is installed. Windows XP/Windows Server 2003 and earlier operating systems are no longer supported by Microsoft" -Remediation (New-RemediationDefinition -ID "UPGRADE_TO_VISTA_SP2" -Description "Upgrade to Windows Vista SP2/Windows Server 2008 SP2 or later"),(New-RemediationDefinition -ID "UPGRADE_TO_7_SP1" -Description "Upgrade to Windows 7 SP1/Windows Server 2008 R2 SP1 or later"),(New-RemediationDefinition -ID "UPGRADE_TO_WINDOWS_8" -Description "Upgrade to Windows 8/Windows Server 2012 or later"),(New-RemediationDefinition -ID "UPGRADE_TO_WINDOWS_8_1" -Description "Upgrade to Windows 8.1/Windows Server 2012 R2 or later"),(New-RemediationDefinition -ID "UPGRADE_TO_WINDOWS_10" -Description "Upgrade to Windows 10/Windows Server 2016 or later")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "UNSUPPORTED_SP_WIN7" -Name "Unsupported service pack" -Value 100 -Reason "{0}{1} is no longer supported by Microsoft when running this service pack" -Remediation (New-RemediationDefinition -ID "UPGRADE_TO_7_SP1" -Description "Upgrade to Windows 7 SP1/Windows Server 2008 R2 SP1 or later")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "UNSUPPORTED_SP_WINVISTA" -Name "Unsupported service pack" -Value 100 -Reason "{0}{1} is no longer supported by Microsoft when running this service pack" -Remediation (New-RemediationDefinition -ID "UPGRADE_TO_VISTA_SP2" -Description "Upgrade to Windows Vista SP2/Windows Server 2008 SP2 or later")
      $penalties.Add($penalty.ID, $penalty)

      return ,$penalties
   }
}


Function New-PenaltyXml() {
<#
   .SYNOPSIS  
   Creates the XML that contains the penalties.
   
   .DESCRIPTION
   Creates the XML that contains the penalties.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   New-PenaltyXml -Penalties $penalties -Path "C:\result.xml"
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The penalties.")]
      [ValidateNotNull()]
      [AllowEmptyCollection()]
      [System.Collections.Hashtable]$Penalties,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The path to save the XML document to.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process {
      if(Test-Path -Path $Path -PathType Leaf) {
         Remove-Item -Path $Path -Force -ErrorAction Stop | Out-Null
      }

      $xmlDoc = New-Object System.Xml.XmlDocument

      [void]$xmlDoc.AppendChild($xmlDoc.CreateXmlDeclaration("1.0", "UTF-8", $null))
      
      $penaltiesElement = $xmlDoc.CreateElement("penalties");

      # creates "penalty" as the DocumentElement aka root
      [void]$xmlDoc.AppendChild($penaltiesElement)

      foreach($penalty in $Penalties.GetEnumerator()) {
         if($penalty.Key -ne $penalty.Value.ID) {
            throw "$($penalty.Key) did not match $($penalty.Value.ID)"
         }

         $penaltyElement = $xmlDoc.CreateElement("penalty")
         $penaltyElement.SetAttribute("id", $penalty.Value.ID)
         $penaltyElement.SetAttribute("name", $penalty.Value.Name)
         $penaltyElement.SetAttribute("value", $penalty.Value.Value)

         $reasonElement = $xmlDoc.CreateElement("reason")
         $reasonElement.InnerText = $penalty.Value.Reason
         [void]$penaltyElement.AppendChild($reasonElement)

         foreach($remediation in $penalty.Value.Remediation) {
            $remediationElement = $xmlDoc.CreateElement("remediation")
            $remediationElement.SetAttribute("id", $remediation.ID)
            $remediationElement.InnerText = $remediation.Description
            [void]$penaltyElement.AppendChild($remediationElement)
         }

         [void]$penaltiesElement.AppendChild($penaltyElement)
      }

      $xmlDoc.Save($Path)
   }
}


Function Main() {
<#
   .SYNOPSIS  
   Main method for generating the XML.
   
   .DESCRIPTION
   Main method for generating the XML.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   Main  
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The path of the output XML file.")]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )
   Process {
      $penalties = Get-PenaltyDefinitions
      New-PenaltyXml -Penalties $penalties -Path $Path
   }
}

$currentPath = Split-Path -Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path -Parent

Main -Path (Join-Path -Path $currentPath -ChildPath "penalties.xml")