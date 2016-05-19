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

      # LL_HIPS penalties

      $penalty = New-PenaltyDefinition -ID "UPDATE_HIPS" -Name "HIPS is outdated" -Value 50 -Reason "The version of HIPS ({0}) is not the latest recommended version ({1})" -Remediation (New-RemediationDefinition -ID "UPDATE_HIPS" -Description "Update HIPS to the latest version")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "UPDATE_HIPS_OLD" -Name "HIPS is very outdated" -Value 100 -Reason "The version of HIPS ({0}) is older than the minimum recommended version ({1}) and is very outdated" -Remediation (New-RemediationDefinition -ID "UPDATE_HIPS" -Description "Update HIPS to the latest version")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "UPDATE_HIPS_CONTENT" -Name "HIPS security content is outdated" -Value 50 -Reason "The HIPS security content version ({0}) is {1} days old which is beyond the limit of {2} days" -Remediation (New-RemediationDefinition -ID "UPDATE_HIPS_CONTENT" -Description "Update HIPS security content to the latest version")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_NOT_PREVENTING_HIGH" -Name "HIPS reaction is not prevent for high severity" -Value 80 -Reason "The HIPS Protection policy is configured for a reaction level of {0} rather than Prevent for high severity events" -Remediation (New-RemediationDefinition -ID "HIPS_PREVENT_HIGH" -Description "Change the HIPS Protection policy so high severity events are set to Prevent")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_NOT_PREVENTING_MEDIUM" -Name "HIPS reaction is not prevent for medium severity" -Value 40 -Reason "The HIPS Protection policy is configured for a reaction level of {0} rather than Prevent for medium severity events" -Remediation (New-RemediationDefinition -ID "HIPS_PREVENT_MEDIUM" -Description "Change the HIPS Protection policy so medium severity events are set to Prevent")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_NOT_LOGGING_LOW" -Name "HIPS reaction is not logging for low severity" -Value 10 -Reason "The HIPS Protection policy is configured for a reaction level of {0} rather than Log (or higher) for low severity events" -Remediation (New-RemediationDefinition -ID "HIPS_LOG_LOW" -Description "Change the HIPS Protection policy so low severity events are at least set to Log")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_SERVICE_NOT_AUTOMATIC" -Name "HIPS service is not automatically starting" -Value 100 -Reason "The HIPS service start mode is set to '{0}' rather than '{1}' so the system is not protected at the next boot" -Remediation (New-RemediationDefinition -ID "SET_HIPS_SERVICE_AUTO" -Description "Change the HIPS service Startup Type to Automatic")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_SERVICE_NOT_RUNNING" -Name "HIPS service is not running" -Value 100 -Reason "The HIPS service state is '{0}' rather than '{1}' so the system is not protected" -Remediation (New-RemediationDefinition -ID "START_HIPS_SERVICE" -Description "Start the HIPS service")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_NOT_ENFORCING" -Name "HIPS is not enforcing" -Value 100 -Reason "HIPS is in adaptive mode (aka audit mode) and not enforcing" -Remediation (New-RemediationDefinition -ID "DISABLE_HIPS_AUDIT_MODE" -Description "Disable HIPS adaptive mode (aka audit mode)")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_NOT_ENABLED" -Name "HIPS is not enabled" -Value 100 -Reason "HIPS is not enabled in HIPS policy" -Remediation (New-RemediationDefinition -ID "ENABLE_HIPS" -Description "Enable HIPS in HIPS policy")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "HIPS_NOT_INSTALLED" -Name "HIPS is not installed" -Value 100 -Reason "HIPS is not installed" -Remediation (New-RemediationDefinition -ID "INSTALL_HIPS" -Description "Install HIPS")
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