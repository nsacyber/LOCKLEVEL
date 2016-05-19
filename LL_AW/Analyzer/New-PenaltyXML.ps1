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

      # LL_AW - SRP penalties

      $penalty = New-PenaltyDefinition -ID "SRP_NOT_WHITELISTING" -Name "SRP is not whitelisting" -Value 100 -Reason "Software Restriction Policies configuration is in '{0}' mode rather than in whitelisting mode" -Remediation (New-RemediationDefinition -ID "CONFIGURE_SRP_WHITELISTING" -Description "Configure SRP to be in whitelisting mode")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_RULE_NOT_ENFORCED" -Name "SRP rule is not enforcing" -Value 50 -Reason "A Software Restriction Policies rules is in '{0}' mode rather than in enforcement mode" -Remediation (New-RemediationDefinition -ID "CONFIGURE_SRP_RULE_ENFORCEMENT" -Description "Configure the SRP rule to be enforced")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_BLACKLIST_RULE_MISSING" -Name "SRP blacklist rule is missing" -Value 25 -Reason "A Software Restriction Policies blacklist rule for '{0}' is not configured which may allow some users to bypass SRP" -Remediation (New-RemediationDefinition -ID "ADD_SRP_BLACKLIST_RULE" -Description "Add a blacklist rule for '{0}' to SRP")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_SCOPE_USERS_ONLY" -Name "SRP scope" -Value 50 -Reason "The Software Restriction Policies scope is configured only for '{0}' rather than 'All Users'" -Remediation (New-RemediationDefinition -ID "CHANGE_SRP_SCOPE" -Description "Change SRP scope to apply to all users")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_BINARIES_NONE" -Name "SRP binaries" -Value 100 -Reason "Software Restriction Policies scope is configured to apply to '{0}' rather than 'All Software Files'" -Remediation (New-RemediationDefinition -ID "CHANGE_SRP_BINARIES" -Description "Change SRP to apply to all executables and libraries")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_BINARIES_EXE_ONLY" -Name "SRP binaries" -Value 75 -Reason "Software Restriction Policies scope is configured to apply to '{0}' rather than 'All Software Files'" -Remediation (New-RemediationDefinition -ID "CHANGE_SRP_BINARIES" -Description "Change SRP to apply to all executables and libraries")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_WHITELIST_RULE_MISSING" -Name "SRP whitelist rule is missing" -Value 75 -Reason "A Software Restriction Policies whitelist rule for '{0}' is not configured " -Remediation (New-RemediationDefinition -ID "ADD_SRP_WHITELIST_RULE" -Description "Add a whitelist rule for '{0}' to SRP")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_NO_PATH_RULES" -Name "No SRP path rules" -Value 25 -Reason "No Software Restriction Policies path rules were found" -Remediation (New-RemediationDefinition -ID "ADD_SRP_PATH_RULE" -Description "Add SRP path rules")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_NO_WHITELIST_RULES" -Name "No SRP whitelist rules" -Value 25 -Reason "No Software Restriction Policies whitelist rules were found" -Remediation (New-RemediationDefinition -ID "ADD_SRP_WHITELIST_RULES" -Description "Add SRP whitelist rules")
      $penalties.Add($penalty.ID, $penalty)
	  
	  $penalty = New-PenaltyDefinition -ID "SRP_NO_BLACKLIST_RULES" -Name "No SRP blacklist rules" -Value 100 -Reason "No Software Restriction Policies blacklist rules were found" -Remediation (New-RemediationDefinition -ID "ADD_SRP_BLACKLIST_RULES" -Description "Add all required SRP blacklist rules")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "SRP_MISSING_EXE_TYPE" -Name "SRP missing executable type" -Value 25 -Reason "An executable type of '{0}' is not in the Software Restriction Policies Designated File Types list" -Remediation (New-RemediationDefinition -ID "ADD_SRP_EXE_TYPE" -Description "Add an executable type of '{0}' to the SRP Designated File Types list")
      $penalties.Add($penalty.ID, $penalty)

      # LL_AW - AppLocker penalties

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_SERVICE_NOT_AUTOMATIC" -Name "AppLocker service is not automatically starting" -Value 100 -Reason "The Application Identity service start mode is set to '{0}' rather than '{1}' so the system is not protected at the next boot" -Remediation (New-RemediationDefinition -ID "SET_APPLOCKER_SERVICE_AUTO" -Description "Change the Application Identity service Startup Type to Automatic")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_SERVICE_NOT_RUNNING" -Name "AppLocker service is not running" -Value 100 -Reason "The Application Identity service state is '{0}' rather than '{1}' so the system is not protected" -Remediation (New-RemediationDefinition -ID "START_APPLOCKER_SERVICE" -Description "Start the Application Identity service")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_RULESET_NOT_ENFORCED" -Name "AppLocker rule set is not enforced" -Value 100 -Reason "The AppLocker rule set '{0}' is set to Audit rather than Enforcement" -Remediation (New-RemediationDefinition -ID "ENFORCE_APPLOCKER_RULESET" -Description "Change the AppLocker rule set '{0}' to enforcement mode")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_RULESET_NOT_CONFIGURED" -Name "AppLocker rule set is not configured" -Value 100 -Reason "The AppLocker rule set '{0}' is not configured" -Remediation (New-RemediationDefinition -ID "CONFIGURE_APPLOCKER_RULESET" -Description "Configure the AppLocker rule set '{0}'.")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_BAD_PUBLISHER" -Name "Bad AppLocker publisher rule" -Value 50 -Reason "AppLocker rule named '{0}' from the '{1}' rule set must be removed due to allowing any signed application to run" -Remediation (New-RemediationDefinition -ID "REMOVE_APPLOCKER_RULE" -Description "Remove the AppLocker rule named '{0}' from the '{1}' rule set")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_BLACKLIST_RULE_MISSING" -Name "AppLocker blacklist rule is missing" -Value 25 -Reason "The AppLocker rule named '{0}' from the '{1}' rule set is missing a required blacklist rule for '{2}'" -Remediation (New-RemediationDefinition -ID "ADD_APPLOCKER_BLACKLIST_RULE" -Description "Add a blacklist rule for '{0}' to the Applocker rule named '{1}' in the '{2}' rule set")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_NO_BLACKLIST_RULES" -Name "AppLocker rule set is missing all blacklist rules" -Value 100 -Reason "The AppLocker rule named '{0}' from the '{1}' rule set is missing all required blacklist rules" -Remediation (New-RemediationDefinition -ID "ADD_APPLOCKER_BLACKLIST_RULES" -Description "Add all blacklist rules to the Applocker rule named '{0}' in the '{1}' rule set")
      $penalties.Add($penalty.ID, $penalty)

      $penalty = New-PenaltyDefinition -ID "APPLOCKER_NO_USERPROFILE_RULES" -Name "AppLocker rule allows execution from user profile" -Value 100 -Reason "The AppLocker rule named '{0}' from the '{1}' rule set allows execution from user profiles" -Remediation (New-RemediationDefinition -ID "REMOVE_APPLOCKER_RULE" -Description "Remove the AppLocker rule named '{0}' from the '{1}' rule set")
      $penalties.Add($penalty.ID, $penalty)

      # LL_AW - generic penalties

      $penalty = New-PenaltyDefinition -ID "NO_WHITELISTING" -Name "No whitelisting found" -Value 100 -Reason "No supported whitelisting implementation was found" -Remediation (New-RemediationDefinition -ID "CONFIGURE_WHITELISTING" -Description "Implement a supported whitelisting technology")
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