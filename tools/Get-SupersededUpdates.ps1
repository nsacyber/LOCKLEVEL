[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")

#requires -version 2
Set-StrictMode -Version 2


Function Get-UniqueRelatedUpdates() {
<#
   .SYNOPSIS  
   Gets a unique list of updates that have the specified relationship with the specified update.
   
   .DESCRIPTION
   Gets a unique list of updates that have the specified relationship with the specified update.
  
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [string]

   .PARAMETER Update
   The update to get related updates for.

   .PARAMETER Relationship
   The the type of related updates to get.
   
   .EXAMPLE
   Get-UniqueRelatedUpdates -Update $update -Relationship ([Microsoft.UpdateServices.Administration.UpdateRelationship]::UpdatesThatSupersedeThisUpdate)
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Hashtable])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The update to get related updates for.")]
      [ValidateNotNullOrEmpty()]
      [Microsoft.UpdateServices.Administration.IUpdate]$Update,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The the type of related updates to get.")]
      [ValidateNotNullOrEmpty()]
      [Microsoft.UpdateServices.Administration.UpdateRelationship]$Relationship
   )
   $unique = @{}

   $queue = New-Object System.Collections.Generic.Queue[object]

   $current = $update.GetRelatedUpdates($Relationship)

   $current | ForEach { $queue.Enqueue($_) }

   while ($queue.Count -gt 0) {
      $item = $queue.Dequeue()

      if(-not($unique.ContainsKey($item.Title))) {
         $unique.Add($item.Title, $item)
      }
         
      if($item.IsSuperseded) {
         $current = $item.GetRelatedUpdates($Relationship)

         $current | ForEach { 
            if(-not($queue.Contains($_)) -and -not($unique.ContainsKey($_.Title))) { 
               $queue.Enqueue($item) 
            }
         }         
      }
   }

   return $unique
}

Function Get-Updates() {
<#
   .SYNOPSIS  
   Gets all the updates associated with specified KB article.
   
   .DESCRIPTION
   Gets all the updates associated with specified KB article.
  
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [string]

   .PARAMETER Server
   The WUS server to query.

   .PARAMETER KB
   The KB article.
   
   .EXAMPLE
   Get-Updates -Server "wsus.myintranet.com" -KB "KB1234567"
   #>
   [CmdletBinding()]
   [OutputType([System.Collections.Generic.List[Microsoft.UpdateServices.Administration.IUpdate]])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The server to check for updates.")]
      [ValidateNotNullOrEmpty()]
      [string]$Server,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="The KB for the update.")]
      [ValidateNotNullOrEmpty()]
      [string]$KB
   )

   $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($Server,$false,80)

   $updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

   $updatescope.TextIncludes = $KB

   $matchCount = $wsus.GetUpdateCount($updatescope)

   $overall = New-Object System.Collections.Generic.List[Microsoft.UpdateServices.Administration.IUpdate]

   if ($matchCount -gt 0) {
      $updates = $wsus.GetUpdates($updatescope)
    
      $updates | ForEach {
         Add-Member -InputObject $_ -TypeName System.Collections.Hashtable -MemberType NoteProperty -Name "Superseded" -Value @{}
         #Add-Member -InputObject $update -TypeName System.Collections.Hashtable -MemberType NoteProperty -Name "Superseding" -Value @{}

	     if($_.IsSuperseded) {
            $supers = Get-UniqueRelatedUpdates -Update $_ -Relationship ([Microsoft.UpdateServices.Administration.UpdateRelationship]::UpdatesThatSupersedeThisUpdate)
            $_.Superseded = $supers
	     }
  
  	     #if($update.HasSupersededUpdates) {
         #   $supers = Get-UniqueRelatedUpdates -Update $update -Relationship ([Microsoft.UpdateServices.Administration.UpdateRelationship]::UpdatesSupersededByThisUpdate)
         #   $update.Superseding = $supers
	     #}

         $overall.Add($_)
      }
   }

   return $overall
}

Function Print-Updates() {
<#
   .SYNOPSIS  
   Prints a summary of all the updates associated with a list of KB articles.
   
   .DESCRIPTION
   Prints a summary of all the updates associated with a list of KB articles.
  
   .INPUTS
   See parameters.
   
   .OUTPUTS
   [string]

   .PARAMETER Server
   The WUS server to query.

   .PARAMETER KB
   The KB article.
   
   .EXAMPLE
   Print-Updates -Server "wsus.myintranet.com" -KB "KB1234567","KB2345678","KB3456789"
   #>
   [CmdletBinding()]
   [OutputType([void])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The server to check for updates.")]
      [ValidateNotNullOrEmpty()]
      [string]$Server,

      [Parameter(Position=1, Mandatory=$true, HelpMessage="A list of KB articles to check")]
      [ValidateNotNullOrEmpty()]
      [string[]]$KB
   )

   $KB | ForEach {
      $kbid = $_
      $overall = @{}
      $unique = New-Object System.Collections.Generic.List[string]

      Write-Host "----------------------------------------------"
      Write-Host "KB: $kbid"
      Write-Host "----------------------------------------------"

      $updates = Get-Updates -Server $Server -KB $kbid

      $updates | ForEach {
         Write-Host "----------------------------------------------"
         Write-Host 'Update title:' $_.Title 
         Write-Host 'Creation Date:' $_.CreationDate 'Update Classification Title:' $_.UpdateClassificationTitle 'Severity:' $_.MsrcSeverity
         Write-Host 'Update ID: ' $_.Id.UpdateId 'Classification:' $_.UpdateClassificationTitle Update for: $_.UpdateType

         Write-Host Superseded: $_.IsSuperseded

         if($_.IsSuperseded) {
            $_.Superseded.Values | ForEach {
               Write-Host Superseded by: $_.Title $_.CreationDate

               if(-not($overall.ContainsKey($_.Title))) {
                  $overall.Add($_.Title, $_)
               }
            }
         }

         #Write-Host Supersedes: $_.HasSupersededUpdates

         #if($_.HasSupersededUpdates) {
         #   $_.Superseding.Values | ForEach {
         #      Write-Host Supersedes: $_.Title $_.CreationDate
         #   }
         #}
      }

      Write-Host ""

      Write-Host Overall superseded patches - $overall.Keys.Count - for patch $kbid are:

      $overall.Keys | Sort-Object | ForEach { Write-Host $_ }

      $overall.Keys | ForEach {
         $kbNumber = $_.Split("(")[1]
         $kbNumber = $kbNumber.Replace(")", "")

         if(-not($unique.Contains($kbNumber))) {
            $unique.Add($kbNumber)
         }
      }

      # add the original searched on KB number to the end of the list
      if(-not($unique.Contains($kbid))) {
         $unique.Add($kbid)
      }

      Write-Host ""

      Write-Host Overall unique KB numbers `(including the original`) - $unique.Count - for $kbid are:
      Write-Host ($unique -join ", ")

      Write-Host ""

   }
}


# Secure Search Path, Control Flow Guard, Certificate Padding, Kernel Null Page, ForceASLR
Print-Updates -KB @("KB2264107", "KB3000850", "KB2893294", "KB2813170", "KB2639308")
