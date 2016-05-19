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

Function Get-Architecture() {
   [CmdletBinding()]
   [OutputType([System.Decimal])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The architecture.")]
      [ValidateNotNullOrEmpty()]
      [UInt32]$Architecture
   )
   Process {
      switch ($Architecture) {
         0 { $name = "x86" ; break}
         1 { $name = "Alpha" ; break}
         2 { $name = "MIPS" ; break}
         3 { $name = "PowerPC" ; break}
         5 { $name = "ARM" ; break}
         6 { $name = "Itanium" ; break} #ia64
         9 { $name = "x64" ; break}
         default { $name = "unknown"; break}
      }
      return $name
   }
}

Function Get-ProductType() {
   [CmdletBinding()]
   [OutputType([System.Decimal])]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The architecture number.")]
      [ValidateNotNullOrEmpty()]
      [UInt32]$ProductType
   )
   Process {
      switch ($ProductType) {
         1 { $role = "workstation" ; break}
         2 { $role = "domain controller" ; break}
         3 { $role = "server" ; break}
         default { $role = "unknown" ;break}
      }
      return $role
   }
}

Function New-SystemXml() {
<#
   .SYNOPSIS  
   Creates the system information XML from the given system information.
   
   .DESCRIPTION
   Creates the system information XML from the given system information.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   New-SystemXml -SystemInformation $info -Path "C:\result.xml"
   #>
   [CmdletBinding()]
   Param(
      [Parameter(Position=0, Mandatory=$true, HelpMessage="The system information.")]
      [ValidateNotNull()]
      [AllowEmptyCollection()]
      [object]$SystemInformation,

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
      
      $systemElement = $xmlDoc.CreateElement("systemInfo");    
      [void]$xmlDoc.AppendChild($systemElement)

      $systemInfo | gm -MemberType NoteProperty | ForEach -Process { 
         $name = $_.Name 
         $value = [object]$systemInfo.$($_.Name) # we don't want it automatically casted to a string so we can use non-primitives as objects in the switch statement
      
         $element = $xmlDoc.CreateElement($name) 

         switch ($name) {
            "timeStamp" {
               if($value -ne $null) {
                  $element.InnerText = ("{0:yyyyMMddHHmmss}" -f $value)
               }           
               break 
            }
            default {
               if($value -ne $null) {
                  $element.InnerText = $value
               }
               break
            }

         }
         [void]$xmlDoc.DocumentElement.AppendChild($element)
      }
      $xmlDoc.Save($Path)
   }
}

Function Get-SystemInformation() {
<#
   .SYNOPSIS  
   Gets the system information.
   
   .DESCRIPTION
   Gets the system information.
     
   .INPUTS
   None
   
   .OUTPUTS
   None
   
   .EXAMPLE
   Get-SystemInformation 
   #>
   [CmdletBinding()]
   Param()
   Begin {
     $type = @'
      using System.Runtime.InteropServices;
      using System;

      namespace Kernel32 
      {
         [StructLayout(LayoutKind.Explicit)]
         public struct _PROCESSOR_INFO_UNION
         {
            [FieldOffset(0)]
            internal UInt32 dwOemId;
            [FieldOffset(0)]
            internal UInt16 wProcessorArchitecture;
            [FieldOffset(2)]
            internal UInt16 wReserved;
         }

         [StructLayout(LayoutKind.Sequential)]
         public struct SYSTEM_INFO
         {
            internal _PROCESSOR_INFO_UNION uProcessorInfo;
            public UInt32 dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public UInt32 dwNumberOfProcessors;
            public UInt32 dwProcessorType;
            public UInt32 dwAllocationGranularity;
            public UInt16 wProcessorLevel;
            public UInt16 wProcessorRevision;
         }

         public class NativeMethods {
            [DllImport("kernel32.dll")]
            public static extern void GetNativeSystemInfo([MarshalAs(UnmanagedType.Struct)] ref SYSTEM_INFO lpSystemInfo);

            public static UInt16 OperatingSystemArchitecture
            {
               get
               {
                  SYSTEM_INFO systemInfo = new SYSTEM_INFO();
                  GetNativeSystemInfo(ref systemInfo);
                  return systemInfo.uProcessorInfo.wProcessorArchitecture;
               }
            }
         }
      }
'@

      Add-Type $type
   }
   Process {

      # make sure the property names have the exact case of what we want the XML elements to be cased as!
      $system = @{}

      $cs = Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object DNSHostName,Domain,Name,DomainRole,SystemType

      $system.hostName = $cs.DNSHostName
      $system.domainName = $cs.Domain

      $os = Get-WmiObject -Class "Win32_OperatingSystem" -Filter "Primary=true" | Select-Object Caption,OSArchitecture,OperatingSystemSKU,OtherTypeDescription,ProductType,ServicePackMajorVersion,ServicePackMinorVersion,Version,CSDVersion

      $osName = $os.Caption -replace "$([char]0x00A9)","" -replace "$([char]0x00AE)","" -replace "$([char]0x2122)","" # remove copyright, registered, and trademark symbols
      $osName = $osName -replace "\(R\)","" -replace "\(TM\)","" # (R) is used on Windows XP X64

      # Windows Server 2003 R2 uses this to signify R2 versus non-R2
      if($os.OtherTypeDescription -ne $null) {
         $osName = ($osName,$os.OtherTypeDescription -join " ")
      }

      $system.osName = $osName.Trim()

      $system.osVersion = [System.Version]$os.Version
      $system.servicePack = $os.ServicePackMajorVersion
      $system.productType = Get-ProductType -ProductType $os.ProductType
      
      #$hostName = [System.Net.Dns]::GetHostName() non-FQDN, $hostEntry.HostName will have FQDN
      #$hostEntry = [System.Net.Dns]::GetHostEntry($hostName)
      #$hostFQDN = $hostEntry.HostName

      $adapters = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Ethernet -and $_.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up })

      # grab the first adapter that has ipv4 addresses we can use
      foreach($adapter in $adapters) {
         $test =  @($adapter.GetIPProperties().UnicastAddresses | Where-Object {$_.IsDnsEligible -eq $true -and $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and -not([System.Net.IPAddress]::IsLoopback($_.Address.IPAddressToString)) })
         if($test -ne $null) {
            break
         }
      }
     
      $ipv4 = @($adapter.GetIPProperties().UnicastAddresses | Where-Object {$_.IsDnsEligible -eq $true -and $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and -not([System.Net.IPAddress]::IsLoopback($_.Address.IPAddressToString)) }) #IsDnsEligible -eq true gets rid of APIPA addresses (169.254.x.x)
     
      if($ipv4 -ne $null) {
         $system.ip4Address = $ipv4[0].Address.IPAddressToString
      } else {
         $system.ip4Address = $null
      }

      # matches the exe version's output but this ends up preferring IPV6 link local addresses to "real" IPv6 addresses. at some point fix the exe version and then remove the -and clause that includes "::"
      $ipv6 = @($adapter.GetIPProperties().UnicastAddresses | Where-Object {$_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and -not([System.Net.IPAddress]::IsLoopback($_.Address.IPAddressToString)) -and $_.Address.IPAddressToString -ne ("::" + $system.ip4Address) })

      if($ipv6 -ne $null) {
         $system.ip6Address = $ipv6[0].Address.IPAddressToString

         # strip off link local portion if it exists
         $index = $system.ip6Address.LastIndexOf("%")

         if ($index -ge 0) { 
            $system.ip6Address = $system.ip6Address[0..($index-1)] -join ""
         }
      } else {
         $system.ip6Address = $null
      }
      
      # could also use $adapter.GetPhysicalAddress().ToString() but we would need to add : characters to it
      #$system.macAddress = $net.MACAddress
      $system.macAddress = ((@($adapter.GetPhysicalAddress().ToString().ToCharArray() | ForEach -Begin {$index = 0} -Process { if ($index % 2 -eq 1) { ("{0}:" -f $_) } else { $_ } $index++ })) -join "").TrimEnd(@(":"))

      $system.timeStamp = [System.DateTime]::Now

      $processor = Get-WmiObject Win32_Processor -Filter "DeviceID='CPU0'" |Select-Object AddressWidth,DataWidth,Architecture,ProcessorId
      $system.hardArch = Get-Architecture -Architecture $processor.Architecture
     
      $system.osArch = Get-Architecture -Architecture ([Kernel32.NativeMethods]::OperatingSystemArchitecture)

      $systemInfo = New-Object -TypeName PSObject -Prop $system

      return $systemInfo
   }
}

Function Main() {
<#
   .SYNOPSIS  
   Main method for getting the system information and generating the XML.
   
   .DESCRIPTION
   Main method for getting the system information and generating the XML.
     
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
      $systemInfo = Get-SystemInformation
      New-SystemXml -SystemInformation $systemInfo -Path $Path
   }
}

#Main -Path (Join-Path -Path $env:USERPROFILE -ChildPath "Desktop\ps_ll_systeminfo.xml")
Main -Path "ps_ll_systeminfo.xml"