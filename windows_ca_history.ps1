 param(            
	[parameter(            
		ValueFromPipeline=$true,            
		ValueFromPipelineByPropertyName=$true
		)
	] 
	[Alias("CN","__SERVER","Computer","CNAME")]            
	[string[]]$ComputerName=$env:ComputerName,            
	[string]$Key = "HKCU"       
)  

function Get-CertificateHistory {            
 <#
    .SYNOPSIS
	Returns the list of installed CA certificates sorted by date

	.DESCRIPTION
	Powershell tool to list installed CA certificates sorted by date, useful in the first incident phase to verify if any suspicious CAs have been installed.

	.PARAMETER Key
	Root Key to query

	HKLM - Placeholder with no corresponding physical hive. This key contains
	other keys that are hives.
	HKU  - Placeholder that contains the user-profile hives of logged-on
	accounts.


	.EXAMPLE
	Get-CertificateHistory -Key HKCU

	.EXAMPLE
	Get-CertificateHistory -Key HKLM

	.EXAMPLE
	Get-RegKeyLastWriteTime -SubKey Software\Microsoft

	.NOTES
	NAME: Get-CertificateHistory
	AUTHOR: Massimiliano Dal Cero [based on Shaunhess's "Reading the LastWriteTime of a registry key using Powershell" project]
	VERSION: 1.0
	LASTEDIT: 17MAR2024
	LICENSE: Creative Commons Attribution 3.0 Unported License
	(http://creativecommons.org/licenses/by/3.0/)

	.LINK
	https://www.linkedin.com/in/dalcero/
	#>            
            
	 [CmdletBinding()]            
				
	 param(            
		[parameter(            
				ValueFromPipeline=$true,            
				ValueFromPipelineByPropertyName=$true
			)
		]
		[Alias("CN","__SERVER","Computer","CNAME")]            
		[string[]]$ComputerName=$env:ComputerName,            
		[string]$Key = "HKCU"
	 )            
            
	PROCESS {            
		switch ($Key) {            
			#"HKCR" { $searchKey = 0x80000000} #HK Classes Root            
			"HKCU" { $searchKey = 0x80000001} #HK Current User            
			"HKLM" { $searchKey = 0x80000002} #HK Local Machine            
			#"HKU"  { $searchKey = 0x80000003} #HK Users            
			#"HKCC" { $searchKey = 0x80000005} #HK Current Config            
			default {            
				"Invalid Key. Use one of the following options: HKCU, HKLM"
			}
		}

		$Subkey = "SOFTWARE\Microsoft\SystemCertificates\Root\Certificates"
				
		$KEYQUERYVALUE = 0x1            
		$KEYREAD = 0x19            
		$KEYALLACCESS = 0x3F            
			  
		foreach($computer in $ComputerName) {            
              
			$sig0 = @'
[DllImport("advapi32.dll", SetLastError = true)]
  public static extern int RegConnectRegistry(
  	string lpMachineName,
	int hkey,
	ref int phkResult);
'@            
			$type0 = Add-Type -MemberDefinition $sig0 -Name Win32Utils -Namespace RegConnectRegistry -Using System.Text -PassThru            
            
			$sig1 = @'
[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
  public static extern int RegOpenKeyEx(
    int hKey,
    string subKey,
    int ulOptions,
    int samDesired,
    out int hkResult);
'@            
			$type1 = Add-Type -MemberDefinition $sig1 -Name Win32Utils -Namespace RegOpenKeyEx -Using System.Text -PassThru            
            
			$sig2 = @'
[DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
extern public static int RegEnumKeyEx(
    int hkey,
    int index,
    StringBuilder lpName,
    ref int lpcbName,
    int reserved,
    int lpClass,
    int lpcbClass,
    out long lpftLastWriteTime);


'@            
			$type2 = Add-Type -MemberDefinition $sig2 -Name Win32Utils -Namespace RegEnumKeyEx -Using System.Text -PassThru            
            
			$sig3 = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern int RegCloseKey(
    int hKey);
'@            
			$type3 = Add-Type -MemberDefinition $sig3 -Name Win32Utils -Namespace RegCloseKey -Using System.Text -PassThru            
			
			$hKey = new-object int            
			$hKeyref = new-object int            
			$searchKeyRemote = $type0::RegConnectRegistry($computer, $searchKey,   [ref]$hKey)            
			$result = $type1::RegOpenKeyEx($hKey, $SubKey, 0, $KEYREAD,   [ref]$hKeyref)            
			
			#initialize variables            
			$builder = New-Object System.Text.StringBuilder 1024            
			$index = 0            
			$length = [int] 1024            
			$time = New-Object Long            
			$objects = New-Object System.Collections.Generic.List[System.Object]
			#234 means more info, 0 means success. Either way, keep reading            
			while ( 0,234 -contains $type2::RegEnumKeyEx($hKeyref, $index++, $builder, [ref] $length, $null, $null, $null, [ref] $time) )            
			{            
				#create output object            
				$o = "" | Select Key, LastWriteTime, ComputerName, Cert            
				$o.ComputerName = "$computer"             
				$o.Key = $builder.ToString()            
				# TODO Change to use the time api    
				#Write-host ((Get-Date $time).ToUniversalTime())
				$timezone=[TimeZoneInfo]::Local
				$Offset=$timezone.BaseUtcOffset.TotalHours
				
				$o.LastWriteTime = (Get-Date $time).AddYears(1600).AddHours($Offset)            
				$objects.add($o)
				$reg_key = "$($key):\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\$($o.Key)\"
				$blob = (gp $reg_key)."Blob"
				$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$blob)
				$o.Cert = $cert
				$length = [int] 1024            
				$builder = New-Object System.Text.StringBuilder 1024            
			}            
			$result = $type3::RegCloseKey($hKey);
		}         
		$objects | Sort-Object -Property LastWriteTime
	}            
} # End Get-CertificateHistory function

Get-CertificateHistory -Key $Key | ForEach { "Last Write: " + $_.LastWriteTime; "`tCertificate Subject: " + $_.Cert.Subject; write-host "" }

