<#
		.SYNOPSIS
		NET-Experts PowerShell Open Source Tools and Functions

		.DESCRIPTION
		Small Tools and Functions that makes the powerful Script language
		PowerShell smarter!

		.NOTES
		New Module Layout

		.LINK
		Support https://github.com/jhochwald/NETX/issues

		.LINK
		Approve-MailAddress
		ConvertTo-Base64
		ConvertFrom-Base64
		ConvertFrom-BinHex
		ConvertTo-BinHex
		Check-SessionArch
		Get-TcpPortStatus
		Clear-AllEventLogs
		Clear-OldFiles
		Clear-TempDir
		Get-Clipboard
		Set-Clipboard
		Save-CommandHistory
		Load-CommandHistory
		Confirm-XMLisValid
		ConvertTo-HashTable
		ConvertTo-hex
		ConvertTo-HumanReadable
		ConvertTo-Objects
		ConvertTo-PlainText
		ConvertTo-StringList
		Create-ZIP
		Disable-IEESEC
		Edit-HostsFile
		ConvertTo-EscapeString
		ConvertFrom-EscapedString
		Expand-ArrayObject
		Expand-CompressedItem
		Explore
		Test-Filelock
		Get-FileLock
		Set-FirewallExceptionRDP
		Set-FirewallExceptionFileSharing
		Get-Accelerators
		Get-AdminUser
		Get-ASCBanner
		Get-AvailibleDriveLetter
		Get-BingSearch
		Get-Calendar
		Get-DiskInfo
		Get-EnvironmentVariables
		Get-ExternalIP
		Get-FreeDiskSpace
		Get-Hash
		Get-HostFileEntry
		Get-HttpHead
		Get-IsSessionElevated
		Get-IsVirtual
		Get-LocalIPAdresses
		Get-LocalListenPort
		Get-MicrosoftUpdateInfo
		Get-myPROCESS
		Get-NetFramework
		Get-NetStat
		Get-NewAesKey
		Get-NewPassword
		Get-Pause
		Get-PendingReboot
		Get-PhoneticSpelling
		Get-PreReqModules
		Get-Quote
		Get-RegKeyLastWriteTime
		Get-RelativePath
		Get-ReqParams
		Get-ScriptDirectory
		Get-ServiceStatus
		Get-ServiceStatusInfo
		Get-ShortDate
		Get-Syntax
		Get-SysType
		Get-TempFile
		Get-TimeStamp
		Get-TopProcesses
		Get-Uptime
		Get-UUID
		Get-ValidateFileName
		Get-ValidateIsIP
		Get-ValidatePath
		Get-Whois
		Invoke-GnuGrep
		Grant-PathFullPermission
		Compress-GZip
		Expand-GZip
		Invoke-PowerHead
		Invoke-PowerHelp
		Set-IgnoreSslTrust
		Set-NotIgnoreSslTrust
		Initialize-Modules
		Initialize-ModuleUpdate
		Invoke-AnimatedSleep
		Invoke-baloonTip
		Invoke-CreateMissingRegistryDrives
		Invoke-GC
		Invoke-NTFSFilesCompression
		Invoke-RemoteScript
		Invoke-VisualEditor
		Convert-IPToBinary
		Convert-IPtoDecimal
		Check-IPaddress
		Get-NtpTime
		Invoke-AppendClassPath
		Invoke-JavaLove
		Get-MaskedJson
		Get-RegularJson
		Invoke-PowerLL
		Reload-PesterModule
		Invoke-PowerHelp_2
		Invoke-MakeDirectory
		Update-SysInfo
		Clean-SysInfo
		Get-MOTD
		Get-SysInfo
		Get-MyLS
		New-BasicAuthHeader
		New-Gitignore
		New-Guid
		Open-InternetExplorer
		Add-AppendPath
		Remove-FromPath
		Out-ColorMatchInfo
		Find-String
		PoSHModuleLoader
		Get-sessionfile
		export-session
		import-session
		Enable-WinRM
		Get-NewPsSession
		Set-CurrentSession
		Send-Command
		Register-Script
		Send-Pushover
		Get-PushoverUserDeviceInfo
		Invoke-RDPSession
		Get-DefaultMessage
		Disable-RemoteDesktop
		Enable-RemoteDesktop
		Reload-Module
		Remove-ItemSafely
		Remove-TempFiles
		Repair-DotNetFrameWorks
		Reset-Prompt
		Get-EncryptSecretText
		Get-DecryptSecretText
		Send-HipChat
		Send-Packet
		Send-Prowl
		Send-SlackChat
		Set-AcceptProtocolViolation
		Set-Culture
		Set-DebugOn
		Set-DebugOff
		Set-Encoding
		Set-FolderDate
		Set-LinuxPrompt
		Set-PowerPrompt
		Set-VisualEditor
		Get-ShortDate_2
		Get-ShortTime
		Invoke-WithElevation
		tail
		tail2
		Test-Method
		Test-ModuleAvailableToLoad
		Test-ProxyBypass
		Test-RemotePOSH
		Test-TCPPort
		Get-Time
		Set-FileTime
		ConvertTo-UnixDate
		ConvertFrom-UnixDate
		ConvertFrom-UrlEncoded
		ConvertTo-UrlEncoded
		Get-TinyURL
		Get-IsGdURL
		Get-TrImURL
		Get-LongURL
		wc
		which
		whoami
		Write-ToLog
#>

<#
		Copyright (c) 2016, Quality Software Ltd.
		All rights reserved.

		Redistribution and use in source and binary forms, with or without
		modification, are permitted provided that the following conditions are met:

		1. Redistributions of source code must retain the above copyright notice,
		this list of conditions and the following disclaimer.

		2. Redistributions in binary form must reproduce the above copyright notice,
		this list of conditions and the following disclaimer in the documentation
		and/or other materials provided with the distribution.

		3. Neither the name of the copyright holder nor the names of its
		contributors may be used to endorse or promote products derived from
		this software without specific prior written permission.

		THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
		AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
		IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
		ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
		LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
		CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
		SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
		INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
		CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
		ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
		THE POSSIBILITY OF SUCH DAMAGE.

		By using the Software, you agree to the License, Terms and Conditions above!
#>

#region ModuleDefaults

# Temp Change to the Module Directory
Push-Location $PSScriptRoot

# Start the Module Loading Mode
$LoadingModule = $true

#endregion ModuleDefaults

#region Externals

#endregion Externals

#region Functions

function Approve-MailAddress {
	<#
			.SYNOPSIS
			REGEX check to see if a given Email address is valid

			.DESCRIPTION
			Checks a given Mail Address against a REGEX Filter to see if it is
			RfC822 complaint
			Not directly related is the REGEX check. Most mailer will not be able
			to handle it if there are non standard chars within the Mail Address...

			.PARAMETER Email
			e.g. "joerg.hochwald@outlook.com"
			Email address to check

			.EXAMPLE
			PS C:\> Approve-MailAddress -Email:"No.Reply@bewoelkt.net"
			True

			Description
			-----------
			Checks a given Mail Address (No.Reply@bewoelkt.net) against a REGEX
			Filter to see if it is RfC822 complaint

			.EXAMPLE
			PS C:\> Approve-MailAddress -Email:"Jörg.hochwald@gmail.com"
			False

			Description
			-----------
			Checks a given Mail Address (JÃ¶rg.hochwald@gmail.com) against a
			REGEX Filter to see if it is RfC822 complaint, and it is NOT

			.EXAMPLE
			PS C:\> Approve-MailAddress -Email:"Joerg hochwald@gmail.com"
			False

			Description
			-----------
			Checks a given Mail Address (Joerg hochwald@gmail.com) against a
			REGEX Filter to see if it is RfC822 complaint, and it is NOT

			.EXAMPLE
			PS C:\> Approve-MailAddress -Email:"Joerg.hochwald@gmail"
			False

			Description
			-----------
			Checks a given Mail Address (Joerg.hochwald@gmail) against a
			REGEX Filter to see if it is RfC822 complaint, and it is NOT

			.NOTES
			Internal Helper function to check Mail addresses via REGEX to see
			if they are RfC822 complaint before use them.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory = $true,
		HelpMessage = 'Enter the Mail Address that you would like to check (Mandatory)')]
		[ValidateNotNullOrEmpty()]
		[Alias('Mail')]
		[System.String]$Email
	)

	BEGIN {
		# Old REGEX check
		Set-Variable -Name 'EmailRegexOld' -Value $("^(?("")("".+?""@)|(([0-9a-zA-Z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-zA-Z])@))(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,6}))$" -as ([regex] -as [type]))

		# New REGEX check (Upper and Lowercase FIX)
		Set-Variable -Name 'EmailRegex' -Value $('^[_a-zA-Z0-9-]+(\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,6})$' -as ([regex] -as [type]))
	}

	PROCESS {
		# Check that the given Address is valid.
		if (($Email -match $EmailRegexOld) -and ($Email -match $EmailRegex)) {
			# Email seems to be valid
			Return $true
		} else {
			# Wow, that looks bad!
			Return $false
		}
	}
}

function ConvertTo-Base64 {
	<#
			.SYNOPSIS
			Convert a String to a Base 64 encoded String

			.DESCRIPTION
			Convert a String to a Base 64 encoded String

			.PARAMETER plain
			Un-Encodes Input String

			.EXAMPLE
			PS C:\> ConvertTo-Base64 -plain "Hello World"
			SABlAGwAbABvACAAVwBvAHIAbABkAA==

			Description
			-----------
			Convert a String to a Base 64 encoded String

			.EXAMPLE
			PS C:\> "Just a String" | ConvertTo-Base64
			SgB1AHMAdAAgAGEAIABTAHQAcgBpAG4AZwA=

			Description
			-----------
			Convert a String to a Base 64 encoded String via Pipe(line)

			.NOTES
			Companion function

			.LINK
			ConvertFrom-Base64
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Unencodes Input String')]
		[ValidateNotNullOrEmpty()]
		[Alias('unencoded')]
		[System.String]$plain
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name 'GetBytes' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'EncodedString' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# GetBytes .NET
		Set-Variable -Name 'GetBytes' -Value $([System.Text.Encoding]::Unicode.GetBytes($plain))

		#  Cobert to Base64 via .NET
		Set-Variable -Name 'EncodedString' -Value $([Convert]::ToBase64String($GetBytes))
	}

	END {
		# Dump the Info
		Write-Output -InputObject $EncodedString
	}
}

function ConvertFrom-Base64 {
	<#
			.SYNOPSIS
			Decode a Base64 encoded String back to a plain String

			.DESCRIPTION
			Decode a Base64 encoded String back to a plain String

			.PARAMETER encoded
			Base64 encoded String

			.EXAMPLE

			PS C:\> ConvertFrom-Base64 -encoded "SABlAGwAbABvACAAVwBvAHIAbABkAA=="
			Hello World

			Description
			-----------
			Decode a Base64 encoded String back to a plain String

			.EXAMPLE
			PS C:\> "SABlAGwAbABvACAAVwBvAHIAbABkAA==" | ConvertFrom-Base64
			Hello World

			Description
			-----------
			Decode a Base64 encoded String back to a plain String via Pipe(line)

			.NOTES
			Companion function

			.LINK
			ConvertTo-Base64
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Base64 encoded String')]
		[ValidateNotNullOrEmpty()]
		[System.String]$encoded
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name 'DecodedString' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Decode the Base64 encoded string back
		Set-Variable -Name 'DecodedString' -Value $(([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))) -as ([System.String] -as [type]))
	}

	END {
		# Dump the Info
		Write-Output -InputObject $DecodedString

		# Cleanup
		Remove-Variable -Name 'DecodedString' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function ConvertFrom-BinHex {
	<#
			.SYNOPSIS
			Convert a HEX Value to a String

			.DESCRIPTION
			Converts a given HEX value back to human readable strings

			.PARAMETER HEX
			HEX String that you like to convert

			.EXAMPLE
			PS C:\> ConvertFrom-BinHex 0c

			Description
			-----------
			Return the regular Value (12) of the given HEX 0c

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			ConvertTo-BinHex

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support: https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[ValidateNotNullOrEmpty()]
		$binhex
	)

	BEGIN {
		# Define a default
		Set-Variable -Name arr -Value $(New-Object byte[] -ArgumentList ($binhex.Length/2))
	}

	PROCESS {
		# Loop over the given string
		for ($i = 0; $i -lt $arr.Length; $i++) {
			$arr[$i] = [Convert]::ToByte($binhex.substring($i * 2, 2), 16)
		}
	}

	END {
		# Return the new value
		Write-Output -InputObject $arr
	}
}

function ConvertTo-BinHex {
	<#
			.SYNOPSIS
			Convert a String to HEX

			.DESCRIPTION
			Converts a given String or Array to HEX and dumps it

			.PARAMETER array
			Array that should be converted to HEX

			.EXAMPLE
			PS C:\> ConvertTo-BinHex 1234

			Description
			-----------
			Return the HEX Value (4d2) of the String 1234

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			ConvertFrom-BinHex

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support: https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[ValidateNotNullOrEmpty()]
		$array
	)

	BEGIN {
		# Define a default
		Set-Variable -Name str -Value $(New-Object system.text.stringbuilder)
	}

	PROCESS {
		# Loop over the String
		$array | ForEach-Object -Process {
			[void]$str.Append($_.ToString('x2'))
		}
	}

	END {
		# Print the String
		Write-Output -InputObject $str.ToString()
	}
}

function Check-SessionArch {
	<#
			.SYNOPSIS
			Show the CPU architecture

			.DESCRIPTION
			You want to know if this is a 64BIT or still a 32BIT system?
			Might be useful, maybe not!

			.EXAMPLE
			PS C:\> Check-SessionArch
			x64

			Description
			-----------
			Shows that the architecture is 64BIT and that the session also
			supports X64

			.NOTES
			Additional information about the function.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		# Figure out if this is a x64 or x86 system via NET call
		if ([System.IntPtr]::Size -eq 8) {
			Return 'x64'
		} elseif ([System.IntPtr]::Size -eq 4) {
			Return 'x86'
		} else {
			Return 'Unknown Type'
		}
	}
}

function Get-TcpPortStatus {
	<#
			.SYNOPSIS
			Check a TCP Port

			.DESCRIPTION
			Opens a connection to a given (or default) TCP Port to a given
			(or default) server.

			This is not a simple port ping, it creates a real connection to
			see if the port is alive!

			.PARAMETER Port
			Port to use e.g. "25", default is 587

			.PARAMETER Server
			SMTP Server to use e.g. "outlook.office365.com" or "192.168.16.10"

			.EXAMPLE
			PS C:\> Get-TcpPortStatus

			Description
			-----------
			Check port 587/TCP on the default Server

			.EXAMPLE
			PS C:\> Get-TcpPortStatus -Port:25 -Server:mx.NET-Experts.net
			True

			Description
			-----------
			Check port 25/TCP on Server mx.NET-Experts.net

			.NOTES
			Internal Helper function to check if we can reach a server via a TCP
			connection on a given port

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([bool])]
	param
	(
		[Parameter(HelpMessage = 'Port to use e.g. 25, default is 587')]
		[Int32]$Port = 587,
		[Parameter(HelpMessage = 'SMTP Server to use e.g. outlook.office365.com or 192.168.16.10')]
		[System.String]$Server = 'outlook.office365.com'
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name ThePortStatus -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Set the defaults for some stuff
		if (-not ($Port)) {
			# This is the default TCP Port to Check
			Set-Variable -Name Port -Value $('587' -as ([System.Int32] -as [type]))
		}

		# Server given?
		if (-not ($Server)) {
			# Do we know any defaults?
			if (-not ($PSEmailServer)) {
				# We have a default SMTP Server, use it!
				Set-Variable -Name Server -Value $("$PSEmailServer" -as ([System.String] -as [type]))
			} else {
				# Aw Snap! No Server given on the command line, no Server configured as default... BAD!
				Write-Error -Message 'No SMTP Server given, no default configured' -ErrorAction:Stop
			}
		}

		# Create a function to open a TCP connection
		Set-Variable -Name ThePortStatus -Value $(New-Object Net.Sockets.TcpClient -ErrorAction:SilentlyContinue)

		# Look if the Server is Online and the port is open
		try {
			# Try to connect to one of the on-premises Exchange front end servers
			$ThePortStatus.Connect($Server, $Port)
		} catch [System.Exception] {
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		}

		# Share the info with the caller
		$ThePortStatus.Client.Connected

		# Cleanup
		Remove-Variable -Name ThePortStatus -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

		# CLOSE THE TCP Connection
		if ($ThePortStatus.Connected) {
			# It works, close the connection
			$ThePortStatus.Close()
		}
	}

	END {
		# Cleanup
		Remove-Variable -Name ThePortStatus -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Clear-AllEventLogs {
	<#
			.SYNOPSIS
			Delete all EventLog entries

			.DESCRIPTION
			Delete all EventLog entries

			.EXAMPLE
			PS C:\> Clear-AllEventLogs

			Description
			-----------
			Ask if it should delete all EventLog entries and you need to confirm it

			.EXAMPLE
			PS C:\> Clear-AllEventLogs -Confirm:$false

			Description
			-----------
			Delete all EventLog entries and you do not need to confirm it

			.NOTES
			Could be great to clean up everything, but everything is gone forever!
	#>

	[CmdletBinding(ConfirmImpact = 'High',
	SupportsShouldProcess = $true)]
	[OutputType([System.String])]
	param ()

	BEGIN {
		if (-not (Get-AdminUser)) {
			Write-Output -InputObject 'Would clean all EventLog entires'
			Write-Output -InputObject ''
			Write-Output -InputObject 'But you need to be Admin to do that!'

			break
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess('Target', 'Operation')) {
			Get-EventLog -List | ForEach-Object -Process {
				Write-Host "Clearing $($_.Log)"
				Clear-EventLog -LogName $_.Log -Confirm:$false
			}
		} else {
			Write-Output -InputObject 'You denied to clean the EventLog entires...'
		}
	}
}

function Clear-OldFiles {
	<#
			.SYNOPSIS
			Removes old Logfiles

			.DESCRIPTION
			Convenience function to cleanup old Files (House Keeping)

			.PARAMETER days
			Files older then this will be deleted, the Default is 7 (For 7 Days)

			.PARAMETER Path
			The Path Where-Object the Logs are located,
			default is C:\scripts\PowerShell\log

			.PARAMETER Extension
			The File Extension that you would like to remove,
			the default is ALL (*)

			.EXAMPLE
			PS C:\> Clear-OldFiles

			Description
			-----------
			Will remove all files older then 7 days from C:\scripts\PowerShell\log
			You need to confirm every action!

			.EXAMPLE
			PS C:\> Clear-OldFiles -Confirm:$false

			Description
			-----------
			Will remove all files older then 7 days from C:\scripts\PowerShell\log
			You do not need to confirm any action!

			.EXAMPLE
			PS C:\> Clear-OldFiles -days:"30" -Confirm:$false

			Description
			-----------
			Will remove all files older then 30 days from C:\scripts\PowerShell\log
			You do not need to confirm any action!

			.EXAMPLE
			PS C:\> Clear-OldFiles -Extension:".csv" -days:"365" -Path:"C:\scripts\PowerShell\export" -Confirm:$false

			Description
			-----------
			Will remove all csv files older then 365 days from
			C:\scripts\PowerShell\export

			You do not need to confirm any action!

			.NOTES
			Want to clean out old logfiles?
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $false)]
	param
	(
		[Parameter(HelpMessage = 'Files older then this will be deleted, the Default is 7 (For 7 Days)')]
		[ValidateNotNullOrEmpty()]
		[System.Int32]$Days = 7,
		[Parameter(HelpMessage = 'The Path Where-Object the Logs are located, default is C:\scripts\PowerShell\log')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Path = 'C:\scripts\PowerShell\log',
		[Parameter(HelpMessage = 'The File Extension that you would like to remove, the drfault is ALL (*)')]
		[ValidateNotNullOrEmpty()]
		[Alias('ext')]
		[System.String]$Extension = '*'
	)

	PROCESS {
		Get-ChildItem $Path -Recurse -Include $Extension |
		Where-Object -FilterScript { $_.CreationTime -lt (Get-Date).AddDays(0 - $Days) } |
		ForEach-Object -Process {
			try {
				Remove-Item $_.FullName -Force -ErrorAction:Stop
				Write-Output "Deleted $_.FullName"
			} catch {
				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
			}
		}
	}
}

function Clear-TempDir {
	<#
			.SYNOPSIS
			Cleanup the TEMP Directory

			.DESCRIPTION
			Cleanup the TEMP Directory

			.PARAMETER Days
			Number of days, older files will be removed!

			.EXAMPLE
			PS C:\> Clear-TempDir
			Freed 439,58 MB disk space

			# Will delete all Files older then 30 Days (This is the default)
			# You have to confirm every item before it is deleted

			.EXAMPLE
			PS C:\> Clear-TempDir -Days:60 -Confirm:$false
			Freed 407,17 MB disk space

			Description
			-----------
			Will delete all Files older then 30 Days (This is the default)
			You do not have to confirm every item before it is deleted

			.NOTES
			Additional information about the function.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[OutputType([System.String])]
	param
	(
		[Parameter(Position = 0,
		HelpMessage = 'Number of days, older files will be removed!')]
		[Alias('RemoveOlderThen')]
		[System.Int32]$Days = 30,
		[switch]$Confirm = $true,
		[Switch]$Whatif = $false
	)

	# Do we want to confirm?
	if (-not ($Confirm)) {
		Set-Variable -Name '_Confirm' -Value $($false -as ([bool] -as [type]))
	} elseif ($Confirm) {
		Set-Variable -Name '_Confirm' -Value $($true -as ([bool] -as [type]))
	}

	# Is there a WhatIf?
	if (-not ($Whatif)) {
		Set-Variable -Name '_WhatIf' -Value $('#')
	} elseif ($Whatif) {
		Set-Variable -Name '_WhatIf' -Value $('-WhatIf')
	}

	# Set the Cut Off Date
	Set-Variable -Name 'cutoff' -Value $((Get-Date) - (New-TimeSpan -Days $Days))

	# Save what we have before we start the Clean up
	Set-Variable -Name 'before' -Value $((Get-ChildItem $env:temp | Measure-Object Length -Sum).Sum)

	# Find all Files within the TEMP Directory and process them
	Get-ChildItem $env:temp |
	Where-Object -FilterScript { ($_.Length) } |
	Where-Object -FilterScript { $_.LastWriteTime -lt $cutoff } |
	Remove-Item -Recurse -Force -ErrorAction:SilentlyContinue -Confirm:$_Confirm

	# How much do we have now?
	Set-Variable -Name 'after' -Value $((Get-ChildItem $env:temp | Measure-Object Length -Sum).Sum)

	'Freed {0:0.00} MB disk space' -f (($before - $after)/1MB)
}

function Get-Clipboard {
	<#
			.SYNOPSIS
			Get the content of the Clipboard

			.DESCRIPTION
			Get the content of the Clipboard

			.NOTES
			STA Mode only!

			.LINK
			Set-Clipboard
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		if ($Host.Runspace.ApartmentState -eq 'STA') {
			Add-Type -AssemblyName PresentationCore
			[Windows.Clipboard]::GetText()
		} else {
			Write-Warning -Message ('Run {0} with the -STA parameter to use this function' -f $Host.Name)
		}
	}
}

function Set-Clipboard {
	<#
			.SYNOPSIS
			Copy Content to the Clipboard

			.DESCRIPTION
			Copy Content to the Clipboard

			.PARAMETER Import
			Content to import

			.NOTES
			STA Mode only!

			.LINK
			Get-Clipboard
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Content to import')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Import
	)

	PROCESS {
		if ($Host.Runspace.ApartmentState -eq 'STA') {
			Add-Type -AssemblyName PresentationCore
			[Windows.Clipboard]::SetText($Import)
		} else {
			Write-Warning -Message ('Run {0} with the -STA parameter to use this function' -f $Host.Name)
		}
	}
}

function Save-CommandHistory {
	<#
			.SYNOPSIS
			Dump the Command History to an XML File

			.DESCRIPTION
			Dump the Command History to an XML File.
			This file is located in the User Profile.
			You can then restore it via Load-CommandHistory

			.EXAMPLE
			PS C:\> Save-CommandHistory

			Description
			-----------
			Dump the Command History to an XML file "commandHistory.xml" in the
			user profile folder

			.NOTES
			Companion command

			.LINK
			Load-CommandHistory
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Where-Object to store the XML History Dump
		Set-Variable -Name 'CommandHistoryDump' -Value $((Join-Path (Split-Path $profile.CurrentUserAllHosts) -ChildPath 'commandHistory.xml') -as ([System.String] -as [type]))

		# Be verbose
		Write-Verbose -Message "Save History to $($CommandHistoryDump)"

		# Dump the History
		Get-History | Export-Clixml -Path $CommandHistoryDump -Force -Confirm:$false -Encoding utf8
	}
}

function Load-CommandHistory {
	<#
			.SYNOPSIS
			Load the old History dumped via Save-CommandHistory

			.DESCRIPTION
			This is the companion Command for Save-CommandHistory
			It loads the old History from a XML File in the users Profile.

			.EXAMPLE
			PS C:\> Load-CommandHistory

			Description
			-----------
			load the Command History from an XML file "commandHistory.xml" in the
			user profile folder

			.NOTES
			Companion command

			.LINK
			Save-CommandHistory
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Where-Object to Find the XML History Dump
		Set-Variable -Name 'CommandHistoryDump' -Value $((Join-Path (Split-Path $profile.CurrentUserAllHosts) -ChildPath 'commandHistory.xml') -as ([System.String] -as [type]))

		# Be verbose
		Write-Verbose -Message 'Clear History to keep things clean'

		# Clear History to keep things clean
		# UP (Cursor) will sill show the existing command history
		Clear-History -Confirm:$false

		# Be verbose
		Write-Verbose -Message "Load History from $($CommandHistoryDump)"

		# Import the History
		Add-History -InputObject (Import-Clixml -Path $CommandHistoryDump)
	}
}

function Confirm-XMLisValid {
	<#
			.SYNOPSIS
			Checks if one, or more, given files looks like valid XML formated

			.DESCRIPTION
			This function do some basic checks to see if one, or more, given files
			looks valid XML formated.
			If you use multiple files at once, the answer is False (Boolean)
			even if just one is not valid!

			.PARAMETER XmlFilePath
			One or more Files to check

			.EXAMPLE
			PS C:\> Confirm-XMLisValid -XmlFilePath 'D:\apache-maven-3.3.9\conf\settings.xml'
			True

			Description
			-----------
			This will check if the file 'D:\apache-maven-3.3.9\conf\settings.xml'
			looks like a valis XML file, what is does.

			.EXAMPLE
			PS C:\> Confirm-XMLisValid -XmlFilePath 'D:\apache-maven-3.3.9\README.txt'
			False

			Description
			-----------
			Looks like the File 'D:\apache-maven-3.3.9\README.txt' is not a
			valid XML formated file.

			.EXAMPLE
			PS C:\> Confirm-XMLisValid -XmlFilePath 'D:\apache-maven-3.3.9\README.txt', 'D:\apache-maven-3.3.9\conf\settings.xml'
			False

			Description
			-----------
			Checks multiple Files to see if they are valid XML files.
			If one is not, "False" is returned!

			.NOTES
			The return is Boolean. The function should never throw an error,
			maximum is a warning! So if you want to catch a problem be aware
			of that!
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'One or more Files to check')]
		[System.String[]]$XmlFilePath
	)

	PROCESS {
		foreach ($XmlFileItem in $XmlFilePath) {

			if (Test-Path -Path $XmlFileItem -ErrorAction:SilentlyContinue) {
				try {
					# Get the file
					$XmlFile = (Get-Item -Path $XmlFileItem)

					# Keep count of how many errors there are in the XML file
					$script:ErrorCount = 0

					# Perform the XML Validation
					$ReaderSettings = (New-Object -TypeName System.Xml.XmlReaderSettings)
					$ReaderSettings.ValidationType = [System.Xml.ValidationType]::Schema
					$ReaderSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessInlineSchema -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation
					$ReaderSettings.add_ValidationEventHandler({ $script:ErrorCount++ })
					$Reader = [System.Xml.XmlReader]::Create($XmlFile.FullName, $ReaderSettings)

					# Now we try to figure out if this is a valid XML file
					try {
						while ($Reader.Read()) { }
					} catch {
						$script:ErrorCount++
					}

					# Close the open file
					$Reader.Close()

					# Verify the results of the XSD validation
					if ($script:ErrorCount -gt 0) {
						# XML is NOT valid
						Return $false
					} else {
						# XML is valid
						Return $true
					}
				} catch {
					Write-Warning -Message "$($MyInvocation.MyCommand.Name) - Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
				}
			} else {
				Write-Warning -Message "$($MyInvocation.MyCommand.Name) - Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
			}
		}
	}
}

function ConvertTo-HashTable {
	<#
			.Synopsis
			Convert an object to a HashTable

			.Description
			Convert an object to a HashTable excluding certain types.

			For example ListDictionaryInternal doesn't support serialization
			therefore can't be converted to JSON.

			.Parameter InputObject
			Object to convert

			.Parameter ExcludeTypeName
			Array of types to skip adding to resulting HashTable.
			Default is to skip ListDictionaryInternal and Object arrays.

			.Parameter MaxDepth
			Maximum depth of embedded objects to convert, default is 4.

			.Example
			$bios = Get-CimInstance win32_bios
			$bios | ConvertTo-HashTable

			Name                           Value
			----                           -----
			SoftwareElementState           3
			Manufacturer                   American Megatrends Inc.
			Caption                        4.6.5
			CurrentLanguage                en|US|iso8859-1

			Description
			-----------
			Convert an object to a HashTable

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	Param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[Object]$InputObject,
		[string[]]$ExcludeTypeName = @('ListDictionaryInternal', 'Object[]'),
		[ValidateRange(1, 10)]
		[System.Int32]$MaxDepth = 4
	)

	BEGIN {
		# Be Verbose
		Write-Verbose -Message "Converting to hashtable $($InputObject.GetType())"
	}

	PROCESS {
		$propNames = $InputObject.psobject.Properties | Select-Object -ExpandProperty Name

		$hash = @{ }

		$propNames | ForEach-Object -Process {
			if (($InputObject.$_)) {
				if ($InputObject.$_ -is [System.String] -or (Get-Member -MemberType Properties -InputObject ($InputObject.$_)).Count -eq 0) {
					$hash.Add($_, $InputObject.$_)
				} else {
					if ($InputObject.$_.GetType().Name -in $ExcludeTypeName) {
						# Be Verbose
						Write-Verbose "Skipped $_"
					} elseif ($MaxDepth -gt 1) {
						$hash.Add($_, (ConvertTo-HashTable -InputObject $InputObject.$_ -MaxDepth ($MaxDepth - 1)))
					}
				}
			}
		}
	}

	END {
		Write-Output -InputObject $hash
	}
}

function ConvertTo-hex {
	<#
			.SYNOPSIS
			Converts a given integer to HEX

			.DESCRIPTION
			Converts any given Integer (INT) to Hex and dumps it to the Console

			.PARAMETER dec
			N.A.

			.EXAMPLE
			PS C:\> ConvertTo-hex "100"
			0x64

			Description
			-----------
			Converts a given integer to HEX

			.NOTES
			Renamed function
			Just a little helper function

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([long])]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[long]$dec
	)

	PROCESS {
		# Print
		Return '0x' + $dec.ToString('X')
	}
}

function ConvertTo-HumanReadable {
	<#
			.SYNOPSIS
			Converts a given number to a more human readable format

			.DESCRIPTION
			Converts a given number to a more human readable format,
			it coverts 1024 to 1KB as example.

			.PARAMETER num
			Input Number

			.EXAMPLE
			PS C:\> ConvertTo-HumanReadable -num '1024'
			1,0 KB

			Description
			-----------
			Converts a given number to a more human readable format

			.EXAMPLE
			PS C:\> (Get-Item 'C:\scripts\PowerShell\profile.ps1').Length | ConvertTo-HumanReadable
			25 KB

			Description
			-----------
			Get the Size of a File (C:\scripts\PowerShell\profile.ps1 in this case)
			and make it human understandable

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Input Number')]
		[System.Int64]$num
	)

	PROCESS {
		switch ($num) { { $num -lt 1000 } { '{0,4:N0}  B' -f ($num)
			break }
			{ $num -lt 10KB } { '{0,4:N1} KB' -f ($num / 1KB)
			break }
			{ $num -lt 1000KB } { '{0,4:N0} KB' -f ($num / 1KB)
			break }
			{ $num -lt 10MB } { '{0,4:N1} MB' -f ($num / 1MB)
			break }
			{ $num -lt 1000MB } { '{0,4:N0} MB' -f ($num / 1MB)
			break }
			{ $num -lt 10GB } { '{0,4:N1} GB' -f ($num / 1GB)
			break }
			{ $num -lt 1000GB } { '{0,4:N0} GB' -f ($num / 1GB)
			break }
			{ $num -lt 10TB } { '{0,4:N1} TB' -f ($num / 1TB)
			break }
			default { '{0,4:N0} TB' -f ($num / 1TB) }
		}
	}
}

function ConvertTo-Objects {
	<#
			.SYNOPSIS
			You receive a result of a query and converts it to an array of objects
			which is

			.DESCRIPTION
			You receive a result of a query and converts it to an array of objects
			which is
			more legible to understand

			.PARAMETER Input
			Input Objects

			.EXAMPLE
			$input = Select-SqlCeServer 'SELECT * FROM TABLE1' 'Data Source=C:\Users\cdbody05\Downloads\VisorImagenesNacional\VisorImagenesNacional\DIVIPOL.sdf;'
			$input | ConvertTo-Objects

			Description
			-----------
			You receive a result of a query and converts it to an array of objects
			which is

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding()]
	[OutputType([System.Object[]])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Input Objects')]
		[Object[]]$Input
	)

	BEGIN {
		# Cleanup
		$arr = @()
		$count = 0
	}

	PROCESS {
		if ($Input) {
			# We load the results in order and loop over what we have then
			foreach ($item in $Input) {
				$count++
				$obj = (New-Object -TypeName PSObject)

				# List all the fields that are in the query
				$obj | Add-Member Noteproperty N $count
				for ($i = 0; $i -lt $item.FieldCount; $i++) { $obj | Add-Member Noteproperty $item.GetName($i) $item[$i] }
				$arr += $obj
			}
		}
	}

	END {
		# Dump
		$arr
	}
}

function ConvertTo-PlainText {
	<#
			.SYNOPSIS
			Convert a secure string back to plain text

			.DESCRIPTION
			Convert a secure string back to plain text

			.PARAMETER secure
			Secure String to convert

			.NOTES
			Helper function

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'Secure String to convert')]
		[ValidateNotNullOrEmpty()]
		[Alias('SecureString')]
		[security.securestring]$secure
	)

	BEGIN {
		# Define the Marshal Variable
		# We use the native .NET Call to do so!
		$marshal = [Runtime.InteropServices.Marshal]
	}

	PROCESS {
		# Return what we have
		# We use the native .NET Call to do so!
		Write-Output -InputObject "$($marshal::PtrToStringAuto($marshal::SecureStringToBSTR($secure)))"
	}
}

function ConvertTo-StringList {
	<#
			.SYNOPSIS
			Function to convert an array into a string list with a delimiter.

			.DESCRIPTION
			Function to convert an array into a string list with a delimiter.

			.PARAMETER Array
			Specifies the array to process.

			.PARAMETER Delimiter
			Separator between value, default is ","

			.EXAMPLE
			$Computers = "Computer1","Computer2"
			ConvertTo-StringList -Array $Computers

			Description
			-----------
			Computer1,Computer2

			.EXAMPLE
			$Computers = "Computer1","Computer2"
			ConvertTo-StringList -Array $Computers -Delimiter "__"

			Description
			-----------
			Computer1__Computer2

			.EXAMPLE
			$Computers = "Computer1"
			ConvertTo-StringList -Array $Computers -Delimiter "__"

			Description
			-----------
			Computer1

			.NOTES
			Based on an idea of Francois-Xavier Cat

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
		HelpMessage = 'Specifies the array to process.')]
		[ValidateNotNullOrEmpty()]
		[System.Array]$array,
		[Parameter(HelpMessage = 'Separator between value')]
		[system.string]$Delimiter = ','
	)

	BEGIN {
		Remove-Variable -Name 'StringList' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Be verbose
		Write-Verbose -Message "Array: $array"

		# Loop over each iten in the array
		foreach ($item in $array) {
			# Adding the current object to the list
			$StringList += "$item$Delimiter"
		}

		# Be verbose
		Write-Verbose -Message "StringList: $StringList"
	}

	END {
		try {
			if ($StringList) {
				$lenght = $StringList.Length

				# Be verbose
				Write-Verbose -Message "StringList Lenght: $lenght"

				# Output Info without the last delimiter
				$StringList.Substring(0, ($lenght - $($Delimiter.length)))
			}
		} catch {
			Write-Warning -Message '[END] Something wrong happening when output the result'
			$Error[0].Exception.Message
		} finally {
			Remove-Variable -Name 'StringList' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Create-ZIP {
	<#
			.SYNOPSIS
			Create a ZIP archive of a given file

			.DESCRIPTION
			Create a ZIP archive of a given file.
			By default within the same directory and the same name as the input
			file.
			This can be changed via command line parameters

			.PARAMETER InputFile
			Mandatory

			The parameter InputFile is the file that should be compressed.
			You can use it like this: "ClutterReport-20150617171648.csv",
			or with a full path like this:
			"C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv"

			.PARAMETER OutputFile
			Optional

			You can use it like this: "ClutterReport-20150617171648",
			or with a full path like this:
			"C:\scripts\PowerShell\export\ClutterReport-20150617171648"

			Do not append the extension!

			.PARAMETER OutputPath
			Optional

			By default the new archive will be created in the same directory as the
			input file, if you would like to have it in another directory specify
			it here like this: "C:\temp\"

			The directory must exist!

			.EXAMPLE
			PS C:\> Create-ZIP -InputFile "C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv"

			Description
			-----------
			This will create the archive "ClutterReport-20150617171648.zip" from
			the given input file
			"C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv".

			The new archive will be located in "C:\scripts\PowerShell\export\"!

			.EXAMPLE
			PS C:\> Create-ZIP -InputFile "C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv" -OutputFile "NewClutterReport"

			Description
			-----------
			This will create the archive "NewClutterReport.zip" from the given
			input file
			"C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv".

			The new archive will be located in "C:\scripts\PowerShell\export\"!

			.EXAMPLE
			PS C:\> Create-ZIP -InputFile "C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv" -OutputPath "C:\temp\"

			Description
			-----------
			This will create the archive "ClutterReport-20150617171648.zip" from
			the given input file
			"C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv".

			The new archive will be located in "C:\temp\"!

			The directory must exist!

			.EXAMPLE
			PS C:\> Create-ZIP -InputFile "C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv" -OutputFile "NewClutterReport" -OutputPath "C:\temp\"

			Description
			-----------
			This will create the archive "NewClutterReport.zip" from the given
			input file
			"C:\scripts\PowerShell\export\ClutterReport-20150617171648.csv".

			The new archive will be located in "C:\temp\"!

			The directory must exist!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
		HelpMessage = 'The parameter InputFile is the file that should be compressed (Mandatory)')]
		[ValidateNotNullOrEmpty()]
		[Alias('Input')]
		[System.String]$InputFile,
		[Alias('Output')]
		[System.String]$OutputFile,
		[System.String]$OutputPath
	)

	BEGIN {
		# Cleanup the variables
		Remove-Variable -Name MyFileName -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name MyFilePath -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name OutArchiv -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name zip -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Extract the Filename, without PATH and EXTENSION
		Set-Variable -Name MyFileName -Value $((Get-Item $InputFile).Name)

		# Check if the parameter "OutputFile" is given
		if (-not ($OutputFile)) {
			# Extract the Filename, without PATH
			Set-Variable -Name OutputFile -Value $((Get-Item $InputFile).BaseName)
		}

		# Append the ZIP extension
		Set-Variable -Name OutputFile -Value $($OutputFile + '.zip')

		# Is the OutputPath Parameter given?
		if (-not ($OutputPath)) {
			# Build the new Path Variable
			Set-Variable -Name MyFilePath -Value $((Split-Path -Path $InputFile -Parent) + '\')
		} else {
			# Strip the trailing backslash if it exists
			Set-Variable -Name OutputPath -Value $($OutputPath.TrimEnd('\'))

			# Build the new Path Variable based on the given OutputPath Parameter
			Set-Variable -Name MyFilePath -Value $(($OutputPath) + '\')
		}

		# Build a new Filename with Path
		Set-Variable -Name OutArchiv -Value $(($MyFilePath) + ($OutputFile))

		# Check if the Archive exists and delete it if so
		If (Test-Path $OutArchiv) {
			# If the File is locked, Unblock it!
			Unblock-File -Path:$OutArchiv -Confirm:$false -ErrorAction:Ignore -WarningAction:Ignore

			# Remove the Archive
			Remove-Item -Path:$OutArchiv -Force -Confirm:$false -ErrorAction:Ignore -WarningAction:Ignore
		}

		# The ZipFile class is not available by default in Windows PowerShell because the
		# System.IO.Compression.FileSystem assembly is not loaded by default.
		Add-Type -AssemblyName 'System.IO.Compression.FileSystem'

		# Create a new Archive
		# We use the native .NET Call to do so!
		Set-Variable -Name zip -Value $([System.IO.Compression.ZipFile]::Open($OutArchiv, 'Create'))

		# Add input to the Archive
		# We use the native .NET Call to do so!
		$null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $InputFile, $MyFileName, 'optimal')

		# Close the archive file
		$zip.Dispose()

		# Waiting for compression to complete...
		do {
			# Wait 1 second and try again if working entries are not null
			Start-Sleep -Seconds:'1'
		} while (($zip.Entries.count) -ne 0)

		# Extended Support for unattended mode
		if ($RunUnattended) {
			# Inform the Robot (Just pass the Archive Filename)
			Write-Output -InputObject "$OutArchiv"
		} else {
			# Inform the operator
			Write-Output -InputObject "Compressed: $InputFile"
			Write-Output -InputObject "Archive: $OutArchiv"
		}

		# If the File is locked, Unblock it!
		Unblock-File -Path:$OutArchiv -Confirm:$false -ErrorAction:Ignore -WarningAction:Ignore
	}

	END {
		# Cleanup the variables
		Remove-Variable -Name MyFileName -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name MyFilePath -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name OutArchiv -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name zip -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Disable-IEESEC {
	<#
			.SYNOPSIS
			Disabling IE Enhanced Security Configuration (IE ESC)

			.DESCRIPTION
			Disabling IE Enhanced Security Configuration (IE ESC)

			.PARAMETER Users
			Apply for Users?

			.PARAMETER Admins
			Apply for Admins?

			.PARAMETER All
			Apply for Users and Admins?

			.EXAMPLE
			PS C:\> Disable-IEESEC -Admins

			Description
			-----------
			Remove the IE Enhanced Security Configuration (IE ESC) for Admin Users

			.EXAMPLE
			PS C:\> Disable-IEESEC -Users

			Description
			-----------
			Remove the IE Enhanced Security Configuration (IE ESC) for regular
			Users

			.EXAMPLE
			PS C:\> Disable-IEESEC -All

			Description
			-----------
			Remove the IE Enhanced Security Configuration (IE ESC) for Admin and
			regular Users

			.EXAMPLE
			PS C:\> Disable-IEESEC -WhatIf
			What if: Performing the operation "Set the new value: Disable" on target "IE Enhanced Security Configuration".

			Description
			-----------
			Show what would be changed without doing it!

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(HelpMessage = 'Apply for Users?')]
		[switch]$Users = ($false),
		[Parameter(HelpMessage = 'Apply for Admins?')]
		[switch]$Admins = ($true),
		[Parameter(HelpMessage = 'Apply for Users and Admins?')]
		[switch]$All = ($false)
	)

	BEGIN {
		if ($All) {
			$Admins = ($true)
			$Users = ($true)
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess('IE Enhanced Security Configuration', 'Set the new value: Disable')) {
			# Set the new value for Admins
			if ($Admins) {
				$Key = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
				try {
					Set-ItemProperty -Path $Key -Name 'IsInstalled' -Value 0 -Scope:Script -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
				} catch {
					# Do nothing
					Write-Verbose -Message 'Minor Exception catched!'
				}
			}

			# Set the new value for Users
			if ($Users) {
				$Key = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
				try {
					Set-ItemProperty -Path $Key -Name 'IsInstalled' -Value 0 -Scope:Script -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
				} catch {
					# Do nothing
					Write-Verbose -Message 'Minor Exception catched!'
				}
			}

			# Enforce the new settings
			Stop-Process -Name Explorer
		}
	}
}

function Edit-HostsFile {
	<#
			.SYNOPSIS
			Edit the Windows Host file

			.DESCRIPTION
			Shortcut to quickly edit the Windows host File. Might be useful for
			testing things without changing the regular DNS.

			Handle with care!

			.EXAMPLE
			PS C:\> Edit-HostsFile

			Description
			-----------
			Opens the Editor configured within the VisualEditor variable to edit
			the Windows Host file

			.NOTES
			Additional information about the function.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Open the Host file with...
		if (-not ($VisualEditor)) {
			# Aw SNAP! The VisualEditor is not configured...
			Write-Error -Message 'System is not configured! The Visual Editor is not given...' -ErrorAction:Stop

			# If you want to skip my VisualEditor function, add the following here instead of the Write-Error:
			# Start-Process -FilePath notepad -ArgumentList "$env:windir\system32\drivers\etc\hosts"
		} else {
			# Here we go: Edit the Host file...
			Start-Process -FilePath $VisualEditor -ArgumentList "$env:windir\system32\drivers\etc\hosts"
		}
	}
}

function ConvertTo-EscapeString {
	<#
			.SYNOPSIS
			HTML on web pages uses tags and other special characters to define
			the page.

			.DESCRIPTION
			HTML on web pages uses tags and other special characters to define
			the page.
			To make sure text is not misinterpreted as HTML tags, you may want to
			escape text and automatically convert any ambiguous text character in
			an encoded format.

			.PARAMETER String
			String to escape

			.EXAMPLE
			PS C:\> ConvertTo-EscapeString -String "Hello World"
			Hello%20World

			Description
			-----------
			In this example we escape the space in the string "Hello World"

			.EXAMPLE
			PS C:\> "http://net-experts.net" | ConvertTo-EscapeString
			http%3A%2F%2Fnet-experts.net

			Description
			-----------
			In this example we escape the URL string

			.NOTES
			This function has a companion: ConvertFrom-EscapedString
			The companion reverses the escaped strings back to regular ones.

			.LINK
			ConvertFrom-EscapedString
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'String to escape')]
		[ValidateNotNullOrEmpty()]
		[Alias('Message')]
		[System.String]$String
	)

	PROCESS {
		# Try to Escape
		try {
			# We use the .NET EscapeDataString provided by the System.URI type
			[System.Uri]::EscapeDataString($String)
		} catch {
			# Whoooops!
			Write-Warning -Message "Sorry, but we Where-Object unable to escape $String"
		}
	}
}

function ConvertFrom-EscapedString {
	<#
			.SYNOPSIS
			Convert an encoded (escaped) string back into the original
			representation

			.DESCRIPTION
			If you have a escaped String this function make it human readable
			again.
			Some Webservices returns strings an escaped format, so we convert an
			encoded (escaped) string back into the original representation

			.PARAMETER String
			String to un-escape

			.EXAMPLE
			PS C:\> ConvertFrom-EscapedString -String "Hello%20World"
			Hello World

			Description
			-----------
			In this example we un-escape the space in the string "Hello%20World"

			.EXAMPLE
			PS C:\> "http%3A%2F%2Fnet-experts.net" | ConvertFrom-EscapedString
			http://net-experts.net

			Description
			-----------
			In this example we un-escape the masked (escaped) URL string

			.NOTES
			This function has a companion: ConvertTo-EscapeString
			The companion escapes any given regular string.

			.LINK
			ConvertTo-EscapeString
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'String to un-escape')]
		[ValidateNotNullOrEmpty()]
		[Alias('Message')]
		[System.String]$String
	)

	PROCESS {
		# Try to Un-escape
		try {
			# We use the .NET UnescapeDataString provided by the System.URI type
			[System.Uri]::UnescapeDataString($String)
		} catch {
			# Whoooops!
			Write-Warning -Message "Sorry, but we Where-Object unable to unescape $String"
		}
	}
}

function Expand-ArrayObject {
	<#
			.SYNOPSIS
			You get an array of objects and performs an expansion of data separated
			by a spacer

			.DESCRIPTION
			You get an array of objects and performs an expansion of data separated
			by a spacer

			.PARAMETER array
			Input Array

			.PARAMETER field
			Field to extract from the Array

			.PARAMETER delimiter
			Delimiter within the Array, default is ";"

			.EXAMPLE
			$arr | Expand-ArrayObject fieldX

			Description
			-----------
			You get an array of objects and performs an expansion of data separated
			by a spacer

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding()]
	[OutputType([System.Object[]])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Input Array')]
		[ValidateNotNullOrEmpty()]
		[System.Array]$array,
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Field to extract from the Array')]
		[System.String]$field,
		[Parameter(HelpMessage = 'Delimiter within the Array')]
		[System.Char]$Delimiter = ';'
	)

	BEGIN {
		[PSObject[]]$array_result = @()
	}

	PROCESS {
		foreach ($item in $array) {
			$item."$field" -split $Delimiter | ForEach-Object -Process { $newItem = $item.PSObject.Copy()
				$newItem."$field" = $_
			$array_result += $newItem }
		}
	}

	END {
		Write-Output -InputObject $array_result
	}
}

function Expand-CompressedItem {
	<#
			.SYNOPSIS
			Expands a compressed archive or container.

			.DESCRIPTION
			Expands a compressed archive or container.

			Currently only ZIP files are supported. Per default the contents of the
			ZIP is expanded in the current directory.
			If an item already exists, you will be visually prompted to overwrite
			it, skip it, or to have a second copy of the item expanded.
			This is due to the mechanism how this is implemented
			(via Shell.Application).

			.PARAMETER InputObject
			Specifies the archive to expand. You can either pass this parameter as
			a path and name to the archive or as a FileInfo object.
			You can also pass an array of archives to the parameter.
			In addition you can pipe a single archive or an array of archives to
			this parameter as well.

			.PARAMETER Path
			Specifies the destination path Where-Object to expand the archive.
			By default this is the current directory.

			.PARAMETER Format
			A description of the Format parameter.

			.EXAMPLE
			PS C:\> Expands an archive 'mydata.zip' to the current directory.

			Description
			-----------
			Expand-CompressedItem mydata.zip

			.EXAMPLE
			PS C:\> Expand-CompressedItem mydata.zip -Confirm

			Description
			-----------
			Expands an archive 'mydata.zip' to the current directory and
			prompts for every item to be extracted.

			.EXAMPLE
			PS C:\> Get-ChildItem Y:\Source\*.zip | Expand-CompressedItem -Path Z:\Destination -Format ZIP -Confirm

			Description
			-----------
			You can also pipe archives to the Cmdlet.
			Enumerate all ZIP files in 'Y:\Source' and pass them to the Cmdlet.
			Each item to be extracted must be confirmed.

			.EXAMPLE
			PS C:\> Expand-CompressedItem "Y:\Source\data1.zip","Y:\Source\data2.zip"

			Description
			-----------
			Expands archives 'data1.zip' and 'data2.zip' to the current directory.

			.EXAMPLE
			PS C:\> @("Y:\Source\data1.zip","Y:\Source\data2.zip") | Expand-CompressedItem

			Description
			-----------
			Expands archives 'data1.zip' and 'data2.zip' to the current directory.

			.NOTES
			See module manifest for required software versions and dependencies at:
			http://dfch.biz/biz/dfch/PS/System/Utilities/biz.dfch.PS.System.Utilities.psd1/

			.LINK
			Online Version: http://dfch.biz/biz/dfch/PS/System/Utilities/Expand-CompressedItem/
	#>

	[CmdletBinding(ConfirmImpact = 'Low',
			HelpUri = 'http://dfch.biz/biz/dfch/PS/System/Utilities/Expand-CompressedItem/',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Specifies the archive to expand. You can either pass this parameter as a path and name to the archive or as a FileInfo object. You can also pass an array of archives to the parameter. In addition you can pipe a single archive or an array of archives to this parameter as well.')]
		[ValidateScript({ Test-Path($_)
		})]
		[System.String]$InputObject,
		[Parameter(Position = 1)]
		[ValidateScript({ Test-Path($_)
		})]
		[System.IO.DirectoryInfo]$Path = $PWD.Path,
		[ValidateSet('default', 'ZIP')]
		[System.String]$Format = 'default'
	)

	BEGIN {
		# Build a string
		[System.String]$fn = ($MyInvocation.MyCommand.Name)

		# Currently only ZIP is supported
		switch ($Format) {
			'ZIP'
			{
				# We use the Shell to extract the ZIP file. If using .NET v4.5 we could have used .NET classes directly more easily.
				Set-Variable -Name ShellApplication -Value $(New-Object -ComObject Shell.Application)
			}
			default {
				# We use the Shell to extract the ZIP file. If using .NET v4.5 we could have used .NET classes directly more easily.
				Set-Variable -Name ShellApplication -Value $(New-Object -ComObject Shell.Application)
			}
		}

		# Set the Variable
		Set-Variable -Name CopyHereOptions -Value $(4 + 1024 + 16)
	}

	PROCESS {
		# Define a variable
		Set-Variable -Name fReturn -Value $($false
		)

		# Remove a variable that we do not need anymore
		Remove-Variable -Name OutputParameter -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

		# Loop over what we have
		foreach ($Object in $InputObject) {
			# Define a new variable
			Set-Variable -Name $Object -Value $(Get-Item $Object)

			# Check what we have here
			if ($pscmdlet.ShouldProcess(("Extract '{0}' to '{1}'" -f $Object.Name, $Path.FullName))) {
				# Set a new variable
				Set-Variable -Name CompressedObject -Value $($ShellApplication.NameSpace($Object.FullName))

				# Loop over what we have
				foreach ($item in $CompressedObject.Items()) {
					if ($pscmdlet.ShouldProcess(("Extract '{0}' to '{1}'" -f $item.Name, $Path.FullName))) {
						($ShellApplication.Namespace($Path.FullName).CopyHere($item, $CopyHereOptions))
					}
				}
			}
		}

		# Show what we have
		Write-Output -InputObject $OutputParameter
	}

	END {
		# Cleanup
		if ($ShellApplication) {
			# Remove a no longer needed variable
			Remove-Variable -Name ShellApplication -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}

		# Set another variable
		Set-Variable -Name datEnd -Value $([datetime]::Now)
	}
}

function Explore {
	<#
			.SYNOPSIS
			Open explorer in this directory

			.DESCRIPTION
			Open the Windows Explorer in this directory

			.PARAMETER Location
			Where to open the Windows Explorer, default is where the command is
			called

			.EXAMPLE
			PS C:\> Explore

			Description
			-----------
			Open the Windows Explorer in this directory

			.EXAMPLE
			PS C:\> Explore 'C:\scripts'

			Description
			-----------
			Open the Windows Explorer in 'C:\scripts'

			.NOTES
			Just a little helper function

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Alias('loc')]
		[System.String]$Location = '.'
	)

	PROCESS {
		# That is easy!
		explorer.exe '/e,'$Location""
	}
}

function Test-Filelock {
	<#
			.SYNOPSIS
			Test if a file is locked

			.DESCRIPTION
			Test if a file is locked

			.PARAMETER Path
			File to check

			.NOTES
			Just a helper function

			.LINK
			Get-FileLock
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'File to check')]
		[Alias('File')]
		[System.IO.FileInfo]$Path
	)

	PROCESS {
		try {
			# initialize variables
			$script:filelocked = $false

			# attempt to open file and detect file lock
			$script:fileInfo = (New-Object -TypeName System.IO.FileInfo -ArgumentList $Path)
			$script:fileStream = ($fileInfo.Open([System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None))

			# close stream if not lock
			if ($fileStream) {
				$fileStream.Close()
			}
		} catch {
			# catch fileStream had failed
			$filelocked = $true

		} finally {
			# return result
			[PSCustomObject]@{
				path       = $Path
				filelocked = $filelocked
			}
		}
	}
}

function Get-FileLock {
	<#
			.SYNOPSIS
			Test if a File is locked

			.DESCRIPTION
			Test if a File is locked

			.PARAMETER Path
			File to check

			.NOTES
			Companion function Test-Filelock is needed!

			.LINK
			Test-Filelock
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'File to check')]
		[ValidateNotNullOrEmpty()]
		[string]$Path
	)

	BEGIN {
		# Check if the helper function exists...
		if (-not (Get-Command Test-Filelock -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)) {
			#
			# Did not see this one coming!
			Write-Error -Message 'Sorry, something is wrong! please check that the command Test-Filelock is available!' -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		}
	}

	PROCESS {
		try {
			if (Test-Path $Path) {
				if ((Get-Item -Path $Path) -is [System.IO.FileInfo]) {
					return Test-Filelock -Path $Path
				} elseif ((Get-Item $Path) -is [System.IO.DirectoryInfo]) {
					Write-Verbose -Message "[$Path] detect as $((Get-Item -Path $Path).GetType().FullName). Skip check."
				}
			} else {
				Write-Error -Message "[$Path] could not be found."
			}
		} catch [System.Exception] {
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		} catch {
			# Did not see this one coming!
			Write-Error -Message "Could not check $Path" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		}
	}
}

function Set-FirewallExceptionRDP {
	<#
			.SYNOPSIS
			Enable RDP via Windows Firewall

			.DESCRIPTION
			Enable RDP via Windows Firewall

			.EXAMPLE
			PS C:\> Set-FirewallExceptionRDP

			Description
			-----------
			Enable RDP via Windows Firewall
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param ()

	PROCESS {
		netsh.exe advfirewall firewall set rule group="remote desktop" new enable=Yes
	}
}

function Set-FirewallExceptionFileSharing {
	<#
			.SYNOPSIS
			Enable File Sharing via Windows Firewall

			.DESCRIPTION
			Enable File Sharing via Windows Firewall

			.EXAMPLE
			PS C:\> Set-FirewallExceptionFileSharing

			Description
			-----------
			Enable File Sharing via Windows Firewall
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param ()

	PROCESS {
		netsh.exe advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
	}
}

function Get-Accelerators {
	<#
			.SYNOPSIS
			Get a list of all .NET functions

			.DESCRIPTION
			Get a list of all .NET functions

			.EXAMPLE
			PS C:\> Get-Accelerators
			Key                                                             Value
			---                                                             -----
			Alias                                                           System.Management.Automation.AliasAttribute

			Description
			-----------
			Get a list of all .NET functions

			.EXAMPLE
			PS C:\> Get-Accelerators | Format-List
			Key   : Alias
			Value : System.Management.Automation.AliasAttribute

			Key   : AllowEmptyCollection
			Value : System.Management.Automation.AllowEmptyCollectionAttribute

			Description
			-----------
			Get a list of all .NET functions

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		[psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')::get
	}
}

function Get-AdminUser {
	<#
			.SYNOPSIS
			Small function to see if we are Admin

			.DESCRIPTION
			Check if the user have started the PowerShell Session as Admin

			.EXAMPLE
			PS C:\> Get-AdminUser
			True

			Description
			-----------
			Return a boolean (True if the user is Admin and False if not)

			.EXAMPLE
			PS C:\> if ( Get-AdminUser ) {Write-Output "Hello Admin User"}

			Description
			-----------
			Prints "Hello Admin User" to the Console if the session is started
			as Admin!

			.NOTES
			Just a little helper function

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param ()

	BEGIN {
		# Set the objects
		Set-Variable -Name 'Id' -Value $([Security.Principal.WindowsIdentity]::GetCurrent())
		Set-Variable -Name 'IdWindowsPrincipal' -Value $(New-Object Security.Principal.WindowsPrincipal -ArgumentList ($Id))
	}

	PROCESS {
		# Return what we have
		Write-Output -InputObject "$($IdWindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
	}
}

function Get-ASCBanner {
	<#
			.SYNOPSIS
			Create an ASC II Banner for a given String

			.DESCRIPTION
			Create an ASC II Banner for a given String

			.PARAMETER IsString
			Is this a String that should be dumped as ASC Art?

			.PARAMETER ASCChar
			Character for the ASC Banner, * is the default

			.EXAMPLE
			PS C:\> Get-ASCBanner -InputString 'Welcome' -IsString -ASCChar '#'
			#     #
			#  #  #  ######  #        ####    ####   #    #  ######
			#  #  #  #       #       #    #  #    #  ##  ##  #
			#  #  #  #####   #       #       #    #  # ## #  #####
			#  #  #  #       #       #       #    #  #    #  #
			#  #  #  #       #       #    #  #    #  #    #  #
			## ##   ######  ######   ####    ####   #    #  ######

			Description
			-----------
			Create an ASC II Banner for a given String

			.EXAMPLE
			PS C:\> Get-ASCBanner -InputString 'NET-Experts' -IsString -ASCChar '*'
			*     * ******* *******         *******
			**    * *          *            *        *    *  *****   ******  *****    *****   ****
			* *   * *          *            *         *  *   *    *  *       *    *     *    *
			*  *  * *****      *     *****  *****      **    *    *  *****   *    *     *     ****
			*   * * *          *            *          **    *****   *       *****      *         *
			*    ** *          *            *         *  *   *       *       *   *      *    *    *
			*     * *******    *            *******  *    *  *       ******  *    *     *     ****

			Description
			-----------
			Create an ASC II Banner for a given String

			.NOTES
			Just for fun!
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				ValueFromRemainingArguments = $true,
				Position = 0,
		HelpMessage = 'The String')]
		[System.string[]]$InputString,
		[Parameter(Position = 1,
		HelpMessage = 'Is this a String that should be dumped as ASC Art?')]
		[switch]$IsString = ($true),
		[Parameter(Position = 2,
		HelpMessage = 'Character for the ASC Banner, * is the default')]
		[char]$ASCChar = '*'
	)

	BEGIN {
		$bit = @(128, 64, 32, 16, 8, 4, 2, 1)
		$chars = @(
			@(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), # ' '
			@(0x38, 0x38, 0x38, 0x10, 0x00, 0x38, 0x38), # '!'
			@(0x24, 0x24, 0x24, 0x00, 0x00, 0x00, 0x00), # '"' UNV
			@(0x28, 0x28, 0xFE, 0x28, 0xFE, 0x28, 0x28), # '#'
			@(0x7C, 0x92, 0x90, 0x7C, 0x12, 0x92, 0x7C), # '$'
			@(0xE2, 0xA4, 0xE8, 0x10, 0x2E, 0x4A, 0x8E), # '%'
			@(0x30, 0x48, 0x30, 0x70, 0x8A, 0x84, 0x72), # '&'
			@(0x38, 0x38, 0x10, 0x20, 0x00, 0x00, 0x00), # '''
			@(0x18, 0x20, 0x40, 0x40, 0x40, 0x20, 0x18), # '('
			@(0x30, 0x08, 0x04, 0x04, 0x04, 0x08, 0x30), # ')'
			@(0x00, 0x44, 0x28, 0xFE, 0x28, 0x44, 0x00), # '*'
			@(0x00, 0x10, 0x10, 0x7C, 0x10, 0x10, 0x00), # '+'
			@(0x00, 0x00, 0x00, 0x38, 0x38, 0x10, 0x20), # ','
			@(0x00, 0x00, 0x00, 0x7C, 0x00, 0x00, 0x00), # '-'
			@(0x00, 0x00, 0x00, 0x00, 0x38, 0x38, 0x38), # '.'
			@(0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80), # '/'
			@(0x38, 0x44, 0x82, 0x82, 0x82, 0x44, 0x38), # '0'
			@(0x10, 0x30, 0x50, 0x10, 0x10, 0x10, 0x7C), # '1'
			@(0x7C, 0x82, 0x02, 0x7C, 0x80, 0x80, 0xFE), # '2'
			@(0x7C, 0x82, 0x02, 0x7C, 0x02, 0x82, 0x7C), # '3'
			@(0x80, 0x84, 0x84, 0x84, 0xFE, 0x04, 0x04), # '4'
			@(0xFE, 0x80, 0x80, 0xFC, 0x02, 0x82, 0x7C), # '5'
			@(0x7C, 0x82, 0x80, 0xFC, 0x82, 0x82, 0x7C), # '6'
			@(0xFC, 0x84, 0x08, 0x10, 0x20, 0x20, 0x20), # '7'
			@(0x7C, 0x82, 0x82, 0x7C, 0x82, 0x82, 0x7C), # '8'
			@(0x7C, 0x82, 0x82, 0x7E, 0x02, 0x82, 0x7C), # '9'
			@(0x10, 0x38, 0x10, 0x00, 0x10, 0x38, 0x10), # ':'
			@(0x38, 0x38, 0x00, 0x38, 0x38, 0x10, 0x20), # ';'
			@(0x08, 0x10, 0x20, 0x40, 0x20, 0x10, 0x08), # '<'
			@(0x00, 0x00, 0xFE, 0x00, 0xFE, 0x00, 0x00), # '=' UNV.
			@(0x20, 0x10, 0x08, 0x04, 0x08, 0x10, 0x20), # '>'
			@(0x7C, 0x82, 0x02, 0x1C, 0x10, 0x00, 0x10), # '?'
			@(0x7C, 0x82, 0xBA, 0xBA, 0xBC, 0x80, 0x7C), # '@'
			@(0x10, 0x28, 0x44, 0x82, 0xFE, 0x82, 0x82), # 'A'
			@(0xFC, 0x82, 0x82, 0xFC, 0x82, 0x82, 0xFC), # 'B'
			@(0x7C, 0x82, 0x80, 0x80, 0x80, 0x82, 0x7C), # 'C'
			@(0xFC, 0x82, 0x82, 0x82, 0x82, 0x82, 0xFC), # 'D'
			@(0xFE, 0x80, 0x80, 0xF8, 0x80, 0x80, 0xFE), # 'E'
			@(0xFE, 0x80, 0x80, 0xF8, 0x80, 0x80, 0x80), # 'F'
			@(0x7C, 0x82, 0x80, 0x9E, 0x82, 0x82, 0x7C), # 'G'
			@(0x82, 0x82, 0x82, 0xFE, 0x82, 0x82, 0x82), # 'H'
			@(0x38, 0x10, 0x10, 0x10, 0x10, 0x10, 0x38), # 'I'
			@(0x02, 0x02, 0x02, 0x02, 0x82, 0x82, 0x7C), # 'J'
			@(0x84, 0x88, 0x90, 0xE0, 0x90, 0x88, 0x84), # 'K'
			@(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xFE), # 'L'
			@(0x82, 0xC6, 0xAA, 0x92, 0x82, 0x82, 0x82), # 'M'
			@(0x82, 0xC2, 0xA2, 0x92, 0x8A, 0x86, 0x82), # 'N'
			@(0xFE, 0x82, 0x82, 0x82, 0x82, 0x82, 0xFE), # 'O'
			@(0xFC, 0x82, 0x82, 0xFC, 0x80, 0x80, 0x80), # 'P'
			@(0x7C, 0x82, 0x82, 0x82, 0x8A, 0x84, 0x7A), # 'Q'
			@(0xFC, 0x82, 0x82, 0xFC, 0x88, 0x84, 0x82), # 'R'
			@(0x7C, 0x82, 0x80, 0x7C, 0x02, 0x82, 0x7C), # 'S'
			@(0xFE, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10), # 'T'
			@(0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x7C), # 'U'
			@(0x82, 0x82, 0x82, 0x82, 0x44, 0x28, 0x10), # 'V'
			@(0x82, 0x92, 0x92, 0x92, 0x92, 0x92, 0x6C), # 'W'
			@(0x82, 0x44, 0x28, 0x10, 0x28, 0x44, 0x82), # 'X'
			@(0x82, 0x44, 0x28, 0x10, 0x10, 0x10, 0x10), # 'Y'
			@(0xFE, 0x04, 0x08, 0x10, 0x20, 0x40, 0xFE), # 'Z'
			@(0x7C, 0x40, 0x40, 0x40, 0x40, 0x40, 0x7C), # '['
			@(0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02), # '\'
			@(0x7C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x7C), # ']'
			@(0x10, 0x28, 0x44, 0x00, 0x00, 0x00, 0x00), # '^'
			@(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE), # '_'
			@(0x00, 0x38, 0x38, 0x10, 0x08, 0x00, 0x00), # '`'
			@(0x00, 0x18, 0x24, 0x42, 0x7E, 0x42, 0x42), # 'a'
			@(0x00, 0x7C, 0x42, 0x7C, 0x42, 0x42, 0x7C), # 'b'
			@(0x00, 0x3C, 0x42, 0x40, 0x40, 0x42, 0x3C), # 'c'
			@(0x00, 0x7C, 0x42, 0x42, 0x42, 0x42, 0x7C), # 'd'
			@(0x00, 0x7E, 0x40, 0x7C, 0x40, 0x40, 0x7E), # 'e'
			@(0x00, 0x7E, 0x40, 0x7C, 0x40, 0x40, 0x40), # 'f'
			@(0x00, 0x3C, 0x42, 0x40, 0x4E, 0x42, 0x3C), # 'g'
			@(0x00, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x42), # 'h'
			@(0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08), # 'i'
			@(0x00, 0x02, 0x02, 0x02, 0x02, 0x42, 0x3C), # 'j'
			@(0x00, 0x42, 0x44, 0x78, 0x48, 0x44, 0x42), # 'k'
			@(0x00, 0x40, 0x40, 0x40, 0x40, 0x40, 0x7E), # 'l'
			@(0x00, 0x42, 0x66, 0x5A, 0x42, 0x42, 0x42), # 'm'
			@(0x00, 0x42, 0x62, 0x52, 0x4A, 0x46, 0x42), # 'n'
			@(0x00, 0x3C, 0x42, 0x42, 0x42, 0x42, 0x3C), # 'o'
			@(0x00, 0x7C, 0x42, 0x42, 0x7C, 0x40, 0x40), # 'p'
			@(0x00, 0x3C, 0x42, 0x42, 0x4A, 0x44, 0x3A), # 'q'
			@(0x00, 0x7C, 0x42, 0x42, 0x7C, 0x44, 0x42), # 'r'
			@(0x00, 0x3C, 0x40, 0x3C, 0x02, 0x42, 0x3C), # 's'
			@(0x00, 0x3E, 0x08, 0x08, 0x08, 0x08, 0x08), # 't'
			@(0x00, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C), # 'u'
			@(0x00, 0x42, 0x42, 0x42, 0x42, 0x24, 0x18), # 'v'
			@(0x00, 0x42, 0x42, 0x42, 0x5A, 0x66, 0x42), # 'w'
			@(0x00, 0x42, 0x24, 0x18, 0x18, 0x24, 0x42), # 'x'
			@(0x00, 0x22, 0x14, 0x08, 0x08, 0x08, 0x08), # 'y'
			@(0x00, 0x7E, 0x04, 0x08, 0x10, 0x20, 0x7E), # 'z'
			@(0x38, 0x40, 0x40, 0xC0, 0x40, 0x40, 0x38), # '{'
			@(0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10), # '|'
			@(0x38, 0x04, 0x04, 0x06, 0x04, 0x04, 0x38), # '}'
			@(0x60, 0x92, 0x0C, 0x00, 0x00, 0x00, 0x00) # '~'
		)
		$o = (New-Object -TypeName psobject)
		$o | Add-Member -MemberType NoteProperty -Name OriginalStrings -Value @()
		$o.psobject.typenames.Insert(0, 'Banner')
	}
	PROCESS {
		$o.OriginalStrings += $InputString
		$output = ''
		$width = [math]::floor(($Host.ui.rawui.buffersize.width - 1)/8)
		# check and bail if a string is too long
		foreach ($substring in $InputString) {
			if ($substring.length -gt $width) {
				throw "strings must be less than $width characters"
			}
		}

		foreach ($substring in $InputString) {
			for ($r = 0; $r -lt 7; $r++) {
				foreach ($c in $substring.ToCharArray()) {
					$bitmap = 0

					if (($c -ge ' ') -and ($c -le [char]'~')) {
						$offset = (([int]$c) - 32)
						$bitmap = ($chars[$offset][$r])
					}

					for ($c = 0; $c -lt 8; $c++) {
						if ($bitmap -band $bit[$c]) { $output += $ASCChar } else { $output += ' ' }
					}
				}

				$output += "`n"
			}
		}
		#$output
		$sb = ($executioncontext.invokecommand.NewScriptBlock("'$output'"))
		$o | Add-Member -Force -MemberType ScriptMethod -Name ToString -Value $sb

		if ($IsString) {
			$o.ToString()
		} else {
			$o
		}
	}
}

function Get-AvailibleDriveLetter {
	<#
			.SYNOPSIS
			Get an available Drive Letter

			.DESCRIPTION
			Get an available Drive Letter, next free available or random

			.PARAMETER Random
			Get a random available Drive letter instead of the next free available

			.EXAMPLE
			PS C:\> Get-AvailibleDriveLetter -Random
			O:

			Description
			-----------
			Get an available Drive Letter (A Random selection of a free letter)

			.EXAMPLE
			PS C:\> Get-AvailibleDriveLetter -Random
			F:

			Description
			-----------
			Get the next available unused Drive Letter (non random)

			.NOTES
			Found the base idea on PowerShellMagazine

			.LINK
			http://www.powershellmagazine.com/2012/01/12/find-an-unused-drive-letter/
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(HelpMessage = 'Get a random available Drive letter instead of the next available')]
		[switch]$Random
	)

	PROCESS {
		if ($Random) {
			Get-ChildItem -Path function:[d-z]: -Name |
			Where-Object -FilterScript { !(Test-Path $_) } |
			Get-Random
		} else {
			for ($j = 67; Get-PSDrive ($d = [char]++$j)2>0) { }$d + ':'
		}
	}
}

function Get-BingSearch {
	<#
			.SYNOPSIS
			Get the Bing results for a string

			.DESCRIPTION
			Get the latest Bin search results for a given string and presents it
			on the console

			.PARAMETER searchstring
			String to search for on Bing

			.EXAMPLE
			PS C:\> Get-BingSearch -searchstring:"Joerg Hochwald"

			Description
			-----------
			Return the Bing Search Results for "Joerg Hochwald"

			.EXAMPLE
			PS C:\> Get-BingSearch -searchstring:"KreativSign GmbH"

			Description
			-----------
			Return the Bing Search Results for "KreativSign GmbH" as a formated
			List (fl = Format-List)

			.NOTES
			This is a function that Michael found useful, so we adopted and
			tweaked it a bit.

			The original function was found somewhere on the Internet!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[ValidateNotNullOrEmpty()]
		[Alias('Search')]
		[System.String]$searchstring = $(throw 'Please specify a search string.')
	)

	BEGIN {
		# Use the native .NET Client implementation
		$client = New-Object -TypeName System.Net.WebClient

		# What to call?
		$url = "http://www.bing.com/search?q={0}`&format=rss" -f $searchstring
	}

	PROCESS {
		# By the way: This is XML ;-)
		[xml]$results = ($client.DownloadString($url))

		# Save the info to a variable
		$channel = ($results.rss.channel)

		# Now we loop over the return
		foreach ($item in $channel.item) {
			# Create a new Object
			$result = (New-Object -TypeName PSObject)

			# Fill the new Object
			$result | Add-Member -MemberType NoteProperty -Name Title -Value $item.title
			$result | Add-Member -MemberType NoteProperty -Name Link -Value $item.link
			$result | Add-Member -MemberType NoteProperty -Name Description -Value $item.description
			$result | Add-Member -MemberType NoteProperty -Name PubDate -Value $item.pubdate

			$sb = {
				$ie = New-Object -ComObject internetexplorer.application
				$ie.navigate($this.link)
				$ie.visible = $true
			}

			$result | Add-Member -MemberType ScriptMethod -Name Open -Value $sb
		}
	}

	END {
		# Dump it to the console
		Write-Output -InputObject $result
	}
}

function Get-Calendar {
	<#
			.SYNOPSIS
			Dumps a Calendar to the Console

			.DESCRIPTION
			Dumps a Calendar to the Console

			You might find it handy to have that on a core Server or in a remote
			PowerShell Session

			.PARAMETER StartDate
			The Date the Calendar should start

			.EXAMPLE
			PS C:\> Get-Calendar
			April 2016
			Mo Tu We Th Fr Sa Su
			01 02 03
			04 05 06 07 08 09 10
			11 12 13 14 15 16 17
			18 19 20 21 22 23 24
			25 26 27 28 29 30

			Description
			-----------
			Dumps a Calendar to the Console

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(HelpMessage = 'The Date the Calendar should start')]
		[ValidateNotNullOrEmpty()]
		[datetime]$StartDate = (Get-Date)
	)

	BEGIN {
		$startDay = (Get-Date (Get-Date $StartDate -Format 'yyyy-MM-01'))
	}

	PROCESS {
		Write-Host -Object (Get-Date $StartDate -Format 'MMMM yyyy')
		Write-Host -Object 'Mo Tu We Th Fr Sa Su'

		For ($i = 1; $i -lt (Get-Date $startDay).dayOfWeek.value__; $i++) {
			Write-Host -Object '   ' -NoNewline
		}

		$processDate = $startDay

		while ($processDate -lt $startDay.AddMonths(1)) {
			Write-Host -Object (Get-Date $processDate -Format 'dd ') -NoNewline

			if ((Get-Date $processDate).dayOfWeek.value__ -eq 0) { Write-Host -Object '' }
			$processDate = $processDate.AddDays(1)
		}

		Write-Host -Object ''
	}
}

function Get-DiskInfo {
	<#
			.SYNOPSIS
			Show free Diskspace for all Disks

			.DESCRIPTION
			This function gets your System Disk Information

			.EXAMPLE
			PS C:\> Get-DiskInfo
			Loading system disk free space information...
			C Drive has 24,77 GB of free space.
			D Drive has 1,64 GB of free space.

			Description
			-----------
			Show free Diskspace for all Disks

			.NOTES
			Internal Helper
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		$wmio = (Get-WmiObject -Class win32_logicaldisk)
		$Drives = ($wmio |
			Where-Object -FilterScript { ($_.size) } |
			Select-Object -Property Deviceid, @{
				name       = 'Free Space'
				Expression = { ($_.freespace/1gb) }
		})
		$DrivesString = (0..$($Drives.count - 1) | ForEach-Object -Process { " $(($Drives[$_]).Deviceid.Replace(':', ' Drive')) has $('{0:N2}' -f $(($Drives[$_]).'free space')) GB of free space.`r`n" })
		$DrivesString = "`r`nLoading system disk free space information...`r`n" + $DrivesString
	}

	END {
		Write-Output -InputObject $DrivesString
	}
}

function Get-EnvironmentVariables {
	<#
			.SYNOPSIS
			Get and list all Environment Variables

			.DESCRIPTION
			Dump all existing Environment Variables.
			Sometimes this comes handy if you do something that changes them an
			you want to compare the before and after values (See examples)

			.EXAMPLE
			PS C:\> Get-EnvironmentVariables

			# Get and list all Environment Variables

			.EXAMPLE
			PS C:\> $before = (Get-EnvironmentVariables)
			PS C:\> Installer
			PS C:\> $after = (Get-EnvironmentVariables)
			PS C:\> Compare-Object -ReferenceObject $before -DifferenceObject $after

			Description
			-----------
			Get and list all Environment Variables and save them to a variable.
			Install, or do whatever you want to do... Something that might change
			the Environment Variables.
			Get and list all Environment Variables again and save them to a
			variable.
			Compare the 2 results...

			.EXAMPLE
			PS C:\> (Get-EnvironmentVariables) | C:\scripts\PowerShell\export\before.txt
			PS C:\> Installer
			PS C:\> reboot
			PS C:\> (Get-EnvironmentVariables) | C:\scripts\PowerShell\export\after.txt
			PS C:\> Compare-Object -ReferenceObject 'C:\scripts\PowerShell\export\before.txt' -DifferenceObject 'C:\scripts\PowerShell\export\after.txt'

			Description
			-----------
			Get and list all Environment Variables and save them to a file.
			Install, or do whatever you want to do... Something that might change
			the Environment Variables.
			Get and list all Environment Variables again and save them to another
			file.
			Compare the 2 results...

			.NOTES
			Initial Version...
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	(Get-ChildItem -Path env: | Sort-Object -Property name)
}

function Get-ExternalIP {
	<#
			.Synopsis
			Gets the current external IP address.

			.Description
			Gets the current external IP address.

			.Example
			PS C:\> Get-ExternalIP
			84.132.180.143

			Description
			-----------
			Gets the current external IP address.

			.LINK
			http://tools.bewoelkt.net/ip.php
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	BEGIN {
		# URL to ask
		$site = 'http://tools.bewoelkt.net/ip.php'
	}

	PROCESS {
		try {
			# Use the native Web call function
			$beginbrowser = (New-Object -TypeName System.Net.WebClient)
			$get = ($beginbrowser.downloadString($site))
		} catch {
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

			# Done!!!
			break
		}
	}

	END {
		# Dump the IP info
		Write-Output -InputObject $get
	}
}

function Get-FreeDiskSpace {
	<#
			.SYNOPSIS
			Show the Free Disk Space of all Disks

			.DESCRIPTION
			This is a Uni* DF like command that shows the available Disk space.
			It's human readable (e.g. more like df -h)

			.EXAMPLE
			PS C:\scripts\PowerShell> Get-FreeDiskSpace
			Name Disk Size(GB) Free (%)
			---- ------------- --------
			C          64         42%
			D           2         84%

			Description
			-----------
			Show the Free Disk Space of all Disks

			.NOTES
			Just a quick hack to make Powershell more Uni* like

			.LINK
			Idea http://www.computerperformance.co.uk/powershell/powershell_get_psdrive.htm
	#>

	[CmdletBinding()]
	[OutputType([System.Array])]
	param ()

	PROCESS {
		# Get all Disks (Only logical drives of type 3)
		$Disks = ((Get-WmiObject -Class win32_logicaldisk | Where-Object -FilterScript { $_.DriveType -eq 3 }).DeviceID)

		# remove the ":" from the windows like Drive letter
		$Disks = ($Disks -replace '[:]', '')

		# Not sexy, but it works!
		# Base Idea is from here: http://www.computerperformance.co.uk/powershell/powershell_get_psdrive.htm
		(Get-PSDrive $Disks | Format-Table -Property Name, @{
				Name       = 'Disk Size(GB)'
				Expression = { '{0,8:N0}' -f ($_.free/1gb + $_.used/1gb) }
			}, @{
				Name       = 'Free (%)'
				Expression = { '{0,6:P0}' -f ($_.free / ($_.free + $_.used)) }
		} -AutoSize)
	}
}

function Get-Hash {
	<#
			.SYNOPSIS
			Dumps the MD5 hash for the given File

			.DESCRIPTION
			Dumps the MD5 hash for the given File

			.PARAMETER File
			File or path to dump MD5 Hash for

			.PARAMETER Hash
			Specifies the cryptographic hash function to use for computing the
			hash value of the contents of the specified file.

			.EXAMPLE
			PS C:\> Get-FileHash -File 'C:\scripts\PowerShell\PesterDocs.ps1'
			069DF9587DB0A8D3BA6D8E840099A2D9

			Description
			-----------
			Dumps the MD5 hash for the given File

			.EXAMPLE
			PS C:\> Get-Hash -File 'C:\scripts\PowerShell\PesterDocs.ps1' -Hash SHA1
			BC6B28A939CB3DBB82C9A7BDA5D80A191E8F06AE

			Description
			-----------
			Dumps the SHA1 hash for the given File

			.NOTES
			Re-factored to make it more flexible
			(cryptographic hash is now a parameter)
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'File or path to dum MD5 Hash for')]
		[System.String]$File,
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Specifies the cryptographic hash function to use for computing the hash value of the contents of the specified file.')]
		[ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')]
		[ValidateNotNullOrEmpty()]
		[System.String]$hash = 'MD5'
	)

	PROCESS {
		if (Get-Command Get-FileHash -ErrorAction:SilentlyContinue) {
			Return (Get-FileHash -Algorithm $hash -Path $File).Hash
		} else {
			Return $false
		}
	}
}

function Get-HostFileEntry {
	<#
			.SYNOPSIS
			Dumps the HOSTS File to the Console

			.DESCRIPTION
			Dumps the HOSTS File to the Console
			It dumps the WINDIR\System32\drivers\etc\hosts

			.EXAMPLE
			PS C:\> Get-HostFileEntry
			IP                                                              Hostname
			--                                                              --------
			10.211.55.123                                                   GOV13714W7
			10.211.55.10                                                    jhwsrv08R2
			10.211.55.125                                                   KSWIN07DEV

			Description
			-----------
			Dumps the HOSTS File to the Console

			.NOTES
			This is just a little helper function to make the shell more flexible
			Sometimes I need to know what is set in the HOSTS File...
			So I came up with that approach.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Cleanup
		$HostOutput = @()

		# Which File to load
		Set-Variable -Name 'HostFile' -Scope:Script -Value -Value $($env:windir + '\System32\drivers\etc\hosts')

		# REGEX Filter
		[regex]$r = '\S'
	}

	PROCESS {
		# Open the File from above
		Get-Content $HostFile |
		Where-Object -FilterScript {
			(($r.Match($_)).value -ne '#') -and ($_ -notmatch "^\s+$") -and ($_.Length -gt 0)
		} |
		ForEach-Object -Process {
			[void]$_ -match '(?<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?<HOSTNAME>\S+)'
			$HostOutput += New-Object -TypeName PSCustomObject -Property @{
				'IP'     = $matches.ip
				'Hostname' = $matches.hostname
			}
		}

		# Dump it to the Console
		Write-Output -InputObject $HostOutput
	}
}

function Get-HttpHead {
	<#
			.Synopsis
			Retrieve HTTP Headers from target web server

			.Description
			This command will get the HTTP headers from the target web server and
			test for the presence of various security related HTTP headers and
			also display the cookie information.

			.PARAMETER url
			The URL for inspection, e.g. https://www.linkedin.com

			.Example
			PS C:> Get-HttpHead -url https://www.linkedin.com
			Header Information for https://www.linkedin.com

			Description
			-----------
			Retrieve HTTPs Headers from www.linkedin.com

			.Example
			PS C:> Get-HttpHead -url http://net-experts.net
			Header Information for http://net-experts.net

			Description
			-----------
			Retrieve HTTP Headers from net-experts.net

			.NOTES
			Based on an idea of Dave Hardy, davehardy20@gmail.com @davehrdy20

			.LINK
			Source: https://github.com/davehardy20/PowerShell-Scripts/blob/master/Get-HttpSecHead.ps1
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
				Position = 0,
		HelpMessage = 'The URL for inspection, e.g. https://www.linkedin.com')]
		[ValidateNotNullOrEmpty()]
		[Alias('link')]
		[System.String]$url
	)

	BEGIN {
		# Cleanup
		$webrequest = $null
		$cookies = $null
		$cookie = $null
	}

	PROCESS {
		$webrequest = (Invoke-WebRequest -Uri $url -SessionVariable websession)
		$cookies = ($websession.Cookies.GetCookies($url))

		Write-Host -Object "`n"
		Write-Host 'Header Information for' $url
		Write-Host -Object ($webrequest.Headers | Out-String)
		Write-Host

		Write-Host -ForegroundColor White -Object "HTTP security Headers`nConsider adding the values in RED to improve the security of the webserver. `n"

		if ($webrequest.Headers.ContainsKey('x-xss-protection')) {
			Write-Host -ForegroundColor Green -Object "X-XSS-Protection Header PRESENT`n"
		} else {
			Write-Host -ForegroundColor Red -Object 'X-XSS-Protection Header MISSING'
		}

		if ($webrequest.Headers.ContainsKey('Strict-Transport-Security')) {
			Write-Host -ForegroundColor Green -Object 'Strict-Transport-Security Header PRESENT'
		} else {
			Write-Host -ForegroundColor Red -Object 'Strict-Transport-Security Header MISSING'
		}

		if ($webrequest.Headers.ContainsKey('Content-Security-Policy')) {
			Write-Host -ForegroundColor Green -Object 'Content-Security-Policy Header PRRESENT'
		} else {
			Write-Host -ForegroundColor Red -Object 'Content-Security-Policy Header MISSING'
		}

		if ($webrequest.Headers.ContainsKey('X-Frame-Options')) {
			Write-Host -ForegroundColor Green -Object 'X-Frame-Options Header PRESENT'
		} else {
			Write-Host -ForegroundColor Red -Object 'X-Frame-Options Header MISSING'
		}

		if ($webrequest.Headers.ContainsKey('X-Content-Type-Options')) {
			Write-Host -ForegroundColor Green -Object 'X-Content-Type-Options Header PRESENT'
		} else {
			Write-Host -ForegroundColor Red -Object 'X-Content-Type-Options Header MISSING'
		}

		if ($webrequest.Headers.ContainsKey('Public-Key-Pins')) {
			Write-Host -ForegroundColor Green -Object 'Public-Key-Pins Header PRESENT'
		} else {
			Write-Host -ForegroundColor Red -Object 'Public-Key-Pins Header MISSING'
		}

		Write-Host -Object "`n"

		Write-Host 'Cookies Set by' $url
		Write-Host -Object "Inspect cookies that don't have the HTTPOnly and Secure flags set."
		Write-Host -Object "`n"

		foreach ($cookie in $cookies) {
			Write-Host -Object "$($cookie.name) = $($cookie.value)"

			if ($cookie.HttpOnly -eq 'True') {
				Write-Host -Object "HTTPOnly Flag Set = $($cookie.HttpOnly)" -ForegroundColor Green
			} else {
				Write-Host -Object "HTTPOnly Flag Set = $($cookie.HttpOnly)" -ForegroundColor Red
			}

			if ($cookie.Secure -eq 'True') {
				Write-Host -Object "Secure Flag Set = $($cookie.Secure)" -ForegroundColor Green
			} else {
				Write-Host -Object "Secure Flag Set = $($cookie.Secure)" -ForegroundColor Red
			}

			Write-Host -Object "Domain = $($cookie.Domain) `n"
		}
	}

	END {
		# Cleanup
		$webrequest = $null
		$cookies = $null
		$cookie = $null
	}
}

function Get-IsSessionElevated {
	<#
			.SYNOPSIS
			Is the Session started as admin (Elevated)

			.DESCRIPTION
			Quick Helper that Return if the session is started as admin (Elevated)
			It returns a Boolean (True or False) and sets a global variable
			(IsSessionElevated) with this Boolean value.
			This might be useful for further use!

			.EXAMPLE
			PS C:\> Get-IsSessionElevated
			True

			Description
			-----------
			If the session is elevated

			.EXAMPLE
			PS C:\> Get-IsSessionElevated
			False

			Description
			-----------
			If the session is not elevated

			.NOTES
			Quick Helper that Return if the session is started as admin (Elevated)

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([bool])]
	param ()

	BEGIN {
		# Build the current Principal variable
		[System.Security.Principal.WindowsPrincipal]$currentPrincipal = (New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ([System.Security.Principal.WindowsIdentity]::GetCurrent()))

		# Do we have admin permission?
		[System.Security.Principal.WindowsBuiltInRole]$administratorsRole = ([System.Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	PROCESS {
		if ($currentPrincipal.IsInRole($administratorsRole)) {
			# Set the Variable
			Set-Variable -Name IsSessionElevated -Scope:Global -Value -Value $true

			# Yep! We have some power...
			Return $true
		} else {
			# Set the Variable
			Set-Variable -Name IsSessionElevated -Scope:Global -Value -Value $false

			# Nope! Regular User Session!
			Return $false
		}
	}
}

function Get-IsVirtual {
	<#
			.SYNOPSIS
			Check if this is a Virtual Machine

			.DESCRIPTION
			If this is a virtual System the Boolean is True, if not it is False

			.EXAMPLE
			PS C:\> Get-IsVirtual
			True

			Description
			-----------
			If this is a virtual System the Boolean is True, if not it is False

			.EXAMPLE
			PS C:\> Get-IsVirtual
			False

			Description
			-----------
			If this is not a virtual System the Boolean is False, if so it is True

			.NOTES
			The Function name is changed!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param ()

	BEGIN {
		# Cleanup
		Remove-Variable -Name SysInfo_IsVirtual -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name SysInfoVirtualType -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name WMI_BIOS -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name WMI_ComputerSystem -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Get some System infos via NET (WMI) call
		Set-Variable -Name 'WMI_BIOS' -Scope:Script -Value -Value $($WMI_BIOS = (Get-WmiObject -Class 'Win32_BIOS' -ErrorAction:Stop | Select-Object -Property 'Version', 'SerialNumber'))
		Set-Variable -Name 'WMI_ComputerSystem' -Scope:Script -Value -Value $((Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction:Stop | Select-Object -Property 'Model', 'Manufacturer'))

		# First we try to figure out if this is a Virtual Machine based on the
		# Bios Serial information that we get via WMI
		if ($WMI_BIOS.SerialNumber -like '*VMware*') {
			Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
			Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('VMWare')
		} elseif ($WMI_BIOS.Version -like 'VIRTUAL') {
			Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
			Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Hyper-V')
		} elseif ($WMI_BIOS.Version -like 'A M I') {
			Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
			Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Virtual PC')
		} elseif ($WMI_BIOS.Version -like '*Xen*') {
			Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
			Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Xen')
		} elseif (($WMI_BIOS.Version -like 'PRLS*') -and ($WMI_BIOS.SerialNumber -like 'Parallels-*')) {
			Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
			Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Parallels')
		}

		# Looks like this is not a Virtual Machine, but to make sure that figure it out!
		# So we try some other information that we have via WMI :-)
		if (-not ($SysInfo_IsVirtual)) {
			if ($WMI_ComputerSystem.Manufacturer -like '*Microsoft*') {
				Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
				Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Hyper-V')
			} elseif ($WMI_ComputerSystem.Manufacturer -like '*VMWare*') {
				Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
				Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('VMWare')
			} elseif ($WMI_ComputerSystem.Manufacturer -like '*Parallels*') {
				Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
				Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Parallels')
			} elseif ($wmisystem.model -match 'VirtualBox') {
				Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
				Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('VirtualBox')
			} elseif ($wmisystem.model -like '*Virtual*') {
				Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($true)
				Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Unknown Virtual Machine')
			}
		}

		# OK, this does not look like a Virtual Machine to us!
		if (-not ($SysInfo_IsVirtual)) {
			Set-Variable -Name 'SysInfo_IsVirtual' -Scope:Script -Value -Value $($false)
			Set-Variable -Name 'SysInfoVirtualType' -Scope:Script -Value -Value $('Not a Virtual Machine')
		}

		# Dump the Boolean Info!
		Write-Output -InputObject "$SysInfo_IsVirtual"

		# Write some Debug Infos ;-)
		Write-Verbose -Message "$SysInfoVirtualType"
	}

	END {
		# Cleanup
		Remove-Variable -Name SysInfo_IsVirtual -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name SysInfoVirtualType -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name WMI_BIOS -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name WMI_ComputerSystem -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Get-LocalIPAdresses {
	<#
			.SYNOPSIS
			Show all local IP Addresses

			.DESCRIPTION
			Show all local IP Addresses

			.PARAMETER LinkLocal
			Show IsIPv6LinkLocal?

			.EXAMPLE
			PS C:\> Get-LocalIPAdresses

			IPAddressToString                                          AddressFamily
			-----------------                                          -------------
			fe80::3db7:8507:3f9a:bb13%11                              InterNetworkV6
			10.211.55.125                                               InterNetwork

			Description
			-----------
			Show all local IP Addresses

			.EXAMPLE
			PS C:\> Get-LocalIPAdresses | Format-List

			IPAddressToString : fe80::3db7:8507:3f9a:bb13%11
			AddressFamily     : InterNetworkV6

			IPAddressToString : 10.211.55.125
			AddressFamily     : InterNetwork

			Description
			-----------
			Show all local IP Addresses, formated

			.EXAMPLE
			PS C:\> Get-LocalIPAdresses -LinkLocal | ConvertTo-Csv -NoTypeInformation
			"IPAddressToString","AddressFamily","IsIPv6LinkLocal"
			"fe80::3db7:8507:3f9a:bb13%11","InterNetworkV6","True"
			"10.211.55.125","InterNetwork","False"

			Description
			-----------
			Show all local IP Addresses as CSV and shows IsIPv6LinkLocal info



			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(HelpMessage = 'Show IsIPv6LinkLocal?')]
		[switch]$LinkLocal
	)

	BEGIN {
		# Cleanup
		$result = @()
	}

	PROCESS {
		$AllIpInfo = @()

		# Get the info via .NET
		$AllIpInfo = ([Net.DNS]::GetHostAddresses([Net.DNS]::GetHostName()))

		# Loop over the Info
		foreach ($SingleIpInfo in $AllIpInfo) {
			$Object = New-Object -TypeName PSObject -Property @{
				AddressFamily     = $SingleIpInfo.AddressFamily
				IPAddressToString = $SingleIpInfo.IPAddressToString
			}

			if ($LinkLocal) {
				if (($SingleIpInfo.IsIPv6LinkLocal) -eq $true) {
					$Object | Add-Member -TypeName 'NoteProperty' -Name IsIPv6LinkLocal -Value $true
				} else {
					$Object | Add-Member -TypeName 'NoteProperty' -Name IsIPv6LinkLocal -Value $false
				}
			}

			# Add
			$result += $Object

			# Cleanup
			$Object = $null
		}

	}

	END {
		# DUMP
		Write-Output -InputObject $result -NoEnumerate
		# Cleanup
		$result = $null
	}
}

function Get-LocalListenPort {
	<#
			.SYNOPSIS
			This parses the native netstat.exe output using the command line
			"netstat -anb" to find all of the network ports in use on a local
			machine and all associated processes and services

			.DESCRIPTION
			This parses the native netstat.exe output using the command line
			"netstat -anb" to find all of the network ports in use on a local
			machine and all associated processes and services

			.EXAMPLE
			PS> Get-LocalListenPort

			This example will find all network ports in uses on the local
			computer with associated processes and services

			.EXAMPLE
			PS> Get-LocalListenPort | Where-Object {$_.ProcessOwner -eq 'svchost.exe'}
			RemotePort    : 0
			ProcessOwner  : svchost.exe
			IPVersion     : IPv4
			LocalPort     : 135
			State         : LISTENING
			LocalAddress  : 0.0.0.0
			RemoteAddress : 0.0.0.0
			Protocol      : TCP
			Service       : RpcSs

			Description
			-----------
			This example will find all network ports in use on the local computer
			that were opened by the svchost.exe process. (Example output trimmed)

			.EXAMPLE
			PS> Get-LocalListenPort | Where-Object {$_.IPVersion -eq 'IPv4'}
			RemotePort    : 0
			ProcessOwner  : svchost.exe
			IPVersion     : IPv4
			LocalPort     : 135
			State         : LISTENING
			LocalAddress  : 0.0.0.0
			RemoteAddress : 0.0.0.0
			Protocol      : TCP
			Service       : RpcSs

			Description
			-----------
			This example will find all network ports in use on the local computer
			using IPv4 only. (Example output trimmed)

			.EXAMPLE
			PS> Get-LocalListenPort | Where-Object {$_.IPVersion -eq 'IPv6'}
			RemotePort    : 0
			ProcessOwner  : svchost.exe
			IPVersion     : IPv6
			LocalPort     : 135
			State         : LISTENING
			LocalAddress  : ::
			RemoteAddress : ::
			Protocol      : TCP
			Service       : RpcSs

			Description
			-----------
			This example will find all network ports in use on the local computer
			using IPv6 only. (Example output trimmed)

			.NOTES
			Based on an idea of Adam Bertram
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		try {
			# Capture the output of the native netstat.exe utility
			# Remove the top row from the result and trim off any leading or trailing spaces from each line
			# Replace all instances of more than 1 space with a pipe symbol.
			# This allows easier parsing of the fields
			$Netstat = (NETSTAT.EXE -anb |
			Where-Object -FilterScript { $_ -and ($_ -ne 'Active Connections') }).Trim() |
			Select-Object -Skip 1 |
			ForEach-Object -Process { $_ -replace '\s{2,}', '|' }

			$i = 0

			foreach ($Line in $Netstat) {
				# Create the hashtable to conver to object later
				$Out = @{
					'Protocol'    = ''
					'State'       = ''
					'IPVersion'   = ''
					'LocalAddress' = ''
					'LocalPort'   = ''
					'RemoteAddress' = ''
					'RemotePort'  = ''
					'ProcessOwner' = ''
					'Service'     = ''
				}

				# If the line is a port
				if ($Line -cmatch '^[A-Z]{3}\|') {
					$Cols = ($Line.Split('|'))
					$Out.Protocol = ($Cols[0])

					# Some ports don't have a state.
					# If they do, there's always 4 fields in the line
					if ($Cols.Count -eq 4) {
						$Out.State = ($Cols[3])
					}

					# All port lines that start with a [ are IPv6
					if ($Cols[1].StartsWith('[')) {
						$Out.IPVersion = 'IPv6'
						$Out.LocalAddress = ($Cols[1].Split(']')[0].TrimStart('['))
						$Out.LocalPort = ($Cols[1].Split(']')[1].TrimStart(':'))

						if ($Cols[2] -eq '*:*') {
							$Out.RemoteAddress = '*'
							$Out.RemotePort = '*'
						} else {
							$Out.RemoteAddress = ($Cols[2].Split(']')[0].TrimStart('['))
							$Out.RemotePort = ($Cols[2].Split(']')[1].TrimStart(':'))
						}
					} else {
						$Out.IPVersion = 'IPv4'
						$Out.LocalAddress = ($Cols[1].Split(':')[0])
						$Out.LocalPort = ($Cols[1].Split(':')[1])
						$Out.RemoteAddress = ($Cols[2].Split(':')[0])
						$Out.RemotePort = ($Cols[2].Split(':')[1])
					}

					# Because the process owner and service are on separate lines than the port line and the number of lines between them is variable this craziness was necessary.
					# This line starts parsing the netstat output at the current port line and searches for all lines after that that are NOT a port line and finds the first one.
					# This is how many lines there are until the next port is defined.
					$LinesUntilNextPortNum = ($Netstat |
						Select-Object -Skip $i |
						Select-String -Pattern '^[A-Z]{3}\|' -NotMatch |
					Select-Object -First 1).LineNumber
					# Add the current line to the number of lines until the next port definition to find the associated process owner and service name

					$NextPortLineNum = ($i + $LinesUntilNextPortNum)
					# This would contain the process owner and service name

					$PortAttribs = ($Netstat[($i + 1)..$NextPortLineNum])
					# The process owner is always enclosed in brackets of, if it can't find the owner, starts with 'Can'

					$Out.ProcessOwner = ($PortAttribs -match '^\[.*\.exe\]|Can')

					if ($Out.ProcessOwner) {
						# Get rid of the brackets and pick the first index because this is an array
						$Out.ProcessOwner = (($Out.ProcessOwner -replace '\[|\]', '')[0])
					}

					# A service is always a combination of multiple word characters at the start of the line
					if ($PortAttribs -match '^\w+$') {
						$Out.Service = (($PortAttribs -match '^\w+$')[0])
					}

					$MyOut = [pscustomobject]$Out
					Write-Output -InputObject $MyOut
				}

				# Keep the counter
				$i++
			}
		} catch {
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		}
	}
}

function Get-MicrosoftUpdateInfo {
	<#
			.SYNOPSIS
			Gives a list of all Microsoft Updates sorted by KB number/HotfixID

			.DESCRIPTION
			Gives a list of all Microsoft Updates sorted by KB number/HotfixID

			.PARAMETER raw
			Just dum the Objects?

			.EXAMPLE
			PS C:\> Get-MicrosoftUpdateInfo

			Description
			-----------
			Return the installed Microsoft Updates

			.EXAMPLE
			PS C:\> $MicrosoftUpdateInfo = (Get-MicrosoftUpdateInfo -raw)
			$MicrosoftUpdateInfo | Where-Object { $_.HotFixID -eq "KB3121461" }

			Description
			-----------
			Return the installed Microsoft Updates in a more raw format, this might
			be handy if you want to reuse it!
			In this example we search for the Update "KB3121461" only and
			displays that info.

			.EXAMPLE
			PS C:\> $MicrosoftUpdateInfo = (Get-MicrosoftUpdateInfo -raw)
			[System.String](($MicrosoftUpdateInfo | Where-Object { $_.HotFixID -eq "KB3121461" }).Title)

			Description
			-----------
			Return the installed Microsoft Updates in a more raw format, this might
			be handy if you want to reuse it!
			In this example we search for the Update "KB3121461" only and
			displays the info about that Update as String.

			.NOTES
			Basic Function found here: http://tomtalks.uk/2013/09/list-all-microsoftwindows-updates-with-powershell-sorted-by-kbhotfixid-Get-microsoftupdate/
			By Tom Arbuthnot. Lyncdup.com

			We just adopted and tweaked it.

			.LINK
			Source: http://tomtalks.uk/2013/09/list-all-microsoftwindows-updates-with-powershell-sorted-by-kbhotfixid-Get-microsoftupdate/

			.LINK
			http://blogs.technet.com/b/tmintner/archive/2006/07/07/440729.aspx

			.LINK
			http://www.gfi.com/blog/windows-powershell-extracting-strings-using-regular-expressions/

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Position = 0,
		HelpMessage = 'Just dum the Objects?')]
		[switch]$raw = $false
	)

	BEGIN {
		$wu = (New-Object -ComObject 'Microsoft.Update.Searcher')

		$totalupdates = ($wu.GetTotalHistoryCount())

		$All = ($wu.QueryHistory(0, $totalupdates))

		# Define a new array to gather output
		$OutputCollection = @()
	}

	PROCESS {
		Foreach ($update in $All) {
			$String = $update.title

			$Regex = 'KB\d*'
			$KB = ($String |
				Select-String -Pattern $Regex |
			Select-Object { $_.Matches })

			$output = (New-Object -TypeName PSobject)
			$output | Add-Member -MemberType NoteProperty -Name 'HotFixID' -Value $KB.' $_.Matches '.Value
			$output | Add-Member -MemberType NoteProperty -Name 'Title' -Value $String
			$OutputCollection += $output

		}
	}

	END {
		if ($raw) {
			Write-Output -InputObject $OutputCollection | Sort-Object -Property HotFixID
		} else {
			# Oupput the collection sorted and formatted:
			$OutputCollection |
			Sort-Object -Property HotFixID |
			Format-Table -AutoSize

			# Return
			Write-Host -Object "$($OutputCollection.Count) Updates Found"
		}
	}
}

function Get-myPROCESS {
	<#
			.SYNOPSIS
			Get our own process information

			.DESCRIPTION
			Get our own process information about the PowerShell Session

			.EXAMPLE
			PS C:\> Get-myProcess

			Handles  NPM(K)    PM(K)      WS(K) VM(M)   CPU(s)     Id ProcessName
			-------  ------    -----      ----- -----   ------     -- -----------
			511      44        79252      93428   664   11,653   3932 powershell

			Description
			-----------
			Get our own process information

			.NOTES
			Just a little helper function that might be useful if you have a long
			running shell session

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Diagnostics.Process])]
	param ()

	BEGIN {
		# Do a garbage collection
		if ((Get-Command Invoke-GC -ErrorAction:SilentlyContinue)) {
			Invoke-GC
		}
	}

	PROCESS {
		# Get the info
		[diagnostics.process]::GetCurrentProcess()
	}
}

function Get-NetFramework {
	<#
			.SYNOPSIS
			A detailed description of the Get-NetFramework function.

			.DESCRIPTION
			This function will retrieve the list of Framework Installed on
			the computer.

			.PARAMETER ComputerName
			Computer Name

			.PARAMETER Credentials
			Credentials to use

			.EXAMPLE
			PS C:\> Get-NetFramework

			PSChildName                                   Version
			-----------                                   -------
			v2.0.50727                                    2.0.50727.4927
			v3.0                                          3.0.30729.4926
			Windows Communication Foundation              3.0.4506.4926
			Windows Presentation Foundation               3.0.6920.4902
			v3.5                                          3.5.30729.4926
			Client                                        4.5.51641
			Full                                          4.5.51641
			Client                                        4.0.0.0

			Description
			-----------
			This function will retrieve the list of Framework Installed on the
			computer.

			.NOTES

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'High',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(HelpMessage = 'Computer Name')]
		[String[]]$ComputerName = "$env:COMPUTERNAME",
		[Parameter(HelpMessage = 'Credentials to use')]
		$Credentials = $Credential
	)

	BEGIN {
		$Splatting = @{
			ComputerName = $ComputerName
		}
	}

	PROCESS {
		if ($PSBoundParameters['Credential']) {
			$Splatting.credential = $Credentials
		}

		Invoke-Command @Splatting -ScriptBlock {
			Write-Verbose -Message "$pscomputername"

			# Get the Net Framework Installed
			$netFramework = (Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
				Get-ItemProperty -Name Version -EA 0 |
				Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } |
			Select-Object -Property PSChildName, Version)

			# Prepare output
			$Properties = @{
				ComputerName      = "$($env:COMPUTERNAME)$($env:USERDNSDOMAIN)"
				PowerShellVersion = $psversiontable.PSVersion.Major
				NetFramework      = $netFramework
			}

			New-Object -TypeName PSObject -Property $Properties
		}
	}
}

function Get-NetStat {
	<#
			.SYNOPSIS
			This function will get the output of netstat -n and parse the output

			.DESCRIPTION
			This function will get the output of netstat -n and parse the output

			.NOTES
			Based on an idea of Francois-Xavier Cat

			.EXAMPLE
			PS C:\> Get-NetStat
			LocalAddressIP     : 10.211.59.125
			LocalAddressPort   : 1321
			State              : ESTABLISHED
			ForeignAddressIP   : 10.211.16.2
			ForeignAddressPort : 10943
			Protocole          : TCP

			Description
			-----------
			This function will get the output of netstat -n and parse the output

			.LINK
			Idea: http://www.lazywinadmin.com/2014/08/powershell-parse-this-netstatexe.html

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Get the output of netstat
		Set-Variable -Name 'data' -Value $(NETSTAT.EXE -n)

		# Keep only the line with the data (we remove the first lines)
		Set-Variable -Name 'data' -Value $($data[4..$data.count])

		# Each line need to be spitted and get rid of unnecessary spaces
		foreach ($Line in $data) {
			# Get rid of the first whitespace, at the beginning of the line
			Set-Variable -Name 'line' -Value $($Line -replace '^\s+', '')

			# Split each property on whitespace block
			Set-Variable -Name 'line' -Value $($Line -split '\s+')

			# Define the properties
			$Properties = @{
				Protocole          = $Line[0]
				LocalAddressIP     = ($Line[1] -split ':')[0]
				LocalAddressPort   = ($Line[1] -split ':')[1]
				ForeignAddressIP   = ($Line[2] -split ':')[0]
				ForeignAddressPort = ($Line[2] -split ':')[1]
				State              = $Line[3]
			}

			# Output the current line
			New-Object -TypeName PSObject -Property $Properties
		}
	}
}

function Get-NewAesKey {
	<#
			.SYNOPSIS
			Get a AES Key

			.DESCRIPTION
			Get a AES Key

			.EXAMPLE
			PS C:\> Get-NewAesKey
			3z38JJzHJghPYm9X95EP8Xbh2fuE8/rPxBi6N7mME9M=

			Description
			-----------
			Get a AES Key

			.NOTES
			Initial Version
	#>
	[CmdletBinding(ConfirmImpact = 'None',
	SupportsShouldProcess = $false)]
	[OutputType([System.String])]
	param ()

	BEGIN {
		# Cleanup
		$NewAesKey = $null
	}

	PROCESS {
		# Generate the Key
		$NewAlgorithm = [System.Security.Cryptography.SymmetricAlgorithm]::Create('Rijndael')
		$KeyBytes = $NewAlgorithm.get_Key()
		$NewAesKey = [System.Convert]::ToBase64String($KeyBytes)

	}

	END {
		# Sump the Key
		Write-Output $NewAesKey

		# Cleanup
		$NewAesKey = $null
	}
}

function Get-NewPassword {
	<#
			.SYNOPSIS
			Generates a New password with varying length and Complexity,

			.DESCRIPTION
			Generate a New Password for a User.  Defaults to 8 Characters
			with Moderate Complexity.  Usage

			GET-NEWPASSWORD or

			GET-NEWPASSWORD $Length $Complexity

			Where $Length is an integer from 1 to as high as you want
			and $Complexity is an Integer from 1 to 4

			.PARAMETER PasswordLength
			Password Length

			.PARAMETER Complexity
			Complexity Level

			.EXAMPLE
			PS C:\> Get-NewPassword
			zemermyya784vKx93

			Description
			-----------
			Create New Password based on the defaults

			.EXAMPLE
			PS C:\> Get-NewPassword 9 1
			zemermyya

			Description
			-----------
			Generate a Password of strictly Uppercase letters 9 letters long

			.EXAMPLE
			PS C:\> Get-NewPassword 5
			zemermyya784vKx93K2sqG

			Description
			-----------
			Generate a Highly Complex password 5 letters long

			.EXAMPLE
			$MYPASSWORD = (ConvertTo-SecureString (Get-NewPassword 8 2) -asplaintext -Force)

			Description
			-----------
			Create a new 8 Character Password of Uppercase/Lowercase and store as
			a Secure.String in Variable called $MYPASSWORD

			.NOTES
			The Complexity falls into the following setup for the Complexity level
			1 - Pure lowercase Ascii
			2 - Mix Uppercase and Lowercase Ascii
			3 - Ascii Upper/Lower with Numbers
			4 - Ascii Upper/Lower with Numbers and Punctuation

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(HelpMessage = 'Password Length')]
		[ValidateNotNullOrEmpty()]
		[Alias('Length')]
		[System.Int32]$PasswordLength = '8',
		[Parameter(HelpMessage = 'Complexity Level')]
		[ValidateNotNullOrEmpty()]
		[Alias('Level')]
		[System.Int32]$Complexity = '3'
	)

	PROCESS {
		# Delare an array holding what I need.  Here is the format
		# The first number is a the number of characters (Ie 26 for the alphabet)
		# The Second Number is Where-Object it resides in the Ascii Character set
		# So 26,97 will pick a random number representing a letter in Asciii
		# and add it to 97 to produce the ASCII Character
		[int32[]]$ArrayofAscii = 26, 97, 26, 65, 10, 48, 15, 33

		# Complexity can be from 1 - 4 with the results being
		# 1 - Pure lowercase Ascii
		# 2 - Mix Uppercase and Lowercase Ascii
		# 3 - Ascii Upper/Lower with Numbers
		# 4 - Ascii Upper/Lower with Numbers and Punctuation
		If ($Complexity -eq $null) {
			Set-Variable -Name 'Complexity' -Scope:Script -Value $(3)
		}

		# Password Length can be from 1 to as Crazy as you want
		#
		If ($PasswordLength -eq $null) {
			Set-Variable -Name 'PasswordLength' -Scope:Script -Value $(10)
		}

		# Nullify the Variable holding the password
		Remove-Variable -Name 'NewPassword' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

		# Here is our loop
		Foreach ($counter in 1..$PasswordLength) {

			# What we do here is pick a random pair (4 possible)
			# in the array to generate out random letters / numbers
			Set-Variable -Name 'pickSet' -Scope:Script -Value $((Get-Random $Complexity) * 2)

			# Pick an Ascii Character and add it to the Password
			# Here is the original line I was testing with
			# [System.Char] (GET-RANDOM 26) +97 Which generates
			# Random Lowercase ASCII Characters
			# [System.Char] (GET-RANDOM 26) +65 Which generates
			# Random Uppercase ASCII Characters
			# [System.Char] (GET-RANDOM 10) +48 Which generates
			# Random Numeric ASCII Characters
			# [System.Char] (GET-RANDOM 15) +33 Which generates
			# Random Punctuation ASCII Characters
			Set-Variable -Name 'NewPassword' -Scope:Script -Value $($NewPassword + [System.Char]((Get-Random $ArrayofAscii[$pickset]) + $ArrayofAscii[$pickset + 1]))
		}
	}

	END {
		# When we're done we Return the $NewPassword
		# BACK to the calling Party
		Write-Output $NewPassword
	}
}

function Get-Pause {
	<#
			.SYNOPSIS
			Wait for user to press any key

			.DESCRIPTION
			Shows a console message and waits for user to press any key.

			Optional:
			The message to display could be set by a command line parameter.

			.PARAMETER PauseMessage
			This optional parameter is the text that the function displays.
			If this is not set, it uses a default text "Press any key..."

			.EXAMPLE
			PS C:\> pause

			Display a console message and wait for user to press any key.
			It shows the default Text "Press any key..."

			.EXAMPLE
			PS C:\> pause "Please press any key"

			Description
			-----------
			Display a console message and wait for user to press any key.
			It shows the Text "Please press any key"

			.EXAMPLE
			PS C:\> pause -PauseMessage "Please press any key"

			Description
			-----------
			Display a console message and wait for user to press any key.
			It shows the Text "Please press any key"

			.NOTES
			PowerShell have no build in function like this

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Text to display')]
		[ValidateNotNullOrEmpty()]
		[Alias('Message')]
		[System.String]$PauseMessage = 'Press any key...'
	)

	BEGIN {
		# Do we need to show the default?
		if (($PauseMessage -eq '') -or ($PauseMessage -eq $null) -or (!$PauseMessage)) {
			# Text to show - Default text!
			Set-Variable -Name 'PauseMessage' -Value $('Press any key...' -as ([System.String] -as [type]))
		}
	}

	PROCESS {
		# This is the Message
		Write-Host "$PauseMessage" -ForegroundColor Yellow

		# Wait for the Keystroke
		$null = ($Host.ui.RawUI.ReadKey('NoEcho,IncludeKeyDown'))
	}

	END {
		# Cleanup
		Remove-Variable -Name 'PauseMessage' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Get-PendingReboot {
	<#
			.SYNOPSIS
			Gets the pending reboot status on a local or remote computer.

			.DESCRIPTION
			This function will query the registry on a local or remote computer and
			determine if the system is pending a reboot, from either Microsoft
			Patching or a Software Installation.
			For Windows 2008+ the function will query the CBS registry key as
			another factor in determining pending reboot state.
			"PendingFileRenameOperations" and "Auto Update\RebootRequired" are
			observed as being consistent across Windows Server 2003 & 2008.

			CBServicing = Component Based Servicing (Windows 2008)
			WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008)
			CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
			PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008)

			.PARAMETER ComputerName
			A single Computer or an array of computer names.

			The default is localhost ($env:COMPUTERNAME).

			.EXAMPLE
			PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize

			Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
			-------- ----------- ------------- ------------ -------------- -------------- -------------
			DC01     False   False           False      False
			DC02     False   False           False      False
			FS01     False   False           False      False

			Description
			-----------
			This example will capture the contents of C:\ServerList.txt and query
			the pending reboot information from the systems contained in the file
			and display the output in a table.
			The null values are by design, since these systems do not have the
			SCCM 2012 client installed, nor was the PendingFileRenameOperations
			value populated.

			.EXAMPLE
			PS C:\> Get-PendingReboot

			Computer     : WKS01
			CBServicing  : False
			WindowsUpdate      : True
			CCMClient    : False
			PendComputerRename : False
			PendFileRename     : False
			PendFileRenVal     :
			RebootPending      : True

			Description
			-----------
			This example will query the local machine for pending reboot information.

			.EXAMPLE
			PS C:\> $Servers = Get-Content C:\Servers.txt
			PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation

			Description
			-----------
			This example will create a report that contains pending reboot
			information.

			.NOTES
			Based on an idea of Brian Wilhite

			.LINK
			Component-Based Servicing: http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

			.LINK
			PendingFileRename/Auto Update: http://support.microsoft.com/kb/2723674

			.LINK
			http://technet.microsoft.com/en-us/library/cc960241.aspx

			.LINK
			http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

			.LINK
			SCCM 2012/CCM_ClientSDK: http://msdn.microsoft.com/en-us/library/jj902723.aspx
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
				Position = 0,
		HelpMessage = 'A single Computer or an array of computer names.')]
		[Alias('CN', 'Computer')]
		[String[]]$ComputerName = "$env:COMPUTERNAME"
	)

	PROCESS {
		Foreach ($Computer in $ComputerName) {
			Try {
				# Setting pending values to false to cut down on the number of else statements
				$CompPendRen, $PendFileRename, $Pending, $SCCM = $false, $false, $false, $false

				# Setting CBSRebootPend to null since not all versions of Windows has this value
				Remove-Variable -Name 'CBSRebootPend' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

				# Querying WMI for build version
				$WMI_OS = (Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction:Stop)

				# Making registry connection to the local/remote computer
				Set-Variable -Name 'HKLM' -Value $([UInt32] '0x80000002')
				Set-Variable -Name 'WMI_Reg' -Value $([WMIClass] "\\$Computer\root\default:StdRegProv")

				# If Vista/2008 & Above query the CBS Reg Key
				If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
					Set-Variable -Name 'RegSubKeysCBS' -Value $($WMI_Reg.EnumKey($HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\'))
					Set-Variable -Name "$CBSRebootPend" -Value $($RegSubKeysCBS.sNames -contains 'RebootPending')
				}

				# Query WUAU from the registry
				Set-Variable -Name 'RegWUAURebootReq' -Value $($WMI_Reg.EnumKey($HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\'))
				Set-Variable -Name 'WUAURebootReq' -Value $($RegWUAURebootReq.sNames -contains 'RebootRequired')

				# Query PendingFileRenameOperations from the registry
				Set-Variable -Name 'RegSubKeySM' -Value $($WMI_Reg.GetMultiStringValue($HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\', 'PendingFileRenameOperations'))
				Set-Variable -Name 'RegValuePFRO' -Value $($RegSubKeySM.sValue)

				# Query ComputerName and ActiveComputerName from the registry
				Set-Variable -Name 'ActCompNm' -Value $($WMI_Reg.GetStringValue($HKLM, 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\', 'ComputerName'))
				Set-Variable -Name 'CompNm' -Value $($WMI_Reg.GetStringValue($HKLM, 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\', 'ComputerName'))


				If ($ActCompNm -ne $CompNm) {
					Set-Variable -Name 'CompPendRen' -Value $($true)
				}

				# If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
				If ($RegValuePFRO) {
					Set-Variable -Name 'PendFileRename' -Value $($true)
				}

				# Determine SCCM 2012 Client Reboot Pending Status
				# To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
				Remove-Variable -Name 'CCMClientSDK' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

				$CCMSplat = @{
					NameSpace    = 'ROOT\ccm\ClientSDK'
					Class        = 'CCM_ClientUtilities'
					Name         = 'DetermineIfRebootPending'
					ComputerName = $Computer
					ErrorAction  = 'Stop'
				}


				Try {
					Set-Variable -Name 'CCMClientSDK' -Value $(Invoke-WmiMethod @CCMSplat)
				} Catch [System.UnauthorizedAccessException] {
					Set-Variable -Name 'CcmStatus' -Value $(Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction:SilentlyContinue)

					If ($CcmStatus.Status -ne 'Running') {
						Write-Warning "$Computer`: Error - CcmExec service is not running."

						Remove-Variable -Name 'CCMClientSDK' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
					}
				} Catch {
					Remove-Variable -Name 'CCMClientSDK' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
				}

				If ($CCMClientSDK) {
					If ($CCMClientSDK.ReturnValue -ne 0) {
						Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"
					}

					If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
						Set-Variable -Name 'SCCM' -Value $($true)
					}
				} Else {
					Remove-Variable -Name 'SCCM' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
				}

				## Creating Custom PSObject and Select-Object Splat
				$SelectSplat = @{
					Property = (
						'Computer',
						'CBServicing',
						'WindowsUpdate',
						'CCMClientSDK',
						'PendComputerRename',
						'PendFileRename',
						'PendFileRenVal',
						'RebootPending'
					)
				}

				New-Object -TypeName PSObject -Property @{
					Computer           = $WMI_OS.CSName
					CBServicing        = $CBSRebootPend
					WindowsUpdate      = $WUAURebootReq
					CCMClientSDK       = $SCCM
					PendComputerRename = $CompPendRen
					PendFileRename     = $PendFileRename
					PendFileRenVal     = $RegValuePFRO
					RebootPending      = ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
				} | Select-Object @SelectSplat
			} Catch {
				Write-Warning "$Computer`: $_"
			}
		}
	}
}

function Get-PhoneticSpelling {
	<#
			.SYNOPSIS
			Get the Phonetic Spelling for a given input String

			.DESCRIPTION
			Get the Phonetic Spelling for a given input String

			.PARAMETER Char
			Input that should be Phonetic Spelled

			.EXAMPLE
			PS C:\> (Get-PhoneticSpelling -Char 'Test').Table

			Char Phonetic
			---- --------
			T Capital-Tango
			e Lowercase-Echo
			s Lowercase-Sierra
			t Lowercase-Tango

			Description
			-----------
			Show the Input and Phonetic Spelling (table) for 'Test'

			.EXAMPLE
			PS C:\> (Get-PhoneticSpelling -Char 'Test').PhoneticForm
			Capital-Tango  Lowercase-Echo  Lowercase-Sierra  Lowercase-Tango

			Description
			-----------
			Convert 'Test' to Phonetic Spelling

			.NOTES
			Simple function to convert a string to Phonetic Spelling
	#>

	[CmdletBinding()]
	[OutputType([System.Object])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Input that should be Phonetic Spelled')]
		[ValidateNotNullOrEmpty()]
		[Char[]]$Char
	)

	BEGIN {
		# Build a HashTable with the alphabet and the matching Phonetic Spelled
		[HashTable]$PhoneticTable = @{
			'a' = 'Alpha'
			'b' = 'Bravo'
			'c' = 'Charlie'
			'd' = 'Delta'
			'e' = 'Echo'
			'f' = 'Foxtrot'
			'g' = 'Golf'
			'h' = 'Hotel'
			'i' = 'India'
			'j' = 'Juliet'
			'k' = 'Kilo'
			'l' = 'Lima'
			'm' = 'Mike'
			'n' = 'November'
			'o' = 'Oscar'
			'p' = 'Papa'
			'q' = 'Quebec'
			'r' = 'Romeo'
			's' = 'Sierra'
			't' = 'Tango'
			'u' = 'Uniform'
			'v' = 'Victor'
			'w' = 'Whiskey'
			'x' = 'X-ray'
			'y' = 'Yankee'
			'z' = 'Zulu'
			'0' = 'Zero'
			'1' = 'One'
			'2' = 'Two'
			'3' = 'Three'
			'4' = 'Four'
			'5' = 'Five'
			'6' = 'Six'
			'7' = 'Seven'
			'8' = 'Eight'
			'9' = 'Nine'
			'.' = 'Period'
			'!' = 'Exclamation-mark'
			'?' = 'Question-mark'
			'@' = 'At'
			'{' = 'Left-brace'
			'}' = 'Right-brace'
			'[' = 'Left-bracket'
			']' = 'Left-bracket'
			'+' = 'Plus'
			'>' = 'Greater-than'
			'<' = 'Less-than'
			'\' = 'Back-slash'
			'/' = 'Forward-slash'
			'|' = 'Pipe'
			':' = 'Colon'
			';' = 'Semi-colon'
			'"' = 'Double-quote'
			"'" = 'Single-quote'
			'(' = 'Left-parenthesis'
			')' = 'Right-parenthesis'
			'*' = 'Asterisk'
			'-' = 'Hyphen'
			'#' = 'Pound'
			'^' = 'Caret'
			'~' = 'Tilde'
			'=' = 'Equals'
			'&' = 'Ampersand'
			'%' = 'Percent'
			'$' = 'Dollar'
			',' = 'Comma'
			'_' = 'Underscore'
			'`' = 'Back-tick'
		}
	}

	PROCESS {
		$result = Foreach ($Character in $Char) {
			if ($PhoneticTable.ContainsKey("$Character")) {
				if ([Char]::IsUpper([Char]$Character)) {
					[PSCustomObject]@{
						Char     = $Character
						Phonetic = "Capital-$($PhoneticTable["$Character"])"
					}
				} elseif ([Char]::IsLower([Char]$Character)) {
					[PSCustomObject]@{
						Char     = $Character
						Phonetic = "Lowercase-$($PhoneticTable["$Character"])"
					}
				} elseif ([Char]::IsNumber([Char]$Character)) {
					[PSCustomObject]@{
						Char     = $Character
						Phonetic = "Number-$($PhoneticTable["$Character"])"
					}
				} else {
					[PSCustomObject]@{
						Char     = $Character
						Phonetic = $PhoneticTable["$Character"]
					}
				}
			} else {
				[PSCustomObject]@{
					Char     = $Character
					Phonetic = $Character
				}
			}
		}

		# Loop over each char
		$InputText = -join $Char

		$TableFormat = ($result |
			Format-Table -AutoSize |
		Out-String)

		$StringFormat = ($result.Phonetic -join '  ')

		# Create the new HashTable
		[hashtable]$Properties = @{
			PhoneticForm = $StringFormat
			Table        = $TableFormat
			InputText    = $InputText
		}

		$Object = (New-Object -TypeName PSObject -Property $Properties)

		$Object.PSObject.Typenames.Insert(0, 'Phonetic')
	}

	END {
		# Dump what we have
		Write-Output $Object
	}
}

function Get-PreReqModules {
	<#
			.SYNOPSIS
			Get all required Office 365 Modules and Software from Microsoft

			.DESCRIPTION
			Get all required Office 365 Modules and Software from Microsoft

			It Downloads:
			-> .NET Framework 4.5.2 Off-line Installer
			-> Microsoft Online Services Sign-In Assistant for IT Professionals RTW
			-> Microsoft Azure Active Directory PowerShell Module
			-> SharePoint Online Management Shell
			-> Skype for Business Online Windows PowerShell Module

			.PARAMETER Path
			Where to Download

			.EXAMPLE
			PS C:\> Get-PreReqModules

			Description
			-----------
			Get all required Office 365 Modules and Software from Microsoft.
			Downloads them to: "c:\scripts\powershell\prereq"
			(Will be created if it doe not exist)

			.EXAMPLE
			PS C:\> Get-PreReqModules -Path 'c:\scripts\download'

			Description
			-----------
			Get all required Office 365 Modules and Software from Microsoft.
			Downloads them to: "c:\scripts\download"
			(Will be created if it doe not exist)


			.NOTES
			Just a helper function based on an idea of En Pointe Technologies

			.NET Framework 4.5.2 Off-line Installer URL
			https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe

			Microsoft Online Services Sign-In Assistant for IT Professionals RTW URL
			https://download.microsoft.com/download/5/0/1/5017D39B-8E29-48C8-91A8-8D0E4968E6D4/en/msoidcli_64.msi

			Microsoft Azure Active Directory PowerShell Module URL
			https://bposast.vo.msecnd.net/MSOPMW/Current/amd64/AdministrationConfig-en.msi

			SharePoint Online Management Shell URL
			https://download.microsoft.com/download/0/2/E/02E7E5BA-2190-44A8-B407-BC73CA0D6B87/sharepointonlinemanagementshell_4915-1200_x64_en-us.msi

			Skype for Business Online Windows PowerShell Module URL
			https://download.microsoft.com/download/2/0/5/2050B39B-4DA5-48E0-B768-583533B42C3B/SkypeOnlinePowershell.exe
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Where to Download')]
		[System.String]$Path = 'c:\scripts\powershell\prereq'
	)

	BEGIN {
		# Is the download path already here?
		if (-not (Test-Path $Path)) {
			(New-Item -ItemType Directory $Path -Force -Confirm:$false) > $null 2>&1 3>&1
		} else {
			Write-Output 'Download path already exists'
		}
	}

	PROCESS {
		<#
				Now download all the required software
		#>

		try {
			# Whare to download and give the Filename
			$dlPath = (Join-Path $Path -ChildPath 'NDP452-KB2901907-x86-x64-AllOS-ENU.exe')

			# Is this file already downloaded?
			if (Test-Path $dlPath) {
				# It exists
				Write-Output "$dlPath exists..."
			} else {
				# Download it
				Write-Output 'Processing: .NET Framework 4.5.2 Off-line Installer'
				Invoke-WebRequest -Uri https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe -OutFile $dlPath
			}
		} catch {
			# Aw Snap!
			Write-Warning -Message 'Unable to download: .NET Framework 4.5.2 Off-line Installer'
		}

		try {
			$dlPath = (Join-Path $Path -ChildPath 'msoidcli_64.msi')

			if (Test-Path $dlPath) {
				Write-Output "$dlPath exists..."
			} else {
				Write-Output 'Processing: Microsoft Online Services Sign-In Assistant for IT Professionals RTW'
				Invoke-WebRequest -Uri https://download.microsoft.com/download/5/0/1/5017D39B-8E29-48C8-91A8-8D0E4968E6D4/en/msoidcli_64.msi -OutFile $dlPath
			}
		} catch {
			Write-Warning -Message 'Unable to download: Microsoft Online Services Sign-In Assistant for IT Professionals RTW'
		}

		try {
			$dlPath = (Join-Path $Path -ChildPath 'AdministrationConfig-en.msi')

			if (Test-Path $dlPath) {
				Write-Output "$dlPath exists..."
			} else {
				Write-Output 'Processing: Microsoft Azure Active Directory PowerShell Module'
				Invoke-WebRequest -Uri https://bposast.vo.msecnd.net/MSOPMW/Current/amd64/AdministrationConfig-en.msi -OutFile $dlPath
			}
		} catch {
			Write-Warning -Message 'Unable to download: Microsoft Azure Active Directory PowerShell Module'
		}

		try {
			$dlPath = (Join-Path $Path -ChildPath 'sharepointonlinemanagementshell_4915-1200_x64_en-us.msi')

			if (Test-Path $dlPath) {
				Write-Output "$dlPath exists..."
			} else {
				Write-Output 'Processing: SharePoint Online Management Shell'
				Invoke-WebRequest -Uri https://download.microsoft.com/download/0/2/E/02E7E5BA-2190-44A8-B407-BC73CA0D6B87/sharepointonlinemanagementshell_4915-1200_x64_en-us.msi -OutFile $dlPath
			}
		} catch {
			Write-Warning -Message 'Unable to download: SharePoint Online Management Shell'
		}

		try {
			$dlPath = (Join-Path $Path -ChildPath 'SkypeOnlinePowershell.exe')

			if (Test-Path $dlPath) {
				Write-Output "$dlPath exists..."
			} else {
				Write-Output 'Processing: Skype for Business Online Windows PowerShell Module'
				Invoke-WebRequest -Uri https://download.microsoft.com/download/2/0/5/2050B39B-4DA5-48E0-B768-583533B42C3B/SkypeOnlinePowershell.exe -OutFile $dlPath
			}
		} catch {
			Write-Warning -Message 'Unable to download: Skype for Business Online Windows PowerShell Module'
		}
	}

	END {
		Write-Output "Prerequisites downloaded to $Path"

		Invoke-Item $Path
	}
}

function Get-Quote {
	<#
			.SYNOPSIS
			Get a random Quote from an Array

			.DESCRIPTION
			Get a random Quote from an Array of Quotes I like.

			I like to put Quotes in slides and presentations, here is a collection
			of whose I used...


			.EXAMPLE
			PS C:\> Get-Quote
			*******************************************************************
			*  The only real mistake is the one from which we learn nothing.  *
			*                                                     Henry Ford  *
			*******************************************************************

			Description
			-----------
			Get a random Quote from an Array

			.NOTES
			Based on an idea of Jeff Hicks

			I just implemented this because it was fun to do so ;-)

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	BEGIN {
		# The quote should include the author separated by " - ".
		$texts = @(
			'It was a mistake to think that GUIs ever would, could, or even should, eliminate CLIs. - Jeffrey Snover',
			"Leader who don't Listen will eventually be surrounded by people who have nothing to say. - @AndyStanley",
			'Good is the enemy of great. - Sir Jonathan Ive',
			'There are 9 rejected ideas for every idea that works. - Sir Jonathan Ive'
			"People's interest is in the product, not in its authorship. - Sir Jonathan Ive",
			"I think it's really important to design things with a kind of personality. - Marc Newson",
			'Intelligence is the ability to adapt to change. - Stephen Hawking',
			'We are all now connected by the Internet, like neurons in a giant brain. - Stephen Hawking',
			'The best ideas start as conversations. - Sir Jonathan Ive',
			'If something is not good enough, stop doing it. - Sir Jonathan Ive',
			"There's no learning without trying lots of ideas and failing lots of times. - Sir Jonathan Ive",
			'Any product that needs a manual to work is broken. - Elon Musk',
			'Business has only two functions: marketing and innovation. - Milan Kundera',
			"Just because something doesn't do what you planned it to do doesn't mean it's useless. - Thomas A. Edison",
			'Great companies are built on great products. - Elon Musk',
			'Test fast, fail fast, adjust fast. - Tom Peters',
			"Winning isn't everything, it's the only thing. - Vince Lombardi (Former NFL Coach)",
			'The only place success comes before work is in the dictionary. - Vince Lombardi (Former NFL Coach)',
			'The measure of who we are is what we do with what we have. - Vince Lombardi (Former NFL Coach)',
			'The greatest accomplishment is not in never falling, but in rising again after you fall. - Vince Lombardi (Former NFL Coach)'
			'Perfection is not attainable. But if we chase perfection, we can catch excellence. - Vince Lombardi (Former NFL Coach)',
			"Stay focused. Your start does not determine how you're going to finish. - Herm Edwards (Former NFL Coach)",
			'Nobody who ever gave his best regretted it. - George S. Halas (Former NFL Coach)',
			"Don't let the noise of others' opinions drown out your own inner voice. - Steve Jobs",
			'One way to remember who you are is to remember who your heroes are. - Walter Isaacson (Steve Jobs)',
			'Why join the navy if you can be a pirate? - Steve Jobs',
			'Innovation distinguishes between a leader and a follower. - Steve Jobs',
			"Sometimes life hits you in the head with a brick. Don't lose faith. - Steve Jobs",
			'Design is not just what it looks like and feels like. Design is how it works. - Steve Jobs',
			"We made the buttons on the screen look so good you'll want to lick them. - Steve Jobs",
			"Things don't have to change the world to be important. - Steve Jobs",
			'Your most unhappy customers are your greatest source of learning. - Bill Gates',
			'Software is a great combination between artistry and engineering. - Bill Gates',
			"Success is a lousy teacher. It seduces smart people into thinking they can't lose. - Bill Gates",
			"If you can't make it good, at least make it look good. - Bill Gates",
			"If you're not making mistakes, then you're not making decisions. - Catherine Cook (MeetMe Co-Founder)",
			"I have not failed. I've just found 10.000 ways that won't work. - Thomas Edison",
			"If you don't build your dream, someone will hire you to help build theirs. - Tony Gaskin (Motivational Speaker)",
			"Don't count the days, make the days count. - Muhammad Ali",
			'Everything you can imagine is real. - Pablo Picasso',
			"In three words I can sum up everything I've learned about life: it goes on. - Robert Frost"
		)

		# get random text
		Set-Variable -Name 'text' -Value $(Get-Random $texts)
	}

	PROCESS {
		# split the text to an array on ' - '
		Set-Variable -Name 'split' -Value $($text -split ' - ')
		Set-Variable -Name 'quote' -Value $($split[0].Trim())
		Set-Variable -Name 'author' -Value $($split[1].Trim())

		# turn the quote into an array of characters
		Set-Variable -Name 'arr' -Value $($quote.ToCharArray())

		$arr | ForEach-Object -Begin {
			# define an array of colors
			#$colors = "Red", "Green", "White", "Magenta"

			# insert a few blank lines
			Write-Host "`n"

			# insert top border
			Write-Host ('*' * $($quote.length + 6))

			# insert side border
			Write-Host '*  ' -NoNewline
		} -Process {

			# write each character in a different holiday color
			Write-Host "$_" -ForegroundColor White -NoNewline
		} -End {
			Write-Host '  *'

			# insert side border
			Write-Host '* ' -NoNewline

			# write the author
			# Write-Host "- $author  *".padleft($quote.length + 4)
			Write-Host "$author  *".padleft($quote.length + 4)

			# insert bottom border
			Write-Host ('*' * $($quote.length + 6))
			Write-Host "`n"
		}
	}

	END {
		# Cleanup
		Remove-Variable -Name 'texts' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'text' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'split' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'quote' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'author' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'arr' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Get-RegKeyLastWriteTime {
	<#
			.SYNOPSIS
			Retrieves the last write time of the supplied registry key

			.DESCRIPTION
			The Registry data that a hive stores in containers are called cells.
			A cell can hold a key, a value, a security descriptor, a list of
			subkeys, or a list of key values.
			Get-RegKeyLastWriteTime retrieves the LastWriteTime through a pointer
			to the FILETIME structure that receives the time at which the
			enumerated subkey was last written. Values do not contain a
			LastWriteTime property, but changes to child values update the
			parent keys lpftLastWriteTime.

			The LastWriteTime is updated when a key is created, modified,
			accessed, or deleted.

			.PARAMETER ComputerName
			Computer name to query (Default is localhost)

			.PARAMETER Key
			Root Key to query, The default is HKLM
			HKCR - Symbolic link to HKEY_LOCAL_MACHINE \SOFTWARE \Classes.
			HKCU - Symbolic link to a key under HKEY_USERS representing a user's profile hive.
			HKLM - Placeholder with no corresponding physical hive. This key contains
			other keys that are hives.
			HKU  - Placeholder that contains the user-profile hives of logged-on accounts.
			HKCC - Symbolic link to the key of the current hardware profile

			.PARAMETER SubKey
			Registry Key to query

			.PARAMETER NoEnumKey
			A description of the NoEnumKey parameter.

			.EXAMPLE
			Get-RegKeyLastWriteTime -ComputerName 'testwks' -Key 'HKLM' -SubKey 'Software'

			Description
			-----------
			Retrieves the last write time of the supplied registry key

			.EXAMPLE
			Get-RegKeyLastWriteTime -SubKey 'Software\Microsoft'

			Description
			-----------
			Retrieves the last write time of the supplied registry key

			.EXAMPLE
			"testwks1","testwks2" | Get-RegKeyLastWriteTime -SubKey 'Software\Microsoft\Windows\CurrentVersion'

			Description
			-----------
			Retrieves the last write time of the supplied registry key

			.NOTES
			LICENSE: Creative Commons Attribution 3.0 Unported License
			(http://creativecommons.org/licenses/by/3.0/)

			.LINK
			http://www.shaunhess.com/journal/2011/7/4/reading-the-lastwritetime-of-a-registry-key-using-powershell.html
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		Position = 0)]
		[ValidateNotNullOrEmpty()]
		[Alias('CN', '__SERVER', 'Computer', 'CNAME', 'IP')]
		[System.String]$ComputerName = ($env:COMPUTERNAME),
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Root Key to query, The default is HKLM')]
		[System.String]$Key = 'HKLM',
		[Parameter(ValueFromPipeline = $true,
				Position = 2,
		HelpMessage = 'Registry Key to query')]
		[System.String]$SubKey,
		[Parameter(ValueFromPipeline = $true,
		Position = 3)]
		[switch]$NoEnumKey
	)

	BEGIN {
		switch ($Key) {
			'HKCR' { $searchKey = 0x80000000 } #HK Classes Root
			'HKCU' { $searchKey = 0x80000001 } #HK Current User
			'HKLM' { $searchKey = 0x80000002 } #HK Local Machine
			'HKU'  { $searchKey = 0x80000003 } #HK Users
			'HKCC' { $searchKey = 0x80000005 } #HK Current Config
			default {
				'Invalid Key. Use one of the following options:
				HKCR, HKCU, HKLM, HKU, HKCC'
			}
		}

		#$KEYQUERYVALUE = 0x1
		$KEYREAD = 0x19
		#$KEYALLACCESS = 0x3F
	}
	PROCESS {
		foreach ($Computer in $ComputerName) {

			$sig0 = @'
[DllImport("advapi32.dll", SetLastError = true)]
public static extern int RegConnectRegistry(
	string lpMachineName,
	int hkey,
	ref int phkResult);
'@
			$type0 = (Add-Type -MemberDefinition $sig0 -Name Win32Utils -Namespace RegConnectRegistry -UsingNamespace System.Text -PassThru)

			Write-Verbose "$type0"

			$sig1 = @'
[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
public static extern int RegOpenKeyEx(
	int hKey,
	string subKey,
	int ulOptions,
	int samDesired,
	out int hkResult);
'@
			$type1 = (Add-Type -MemberDefinition $sig1 -Name Win32Utils -Namespace RegOpenKeyEx -UsingNamespace System.Text -PassThru)

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
			$type2 = (Add-Type -MemberDefinition $sig2 -Name Win32Utils -Namespace RegEnumKeyEx -UsingNamespace System.Text -PassThru)

			$sig4 = @'
[DllImport("advapi32.dll")]
public static extern int RegQueryInfoKey(
	int hkey,
	StringBuilder lpClass,
	ref int lpcbClass,
	int lpReserved,
	out int lpcSubKeys,
	out int lpcbMaxSubKeyLen,
	out int lpcbMaxClassLen,
	out int lpcValues,
	out int lpcbMaxValueNameLen,
	out int lpcbMaxValueLen,
	out int lpcbSecurityDescriptor,
	out long lpftLastWriteTime);
'@
			$type4 = (Add-Type -MemberDefinition $sig4 -Name Win32Utils -Namespace RegQueryInfoKey -UsingNamespace System.Text -PassThru)

			$sig3 = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern int RegCloseKey(
	int hKey);
'@
			$type3 = (Add-Type -MemberDefinition $sig3 -Name Win32Utils -Namespace RegCloseKey -UsingNamespace System.Text -PassThru)

			$hKey = (New-Object int)
			$hKeyref = (New-Object int)
			#$searchKeyRemote = $type0::RegConnectRegistry($computer, $searchKey, [ref]$hKey)
			$result = $type1::RegOpenKeyEx($hKey, $SubKey, 0, $KEYREAD, [ref]$hKeyref)

			if ($NoEnumKey) {
				#initialize variables
				$time = (New-Object Long)
				$result = ($type4::RegQueryInfoKey($hKeyref, $null, [ref]$null, 0, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$null, [ref]$time))

				#create output object
				$o = '' | Select-Object Key, LastWriteTime, ComputerName
				$o.ComputerName = "$Computer"
				$o.Key = "$Key\$SubKey"

				# TODO Change to use the time api
				$o.LastWriteTime = (Get-Date $time).AddYears(1600).AddHours(-4)
				$o
			} else {
				#initialize variables
				$builder = (New-Object System.Text.StringBuilder -ArgumentList 1024)
				$index = 0
				$length = [int] 1024
				$time = (New-Object Long)

				#234 means more info, 0 means success. Either way, keep reading
				while (0, 234 -contains $type2::RegEnumKeyEx($hKeyref, $index++ , $builder, [ref]$length, $null, $null, $null, [ref]$time)) {
					#create output object
					$o = '' | Select-Object Key, LastWriteTime, ComputerName
					$o.ComputerName = "$Computer"
					$o.Key = $builder.ToString()

					# TODO Change to use the time api
					$o.LastWriteTime = (Get-Date $time).AddYears(1600).AddHours(-4)
					$o

					#reinitialize for next time through the loop
					$length = [int] 1024
					$builder = (New-Object System.Text.StringBuilder -ArgumentList 1024)
				}
			}
			$result = $type3::RegCloseKey($hKey)
		}
	}
}

function Get-RelativePath {
	<#
			.SYNOPSIS
			Get a path to a file (or folder) relative to another folder

			.DESCRIPTION
			Converts the FilePath to a relative path rooted in the specified Folder

			.PARAMETER Folder
			The folder to build a relative path from

			.PARAMETER FilePath
			The File (or folder) to build a relative path TO

			.PARAMETER Resolve
			If true, the file and folder paths must exist

			.Example
			PS C:\> Get-RelativePath ~\Documents\WindowsPowerShell\Logs\ ~\Documents\WindowsPowershell\Modules\Logger\log4net.xslt
			..\Modules\Logger\log4net.xslt

			Description
			-----------
			Returns a path to log4net.xslt relative to the Logs folder

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'The folder to build a relative path from')]
		[System.String]$Folder,
		[Parameter(Mandatory = $true,
				ValueFromPipelineByPropertyName = $true,
				Position = 1,
		HelpMessage = 'The File (or folder) to build a relative path TO')]
		[Alias('FullName')]
		[System.String]$FilePath,
		[Parameter(HelpMessage = 'If true, the file and folder paths must exist')]
		[switch]$Resolve
	)

	BEGIN {
		# FROM (Compare 1)
		$from = $Folder = (Split-Path $Folder -NoQualifier -Resolve:$Resolve)

		# TO (Compare 2)
		$to = $FilePath = (Split-Path $FilePath -NoQualifier -Resolve:$Resolve)
	}

	PROCESS {
		# Now we compare what we have
		while ($from -and $to -and ($from -ne $to)) {
			# Check the Length of both
			if ($from.Length -gt $to.Length) {
				$from = (Split-Path $from)
			} else {
				$to = (Split-Path $to)
			}
		}

		# Setup and fill the Variables
		$FilePath = ($FilePath -replace '^' + [regex]::Escape($to) + '\\')
		$from = ($Folder)

		# compare to figure out what to show
		while ($from -and $to -and $from -gt $to) {
			# Setup and fill the Variables
			$from = (Split-Path $from)
			$FilePath = (Join-Path '..' -ChildPath $FilePath)
		}
	}

	END {
		# Do a garbage collection
		Write-Output $FilePath
	}
}

function Get-ReqParams {
	<#
			.SYNOPSIS
			A quick way to view required parameters on a cmdlet

			.DESCRIPTION
			A quick way to view required parameters on a cmdlet, function,
			provider, script or workflow

			.PARAMETER command
			Gets required parameters of the specified command or concept.
			Enter the name of a cmdlet, function, provider, script, or workflow,
			such as "Get-Member", a conceptual topic name, such as "about_Objects",
			or an alias, such as "ls".

			.EXAMPLE
			PS C:\> PS C:\scripts\PowerShell> Get-ReqParams -command 'New-ADUser'

			-Name <String>
			Specifies the name of the object. This parameter sets the Name property of the Active Directory object. The LDAP Display
			Name (ldapDisplayName) of this property is name.

			Required?                    true
			Position?                    2
			Default value
			Accept pipeline input?       True (ByPropertyName)
			Accept wildcard characters?  false

			.NOTES
			Just a filter for Get-Help
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'cmdlet')]
		[ValidateNotNullOrEmpty()]
		[Alias('cmd')]
		[System.String]$command
	)

	PROCESS {
		Get-Help $command -Parameter * | Where-Object { $_.required -eq $true }
	}
}

function Get-ScriptDirectory {
	<#
			.SYNOPSIS
			Get the Directory of the Script that invokes this function

			.DESCRIPTION
			Get the Directory of the Script that invokes this function

			.EXAMPLE
			PS C:\> .\test.ps1
			C:\scripts\PowerShell

			Description
			-----------
			Get the Directory of the Script that invokes this function

			.NOTES
			Just a quick helper to reduce the script header overhead

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

function Get-ServiceStatus {
	<#
			.SYNOPSIS
			List Services Where-Object StartMode is AUTOMATIC that are NOT running

			.DESCRIPTION
			This function will list services from a local or remote computer
			Where-Object the StartMode property is set to "Automatic" and
			Where-Object the state is different from RUNNING
			(so mostly Where-Object the state is NOT RUNNING)

			.PARAMETER ComputerName
			Computer Name to execute the function

			.EXAMPLE
			PS C:\> Get-ServiceStatus
			DisplayName                                  Name                           StartMode State
			-----------                                  ----                           --------- -----
			Microsoft .NET Framework NGEN v4.0.30319_X86 clr_optimization_v4.0.30319_32 Auto      Stopped
			Microsoft .NET Framework NGEN v4.0.30319_X64 clr_optimization_v4.0.30319_64 Auto      Stopped
			Multimedia Class Scheduler                   MMCSS                          Auto      Stopped

			Description
			-----------
			List Services Where-Object StartMode is AUTOMATIC that are NOT running

			.NOTES
			Just an initial Version of the Function,
			it might still need some optimization.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Position = 0,
		HelpMessage = 'Computer Name to execute the function')]
		[System.String]$ComputerName = "$env:COMPUTERNAME"
	)

	PROCESS {
		# Try one or more commands
		try {
			# Cleanup
			Remove-Variable -Name 'ServiceStatus' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

			# Get the Infos
			Set-Variable -Name 'ServiceStatus' -Value $(Get-WmiObject Win32_Service -ComputerName $ComputerName |
				Where-Object { ($_.startmode -like '*auto*') -and ($_.state -notlike '*running*') } |
				Select-Object DisplayName, Name, StartMode, State |
			Format-Table -AutoSize)

			# Dump it to the Console
			Write-Output -InputObject $ServiceStatus
		} catch {
			# Whoopsie!!!
			Write-Warning -Message 'Could not get the list of services for $ComputerName'
		} finally {
			# Cleanup
			Remove-Variable -Name 'ServiceStatus' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Get-ServiceStatusInfo {
	<#
			.SYNOPSIS
			This function identifies all services that are configured to auto start
			with system but are in stopped state

			.DESCRIPTION
			This function identifies all services that are configured to auto start
			with system but are in stopped state

			.EXAMPLE
			PS C:\Windows\system32> Get-ServiceStatusInfo

			Checking System Service status...
			Total 4 services identified that have startup type configured to Auto start, but are in stopped state.
			1. Microsoft .NET Framework NGEN v4.0.30319_X86 .
			2. Microsoft .NET Framework NGEN v4.0.30319_X64 .
			3. Multimedia Class Scheduler .
			4. Software Protection .

			Description
			-----------
			This function identifies all services that are configured to auto
			start with system but are in stopped state

			.NOTES
			Internal Helper
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		$Services = $(Get-WmiObject -Class win32_service |
			Where-Object { $_.startmode -eq 'Auto' -and $_.State -eq 'Stopped' } |
		Select-Object displayname -ExpandProperty displayname)
		$count = ($Services.count)
		$ServicesString = "`r`nChecking System Service status...`r`nTotal $count services identified that have startup type configured to Auto start, but are in stopped state."
		$ServicesString = ($ServicesString + $(1..$count | ForEach-Object { "`r`n $_. $($Services[$($_) - 1]) ." }))
	}

	END {
		Write-Output $ServicesString
	}
}

function Get-ShortDate {
	<#
			.SYNOPSIS
			Get a short Date String

			.DESCRIPTION
			Get a short Date String, just the date not the time

			.EXAMPLE
			PS C:\> Get-ShortDate
			05.03.2016

			Description
			-----------
			Get a short Date String

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		(Get-Date).toShortDateString()
	}
}

function Get-Syntax {
	<#
			.SYNOPSIS
			Get the syntax of a cmdlet, even if we have no help for it

			.DESCRIPTION
			Helper function to get the syntax of a alias or cmdlet,
			even if we have no help for it

			.PARAMETER cmdlet
			command-let that you want to check

			.EXAMPLE
			PS C:\> Get-syntax Get-syntax

			Description
			-----------
			Get the syntax and parameters for the cmdlet "Get-syntax".
			Makes no sense at all, but this is just an example!

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[ValidateNotNullOrEmpty()]
		[Alias('Command')]
		$cmdlet
	)

	PROCESS {
		# Use Get-Command to show the syntax
		Get-Command $cmdlet -Syntax
	}
}

function Get-SysType {
	<#
			.SYNOPSIS
			Show if the system is Workstation or a Server

			.DESCRIPTION
			This function shows of the system is a server or a workstation.
			Additionally it can show more detailed infos (like Domain Membership)

			.PARAMETER d
			Shows a more detailed information, including the domain level

			.EXAMPLE
			PS C:\> Get-SysType
			Workstation

			Description
			-----------
			The system is a Workstation (with or without Domain membership)

			.EXAMPLE
			PS C:\>  Get-SysType -d
			Standalone Server

			Description
			-----------
			The system is a non domain joined server.

			.NOTES
			Wrote this for myself to see what system I was connected to via
			Remote PowerShell

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Position = 0,
		HelpMessage = 'Displays a more detailed info')]
		[Alias('detail')]
		[switch]$d
	)

	BEGIN {
		# Cleanup
		$role = $null

		# Read role
		$role = ((Get-WmiObject Win32_ComputerSystem).DomainRole)
	}

	PROCESS {
		if ($d) {
			Switch ($role) {
				0 { Return 'Standalone Workstation' }
				1 { Return 'Member Workstation' }
				2 { Return 'Standalone Server' }
				3 { Return 'Member Server' }
				4 { Return 'Backup Domain Controller' }
				5 { Return 'Primary Domain Controller' }
				default { Return 'Unknown' }
			}
		} else {
			if (($role) -eq '0' -OR ($role) -eq '1') {
				Return 'Workstation'
			} elseif (($role) -gt '1' -AND ($role) -le '5') {
				Return 'Server'
			} else {
				Return 'Unknown'
			}
		}
	}

	END {
		# Cleanup
		$role = $null
	}
}

function Get-TempFile {
	<#
			.SYNOPSIS
			Creates a string with a temp file

			.DESCRIPTION
			Creates a string with a temp file

			.PARAMETER Extension
			File Extension as a string.
			The default is "tmp"

			.EXAMPLE
			PS C:\> New-TempFile
			C:\Users\josh\AppData\Local\Temp\332ddb9a-5e52-4687-aa01-1d67ab6ae2b1.tmp

			Description
			-----------
			Returns a String of the Temp File with the extension TMP.

			.EXAMPLE
			PS C:\> New-TempFile -Extension txt
			C:\Users\josh\AppData\Local\Temp\332ddb9a-5e52-4687-aa01-1d67ab6ae2b1.txt

			Description
			-----------
			Returns a String of the Temp File with the extension TXT

			.EXAMPLE
			PS C:\> $foo = (New-TempFile)
			PS C:\> New-Item -Path $foo -Force -Confirm:$false
			PS C:\> Add-Content -Path:$LogPath -Value:"Test" -Encoding UTF8 -Force
			C:\Users\josh\AppData\Local\Temp\d08cec6f-8697-44db-9fba-2c369963a017.tmp

			Description
			-----------
			Creates a temp File: C:\Users\josh\AppData\Local\Temp\d08cec6f-8697-44db-9fba-2c369963a017.tmp

			And fill the newly created file with the String "Test"

			.NOTES
			Helper to avoid "System.IO.Path]::GetTempFileName()" usage.

			.LINK
			Idea: http://powershell.com/cs/blogs/tips/archive/2015/10/15/creating-temporary-filenames.aspx

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(HelpMessage = 'File Extension as a string. like tmp')]
		[System.String]$Extension = 'tmp'
	)

	BEGIN {
		$elements = @()
	}


	PROCESS {
		# Define objects
		$elements += [System.IO.Path]::GetTempPath()
		$elements += [System.Guid]::NewGuid()
		$elements += $Extension.TrimStart('.')
	}

	END {
		# Here we go: This is a Teampfile
		'{0}{1}.{2}' -f $elements
	}
}

function Get-TimeStamp {
	<#
			.SYNOPSIS
			Get-TimeStamp dumps a default Time-Stamp

			.DESCRIPTION
			Get-TimeStamp dumps a default Time-Stamp in the following format:
			yyyy-MM-dd HH:mm:ss

			.EXAMPLE
			PS C:\> Get-TimeStamp
			2015-12-13 18:05:18

			Description
			-----------
			Get a Time-Stamp as i would like it.

			.NOTES
			This is just a little helper function to make the shell more flexible
			It is just a kind of a leftover: Used that within my old logging
			functions a lot

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	PROCESS {
		Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
	}
}

function Get-TopProcesses {
	<#
			.SYNOPSIS
			Make the PowerShell a bit more *NIX like

			.DESCRIPTION
			This is a PowerShell Version of the well known *NIX like TOP

			.EXAMPLE
			PS C:\> top

			Description
			-----------
			Shows the top CPU consuming processes

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Define objects
		Set-Variable -Name SetValX -Value $([Console]::CursorLeft)
		Set-Variable -Name SetValY -Value $([Console]::CursorTop)
	}

	PROCESS {
		# figure out what uses the most CPU Time
		While ($true) {
			# Get the fist 30 items
			(Get-Process |
				Sort-Object -Descending CPU |
			Select-Object -First 30)

			# Wait 2 seconds
			Start-Sleep -Seconds 2

			# Dump the Info
			[Console]::SetCursorPosition(${SetValX}, ${SetValY} + 3)
		}
	}
}

# Uni* like Uptime
function Get-Uptime {
	<#
			.SYNOPSIS
			Show how long system has been running

			.DESCRIPTION
			Uni* like Uptime - The uptime utility displays the current time,
			the length of time the system has been up

			.EXAMPLE
			PS C:\> Get-Uptime
			Uptime: 0 days, 2 hours, 11 minutes

			Description
			-----------
			Returns the uptime of the system, the time since last reboot/startup

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		# Define objects
		$os = (Get-WmiObject win32_operatingsystem)
		$uptime = ((Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime)))
		$Display = 'Uptime: ' + $uptime.Days + ' days, ' + $uptime.Hours + ' hours, ' + $uptime.Minutes + ' minutes'
	}

	END {
		# Dump the Infos
		Write-Output $Display
	}
}

function Get-UUID {
	<#
			.SYNOPSIS
			Generates a UUID String

			.DESCRIPTION
			Generates a UUID String and is a uuidgen.exe replacement

			.EXAMPLE
			PS C:\> Get-UUID
			a08cdabe-f598-4930-a537-80e7d9f15dc3

			Description
			-----------
			Generates a UUID String

			.NOTES
			Just a little helper function

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		# Call NET function
		[guid]::NewGuid().ToString('d')
	}
}

function Get-ValidateFileName {
	<#
			.SYNOPSIS
			Validates if the file name has valid characters

			.DESCRIPTION
			Validates if the file name has valid characters

			.PARAMETER FileName
			A string containing a file name

			.EXAMPLE
			PS C:\> Get-ValidateFileName test1.ps1
			True

			Description
			-----------
			Validates if the file name has valid characters

			.EXAMPLE
			PS C:\> Get-ValidateFileName -Filename 'test1.ps1'
			True

			Description
			-----------
			Validates if the file name has valid characters

			.OUTPUTS
			System.Boolean

			.NOTES
			Very easy helper function

			.INPUTS
			System.String
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'A string containing a file name')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Filename
	)

	PROCESS {
		$invalidChars = [System.IO.Path]::GetInvalidFileNameChars()

		foreach ($fileChar in $Filename) {
			foreach ($invalid in $invalidChars) {
				if ($fileChar -eq $invalid) {
					return $false
				}
			}
		}

		return $true
	}
}

function Get-ValidateIsIP {
	<#
			.SYNOPSIS
			Validates if input is an IP Address

			.DESCRIPTION
			Validates if input is an IP Address

			.PARAMETER IP
			A string containing an IP address

			.EXAMPLE
			PS C:\> Get-ValidateIsIP 10.211.55.125
			True

			Description
			-----------
			Validates if input is an IP Address

			.EXAMPLE
			PS C:\> Get-ValidateIsIP -IP '10.211.55.125'
			True

			Description
			-----------
			Validates if input is an IP Address

			.EXAMPLE
			PS C:\> Get-ValidateIsIP -IP 'fe80::3db7:8507:3f9a:bb13%11'
			True

			Description
			-----------
			Validates if input is an IP Address

			.OUTPUTS
			System.Boolean

			.NOTES
			Very easy helper function

			.INPUTS
			System.String
	#>

	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'A string containing an IP address')]
		[ValidateNotNullOrEmpty()]
		[System.String]$IP
	)

	PROCESS {
		try {
			return ([System.Net.IPAddress]::Parse($IP))
		} catch {
			Write-Debug 'Something is wrong!!!'
		}

		return $false
	}
}

function Get-ValidatePath {
	<#
			.SYNOPSIS
			Validates if path has valid characters

			.DESCRIPTION
			Validates if path has valid characters

			.PARAMETER Path
			A string containing a directory or file path

			.EXAMPLE
			PS C:\> Get-ValidatePath C:\Users\josh\Documents
			True

			Description
			-----------
			Validates if path has valid characters

			.EXAMPLE
			PS C:\> Get-ValidatePath -Path "C:\Users\josh\Documents"
			True

			Description
			-----------
			Validates if path has valid characters

			.OUTPUTS
			System.Boolean

			.NOTES
			Very easy helper function

			.INPUTS
			System.String
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'A string containing a directory or file path')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Path
	)

	PROCESS {
		$invalidChars = [System.IO.Path]::GetInvalidPathChars()

		foreach ($pathChar in $Path) {
			foreach ($invalid in $invalidChars) {
				if ($pathChar -eq $invalid) {
					return $false
				}
			}
		}

		return $true
	}
}

function Get-Whois {
	<#
			.SYNOPSIS
			Script to retrieve WhoIs information from a list of domains

			.DESCRIPTION
			This script will, by default, create a report of WhoIs information on
			1 or more Internet domains. Not all Top-Level Domains support Whois
			queries! e.g. .de (Germany) domains!

			Report options are CSV, Json, XML, HTML, and object (default) output.
			Dates in the CSV, Json, and HTML options are formatted for the culture
			settings on the PC.
			Columns in HTML report are also sortable, just click on the headers.

			.PARAMETER Domain
			One or more domain names to check. Accepts pipeline.

			.PARAMETER Path
			Path Where-Object the resulting HTML or CSV report will be saved.

			Default is: C:\scripts\PowerShell\export

			.PARAMETER RedThresold
			If the number of days left before the domain expires falls below this
			number the entire row will be highlighted in Red (HTML reports only).

			Default is 30 (Days)

			.PARAMETER YellowThresold
			If the number of days left before the domain expires falls below this
			number the entire row will be highlighted in Yellow (HTML reports only)

			Default is 90 (Days)

			.PARAMETER GreyThresold
			If the number of days left before the domain expires falls below this
			number the entire row will be highlighted in Grey (HTML reports only).

			Default is 365 (Days)

			.PARAMETER OutputType
			Specify what kind of report you want.  Valid types are Json, XML,HTML,
			CSV, or Object.

			The default is Object.

			.EXAMPLE
			PS C:\> Get-Whois -Domain "NET-Experts.net","timberforest.com"

			Description
			-----------
			Will create object Whois output of the domain registration data.

			.EXAMPLE
			PS C:\> Get-Whois -Domain "NET-Experts.net" -OutputType json

			Description
			-----------
			Will create Json Whois Report of the domain registration data.

			.NOTES
			Based on an idea of Martin Pugh (Martin Pugh)

			.LINK
			Source: http://community.spiceworks.com/scripts/show/2809-whois-report-Get-whois-ps1

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'One or more domain names to check. Accepts pipeline.')]
		[System.String]$Domain,
		[Parameter(HelpMessage = 'Path Where-Object the resulting HTML or CSV report will be saved. Default is: C:\scripts\PowerShell\export')]
		[System.String]$Path = 'C:\scripts\PowerShell\export',
		[Parameter(HelpMessage = 'If the number of days left before the domain expires falls below this number the entire row will be highlighted in Red (HTML reports only). Default is 30 (Days)')]
		[System.Int32]$RedThresold = 30,
		[Parameter(HelpMessage = 'If the number of days left before the domain expires falls below this number the entire row will be highlighted in Yellow (HTML reports only). Default is 90 (Days)')]
		[System.Int32]$YellowThresold = 90,
		[Parameter(HelpMessage = 'If the number of days left before the domain expires falls below this number the entire row will be highlighted in Grey (HTML reports only). Default is 365 (Days)')]
		[System.Int32]$GreyThresold = 365,
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Specify what kind of report you want.  Valid types are Json, XML,HTML, CSV, or Object. The default is Object.')]
		[ValidateSet('object', 'json', 'csv', 'html', 'html', 'xml')]
		[System.String]$OutputType = 'object'
	)

	BEGIN {
		# Be Verbose
		Write-Verbose "$(Get-Date): Get-WhoIs script beginning."

		# Validate the path
		If ($Path) {
			If (Test-Path $Path) {
				If (-not (Get-Item $Path).PSisContainer) {
					# Aw Snap!
					Write-Error  "You cannot specify a file in the Path parameter, must be a folder: $Path"

					# Die headers
					exit 1
				}
			} Else {
				# Aw Snap!
				Write-Error  "Unable to locate: $Path"

				# Die hard!
				exit 1
			}
		} Else {
			$Path = (Split-Path $MyInvocation.MyCommand.Path)
		}

		# Create the Web Proxy instance
		$WC = (New-WebServiceProxy 'http://www.webservicex.net/whois.asmx?WSDL')

		# Cleanup
		$data = @()
	}

	PROCESS {
		# Loop over the given domains
		$data += ForEach ($Dom in $Domain) {
			# Be Verbose
			Write-Verbose "$(Get-Date): Querying for $Dom"

			# Cleanup
			$DNError = ''

			Try {
				$raw = $WC.GetWhoIs($Dom)
			} Catch {
				# Some domains throw an error, I assume because the WhoIs server isn't returning standard output
				$DNError = "$($Dom.ToUpper()): Unknown Error retrieving WhoIs information"
			}

			# Test if the domain name is good or if the data coming back is ok--Google.Com just returns a list of domain names so no good
			If ($raw -match 'No match for') {
				$DNError = "$($Dom.ToUpper()): Unable to find registration for domain"
			} ElseIf ($raw -notmatch 'Domain Name: (.*)') {
				$DNError = "$($Dom.ToUpper()): WhoIs data not in correct format"
			}

			If ($DNError) {
				# Use 999899 to tell the script later that this is a bad domain and color it properly in HTML (if HTML output requested)
				[PSCustomObject]@{
					DomainName  = $DNError
					Registrar   = ''
					WhoIsServer = ''
					NameServers = ''
					DomainLock  = ''
					LastUpdated = ''
					Created     = ''
					Expiration  = ''
					DaysLeft    = 999899
				}

				# Bad!
				Write-Warning -Message "$DNError"
			} Else {
				# Parse out the DNS servers
				$NS = ForEach ($Match in ($raw | Select-String -Pattern 'Name Server: (.*)' -AllMatches).Matches) {
					$Match.Groups[1].Value
				}

				#Parse out the rest of the data
				[PSCustomObject]@{
					DomainName  = (($raw | Select-String -Pattern 'Domain Name: (.*)').Matches.Groups[1].Value)
					Registrar   = (($raw | Select-String -Pattern 'Registrar: (.*)').Matches.Groups[1].Value)
					WhoIsServer = (($raw | Select-String -Pattern 'WhoIs Server: (.*)').Matches.Groups[1].Value)
					NameServers = ($NS -join ', ')
					DomainLock  = (($raw | Select-String -Pattern 'Status: (.*)').Matches.Groups[1].Value)
					LastUpdated = [datetime]($raw | Select-String -Pattern 'Updated Date: (.*)').Matches.Groups[1].Value
					Created     = [datetime]($raw | Select-String -Pattern 'Creation Date: (.*)').Matches.Groups[1].Value
					Expiration  = [datetime]($raw | Select-String -Pattern 'Expiration Date: (.*)').Matches.Groups[1].Value
					DaysLeft    = ((New-TimeSpan -Start (Get-Date) -End ([datetime]($raw | Select-String -Pattern 'Expiration Date: (.*)').Matches.Groups[1].Value)).Days)
				}
			}
		}
	}

	END {
		# Be Verbose
		Write-Verbose "$(Get-Date): Producing $OutputType report"

		#
		$WC.Dispose()

		# Sort the Domain Data
		$data = $data | Sort-Object DomainName

		# What kind of output?
		Switch ($OutputType) {
			'object'
			{
				# Dump to Console
				(Write-Output $data | Select-Object DomainName, Registrar, WhoIsServer, NameServers, DomainLock, LastUpdated, Created, Expiration, @{
						Name       = 'DaysLeft'
						Expression = { If ($_.DaysLeft -eq 999899) { 0 } Else { $_.DaysLeft } }
				})
			}
			'csv'
			{
				# Export a CSV
				$ReportPath = (Join-Path -Path $Path -ChildPath 'WhoIs.CSV')
				($data |
					Select-Object DomainName, Registrar, WhoIsServer, NameServers, DomainLock, @{
						Name       = 'LastUpdated'
						Expression = { Get-Date $_.LastUpdated -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, @{
						Name       = 'Created'
						Expression = { Get-Date $_.Created -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, @{
						Name       = 'Expiration'
						Expression = { Get-Date $_.Expiration -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, DaysLeft |
				Export-Csv $ReportPath -NoTypeInformation)
			}
			'xml'
			{
				# Still like XML?
				$ReportPath = (Join-Path -Path $Path -ChildPath 'WhoIs.XML')
				($data |
					Select-Object DomainName, Registrar, WhoIsServer, NameServers, DomainLock, LastUpdated, Created, Expiration, @{
						Name       = 'DaysLeft'
						Expression = { If ($_.DaysLeft -eq 999899) { 0 } Else { $_.DaysLeft } }
					} |
				Export-Clixml $ReportPath)
			}
			'json'
			{
				# I must admin: I like Json...
				$ReportPath = (Join-Path -Path $Path -ChildPath 'WhoIs.json')
				$JsonData = ($data | Select-Object DomainName, Registrar, WhoIsServer, NameServers, DomainLock, @{
						Name       = 'LastUpdated'
						Expression = { Get-Date $_.LastUpdated -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, @{
						Name       = 'Created'
						Expression = { Get-Date $_.Created -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, @{
						Name       = 'Expiration'
						Expression = { Get-Date $_.Expiration -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
				}, DaysLeft)
				ConvertTo-Json -InputObject $JsonData -Depth 10 > $ReportPath
			}
			'html'
			{
				# OK, HTML is should be!
				$Header = @"
<script src="http://kryogenix.org/code/browser/sorttable/sorttable.js"></script>
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TR:Hover TD {Background-Color: #C1D5F8;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;cursor: pointer;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
</style>
<title>
WhoIS Report
</title>
"@

				$PreContent = @"
<p><h1>WhoIs Report</h1></p>
"@

				$PostContent = @"
<p><br/><h3>Legend</h3>
<pre><span style="background-color:red">    </span>  Expires in under $RedThreshold days
<span style="background-color:yellow">    </span>  Expires in under $YellowThreshold days
<span style="background-color:#B0C4DE">    </span>  Expires in under $GreyThreshold days
<span style="background-color:#DEB887">    </span>  Problem retrieving information about domain/Domain not found</pre></p>
<h6><br/>Run on: $(Get-Date)</h6>
"@

				$RawHTML = ($data |
					Select-Object DomainName, Registrar, WhoIsServer, NameServers, DomainLock, @{
						Name       = 'LastUpdated'
						Expression = { Get-Date $_.LastUpdated -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, @{
						Name       = 'Created'
						Expression = { Get-Date $_.Created -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, @{
						Name       = 'Expiration'
						Expression = { Get-Date $_.Expiration -Format (Get-Culture).DateTimeFormat.ShortDatePattern }
					}, DaysLeft |
				ConvertTo-Html -Head $Header -PreContent $PreContent -PostContent $PostContent)

				$HTML = ForEach ($Line in $RawHTML) {
					if ($Line -like '*<tr><td>*') {
						$Value = [float](([xml]$Line).SelectNodes('//td').'#text'[-1])

						if ($Value) {
							if ($Value -eq 999899) {
								$Line.Replace('<tr><td>', '<tr style="background-color: #DEB887;"><td>').Replace('<td>999899</td>', '<td>0</td>')
							} elseif ($Value -lt $RedThreshold) {
								$Line.Replace('<tr><td>', '<tr style="background-color: red;"><td>')
							} elseif ($Value -lt $YellowThreshold) {
								$Line.Replace('<tr><td>', '<tr style="background-color: yellow;"><td>')
							} elseif ($Value -lt $GreyThreshold) {
								$Line.Replace('<tr><td>', '<tr style="background-color: #B0C4DE;"><td>')
							} else {
								$Line
							}
						}
					} elseif ($Line -like '*<table>*') {
						$Line.Replace('<table>', '<table class="sortable">')
					} else {
						$Line
					}
				}

				# File name
				$ReportPath = (Join-Path -Path $Path -ChildPath 'WhoIs.html')

				# Dump the HTML
				($HTML | Out-File $ReportPath -Encoding ASCII)

				# Immediately display the html if in debug mode
				if ($pscmdlet.MyInvocation.BoundParameters['Debug'].IsPresent) {
					& $ReportPath
				}
			}
		}

		# Be Verbose
		Write-Verbose "$(Get-Date): Get-WhoIs script completed!"
	}
}

# Old implementation of the above GREP tool
# More complex but even more UNI* like
function Invoke-GnuGrep {
	<#
			.SYNOPSIS
			File pattern searcher

			.DESCRIPTION
			This command emulates the well known (and loved?) GNU file
			pattern searcher

			.PARAMETER pattern
			Pattern (STRING) - Mandatory

			.PARAMETER filefilter
			File (STRING) - Mandatory

			.PARAMETER r
			Recurse

			.PARAMETER i
			Ignore case

			.PARAMETER l
			List filenames

			.EXAMPLE
			Invoke-GnuGrep

			Description
			-----------
			File pattern searcher

			.EXAMPLE
			Invoke-GnuGrep

			Description
			-----------
			File pattern searcher

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues

	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = ' Pattern (STRING) - Mandatory')]
		[ValidateNotNullOrEmpty()]
		[Alias('PaternString')]
		[System.String]$pattern,
		[Parameter(Mandatory = $true,
				Position = 1,
		HelpMessage = ' File (STRING) - Mandatory')]
		[ValidateNotNullOrEmpty()]
		[Alias('FFilter')]
		[System.String]$filefilter,
		[Alias('Recursive')]
		[switch]$r,
		[Alias('IgnoreCase')]
		[switch]$i,
		[Alias('ListFilenames')]
		[switch]$l
	)

	BEGIN {
		# Define object
		Set-Variable -Name path -Value $($PWD)

		# need to add filter for files only, no directories
		Set-Variable -Name files -Value $(Get-ChildItem $Path -Include "$filefilter" -Recurse:$r)
	}

	PROCESS {
		# What to do?
		if ($l) {
			# Do we need to loop?
			$files | ForEach-Object {
				# What is it?
				if ($(Get-Content $_ | Select-String -Pattern $pattern -CaseSensitive:$i).Count > 0) {
					$_ | Select-Object path
				}
			}
			Select-String $pattern $files -CaseSensitive:$i
		} else {
			$files | ForEach-Object {
				$_ | Select-String -Pattern $pattern -CaseSensitive:$i
			}
		}
	}
}

function Grant-PathFullPermission {
	<#
			.SYNOPSIS
			Grant Full Access Permission for a given user to a given Path

			.DESCRIPTION
			Grant Full Access Permission for a given user to a given Path

			.PARAMETER path
			Path you want to grant the access to

			.PARAMETER user
			User you want to grant the access to

			.EXAMPLE
			PS C:\> Grant-PathFullPermission -path 'D:\dev' -user 'John'

			Description
			-----------
			Grant Full Access Permission for a given user 'John' to a given
			Path 'D:\dev'

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Path you want to grant the access to')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Path,
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'User you want to grant the access to')]
		[System.String]$user
	)

	BEGIN {
		if (-not (Test-Path -Path $Path -PathType Container)) {
			Write-Error -Message "Sorry $Path does not exist!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		} else {
			Write-Output "Set full permission on $Path for $user."
		}
	}

	PROCESS {
		# Get the existing ACL for the Path
		try {
			($acl = (Get-Acl -Path $Path -ErrorAction:Stop -WarningAction:SilentlyContinue)) > $null 2>&1 3>&1
		} catch {
			# Whoopsie
			Write-Error -Message "Could not get existing ACL for $Path" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		}

		# Do we have inheritance?
		$inheritance = $(
			if (Test-Path -Path $Path -PathType Container) {
				'ContainerInherit, ObjectInherit'
			} else {
				'None'
		})

		# Build a new Rule...
		$rule = (New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($user, 'FullControl', $inheritance, 'None', 'Allow'))

		# Set the new rule
		$acl.SetAccessRule($rule)

		# Apply the new Rule to the Path
		try {
			(Set-Acl -Path $Path -AclObject $acl -ErrorAction:Stop -WarningAction:SilentlyContinue) > $null 2>&1 3>&1
		} catch {
			# Whoopsie
			Write-Error -Message "Could not set new ACL for $user on $Path" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		}
	}
}

function Compress-GZip {
	<#
			.SYNOPSIS
			GZip Compress (.gz)

			.DESCRIPTION
			A buffered GZip (.gz) Compress function that support pipelined input

			.PARAMETER FullName
			Input File

			.PARAMETER GZipPath
			Name of the GZ Archive

			.PARAMETER Force
			Enforce it?

			.Example
			Get-ChildItem .\locations.txt | Compress-GZip -Verbose -WhatIf
			VERBOSE: Reading from: C:\scripts\PowerShell\locations.txt
			VERBOSE: Compressing to: C:\scripts\PowerShell\locations.txt.gz
			What if: Performing the operation "Compress-GZip" on target "Create new Compressed File @ C:\scripts\PowerShell\locations.txt.gz".
			What if: Performing the operation "Compress-GZip" on target "Creating Compress File @ C:\scripts\PowerShell\locations.txt.gz".

			Description
			-----------
			Simulate GZip Compress '.\locations.txt'

			.Example
			Get-ChildItem .\NotCompressFile.xml | Compress-GZip

			Description
			-----------
			GZip Compress '.\NotCompressFile.xml' to '.\NotCompressFile.xml.gz'

			.Example
			Compress-GZip -FullName "C:\scripts\NotCompressFile.xml" -NewName "Compressed.xml.funkyextension"

			Description
			-----------
			GZip Compress "C:\scripts\NotCompressFile.xml" and generates the
			archive "Compressed.xml.funkyextension" instead of the default '.gz'

			.NOTES
			Copyright 2013 Robert Nees
			Licensed under the Apache License, Version 2.0 (the "License");

			.LINK
			http://sushihangover.blogspot.com
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Input File')]
		[Alias('PSPath')]
		[System.String]$FullName,
		[Parameter(ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Name of the GZ Archive')]
		[Alias('NewName')]
		[System.String]$GZipPath,
		[Parameter(HelpMessage = 'Enforce it?')]
		[switch]$Force
	)

	PROCESS {
		$_BufferSize = 1024 * 8
		if (Test-Path -Path $FullName -PathType Leaf) {
			# Be Verbose
			Write-Verbose "Reading from: $FullName"

			if ($GZipPath.Length -eq 0) {
				$tmpPath = (Get-ChildItem -Path $FullName)
				$GZipPath = (Join-Path -Path ($tmpPath.DirectoryName) -ChildPath ($tmpPath.Name + '.gz'))
			}

			if (Test-Path -Path $GZipPath -PathType Leaf -IsValid) {
				Write-Verbose "Compressing to: $GZipPath"
			} else {
				Write-Error -Message "$FullName is not a valid path/file"
				return
			}
		} else {
			Write-Error -Message "$GZipPath does not exist"
			return
		}

		if (Test-Path -Path $GZipPath -PathType Leaf) {
			If ($Force.IsPresent) {
				if ($pscmdlet.ShouldProcess("Overwrite Existing File @ $GZipPath")) {
					Set-FileTime $GZipPath
				}
			}
		} else {
			if ($pscmdlet.ShouldProcess("Create new Compressed File @ $GZipPath")) {
				Set-FileTime $GZipPath
			}
		}

		if ($pscmdlet.ShouldProcess("Creating Compress File @ $GZipPath")) {
			# Be Verbose
			Write-Verbose 'Opening streams and file to save compressed version to...'

			$Input = (New-Object System.IO.FileStream -ArgumentList (Get-ChildItem -Path $FullName).FullName, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read))
			$output = (New-Object System.IO.FileStream -ArgumentList (Get-ChildItem -Path $GZipPath).FullName, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None))
			$gzipStream = (New-Object System.IO.Compression.GzipStream -ArgumentList $output, ([IO.Compression.CompressionMode]::Compress))

			try {
				$buffer = (New-Object byte[] -ArgumentList ($_BufferSize))
				while ($true) {
					$read = ($Input.Read($buffer, 0, ($_BufferSize)))
					if ($read -le 0) {
						break
					}
					$gzipStream.Write($buffer, 0, $read)
				}
			} finally {
				# Be Verbose
				Write-Verbose 'Closing streams and newly compressed file'

				$gzipStream.Close()
				$output.Close()
				$Input.Close()
			}
		}
	}
}

function Expand-GZip {
	<#
			.SYNOPSIS
			GZip Decompress (.gz)

			.DESCRIPTION
			A buffered GZip (.gz) Decompress function that support pipelined input

			.PARAMETER FullName
			The input file

			.PARAMETER GZipPath
			Name of the GZip Archive

			.PARAMETER Force
			Enforce it?

			.Example
			Get-ChildItem .\locations.txt.gz | Expand-GZip -Verbose -WhatIf
			VERBOSE: Reading from: C:\scripts\PowerShell\locations.txt.gz
			VERBOSE: Decompressing to: C:\scripts\PowerShell\locations.txt
			What if: Performing the operation "Expand-GZip" on target "Creating Decompressed File @ C:\scripts\PowerShell\locations.txt".

			Description
			-----------
			Simulate GZip Decompress of archive 'locations.txt.gz'

			.Example
			Get-ChildItem .\locations.txt.gz | Expand-GZip

			Description
			-----------
			GZip Decompress 'locations.txt.gz' to 'locations.txt'

			.Example
			Expand-GZip -FullName 'locations.txt.gz' -NewName 'NewLocations.txt' instead of the default 'locations.txt'

			Description
			-----------
			GZip Decompress 'locations.txt.gz' to 'NewLocations.txt

			.NOTES
			Copyright 2013 Robert Nees
			Licensed under the Apache License, Version 2.0 (the "License");

			.LINK
			http://sushihangover.blogspot.com
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'The input file')]
		[Alias('PSPath')]
		[System.String]$FullName,
		[Parameter(ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Name of the GZip Archive')]
		[Alias('NewName')]
		[System.String]$GZipPath = $null,
		[Parameter(HelpMessage = 'Enforce it?')]
		[switch]$Force
	)

	PROCESS {
		if (Test-Path -Path $FullName -PathType Leaf) {
			# Be Verbose
			Write-Verbose "Reading from: $FullName"

			if ($GZipPath.Length -eq 0) {
				$tmpPath = (Get-ChildItem -Path $FullName)
				$GZipPath = (Join-Path -Path ($tmpPath.DirectoryName) -ChildPath ($tmpPath.BaseName))
			}

			if (Test-Path -Path $GZipPath -PathType Leaf -IsValid) {
				Write-Verbose "Decompressing to: $GZipPath"
			} else {
				Write-Error -Message "$GZipPath is not a valid path/file"
				return
			}
		} else {
			Write-Error -Message "$FullName does not exist"
			return
		}
		if (Test-Path -Path $GZipPath -PathType Leaf) {
			If ($Force.IsPresent) {
				if ($pscmdlet.ShouldProcess("Overwrite Existing File @ $GZipPath")) {
					Set-FileTime $GZipPath
				}
			}
		} else {
			if ($pscmdlet.ShouldProcess("Create new decompressed File @ $GZipPath")) {
				Set-FileTime $GZipPath
			}
		}
		if ($pscmdlet.ShouldProcess("Creating Decompressed File @ $GZipPath")) {
			# Be Verbose
			Write-Verbose 'Opening streams and file to save compressed version to...'

			$Input = (New-Object System.IO.FileStream -ArgumentList (Get-ChildItem -Path $FullName).FullName, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read))
			$output = (New-Object System.IO.FileStream -ArgumentList (Get-ChildItem -Path $GZipPath).FullName, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None))
			$gzipStream = (New-Object System.IO.Compression.GzipStream -ArgumentList $Input, ([IO.Compression.CompressionMode]::Decompress))

			try {
				$buffer = (New-Object byte[] -ArgumentList (1024))
				while ($true) {
					$read = ($gzipStream.Read($buffer, 0, 1024))
					if ($read -le 0) {
						break
					}
					$output.Write($buffer, 0, $read)
				}
			} finally {
				# Be Verbose
				Write-Verbose 'Closing streams and newly decompressed file'

				$gzipStream.Close()
				$output.Close()
				$Input.Close()
			}
		}
	}
}

function Invoke-PowerHead {
	<#
			.SYNOPSIS
			Display first lines of a file

			.DESCRIPTION
			This filter displays the first count lines or bytes of each of the
			specified files, or of the standard input if no files are specified.

			If count is omitted it defaults to 10.

			.PARAMETER File
			Filename

			.PARAMETER count
			A description of the count parameter, default is 10.

			.EXAMPLE
			PS C:\> head 'C:\scripts\info.txt'

			Description
			-----------
			Display first 10 lines of a file 'C:\scripts\info.txt'

			.EXAMPLE
			PS C:\> Invoke-PowerHead -File 'C:\scripts\info.txt'

			Description
			-----------
			Display first 10 lines of a file 'C:\scripts\info.txt'

			.EXAMPLE
			PS C:\> Invoke-PowerHead -File 'C:\scripts\info.txt' -count '2'

			Description
			-----------
			Display first 2 lines of a file 'C:\scripts\info.txt'

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
		HelpMessage = 'Filename')]
		[ValidateNotNullOrEmpty()]
		[Alias('FileName')]
		[System.String]$File,
		[Alias('Counter')]
		[System.Int32]$count = 10
	)

	BEGIN {
		# Does this exist?
		if (-not (Test-Path $File)) {
			# Aw Snap!
			Write-Error -Message:"Unable to locate file $File" -ErrorAction:Stop

			Return
		}
	}

	PROCESS {
		# Show the fist X entries
		Return (Get-Content $File | Select-Object -First $count)
	}
}

function Invoke-PowerHelp {
	<#
			.SYNOPSIS
			Wrapper that use the cmdlet Get-Help -full

			.DESCRIPTION
			Wrapper that use the regular cmdlet Get-Help -full to show all
			technical informations about the given command

			.EXAMPLE
			PS C:\> help Get-item

			Description
			-----------
			Show the full technical informations of the Get-item cmdlet

			.NOTES
			This is just a little helper function to make the shell more flexible

			.PARAMETER cmdlet
			command-let

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Make the console clean
		[System.Console]::Clear()
		[System.Console]::SetWindowPosition(0, [System.Console]::CursorTop)
	}

	PROCESS {
		# Get the FULL Help Message for the given command-let
		Get-Help $args[0] -Full
	}
}

function Set-IgnoreSslTrust {
	<#
			.SYNOPSIS
			This workaround completely disables SSL certificate checks

			.DESCRIPTION
			This workaround disables the SSL certificate trust checking.
			This seems to be useful if you need to use self signed SSL certificates

			But there is a string attached:
			This is very dangerous.

			And this is not a joke, it is dangerous, because you leave the door
			wide open (and honestly it means completely open) for bad certificates,
			hijacked certificates and even Man-In-The-middle attacks!

			So really think twice before you use this in a production environment!

			.EXAMPLE
			PS C:\> Set-IgnoreSslTrust

			Description
			-----------
			This workaround completely disables SSL certificate checks.
			Do this only if you know what you are doing here!!!

			.NOTES
			Be carefull:
			If you really need to disable the SSL Trust setting,
			just use it for the calls you really need to!

			.LINK
			Source: https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager.servercertificatevalidationcallback.aspx
			Source: https://msdn.microsoft.com/en-us/library/system.net.security.remotecertificatevalidationcallback.aspx

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'High',
	SupportsShouldProcess = $true)]
	param ()

	PROCESS {
		# Set the SSL Ignore based on the configuration Value Leaves the door wide open...
		# Think before set this Boolean to $true
		if ($IgnoreSslTrust) {
			# AGAIN:
			# Think before you enable this! It could be very dangerous!!!
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { Return $true }

			# Be Verbose
			Write-Verbose -Message:'SSL Trust IS ignored - BAD IDEA'

			Write-Warning -Message:'SSL Trust IS ignored - BAD IDEA'
		} else {
			[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { Return $false }

			# Be Verbose
			Write-Verbose -Message:'SSL Trust is NOT ignored - GOOD IDEA'
		}
	}
}

function Set-NotIgnoreSslTrust {
	<#
			.SYNOPSIS
			Enables the SSL certificate checks

			.DESCRIPTION
			This is a companion function for the usage of the
			"Set-IgnoreSslTrust" function
			It might be a great idea to disable the SSL Trust check for a single
			call (If you real need to do it) via the "Set-IgnoreSslTrust"
			function and then enable it directly after the call
			via "Set-NotIgnoreSslTrust"

			.EXAMPLE
			PS C:\> Set-NotIgnoreSslTrust

			Description
			-----------
			Enables the SSL certificate checks

			.NOTES
			Do yourself a favor and use this function right after a call
			without SSL Trust check!!!

			.LINK
			Source: https://msdn.microsoft.com/en-us/library/system.net.servicepointmanager.servercertificatevalidationcallback.aspx
			Source: https://msdn.microsoft.com/en-us/library/system.net.security.remotecertificatevalidationcallback.aspx
	#>

	[CmdletBinding(ConfirmImpact = 'Low',
	SupportsShouldProcess = $true)]
	param ()

	PROCESS {
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { Return $false }

		# Be Verbose
		Write-Verbose -Message:'SSL Trust is NOT ignored - GOOD IDEA'
	}
}

function Initialize-Modules {
	<#
			.SYNOPSIS
			Initialize PowerShell Modules

			.DESCRIPTION
			Initialize PowerShell Modules

			.NOTES
			Needs to be documented (Issue NETXDEV-23 opened)

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# is this a module?
		Get-Module |
		Where-Object { Test-Method $_.Name $_.Name } |
		ForEach-Object
		{
			# Define object
			Set-Variable -Name functionName -Value $($_.Name)

			# Show a verbose message
			Write-Verbose "Initializing Module $functionName"

			# Execute
			$null = Invoke-Expression $functionName
		}
	}
}

function Initialize-ModuleUpdate {
	<#
			.SYNOPSIS
			Refresh the PowerShell Module Information

			.DESCRIPTION
			Refresh the PowerShell Module Information
			Wrapper for the following command: Get-Module -ListAvailable -Refresh

			.PARAMETER Verbosity
			Verbose output, default is not

			.EXAMPLE
			PS C:\> Initialize-ModuleUpdate -Verbose

			Description
			-----------
			Refresh the PowerShell Module Information

			.EXAMPLE
			PS C:\> Initialize-ModuleUpdate -Verbose

			Description
			-----------
			Refresh the PowerShell Module Information

			.NOTES
			PowerShell will auto-load modules. However, with some modules, this
			technique may fail.

			Their cmdlets will still only be available after you manually import
			the module using Import-Module.

			The reason most likely is the way these modules were built.

			PowerShell has no way of detecting which cmdlets are exported by
			these modules.

	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Position = 0,
		HelpMessage = 'Verbosity? Default is not')]
		[switch]$Verbosity = "$false"
	)

	BEGIN {
		Write-Output 'Update...'
	}

	PROCESS {
		if ($Verbosity) {
			Get-Module -ListAvailable -Refresh
		} else {
			(Get-Module -ListAvailable -Refresh) > $null 2>&1 3>&1
		}
	}
}

function Invoke-AnimatedSleep {
	<#
			.SYNOPSIS
			Animated sleep

			.DESCRIPTION
			Takes the title and displays a looping animation for a given number of
			seconds.
			The animation will delete itself once it's finished,
			to save on console scrolling.

			.PARAMETER seconds
			A number of seconds to sleep for

			.PARAMETER title
			Some words to put next to the thing

			.EXAMPLE
			PS C:\> Invoke-AnimatedSleep

			Description
			-----------
			Will display a small animation for 1 second

			.EXAMPLE
			PS C:\> Invoke-AnimatedSleep 5

			Description
			-----------
			Will display a small animation for 5 seconds

			.EXAMPLE
			PS C:\> Invoke-AnimatedSleep 10 "Waiting for domain sync"

			Description
			-----------
			Will display "Waiting for domain sync " and a small animation for
			10 seconds

			.NOTES
			Based on an idea of Doug Kerwin

			.LINK
			Source https://github.com/dwkerwin/powershell_profile/blob/master/autoload-scripts/vendor/sleepanim.ps1
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
		Position = 1)]
		[int]$seconds = 1,
		[Parameter(ValueFromPipeline = $true,
		Position = 2)]
		[string]$title = 'Sleeping'
	)

	BEGIN {
		$blank = "`b" * ($title.length + 11)
		$clear = ' ' * ($title.length + 11)
		$anim = @('0o.......o', 'o0o.......', '.o0o......', '..o0o.....', '...o0o....', '....o0o...', '.....o0o..', '......o0o.', '.......o0o', 'o.......o0') # Animation sequence characters
	}

	PROCESS {
		while ($seconds -gt 0) {
			$anim | ForEach-Object {
				Write-Host "$blank$title $_" -NoNewline -ForegroundColor Yellow
				Start-Sleep -Milliseconds 100
			}

			$seconds--
		}
	}

	END {
		Write-Host "$blank$clear$blank" -NoNewline
	}
}

function Invoke-baloonTip {
	<#
			.SYNOPSIS
			Shows a Windows Balloon notification

			.DESCRIPTION
			Shows a Windows Balloon notification

			.PARAMETER Title
			Title of the Balloon Tip

			.PARAMETER Message
			Message of the Balloon Tip

			.PARAMETER Icon
			Type for the Balloon

			.EXAMPLE
			PS C:\> Invoke-baloonTip

			Description
			-----------
			Show a windows Balloon with the Title "Title" and the Text "Message..."
			as "Information".

			This is the default values for everything.

			.EXAMPLE
			PS C:\> Invoke-baloonTip -Title 'Diskspace!!!' -Message 'Diskspace on c: is low' -Icon 'Exclamation'

			Description
			-----------
			This shows an Balloon with the Title "Diskspace!!!",
			the message is "Diskspace on c: is low" as "Exclamation"

			.EXAMPLE
			PS C:\> Invoke-baloonTip -Title 'Reconnect?' -Message 'Should is reconnect to Office 365???' -Icon 'Question'

			Description
			-----------
			This shows an Balloon with the Title "Reconnect?",
			the message is "Should is reconnect to Office 365???" as "Question"

			.NOTES
			Tested with Windows 7, Windows 8/8.1 and Windows Server 2012/2012R2
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Title of the Baloon Tip')]
		[System.String]$title = 'Information',
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Message of the Baloon Tip')]
		[System.String]$Message = 'Message...',
		[Parameter(ValueFromPipeline = $true,
				Position = 2,
		HelpMessage = 'Type for the Ballon')]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Question', 'Exclamation', 'Information')]
		[System.String]$Icon = 'Information'
	)

	BEGIN {
		[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
	}

	PROCESS {
		$notification = (New-Object System.Windows.Forms.NotifyIcon)

		# Define the icon for the system tray
		$notification.Icon = [System.Drawing.SystemIcons]::$Icon

		#Display title of balloon window
		$notification.BalloonTipTitle = $title

		#Type of balloon icon
		$notification.BalloonTipIcon = 'Info'

		#Notification message
		$notification.BalloonTipText = $Message

		#Make balloon tip visible when called
		$notification.Visible = $true

		#Call the balloon notification
		$notification.ShowBalloonTip(15000)
	}

	END {
		if ($debug) {
			Write-Output $notification
		}
	}
}

function Invoke-CreateMissingRegistryDrives {
	<#
			.SYNOPSIS
			Create Missing Registry Drives

			.DESCRIPTION
			Create Missing Registry Drives

			.EXAMPLE
			PS C:\> Invoke-CreateMissingRegistryDrives

			Description
			-----------
			Create Missing Registry Drives

			.NOTES
			Based on an idea of ALIENQuake

			.LINK
			ALIENQuake https://github.com/ALIENQuake/WindowsPowerShell
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		$null = New-PSDrive -Name 'HKU' -PSProvider 'Registry' -Root Registry::HKEY_USERS -EA 0
		$null = New-PSDrive -Name 'HKCR' -PSProvider 'Registry' -Root Registry::HKEY_CLASSES_ROOT -EA 0
		$null = New-PSDrive -Name 'HKCC' -PSProvider 'Registry' -Root Registry::HKEY_CURRENT_CONFIG -EA 0
	}
}

function Invoke-GC {
	<#
			.SYNOPSIS
			Do a garbage collection

			.DESCRIPTION
			Do a garbage collection within the PowerShell Session

			.EXAMPLE
			PS C:\> Invoke-GC

			Description
			-----------
			Do a garbage collection

			.NOTES
			Just a little helper function to do garbage collection
			PowerShell sometimes do not cleanup and this uses more memory then
			it should...
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Call the .NET function
		[void]([System.GC]::Collect())
	}
}

function Invoke-NTFSFilesCompression {
	<#
			.SYNOPSIS
			Compress files with given extension older than given amount of time

			.DESCRIPTION
			The function is intended for compressing (using the NTFS compression)
			all files with particular extensions older than given time unit

			.PARAMETER Path
			The folder path that contain files. Folder path can be pipelined.

			.PARAMETER OlderThan
			The count of units that are base to comparison file age.

			.PARAMETER TimeUnit
			The unit of time that are used to count.

			The default time unit are minutes.

			.PARAMETER Extension
			The extension of files that will be processed.

			The default file extension is log.

			.PARAMETER OlderThan
			The count of units that are base to comparison file age.

			.EXAMPLE
			Invoke-NTFSFilesCompression -Path "C:\test" -OlderThan "20"

			Description
			-----------
			Compress files with extension log in folder 'c:\test' that are older
			than 20 minutes

			.EXAMPLE
			Invoke-NTFSFilesCompression -Path "C:\test" -OlderThan "1" -TimeUnit "hours" -Extension "txt"

			Description
			-----------
			Compress files with extension txt in folder 'c:\test' that are
			older than 1 hour

			.NOTES
			Based on an idea of  Wojciech Sciesinski
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
		HelpMessage = 'The folder path that contain files. Folder path can be pipelined.')]
		[string[]]$Path,
		[Parameter(Mandatory = $true,
		HelpMessage = 'The count of units that are base to comparison file age.')]
		[int]$OlderThan,
		[Parameter(HelpMessage = 'The unit of time that are used to count. The default time unit are minutes.')]
		[ValidateSet('minutes', 'hours', 'days', 'weeks')]
		[string[]]$TimeUnit = 'minutes',
		[Parameter(HelpMessage = 'The extention of files that will be processed. The default file extenstion is log.')]
		[string[]]$Extension = 'log'
	)

	BEGIN {
		$excludedfiles = 'temp.log', 'temp2.log', 'source.log'

		# translate action to numeric value required by the method
		switch ($TimeUnit) {
			'minutes' {
				$multiplier = 1
				break
			}
			'hours' {
				$multiplier = 60
				break
			}
			'days' {
				$multiplier = 1440
				break
			}
			'weeks' {
				$multiplier = 10080
				break
			}
		}

		$OlderThanMinutes = $($OlderThan * $multiplier)
		$compressolder = $(Get-Date).AddMinutes(- $OlderThanMinutes)
		$filterstring = '*.' + $Extension
		$files = (Get-ChildItem -Path $Path -Filter $filterstring)
	}

	PROCESS {
		ForEach ($i in $files) {
			if ($i.Name -notin $excludedfiles) {
				$filepathforquery = $($i.FullName).Replace('\', '\\')
				$File = (Get-WmiObject -Query "SELECT * FROM CIM_DataFile Where-Object Name='$filepathforquery'")

				if ((-not ($File.compressed)) -and $i.LastWriteTime -lt $compressolder) {
					Write-Verbose "Start compressing file $i.name"

					#Invoke compression
					[void]$File.Compress()
				} #End if
			} #End if
		}
	}
}

function Invoke-RemoteScript {
	<#
			.SYNOPSIS
			A brief description of the Invoke-RemoteScript function.

			.DESCRIPTION
			A detailed description of the Invoke-RemoteScript function.

			.PARAMETER Computer
			The remote computer to execute files on.

			.PARAMETER Folder
			Any folders (on the local computer) that need copied to the remote
			computer prior to execution

			.PARAMETER Script
			The Powershell script path (on the local computer) that needs
			executed on the remote computer

			.PARAMETER Drive
			The remote drive letter the script will be executed on and the
			folder will be copied to

			.NOTES
			Additional information about the function.

			.LINK
			Idea: http://www.leeholmes.com/blog/2009/11/20/testing-for-powershell-remoting-test-psremoting/
	#>

	[CmdletBinding(ConfirmImpact = 'None',
	SupportsShouldProcess = $false)]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'The remote computer to execute files on.')]
		[Alias('Computername')]
		[System.String]$Computer,
		[Parameter(Mandatory = $true,
		HelpMessage = 'Any folders (on the local computer) that need copied to the remote computer prior to execution')]
		[Alias('FolderPath')]
		[System.String]$Folder,
		[Parameter(Mandatory = $true,
		HelpMessage = 'The Powershell script path (on the local computer) that needs executed on the remote computer')]
		[Alias('ScriptPath')]
		[System.String]$Script,
		[Parameter(HelpMessage = 'The remote drive letter the script will be executed on and the folder will be copied to')]
		[Alias('RemoteDrive')]
		[System.String]$Drive = 'C'
	)

	BEGIN {
		# Helper function
		function Test-PsRemoting {
			param (
				[Parameter(Mandatory = $true)]
				$ComputerName
			)

			try {
				$errorActionPreference = 'Stop'
				$result = Invoke-Command -ComputerName $ComputerName { 1 }
			} catch {
				Write-Verbose $_
				Return $false
			}

			# What?
			if ($result -ne 1) {
				Write-Verbose "Remoting to $ComputerName returned an unexpected result."
				Return $false
			}
			Return $true
		}

		# Be Verbose
		Write-Verbose 'Validating prereqs for remote script execution...'

		if (-not (Test-Path $Folder)) {
			throw 'Folder path does not exist'
		} elseif (-not (Test-Path $Script)) {
			throw 'Script path does not exist'
		} elseif ((Get-ItemProperty -Path $Script).Extension -ne '.ps1') {
			throw 'Script specified is not a Powershell script'
		}

		$ScriptName = ($Script | Split-Path -Leaf)
		$RemoteFolderPath = ($Folder | Split-Path -Leaf)
		$RemoteScriptPath = "$Drive`:\$RemoteFolderPath\$ScriptName"
	}

	PROCESS {
		# Be Verbose
		Write-Verbose "Copying the folder $Folder to the remote computer $Computer..."

		Copy-Item $Folder -Recurse -Destination "\\$Computer\$Drive`$" -Force

		# Be Verbose
		Write-Verbose "Copying the script $ScriptName to the remote computer $Computer..."

		Copy-Item $Script -Destination "\\$Computer\$Drive`$\$RemoteFolderPath" -Force

		# Be Verbose
		Write-Verbose "Executing $RemoteScriptPath on the remote computer $Computer..."

		([WMICLASS]"\\$Computer\Root\CIMV2:Win32_Process").create("powershell.exe -File $RemoteScriptPath -NonInteractive -NoProfile")
	}
}

function Invoke-VisualEditor {
	<#
			.SYNOPSIS
			Wrapper to edit files

			.DESCRIPTION
			This is a quick wrapper that edits files with editor from the
			VisualEditor variable

			.PARAMETER args
			Arguments

			.PARAMETER Filename
			File that you would like to edit

			.EXAMPLE
			PS C:\> Invoke-VisualEditor example.txt

			Description
			-----------
			Invokes Note++ or ISE and edits "example.txt".
			This is possible, even if the File does not exists...
			The editor should ask you if it should create it for you

			.EXAMPLE
			PS C:\> Invoke-VisualEditor

			Description
			-----------
			Invokes Note++ or ISE without opening a file

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Position = 0)]
		[Alias('File')]
		[System.String]$args
	)

	PROCESS {
		# Call the newly set Editor
		if (-not ($VisualEditor)) {
			# Aw SNAP! The VisualEditor is not configured...
			Write-Error -Message:'System is not configured well! The Visual Editor is not given...' -ErrorAction:Stop
		} else {
			# Yeah! Do it...
			if (-not ($args)) {
				#
				Start-Process -FilePath $VisualEditor
			} else {
				#
				Start-Process -FilePath $VisualEditor -ArgumentList "$args"
			}
		}
	}
}

function Convert-IPToBinary {
	<#
			.SYNOPSIS
			Converts an IP address string to it's binary string equivalent

			.DESCRIPTION
			Takes a IP as a string and returns the same IP address as a binary
			string with no decimal points

			.PARAMETER IP
			The IP address which will be converted to a binary string

			.EXAMPLE
			PS C:\> Convert-IPToBinary -IP '10.211.55.1'
			Binary                                                          IPAddress
			------                                                          ---------
			00001010110100110011011100000001                                10.211.55.1

			Description
			-----------
			Converts 10.211.55.1 to it's binary string equivalent
			00001010110100110011011100000001

			.NOTES
			Works with IPv4 addresses only!
	#>

	[CmdletBinding()]
	[OutputType([psobject])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'The IP address which will be converted to a binary string')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')]
		[Alias('IPAddress')]
		[String]$IP
	)

	BEGIN {
		$Binary = $null
		$result = $null
		$SingleIP = $null
	}

	PROCESS {
		foreach ($SingleIP in $IP) {
			try {
				$SingleIP.split('.') | ForEach-Object { $Binary = $Binary + $([convert]::toString($_, 2).padleft(8, '0')) }
			} catch [System.Exception] {
				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the hard way...
				exit 1
			} catch {
				Write-Error -Message "Could not convert $SingleIP!" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the hard way...
				exit 1
			}

			$result = New-Object PSObject -Property @{
				IPAddress = $SingleIP
				Binary    = $Binary
			}
		}
	}

	END {
		Write-Output $result
	}
}

function Convert-IPtoDecimal {
	<#
			.SYNOPSIS
			Converts an IP address to decimal.

			.DESCRIPTION
			Converts an IP address to decimal value.

			.PARAMETER IPAddress
			An IP Address you want to check

			.EXAMPLE
			PS C:\> Convert-IPtoDecimal -IPAddress '127.0.0.1','192.168.0.1','10.0.0.1'

			decimal		IPAddress
			-------		---------
			2130706433	127.0.0.1
			3232235521	192.168.0.1
			167772161	10.0.0.1

			Description
			-----------
			Converts an IP address to decimal.

			.EXAMPLE
			PS C:\> Convert-IPtoDecimal '127.0.0.1','192.168.0.1','10.0.0.1'

			decimal		IPAddress
			-------		---------
			2130706433	127.0.0.1
			3232235521	192.168.0.1
			167772161	10.0.0.1

			Description
			-----------
			Converts an IP address to decimal.

			.EXAMPLE
			PS C:\> '127.0.0.1','192.168.0.1','10.0.0.1' |  Convert-IPtoDecimal

			decimal		IPAddress
			-------		---------
			2130706433	127.0.0.1
			3232235521	192.168.0.1
			167772161	10.0.0.1

			Description
			-----------
			Converts an IP address to decimal.

			.NOTES
			Sometimes I need to have that info, so I decided it would be great
			to have a functions who do the job!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([psobject])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'An IP Address you want to check')]
		[Alias('IP')]
		[System.String]$IPAddress
	)

	BEGIN {
		# Dummy block - We so nothing here
	}

	PROCESS {
		# OK make sure the we have a string here!
		# Then we split everthing based on the DOTs.
		[String[]]$IP = $IPAddress.Split('.')

		# Create a new object and transform it to Decimal
		$Object = New-Object -TypeName psobject -Property (@{
				'IPAddress' = $($IPAddress)
				'Decimal' = [Int64](
					([Int32]::Parse($IP[0]) * [Math]::Pow(2, 24) +
						([Int32]::Parse($IP[1]) * [Math]::Pow(2, 16) +
							([Int32]::Parse($IP[2]) * [Math]::Pow(2, 8) +
								([Int32]::Parse($IP[3])
								)
							)
						)
					)
				)
		})
	}

	END {
		# Dump the info to the console
		Write-Output $Object
	}
}

function Check-IPaddress {
	<#
			.SYNOPSIS
			Check if a given IP Address seems to be valid

			.DESCRIPTION
			Check if a given IP Address seems to be valid.
			We use the .NET function to do so. This is not 100% reliable,
			but is enough most times.

			.PARAMETER IPAddress
			An IP Address you want to check

			.EXAMPLE
			PS C:\> Check-IPaddress -IPAddress '10.10.16.10'
			True

			Description
			-----------
			Check if a given IP Address seems to be valid

			.EXAMPLE
			PS C:\> Check-IPaddress -IPAddress '010.010.016.010'
			True

			Description
			-----------
			Check if a given IP Address seems to be valid

			.EXAMPLE
			PS C:\> Check-IPaddress -IPAddress '10.10.16.01O'
			False

			Description
			-----------
			Check if a given IP Address seems to be valid

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipelineByPropertyName = $true,
				Position = 0,
		HelpMessage = 'An IP Address you want to check')]
		[ValidateScript({
					$_ -match [IPAddress]
					$_
		})]
		[Alias('IP')]
		[System.String]$IPAddress
	)

	PROCESS {
		# Use the .NET Call to figure out if the given address is valid or not.
		Set-Variable -Name 'IsValid' -Scope:Script -Value $(($IPAddress -As [IPAddress]) -As [Bool])
	}

	END {
		# Dump the bool value to the console
		Write-Output $IsValid
	}
}

function Get-NtpTime {
	<#
			.SYNOPSIS
			Get the NTP Time from a given Server

			.DESCRIPTION
			Get the NTP Time from a given Server.

			.PARAMETER Server
			NTP Server to use. The default is de.pool.ntp.org

			.EXAMPLE
			PS C:\scripts\PowerShell> Get-NtpTime -Server 'de.pool.ntp.org'
			5. April 2016 00:58:59

			Description
			-----------
			Get the NTP Time from a given Server

			.NOTES
			This sends an NTP time packet to the specified NTP server and reads
			back the response.
			The NTP time packet from the server is decoded and returned.

			Note: this uses NTP (rfc-1305: http://www.faqs.org/rfcs/rfc1305.html)
			on UDP 123.
			Because the function makes a single call to a single server this is
			strictly a SNTP client (rfc-2030).
			Although the SNTP protocol data is similar (and can be identical) and
			the clients and servers are often unable to distinguish the difference.
			Where-Object SNTP differs is that is does not accumulate historical
			data (to enable statistical averaging) and does not retain a session
			between client and server.

			An alternative to NTP or SNTP is to use Daytime (rfc-867) on TCP
			port 13 - although this is an old protocol and is not supported
			by all NTP servers.

			.LINK
			Source: https://chrisjwarwick.wordpress.com/2012/08/26/getting-ntpsntp-network-time-with-powershell/
	#>

	[CmdletBinding()]
	[OutputType([datetime])]
	param
	(
		[Parameter(HelpMessage = 'NTP Server to use. The default is de.pool.ntp.org')]
		[Alias('NETServer')]
		[System.String]$Server = 'de.pool.ntp.org'
	)

	PROCESS {
		# Construct client NTP time packet to send to specified server
		# (Request Header: [00=No Leap Warning; 011=Version 3; 011=Client Mode]; 00011011 = 0x1B)
		[Byte[]]$NtpData = , 0 * 48
		$NtpData[0] = 0x1B

		# Create the connection
		$Socket = New-Object Net.Sockets.Socket -ArgumentList ([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)

		# Configure the connection
		$Socket.Connect($Server, 123)
		[Void]$Socket.Send($NtpData)

		# Returns length - should be 48
		[Void]$Socket.Receive($NtpData)

		# Close the connection
		$Socket.Close()

		<#
				Decode the received NTP time packet

				We now have the 64-bit NTP time in the last 8 bytes of the received data.
				The NTP time is the number of seconds since 1/1/1900 and is split into an
				integer part (top 32 bits) and a fractional part, multiplied by 2^32, in the
				bottom 32 bits.
		#>

		# Convert Integer and Fractional parts of 64-bit NTP time from byte array
		$IntPart = 0

		foreach ($Byte in $NtpData[40..43]) {
			$IntPart = ($IntPart * 256 + $Byte)
		}

		$FracPart = 0

		foreach ($Byte in $NtpData[44..47]) {
			$FracPart = ($FracPart * 256 + $Byte)
		}

		# Convert to Milliseconds (convert fractional part by dividing value by 2^32)
		[UInt64]$Milliseconds = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)

		# Create UTC date of 1 Jan 1900,
		# add the NTP offset and convert result to local time
		(New-Object DateTime -ArgumentList (1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddMilliseconds($Milliseconds).ToLocalTime()
	}
}

function Invoke-AppendClassPath {
	<#
			.SYNOPSIS
			Append a given path to the Class Path

			.DESCRIPTION
			Appends a given path to the Java Class Path.
			Useful if you still need that old Java crap!

			By the way: I hate Java!

			.EXAMPLE
			PS C:\> append-classpath "."

			Description
			-----------
			Include the directory Where-Object you are to the Java Class Path

			.NOTES
			This is just a little helper function to make the shell more flexible

			.PARAMETER path
			Path to include in the Java Class Path

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param ()

	PROCESS {
		# Do we have a class path?
		if ([System.String]::IsNullOrEmpty($env:CLASSPATH)) {
			$env:CLASSPATH = ($args)
		} else {
			$env:CLASSPATH += ';' + $args
		}
	}
}

function Invoke-JavaLove {
	<#
			.SYNOPSIS
			Set the JAVAHOME Variable to use JDK and/or JRE instances withing the
			Session

			.DESCRIPTION
			You are still using Java Stuff?
			OK... Your choice, so we do you the favor and create/fill the
			variable JAVAHOME based on the JDK/JRE that we found.
			It also append the Info to the PATH variable to make things easier
			for you.
			But think about dropping the buggy Java crap as soon as you can.
			Java is not only buggy, there are also many Security issues with it!

			.EXAMPLE
			PS C:\> JavaLove

			Description
			-----------
			Find the installed JDK and/or JRE version and crate the JDK_HOME
			and JAVA_HOME variables for you.
			It also appends the Path to the PATH  and CLASSPATH variable to make
			it easier for you.

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param ()

	BEGIN {
		# Where-Object do we want to search for the Java crap?
		Set-Variable -Name baseloc -Value $("$env:ProgramFiles\Java\")
	}

	PROCESS {
		# Show Java a little love...
		# And I have no idea why I must do that!
		if ((Test-Path $baseloc)) {
			# Include JDK if found
			Set-Variable -Name sdkdir -Value $(Resolve-Path "$baseloc\jdk*")

			# Do we have a SDK?
			if (($sdkdir) -and (Test-Path $sdkdir)) {
				# Set the enviroment
				$env:JDK_HOME = $sdkdir

				# Tweak the PATH
				append-path "$sdkdir\bin"
			}

			# Include JRE if found
			$jredir = (Resolve-Path "$baseloc\jre*")

			# Do we have a JRE?
			if (($jredir) -and (Test-Path $jredir)) {
				# Set the enviroment
				$env:JAVA_HOME = $jredir

				# Tweak the PATH
				append-path "$jredir\bin"
			}

			# Update the Classpath
			Invoke-AppendClassPath '.'
		}
	}
}

function Get-MaskedJson {
	<#
			.SYNOPSIS
			Masks all special characters within a JSON File

			.DESCRIPTION
			Masks all special characters within a JSON File.
			mostly used with C# or some other windows tools.

			.PARAMETER json
			Regular Formated JSON String or File

			.EXAMPLE
			Get-MaskedJson '{"name":"John", "Age":"21"}'
			{\"name\":\"John\", \"Age\":\"21\"}

			Description
			-----------
			Masks all special characters within a JSON File

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Regular Formated JSON String or File')]
		[System.String]$json
	)

	PROCESS {
		$json -replace '"', '\"'
	}
}

function Get-RegularJson {
	<#
			.SYNOPSIS
			Converts a C# dumped JSON to regular JSON

			.DESCRIPTION
			A detailed description of the Get-RegularJson function.

			.PARAMETER csjson
			C# formated JSON (The one with mased characters)

			.EXAMPLE
			Get-RegularJson '{\"name\":\"John\", \"Age\":\"21\"}'
			{"name":"John", "Age":"21"}

			Description
			-----------
			Converts a C# dumped JSON to regular JSON

			.NOTES
			Additional information about the function.
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'C# formated JSON (The one with mased characters)')]
		[System.String]$csjson
	)

	PROCESS {
		$csjson -replace '\\"', '"'
	}
}

# Make Powershell more Uni* like
function Invoke-PowerLL {
	<#
			.SYNOPSIS
			Quick helper to make my PowerShell a bit more like *nix

			.DESCRIPTION
			Everyone ever used a modern Unix and/or Linux system knows and love
			the colored output of LL

			This function is hack to emulate that on PowerShell.

			.PARAMETER dir
			Show the content of this Directory

			.PARAMETER all
			Show all files, included the hidden ones!

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Alias('Directory')]
		$dir = '.',
		[Alias('ShowAll')]
		$All = $false
	)

	BEGIN {
		# Define object
		Set-Variable -Name origFg -Value $($Host.UI.RawUI.ForegroundColor)
	}

	PROCESS {
		# What to do?
		if ($All) {
			Set-Variable -Name toList -Value $(Get-ChildItem -Force $dir)
		} else {
			Set-Variable -Name toList -Value $(Get-ChildItem $dir)
		}

		# Define the display colors for given extensions
		foreach ($item in $toList) {
			Switch ($item.Extension) {
				'.exe' { $Host.UI.RawUI.ForegroundColor = 'DarkYellow' }
				'.hta' { $Host.UI.RawUI.ForegroundColor = 'DarkYellow' }
				'.cmd' { $Host.UI.RawUI.ForegroundColor = 'DarkRed' }
				'.ps1' { $Host.UI.RawUI.ForegroundColor = 'DarkGreen' }
				'.html' { $Host.UI.RawUI.ForegroundColor = 'Cyan' }
				'.htm' { $Host.UI.RawUI.ForegroundColor = 'Cyan' }
				'.7z' { $Host.UI.RawUI.ForegroundColor = 'Magenta' }
				'.zip' { $Host.UI.RawUI.ForegroundColor = 'Magenta' }
				'.gz' { $Host.UI.RawUI.ForegroundColor = 'Magenta' }
				'.rar' { $Host.UI.RawUI.ForegroundColor = 'Magenta' }
				Default { $Host.UI.RawUI.ForegroundColor = $origFg }
			}

			# All directories a Dark Grey
			if ($item.Mode.StartsWith('d')) {
				$Host.UI.RawUI.ForegroundColor = 'DarkGray'
			}

			# Dump it
			$item
		}
	}

	END {
		$Host.UI.RawUI.ForegroundColor = $origFg
	}
}

# Make Powershell more Uni* like
function Reload-PesterModule {
	<#
			.SYNOPSIS
			Load Pester Module

			.DESCRIPTION
			Load the Pester PowerShell Module to the Global context.
			Pester is a Mockup, Unit Test and Function Test Module for PowerShell

			.NOTES
			Pester Module must be installed

			.LINK
			Pester: https://github.com/pester/Pester

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Lets check if the Pester PowerShell Module is installed
		if (Get-Module -ListAvailable -Name Pester -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) {
			try {
				#Make sure we remove the Pester Module (if loaded)
				Remove-Module -Name [P]ester -Force -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

				# Import the Pester PowerShell Module in the Global context
				Import-Module -Name [P]ester -DisableNameChecking -Force -Scope Global -ErrorAction:Stop -WarningAction:SilentlyContinue
			} catch {
				# Sorry, Pester PowerShell Module is not here!!!
				Write-Error -Message:'Error: Pester Module was not imported...' -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the hard way...
				exit 1
			}
		} else {
			# Sorry, Pester PowerShell Module is not here!!!
			Write-Warning  'Pester Module is not installed! Go to https://github.com/pester/Pester to get it!'
		}
	}
}

# Make Powershell more Uni* like
function Invoke-PowerHelp {
	<#
			.SYNOPSIS
			Wrapper of Get-Help

			.DESCRIPTION
			This wrapper uses Get-Help -full for a given cmdlet and shows
			everything paged. This is very much like the typical *nix like man

			.EXAMPLE
			PS C:\> man Get-item

			Description
			-----------
			Shows the complete help text of the cmdlet "Get-item", page by page

			.NOTES
			This is just a little helper function to make the shell more flexible

			.PARAMETER cmdlet
			command-let

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Cleanup the console
		[System.Console]::Clear()
		[System.Console]::SetWindowPosition(0, [System.Console]::CursorTop)
	}

	PROCESS {
		# get the Help for given command-let
		Get-Help $args[0] -Full | Out-Host -Paging
	}
}

# Make Powershell more Uni* like
function Invoke-MakeDirectory {
	<#
			.SYNOPSIS
			Wrapper of New-Item

			.DESCRIPTION
			Wrapper of New-Item to create a directory

			.PARAMETER Directory
			Directory name to create

			.PARAMETER path
			Name of the directory that you would like to create

			.EXAMPLE
			PS C:\> mkdir test

			Description
			-----------
			Creates a directory with the name "test"

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Directory name to create')]
		[Alias('dir')]
		[System.String]$Directory
	)

	PROCESS {
		try {
			# Do it: Create the directory
			New-Item -type directory -Force -Path $Directory -Confirm:$false -ErrorAction:stop -WarningAction:SilentlyContinue
		} catch {
			Write-Error "Sorry, we had a problem while we try to create $Directory"
		}
	}
}

function Update-SysInfo {
	<#
			.SYNOPSIS
			Update Information about the system

			.DESCRIPTION
			This function updates the informations about the systems it runs on

			.EXAMPLE
			PS C:\> Update-SysInfo

			Description
			-----------
			Update Information about the system, no output!

			.LINK
			Based on an idea found here: https://github.com/michalmillar/ps-motd/blob/master/Get-MOTD.ps1

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues

	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Call Companion to Cleanup
		if ((Get-Command Clean-SysInfo -ErrorAction:SilentlyContinue)) {
			Clean-SysInfo
		}
	}

	PROCESS {
		# Fill Variables with values
		Set-Variable -Name Operating_System -Scope:Global -Value $(Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory, Caption, Version, SystemDrive)
		Set-Variable -Name Processor -Scope:Global -Value $(Get-CimInstance -ClassName Win32_Processor | Select-Object -Property Name, LoadPercentage)
		Set-Variable -Name Logical_Disk -Scope:Global -Value $(Get-CimInstance -ClassName Win32_LogicalDisk |
			Where-Object -Property DeviceID -EQ -Value $(${Operating_System}.SystemDrive) |
		Select-Object -Property Size, FreeSpace)
		Set-Variable -Name Get_Date -Scope:Global -Value $(Get-Date)
		Set-Variable -Name Get_OS_Name -Scope:Global -Value $(${Operating_System}.Caption)
		Set-Variable -Name Get_Kernel_Info -Scope:Global -Value $(${Operating_System}.Version)
		Set-Variable -Name Get_Uptime -Scope:Global -Value $("$((${Get_Uptime} = ${Get_Date} - $(${Operating_System}.LastBootUpTime)).Days) days, $(${Get_Uptime}.Hours) hours, $(${Get_Uptime}.Minutes) minutes")
		Set-Variable -Name Get_Shell_Info -Scope:Global -Value $('{0}.{1}' -f $psversiontable.PSVersion.Major, $psversiontable.PSVersion.Minor)
		Set-Variable -Name Get_CPU_Info -Scope:Global -Value $(${Processor}.Name -replace '\(C\)', '' -replace '\(R\)', '' -replace '\(TM\)', '' -replace 'CPU', '' -replace '\s+', ' ')
		Set-Variable -Name Get_Process_Count -Scope:Global -Value $((Get-Process).Count)
		Set-Variable -Name Get_Current_Load -Scope:Global -Value $(${Processor}.LoadPercentage)
		Set-Variable -Name Get_Memory_Size -Scope:Global -Value $('{0}mb/{1}mb Used' -f (([math]::round(${Operating_System}.TotalVisibleMemorySize/1KB)) - ([math]::round(${Operating_System}.FreePhysicalMemory/1KB))), ([math]::round(${Operating_System}.TotalVisibleMemorySize/1KB)))
		Set-Variable -Name Get_Disk_Size -Scope:Global -Value $('{0}gb/{1}gb Used' -f (([math]::round(${Logical_Disk}.Size/1GB)) - ([math]::round(${Logical_Disk}.FreeSpace/1GB))), ([math]::round(${Logical_Disk}.Size/1GB)))

		# Do we have the NET-Experts Base Module?
		if ((Get-Command Get-NETXCoreVer -ErrorAction:SilentlyContinue)) {
			Set-Variable -Name MyPoSHver -Scope:Global -Value $(Get-NETXCoreVer -s)
		} else {
			Set-Variable -Name MyPoSHver -Scope:Global -Value $('Unknown')
		}

		# Are we Admin?
		If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
			Set-Variable -Name AmIAdmin -Scope:Global -Value $('(User)')
		} else {
			Set-Variable -Name AmIAdmin -Scope:Global -Value $('(Admin)')
		}

		# Is this a Virtual or a Real System?
		if ((Get-Command Get-IsVirtual -ErrorAction:SilentlyContinue)) {
			if (Get-IsVirtual) {
				Set-Variable -Name IsVirtual -Scope:Global -Value $('(Virtual)')
			} else {
				Set-Variable -Name IsVirtual -Scope:Global -Value $('(Real)')
			}
		} else {
			# No idea what to do without the command-let!
			Remove-Variable IsVirtual -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}

		<#
				# This is the old way (Will be removed soon)
				if (Get-adminuser -ErrorAction:SilentlyContinue) {
				if (Get-adminuser) {
				Set-Variable -Name AmIAdmin -Scope:Global -Value $("(Admin)")
				} elseif (-not (Get-adminuser)) {
				Set-Variable -Name AmIAdmin -Scope:Global -Value $("(User)")
				} else {
				Set-Variable -Name AmIAdmin -Scope:Global -Value $("")
				}
				}
		#>

		# What CPU type do we have here?
		if ((Check-SessionArch -ErrorAction:SilentlyContinue)) {
			Set-Variable -Name CPUtype -Scope:Global -Value $(Check-SessionArch)
		}

		# Define object
		Set-Variable -Name MyPSMode -Scope:Global -Value $($Host.Runspace.ApartmentState)
	}
}

function Clean-SysInfo {
	<#
			.SYNOPSIS
			Companion for Update-SysInfo

			.DESCRIPTION
			Cleanup for variables from the Update-SysInfo function

			.EXAMPLE
			PS C:\> Clean-SysInfo

			Description
			-----------
			Cleanup for variables from the Update-SysInfo function

			.NOTES

	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Cleanup old objects
		Remove-Variable Operating_System -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Processor -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Logical_Disk -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Date -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_OS_Name -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Kernel_Info -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Uptime -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Shell_Info -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_CPU_Info -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Process_Count -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Current_Load -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Memory_Size -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable Get_Disk_Size -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable MyPoSHver -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable AmIAdmin -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable CPUtype -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable MyPSMode -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable IsVirtual -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Get-MOTD {
	<#
			.SYNOPSIS
			Displays system information to a host.

			.DESCRIPTION
			The Get-MOTD cmdlet is a system information tool written in PowerShell.

			.EXAMPLE
			PS C:\> Get-MOTD

			Description
			-----------
			Display the colorful Message of the Day with a Microsoft Logo and some
			system infos

			.NOTES
			inspired by this: https://github.com/michalmillar/ps-motd/blob/master/Get-MOTD.ps1

			The Microsoft Logo, PowerShell, Windows and some others are registered
			Trademarks by Microsoft Corporation.

			I do not own them, i just use them here :-)

			I moved some stuff in a separate function to make it reusable
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Update the Infos
		Update-SysInfo
	}

	PROCESS {
		# Write to the Console
		Write-Host -Object ('')
		Write-Host -Object ('')
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Red
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Green
		Write-Host -Object ('    Date/Time: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Date}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Red
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Green
		Write-Host -Object ('         User: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${env:UserName} ${AmIAdmin}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Red
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Green
		Write-Host -Object ('         Host: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("$env:COMPUTERNAME") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Red
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Green
		Write-Host -Object ('           OS: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_OS_Name}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Red
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Green
		Write-Host -Object ('       Kernel: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ('NT ') -NoNewline -ForegroundColor Gray
		Write-Host -Object ("${Get_Kernel_Info} - ${CPUtype}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Red
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Green
		Write-Host -Object ('       Uptime: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Uptime}") -ForegroundColor Gray
		Write-Host -Object ('') -NoNewline
		Write-Host -Object ('                                  NETX PoSH: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${MyPoSHver} (${localDomain} - ${environment})") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Blue
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Yellow
		Write-Host -Object ('        Shell: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("Powershell ${Get_Shell_Info} - ${MyPSMode} Mode") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Blue
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Yellow
		Write-Host -Object ('          CPU: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_CPU_Info} ${IsVirtual}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Blue
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Yellow
		Write-Host -Object ('    Processes: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Process_Count}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Blue
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Yellow
		Write-Host -Object ('         Load: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Current_Load}") -NoNewline -ForegroundColor Gray
		Write-Host -Object ('%') -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Blue
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Yellow
		Write-Host -Object ('       Memory: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Memory_Size}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Blue
		Write-Host -Object (' ███████████') -NoNewline -ForegroundColor Yellow
		Write-Host -Object ('         Disk: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Disk_Size}") -ForegroundColor Gray
		Write-Host -Object ('      ') -NoNewline
		Write-Host -Object ('')
		Write-Host -Object ('')
	}

	END {
		# Call Cleanup
		if ((Get-Command Clean-SysInfo -ErrorAction:SilentlyContinue)) {
			Clean-SysInfo
		}
	}
}

function Get-SysInfo {
	<#
			.SYNOPSIS
			Displays Information about the system

			.DESCRIPTION
			Displays Information about the system it is started on

			.EXAMPLE
			PS C:\> Get-SysInfo

			Description
			-----------
			Display some system infos

			.NOTES
			Based on an idea found here: https://github.com/michalmillar/ps-motd/blob/master/Get-MOTD.ps1
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Update the Infos
		Update-SysInfo
	}

	PROCESS {
		# Write to the Console
		Write-Host -Object ('')
		Write-Host -Object ('  Date/Time: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Date}") -ForegroundColor Gray
		Write-Host -Object ('  User:      ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${env:UserName} ${AmIAdmin}") -ForegroundColor Gray
		Write-Host -Object ('  Host:      ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("$env:COMPUTERNAME") -ForegroundColor Gray
		Write-Host -Object ('  OS:        ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_OS_Name}") -ForegroundColor Gray
		Write-Host -Object ('  Kernel:    ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ('NT ') -NoNewline -ForegroundColor Gray
		Write-Host -Object ("${Get_Kernel_Info} - ${CPUtype}") -ForegroundColor Gray
		Write-Host -Object ('  Uptime:    ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Uptime}") -ForegroundColor Gray
		Write-Host -Object ('  NETX PoSH: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${MyPoSHver} (${localDomain} - ${environment})") -ForegroundColor Gray
		Write-Host -Object ('  Shell:     ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("Powershell ${Get_Shell_Info} - ${MyPSMode} Mode") -ForegroundColor Gray
		Write-Host -Object ('  CPU:       ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_CPU_Info} ${IsVirtual}") -ForegroundColor Gray
		Write-Host -Object ('  Processes: ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Process_Count}") -ForegroundColor Gray
		Write-Host -Object ('  Load:      ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Current_Load}") -NoNewline -ForegroundColor Gray
		Write-Host -Object ('%') -ForegroundColor Gray
		Write-Host -Object ('  Memory:    ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Memory_Size}") -ForegroundColor Gray
		Write-Host -Object ('  Disk:      ') -NoNewline -ForegroundColor DarkGray
		Write-Host -Object ("${Get_Disk_Size}") -ForegroundColor Gray
		Write-Host -Object ('')
	}

	END {
		# Call Cleanup
		if ((Get-Command Clean-SysInfo -ErrorAction:SilentlyContinue)) {
			Clean-SysInfo
		}
	}
}

# Make Powershell more Uni* like
function Get-MyLS {
	<#
			.SYNOPSIS
			Wrapper for Get-ChildItem

			.DESCRIPTION
			This wrapper for Get-ChildItem shows all directories and files
			(even hidden ones)

			.PARAMETER loc
			A description of the loc parameter.

			.PARAMETER location
			This optional parameters is useful if you would like to see the
			content of another directory

			.EXAMPLE
			PS C:\> myls

			Description
			-----------
			Show the content of the directory Where-Object you are

			.EXAMPLE
			PS C:\> myls c:\

			Description
			-----------
			Show the content of "c:\"

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues

	#>

	[CmdletBinding()]
	param
	(
		[Alias('Location')]
		[System.String]$loc = '.'
	)

	PROCESS {
		# Execute GCI
		Get-ChildItem -Force -att !a "$loc"
		Get-ChildItem -Force -att !d "$loc"
	}
}

function New-BasicAuthHeader {
	<#
			.SYNOPSIS
			Create a basic authentication header for Web requests

			.DESCRIPTION
			Create a basic authentication header for Web requests, often used
			in Rest API Calls (Works perfect for Invoke-RestMethod calls)

			.PARAMETER user
			User name to use

			.PARAMETER password
			Password to use

			.EXAMPLE
			PS C:\> New-BasicAuthHeader -user 'apiuser' -password 'password'
			YXBpdXNlcjpwYXNzd29yZA==

			Description
			-----------
			Create a valid password and Auth header, perfect for REST Web Services

			.EXAMPLE
			PS C:\> Invoke-RestMethod -Uri 'https://service.contoso.com/api/auth' -Method 'Get' -Headers @{Authorization=("Basic {0}" -f (New-BasicAuthHeader 'apiuser' 'password'))}

			Description
			-----------
			Call the URI 'https://service.contoso.com/api/auth' with an basic
			authentication header for the given credentials.

			.NOTES
			Very basic for now!
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'User name to use')]
		[ValidateNotNullOrEmpty()]
		[System.String]$user,
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 2,
		HelpMessage = 'Password to use')]
		[ValidateNotNullOrEmpty()]
		[System.String]$password
	)

	BEGIN {
		# Cleanup
		$BasicAuthHeader = $null
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess('BasicAuthHeader', 'Create')) {
			$BasicAuthHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(('{0}:{1}' -f $user, $password)))
		}
	}

	END {
		if ($BasicAuthHeader) {
			Write-Output $BasicAuthHeader
		}

		# Cleanup
		$BasicAuthHeader = $null
		$user = $null
		$password = $null
	}
}

function New-Gitignore {
	<#
			.SYNOPSIS
			Create a new .gitignore file with my default settings

			.DESCRIPTION
			Downloads my default .gitignore from GitHub and creates it within
			the directory from Where-Object this function is called.

			.PARAMETER Source
			The Source for the .gitignore

			.EXAMPLE
			PS C:\scripts\PowerShell\test> New-Gitignore
			Creating C:\scripts\PowerShell\test\.gitignore
			C:\scripts\PowerShell\test\.gitignore successfully created.

			Description
			-----------
			The default: We downloaded the default .gitignore from GitHub

			.EXAMPLE
			PS C:\scripts\PowerShell\test\> New-Gitignore
			WARNING: You already have a .gitignore in this dir.
			Fetch a fresh one from GitHub?
			Removing existing .gitignore.
			Creating C:\scripts\PowerShell\test\.gitignore
			C:\scripts\PowerShell\test\.gitignore successfully created.

			Description
			-----------
			In this example we had an existing .gitignore and downloaded the
			default one from GitHub...

			.EXAMPLE
			PS C:\scripts\PowerShell\test> New-Gitignore
			WARNING: You already have a .gitignore in this dir.
			Fetch a fresh one from GitHub?
			Existing .gitignore will not be changed.

			Description
			-----------
			In this Example we had an existing .gitignore and we decided to
			stay with em!

			.NOTES
			Additional information about the function.

			.LINK
			SourceFile https://raw.githubusercontent.com/jhochwald/MyPowerShellStuff/master/.gitignore

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'The Source for the .gitignore')]
		[System.String]$Source = 'https://raw.githubusercontent.com/jhochwald/MyPowerShellStuff/master/.gitignore'
	)

	BEGIN {
		$GitIgnore = "$PWD\.gitignore"
	}

	PROCESS {
		if (Test-Path $GitIgnore) {
			Write-Warning 'You already have a .gitignore in this dir.'
			Write-Output ''
			Write-Output 'Fetch a fresh one from GitHub?'

			$Answer = ([Console]::ReadKey('NoEcho,IncludeKeyDown'))

			if ($Answer.Key -ne 'Enter' -and $Answer.Key -ne 'y') {
				Write-Output ''
				Write-Output 'Existing .gitignore will not be changed.'
				return
			}

			Write-Output ''
			Write-Host 'Removing existing .gitignore.'

			try {
				(Remove-Item -Path "$PWD\.gitignore" -Force -Confirm:$false -WarningAction:SilentlyContinue -ErrorAction:Stop) > $null 2>&1 3>&1
			} catch {
				Write-Output ''
				Write-Output ''
				Write-Warning "Unable to remove existing $PWD\.gitignore"
				break
			}
		}

		Write-Output ''
		Write-Output "Creating $PWD\.gitignore"

		try {
			$WC = (New-Object System.Net.WebClient)
			$WC.DownloadString($Source) | New-Item -ItemType file -Path $PWD -Name '.gitignore' -Force -Confirm:$false -WarningAction:SilentlyContinue -ErrorAction:Stop > $null 2>&1 3>&1

			Write-Output ''
			Write-Output "$PWD\.gitignore successfully created."
		} catch {
			Write-Output ''
			Write-Output ''
			Write-Warning "Unable to create $PWD\.gitignore"
		}
	}
}

function New-Guid {
	<#
			.SYNOPSIS
			Creates a new Guid object and displays it to the screen

			.DESCRIPTION
			Uses static System.Guid.NewGuid() method to create a new Guid object

			.EXAMPLE
			PS C:\> New-Guid
			fd6bd476-db80-44e7-ab34-47437adeb8e3

			Description
			-----------
			Creates a new Guid object and displays its GUI to the screen

			.NOTES
			This is just a quick & dirty helper function to generate GUID's
			this is neat if you need a new GUID for an PowerShell Module.

			If you have Visual Studio, you might find this function useless!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	BEGIN {
		# Define object via NET
		[System.Guid]$guidObject = [System.Guid]::NewGuid()
	}

	PROCESS {
		# Dump the new Object
		Write-Output "$($guidObject.Guid)"
	}
}

function Open-InternetExplorer {
	<#
			.SYNOPSIS
			Workaround for buggy internetexplorer.application

			.DESCRIPTION
			This Workaround is neat, because the native implementation is unable to
			bring the new Internet Explorer Window to the front (give em focus).
			It needs his companion: Add-NativeHelperType

			.PARAMETER Url
			The URL you would like to open in Internet Explorer

			.PARAMETER Foreground
			Should the new Internet Explorer start in the foreground?

			The default is YES.

			.PARAMETER FullScreen
			Should the new Internet Explorer Session start in Full Screen

			The Default is NO

			.EXAMPLE
			PS C:\> Open-InternetExplorer -Url 'http://net-experts.net' -FullScreen -InForeground

			Description
			-----------
			Start Internet Explorer in Foreground and fullscreen,
			it also opens http://net-experts.net

			.EXAMPLE
			PS C:\> Open-InternetExplorer -Url 'https://portal.office.com'

			Description
			-----------
			Start Internet Explorer in Foreground with the URL
			https://portal.office.com

			.LINK
			Source: http://superuser.com/questions/848201/focus-ie-window-in-powershell

			.LINK
			Info: https://msdn.microsoft.com/en-us/library/windows/desktop/ms633539(v=vs.85).aspx

			.NOTES
			It needs his companion: Add-NativeHelperType
			Based on a snippet from Crippledsmurf
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'The URL you would like to open in Internet Explorer')]
		[System.String]$url = 'http://support.NET-Experts.net',
		[Parameter(HelpMessage = 'Should the new Internet Explorer start in the foreground? The default is YES.')]
		[Alias('fg')]
		[switch]$Foreground = $true,
		[Parameter(HelpMessage = 'Should the new Internet Explorer Session start in Full Screen, the Default is NO')]
		[Alias('fs')]
		[switch]$FullScreen = $false
	)
	BEGIN {
		# If we want to start in Foreground, we use our helper
		if ($Foreground) {
			Add-NativeHelperType
		}
	}

	PROCESS {
		# Initiate a new IE
		$internetExplorer = New-Object -ComObject 'InternetExplorer.Application'

		# The URL to open
		$internetExplorer.navigate($url)

		# Should is be Visible?
		$internetExplorer.Visible = $true

		# STart un fullscreen?
		$internetExplorer.FullScreen = $FullScreen

		# Here is the Magic!
		if ($Foreground) {
			[NativeHelper]::SetForeground($internetExplorer.HWND) > $null 2>&1 3>&1
		}
	}

	END {
		# Be verbose
		Write-Verbose -Message "$internetExplorer"
	}
}

function Add-AppendPath {
	<#
			.SYNOPSIS
			Appends a given folder (Directory) to the Path

			.DESCRIPTION
			Appends a given folder (Directory) to the Path

			.EXAMPLE
			PS C:\> Add-AppendPath

			Description
			-----------
			Adds "C:\scripts\PowerShell\" (the default) to the Path

			.EXAMPLE
			PS C:\> Add-AppendPath -Path 'C:\scripts\batch\'

			Description
			-----------
			Adds 'C:\scripts\batch\' to the Path

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>
	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Path to add to the system path')]
		[ValidateNotNullOrEmpty()]
		[Alias('Folder')]
		[System.String]$Pathlist = 'C:\scripts\PowerShell\'
	)

	PROCESS {
		foreach ($Path in $Pathlist) {
			# Save the Path
			$OriginalPaths = ($env:Path)

			# Check if the given Folder is already in the Path!
			$ComparePath = ('*' + $Path + '*')

			if (-not ($OriginalPaths -like $ComparePath)) {
				# Nope, so we add the folder to the Path!
				$env:Path = ($env:Path + ';' + $BasePath)
			}

			# Cleanup
			$ComparePath = $null
			$OriginalPaths = $null
		}
	}
}

function Remove-FromPath {
	<#
			.SYNOPSIS
			Removes given Directory or Directories from the PATH

			.DESCRIPTION
			Removes given Directory or Directories from the PATH

			.PARAMETER Pathlist
			The PATH to remove

			.EXAMPLE
			PS C:\> Remove-FromPath -Pathlist 'C:\scripts\batch\'

			Description
			-----------
			Removes 'C:\scripts\batch\' from the Path

			.LINK
			Add-AppendPath

			.NOTES
			Just a little helper function
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(HelpMessage = 'The PATH to remove')]
		[ValidateNotNullOrEmpty()]
		[System.String[]]$Pathlist
	)

	PROCESS {
		foreach ($Path in $Pathlist) {
			$Path = @() + $Path
			$paths = ($env:Path -split ';')
			$paths = ($paths | Where-Object { $Path -notcontains $_ })
			$env:Path = $paths -join ';'
		}
	}
}

function Out-ColorMatchInfo {
	<#
			.Synopsis
			Highlights MatchInfo objects similar to the output from grep.

			.Description
			Highlights MatchInfo objects similar to the output from grep.

			.PARAMETER match
			Matching word

			.NOTES
			modified by     : Joerg Hochwald
			last modified   : 2016-02-09

			.LINK
			Source http://poshcode.org/1095
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
		HelpMessage = 'Matching word')]
		[Microsoft.PowerShell.Commands.MatchInfo]$Match
	)

	BEGIN {
		function Get-RelativePath {
			param
			(
				[string]
				$Path
			)

			$Path = $Path.Replace($PWD.Path, '')

			if ($Path.StartsWith('\') -and (-not $Path.StartsWith('\\'))) {
				$Path = $Path.Substring(1)
			}

			$Path
		}

		function Write-PathAndLine {
			param
			(
				[Object]
				$Match
			)

			Write-Host (Get-RelativePath $Match.Path) -ForegroundColor White -NoNewline
			Write-Host ':' -ForegroundColor Cyan -NoNewline
			Write-Host $Match.LineNumber -ForegroundColor DarkYellow
		}

		function Write-HighlightedMatch {
			param
			(
				[Object]
				$Match
			)

			$index = 0

			foreach ($m in $Match.Matches) {
				Write-Host $Match.Line.SubString($index, $m.Index - $index) -NoNewline
				Write-Host $m.Value -ForegroundColor Red -NoNewline
				$index = $m.Index + $m.Length
			}

			if ($index -lt $Match.Line.Length) {
				Write-Host $Match.Line.SubString($index) -NoNewline
			}
			''
		}
	}

	PROCESS {
		Write-PathAndLine $Match

		$Match.Context.DisplayPreContext

		Write-HighlightedMatch $Match

		$Match.Context.DisplayPostContext
		''
	}
}

function Find-String {
	<#
			.Synopsis
			Searches text files by pattern and displays the results.

			.Description
			Searches text files by pattern and displays the results.

			.PARAMETER pattern
			A description of the pattern parameter.

			.PARAMETER include
			A description of the include parameter.

			.PARAMETER recurse
			A description of the recurse parameter.

			.PARAMETER caseSensitive
			A description of the caseSensitive parameter.

			.PARAMETER directoryExclude
			A description of the directoryExclude parameter.

			.PARAMETER context
			A description of the context parameter.

			.Notes
			TODO: Documentation

			.LINK
			Out-ColorMatchInfo

			.LINK
			http://weblogs.asp.net/whaggard/archive/2007/03/23/powershell-script-to-find-strings-and-highlight-them-in-the-output.aspx
			http://poshcode.org/426
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[regex]$pattern,
		[string[]]$include = '*',
		[switch]$recurse = $true,
		[switch]$caseSensitive = $false,
		[string[]]$directoryExclude = 'x{999}',
		[int[]]$context = 0
	)

	BEGIN {
		if ((-not $caseSensitive) -and (-not $pattern.Options -match 'IgnoreCase')) {
			$pattern = New-Object regex -ArgumentList $pattern.ToString(), @($pattern.Options, 'IgnoreCase')
		}
	}

	PROCESS {
		$allExclude = $directoryExclude -join '|'
		Get-ChildItem -Recurse:$recurse -Include:$include |
		Where-Object { $_.FullName -notmatch $allExclude } |
		Select-String -CaseSensitive:$caseSensitive -Pattern:$pattern -AllMatches -Context $context |
		Out-ColorMatchInfo
	}
}

function PoSHModuleLoader {
	<#
			.SYNOPSIS
			Loads all Script modules

			.DESCRIPTION
			Loads all Script modules

			.NOTES
			Old function that we no longer use

			.EXAMPLE
			PS C:\> PoSHModuleLoader

			Description
			-----------
			Loads all Script modules

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Load some PoSH modules
		(Get-Module -ListAvailable |
			Where-Object { $_.ModuleType -eq 'Script' } |
		Import-Module -DisableNameChecking -Force -Scope Global -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)
	}
}

<#
		Simple Functions to save and restore PowerShell session information
#>
function Get-sessionfile {
	<#
			.SYNOPSIS
			Restore PowerShell Session information

			.DESCRIPTION
			This command shows many PowerShell Session informations.

			.PARAMETER sessionName
			Name of the Session you would like to dump

			.EXAMPLE
			PS C:\> Get-sessionfile $O365Session
			C:\Users\adm.jhochwald\AppData\Local\Temp\[PSSession]Session2

			Description
			-----------
			Returns the Session File for a given Session

			.EXAMPLE
			PS C:\> Get-sessionfile
			C:\Users\adm.jhochwald\AppData\Local\Temp\

			Description
			-----------
			Returns the Session File of the running session, cloud be none!

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('Session')]
		[System.String]$sessionName
	)

	PROCESS {
		# DUMP
		Return "$([io.path]::GetTempPath())$sessionName"
	}
}

function export-session {
	<#
			.SYNOPSIS
			Export PowerShell session info to a file

			.DESCRIPTION
			This is a (very) poor man approach to save some session infos

			Our concept of session is simple and only considers:
			- history
			- The export-session

			But still can be very handy and useful. If you type in some sneaky
			commands, or some very complex things and you did not copied these to
			another file or script it can save you a lot of time if you need to
			do it again (And this is often the case)

			Even if you just want to dump it quick to copy it some when later to
			a documentation or script this might be useful.

			.EXAMPLE
			PS C:\> export-session

			Description
			-----------
			Export the history and the export-session to a default File like
			'session-2016040512.ps1session', dynamically generated based on
			Time/date

			.EXAMPLE
			PS C:\> export-session -sessionName 'C:\scripts\mySession'

			Description
			-----------
			Export the history and the export-session to the File
			'C:\scripts\mySession.ps1session'

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Name of the Session File')]
		[ValidateNotNullOrEmpty()]
		[System.String]$sessionName = "session-$(Get-Date -Format yyyyMMddhh)"
	)

	BEGIN {
		# Define object
		Set-Variable -Name file -Value $(Get-sessionfile $sessionName)
	}

	PROCESS {
		#
		(Get-Location).Path > "$File-pwd.ps1session"

		#
		Get-History | Export-Csv "$File-hist.ps1session"
	}

	END {
		# Dump what we have
		Write-Output "Session $sessionName saved"
	}
}

function import-session {
	<#
			.SYNOPSIS
			Import a PowerShell session info from file

			.DESCRIPTION
			This is a (very) poor man approach to restore some session infos

			Our concept of session is simple and only considers:
			- history
			- The current directory

			But still can be very handy and useful. If you type in some sneaky
			commands, or some very complex things and you did not copied these to
			another file or script it can save you a lot of time if you need
			to do it again (And this is often the case)

			Even if you just want to dump it quick to copy it some when later to a
			documentation or script this might be useful.

			.EXAMPLE
			PS C:\> import-session -sessionName 'C:\scripts\mySession'

			Description
			-----------
			Import the history and the export-session from the File
			'C:\scripts\mySession.ps1session'

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('Session')]
		[System.String]$sessionName
	)

	BEGIN {
		# Define object
		Set-Variable -Name file -Value $(Get-sessionfile $sessionName)
	}

	PROCESS {
		# What do we have?
		if (-not [io.file]::Exists("$File-pwd.ps1session")) {
			Write-Error -Message:"Session file doesn't exist" -ErrorAction:Stop
		} else {
			Set-Location (Get-Content "$File-pwd.ps1session")
			Import-Csv "$File-hist.ps1session" | Add-History
		}
	}
}

function Enable-WinRM {
	<#
			.SYNOPSIS
			Enables Remote PowerShell

			.DESCRIPTION
			Enables Remote PowerShell on the local host

			.EXAMPLE
			PS C:\> Enable-WinRM

			Description
			-----------
			Enables Windows Remote (WinRM) on the local system

			.NOTES
			Additional information about the function.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param ()

	PROCESS {
		try {
			Enable-PSRemoting -Force -Confirm:$false
		} catch {
			Write-Error 'Unable to enable PowerShell Remoting'
			break
		}

		try {
			Set-Item wsman:\localhost\client\trustedhosts -Value * -Force -Confirm:$false
		} catch {
			Write-Error 'Unable to set trusted hosts for PowerShell Remoting'
			break
		}

		try {
			Restart-Service WinRM -Force
		} catch {
			Write-Error 'Restart of WinRM service failed!'
			break
		}
	}
}

function Get-NewPsSession {
	<#
			.SYNOPSIS
			Create a session and the given credentials are used

			.DESCRIPTION
			Create a session and the given credentials are used

			.PARAMETER computerName
			Name of the System

			.PARAMETER PsCredentials
			Credentials to use

			.EXAMPLE
			PS C:\> Get-NewPsSession -ComputerName 'Raven' -PsCredentials $myCreds

			Description
			-----------
			Open a PowerShell Session to the System 'Raven' and use the
			credentials stored in the Variable '$myCreds'

			.EXAMPLE
			PS C:\> Get-NewPsSession -ComputerName 'Raven' -PsCredentials (Get-Credentials)

			Description
			-----------
			Open a PowerShell Session to the System 'Raven' and ask for the
			credentials to use

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Name of the System')]
		[ValidateNotNullOrEmpty()]
		[Alias('Computer')]
		$ComputerName = ($env:COMPUTERNAME),
		[Parameter(HelpMessage = 'Credentials to use')]
		[ValidateNotNullOrEmpty()]
		$PsCredentials = ($Credentials)
	)

	PROCESS {
		New-PSSession -ComputerName $ComputerName -Credential $credencial
	}
}

function Set-CurrentSession {
	<#
			.SYNOPSIS
			Make the Session globally available

			.DESCRIPTION
			Make the Session globally available

			.PARAMETER session
			Session to use

			.EXAMPLE
			PS C:\> Set-CurrentSession -session $psSession

			Description
			-----------
			Make the Session in the variable '$psSession' globally available
			Might be useful if you open a session from within a script and want
			to use it after the script is finished!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
		HelpMessage = 'Session to use')]
		$session
	)

	PROCESS {
		Set-Variable -Name 'remoteSession' -Scope:Global -Value $($session)
	}
}

function Send-Command {
	<#
			.SYNOPSIS
			Obsolete command!

			.DESCRIPTION
			Only an Alias for Invoke-Command

			.LINK
			Invoke-Command
	#>
	(Set-Alias Send-Command -Value Invoke-Command -Option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1
}

function Register-Script {
	<#
			.SYNOPSIS
			Obsolete command!

			.DESCRIPTION
			Only an Alias for Invoke-Command

			.LINK
			Invoke-Command
	#>
	(Set-Alias Send-Command -Value Invoke-Command -Option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1
}

function Send-Pushover {
	<#
			.SYNOPSIS
			Sends a push message via Pushover

			.DESCRIPTION
			We established a lot of automated messaging and push services,
			Pushover was missing!

			We do not use Pushover that much, but sometimes it is just nice to
			have the function ready...

			.EXAMPLE
			PS C:\> Send-Pushover -User "USERTOKEN" -token "APPTOKEN" -Message "Test"

			Description
			-----------
			Send the message "Test" to all your devices. The App Name is
			displayed a title of the push

			.EXAMPLE
			PS C:\> Send-Pushover -User "USERTOKEN" -token "APPTOKEN" -Message "Test" -device "Josh-iPadPro"

			Description
			-----------
			Send the message "Test" to the device with the name "Josh-iPadPro".
			The App Name is displayed a title of the push

			.EXAMPLE
			PS C:\> Send-Pushover -User "USERTOKEN" -token "APPTOKEN" -Message "Test" -title "Hello!" -sound "cosmic"

			Description
			-----------
			Send the message "Test" to all your devices. It will have the
			Title "Hello!" and use the notification sound "cosmic"

			.EXAMPLE
			PS C:\> Send-Pushover -User "USERTOKEN" -token "APPTOKEN" -Message "Nice URL for you" -title "Hello!" -url "http://net-experts.net" -url_title "My Site"

			Description
			-----------
			Send the message "Nice URL for you" with the title "Hello!" to all
			your devices.
			The Push contains a link to "http://net-experts.net" with the
			URL title "My Site"

			.PARAMETER User
			The user/group key (not e-mail address) of your user (or you),
			viewable when logged into our Pushover dashboard

			.PARAMETER Message
			Your message, can be HTML like formated

			.PARAMETER token
			Your Pushover application API token

			.PARAMETER device
			Your device name to send the message directly to that device,
			rather than all of the devices (multiple devices may be separated by
			a comma). You can use Get-PushoverUserDeviceInfo to get a list of
			all registered devices.

			.PARAMETER title
			Your message title, otherwise your app name is used

			.PARAMETER url
			A supplementary URL to show with your message

			.PARAMETER url_title
			A title for your supplementary URL, otherwise just the URL is shown

			.PARAMETER priority
			The Push priority (-2 to +2)

			.PARAMETER sound
			The name of one of the sounds supported by device clients to override
			the user's default sound choice

			.NOTES
			Based on our Send-SlackChat function

			.LINK
			Get-PushoverUserDeviceInfo

			.LINK
			Info: https://pushover.net

			.LINK
			API: https://pushover.net/api

			.LINK
			Send-SlackChat

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'The user/group key of your user, viewable when logged into our Pushover dashboard')]
		[ValidateNotNullOrEmpty()]
		[System.String]$user,
		[Parameter(Mandatory = $true,
				Position = 1,
		HelpMessage = 'Your message, can be HTML like formated')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Message,
		[Parameter(Position = 2,
		HelpMessage = 'Your Pushover application API token')]
		[ValidateNotNullOrEmpty()]
		[System.String]$token,
		[Parameter(HelpMessage = 'Your device name to send the message directly to that device, rather than all of the devices')]
		$device,
		[Parameter(HelpMessage = 'Your message title, otherwise your app name is used')]
		$title,
		[Parameter(HelpMessage = 'A supplementary URL to show with your message')]
		$url,
		[Parameter(HelpMessage = 'A title for your supplementary URL, otherwise just the URL is shown')]
		$url_title,
		[Parameter(HelpMessage = 'The Push priority (-2 to +2)')]
		[ValidateSet('-2', '-1', '0', '1', '2')]
		$priority = '0',
		[Parameter(HelpMessage = 'The name of one of the sounds supported by device clients to override the user''s default sound choice')]
		[ValidateSet('pushover', 'bike', 'bugle', 'cashregister', 'classical', 'cosmic', 'falling', 'gamelan', 'incoming', 'intermission', 'magic', 'mechanical', 'pianobar', 'siren', 'spacealarm', 'tugboat', 'alien', 'climb', 'persistent', 'echo', 'updown', 'none')]
		$sound = 'pushover'
	)

	BEGIN {
		# Cleanup all variables...
		Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'myMethod' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		Set-Variable -Name 'uri' -Value $('https://api.pushover.net/1/messages.json')

		# Build the body as per https://pushover.net/faq#library
		# We convert this to JSON then...
		Set-Variable -Name 'body' -Value $(@{
				token   = $token
				user    = $user
				message = $Message
		})

		# Sent a push to a special Device? Could be a list separated by comma
		if ($device) {
			$TmpBody = @{
				device = $device
			}
			$body = $body + $TmpBody
			$TmpBody = $null
		}

		# Want a Title for this Push?
		if ($title) {
			$TmpBody = @{
				title = $title
			}
			$body = $body + $TmpBody
			$TmpBody = $null
		}

		# Attach a URL to the push?
		if ($url) {
			# Encode the URL if possible
			if ((Get-Command ConvertTo-UrlEncoded -ErrorAction:SilentlyContinue)) {
				try {
					$url = (ConvertTo-UrlEncoded $url)
				} catch {
					# Argh! Use a unencoded URL
					$UrlEncoded = ($url)
				}
			} else {
				# Use a unencoded URL
				$UrlEncoded = ($url)
			}
			$TmpBody = @{
				url = $UrlEncoded
			}
			$body = $body + $TmpBody
			$TmpBody = $null
		}

		# Give the URL a nice title. Just URLs suck!
		if ($url_title) {
			$TmpBody = @{
				url_title = $url_title
			}
			$body = $body + $TmpBody
			$TmpBody = $null
		}

		# Set a Priotity for this push
		if ($priority) {
			$TmpBody = @{
				priority = $priority
			}
			$body = $body + $TmpBody
			$TmpBody = $null
		}

		# Special Sound?
		if ($sound) {
			$TmpBody = @{
				sound = $sound
			}
			$body = $body + $TmpBody
			$TmpBody = $null
		}

		# Convert the Body Variable to JSON Check if the Server understands Compression,
		# could reduce bandwidth Be careful with the Depth Parameter, bigger values means less performance
		Set-Variable -Name 'myBody' -Value $(ConvertTo-Json $body -Depth 2 -Compress:$false)

		# Method to use for the RESTful Call
		Set-Variable -Name 'myMethod' -Value $('POST' -as ([System.String] -as [type]))

		# Use the API via RESTful call
		try {
			(Invoke-RestMethod -Uri $uri -Method $myMethod -Body $body -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts WindowsPowerShell Service $CoreVersion" -ErrorAction:Stop -WarningAction:SilentlyContinue)
		} catch [System.Exception] {
			<#
					Argh!
					That was an Exception...
			#>

			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		} catch {
			# Whoopsie!
			# That should not happen...
			Write-Warning -Message "Could not send notification to your Slack $user"
		} finally {
			# Cleanup all variables...
			Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'myMethod' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Get-PushoverUserDeviceInfo {
	<#
			.SYNOPSIS
			Retrieves a list of registered devices with Pushover

			.DESCRIPTION
			Perfect in combination with the Send-Pushover command to send a
			notification using the "device" parameter of Send-Pushover

			.PARAMETER User
			The user/group key (not e-mail address) of your user (or you),
			viewable when logged into our Pushover dashboard

			.PARAMETER token
			Your Pushover application API token

			.EXAMPLE
			PS C:\> Get-PushoverUserDeviceInfo -User "John" -token "APPTOKEN"

			John-Mac
			John-iPadMini
			John-iPhone5S
			John-S5

			Description
			-----------
			Get all Devices for User 'John'

			.LINK
			Send-Pushover

			.LINK
			Info: https://pushover.net

			.LINK
			API: https://pushover.net/api

			.LINK
			Send-SlackChat

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues

	#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'The user/group key of your user, viewable when logged into our Pushover dashboard')]
		[ValidateNotNullOrEmpty()]
		[System.String]$user,
		[Parameter(Position = 2,
		HelpMessage = 'Your Pushover application API token')]
		[ValidateNotNullOrEmpty()]
		[System.String]$token
	)
	BEGIN {
		# Cleanup all variables...
		Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'myMethod' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		Set-Variable -Name 'uri' -Value $('https://api.pushover.net/1/users/validate.json')

		# Build the body as per https://pushover.net/faq#library
		# We convert this to JSON then...
		Set-Variable -Name 'body' -Value $(@{
				token = $token
				user  = $user
		})

		# Convert the Body Variable to JSON Check if the Server understands Compression,
		# could reduce bandwidth Be careful with the Depth Parameter, bigger values means less performance
		Set-Variable -Name 'myBody' -Value $(ConvertTo-Json $body -Depth 2 -Compress:$false)

		# Method to use for the RESTful Call
		Set-Variable -Name 'myMethod' -Value $('POST' -as ([System.String] -as [type]))

		# Use the API via RESTful call
		try {
			$PushoverUserDeviceInfo = (Invoke-RestMethod -Uri $uri -Method $myMethod -Body $body -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts WindowsPowerShell Service $CoreVersion" -ErrorAction:Stop -WarningAction:SilentlyContinue)
		} catch [System.Exception] {
			<#
					Argh!

					That was an Exception...
			#>

			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		} catch {
			# Whoopsie!
			# That should not happen...
			Write-Warning -Message "Could not send notification to your Slack $user"
		} finally {
			# Cleanup all variables...
			Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'myMethod' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}

	END {
		Return ($PushoverUserDeviceInfo.devices)
	}
}

function Invoke-RDPSession {
	<#
			.SYNOPSIS
			Wrapper for the Windows RDP Client

			.DESCRIPTION
			Just a wrapper for the Windows Remote Desktop Protocol (RDP) Client.

			.PARAMETER Server
			The Host could be a host name or an IP address

			.PARAMETER Port
			The RDP Port to use

			.EXAMPLE
			PS C:\> Invoke-RDPSession SNOOPY

			Description
			-----------
			Opens a Remote Desktop Session to the system with the Name SNOOPY

			.EXAMPLE
			PS C:\> Invoke-RDPSession -Server "deepblue.fra01.kreativsign.net"

			Description
			-----------
			Opens a Remote Desktop Session to the system
			"deepblue.fra01.kreativsign.net"

			.EXAMPLE
			PS C:\> Invoke-RDPSession -host '10.10.16.10'

			Description
			-----------
			Opens a Remote Desktop Session to the system with the IPv4
			address 10.10.16.10

			.NOTES
			We use the follwing defaults: /admin /w:1024 /h:768
			Change this within the script if you like other defaults.
			A future version might provide more parameters

			The default Port is 3389.
			You might want to change that via the commandline parameter

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 1,
		HelpMessage = 'The Host could be a host name or an IP address')]
		[ValidateNotNullOrEmpty()]
		[Alias('RDPHost')]
		[System.String]$Server,
		[Parameter(Position = 2,
		HelpMessage = 'The RDP Port to use')]
		[Alias('RDPPort')]
		[System.Int32]$Port = 3389
	)

	BEGIN {
		# Test RemoteDesktop Connection is valid or not
		try {
			$TestRemoteDesktop = New-Object System.Net.Sockets.TCPClient -ArgumentList $Server, $Port
		} catch [System.Exception] {
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		} catch {
			# Did not see this one coming!
			Write-Error -Message "Sorry, but $Server did not answer on port $Port" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		}
	}

	PROCESS {
		# What do we have?
		if (-not ($Server)) {
			Write-Error -Message 'Mandatory Parameter HOST is missing' -ErrorAction:Stop
		} else {
			if ($TestRemoteDesktop) {
				$RDPHost2Connect = ($Server + ':' + $Port)
				Start-Process -FilePath mstsc -ArgumentList "/admin /w:1024 /h:768 /v:$RDPHost2Connect"
			} else {
				# Did not see this one coming!
				Write-Error -Message "Sorry, but $Server did not answer on port $Port" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the hard way...
				exit 1
			}
		}
	}
}

function Get-DefaultMessage {
	<#
			.SYNOPSIS
			Helper Function to show default message used in VERBOSE/DEBUG/WARNING

			.DESCRIPTION
			Helper Function to show default message used in VERBOSE/DEBUG/WARNING
			and... HOST in some case.
			This is helpful to standardize the output messages

			.PARAMETER Message
			Specifies the message to show

			.EXAMPLE
			PS C:\> Get-DefaultMessage -Message "Test"
			[2016.04.04-23:53:26:61][] Test

			Description
			-----------
			Display the given message with a Time-Stamp

			.EXAMPLE
			PS C:\> .\dummy.ps1
			[2016.04.04-23:53:26:61][dummy.ps1] Test

			Description
			-----------
			Use the function from within another script
			The following code is used in "dummy.ps1"
			Get-DefaultMessage -Message "Test"

			.NOTES
			Based on an ideas of Francois-Xavier Cat

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	param
	(
		[Parameter(HelpMessage = 'Specifies the message to show')]
		[System.String]$Message
	)

	PROCESS {
		# Set the Variables
		Set-Variable -Name 'DateFormat' -Scope:Script -Value $(Get-Date -Format 'yyyy/MM/dd-HH:mm:ss:ff')
		Set-Variable -Name 'FunctionName' -Scope:Script -Value $((Get-Variable -Scope 1 -Name MyInvocation -ValueOnly).MyCommand.Name)

		# Dump to the console
		Write-Output "[$DateFormat][$functionName] $Message"
	}
}

function Disable-RemoteDesktop {
	<#
			.SYNOPSIS
			The function Disable-RemoteDesktop will disable RemoteDesktop on a
			local or remote machine.

			.DESCRIPTION
			The function Disable-RemoteDesktop will disable RemoteDesktop on a
			local or remote machine.

			.PARAMETER ComputerName
			Specifies the computername

			.PARAMETER Credentials
			Specifies the Credentials to use

			.PARAMETER CimSession
			Specifies one or more existing CIM Session(s) to use

			.EXAMPLE
			PS C:\> Disable-RemoteDesktop -ComputerName 'DC01'

			Description
			-----------
			Disable RDP on Server 'DC01'

			.EXAMPLE
			PS C:\> Disable-RemoteDesktop -ComputerName DC01 -Credentials (Get-Credentials -cred "FX\SuperAdmin")

			Description
			-----------
			Disable RDP on Server 'DC01' and use the Domain (FX) Credentials
			for 'SuperAdmin', The password will be queried.

			.EXAMPLE
			PS C:\> Disable-RemoteDesktop -CimSession $Session

			Description
			-----------
			Disable RDP for the host where the CIM Session '$Session' is open.

			.EXAMPLE
			PS C:\> Disable-RemoteDesktop -CimSession $Session1,$session2,$session3

			Description
			-----------
			Disable RDP for the host where the CIM Sessions
			'$Session1,$session2,$session3' are open.

			.NOTES
			Based on an idea of Francois-Xavier Cat
	#>

	[CmdletBinding(DefaultParameterSetName = 'CimSession',
			ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ParameterSetName = 'Main',
				ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Specifies the computername')]
		[Alias('CN', '__SERVER', 'PSComputerName')]
		[String[]]$ComputerName = "$env:COMPUTERNAME",
		[Parameter(ParameterSetName = 'Main',
		HelpMessage = 'Specifies the credential to use')]
		[System.Management.Automation.Credential()]
		[Alias('RunAs')]
		[PSCredential]$Credentials = '[System.Management.Automation.PSCredential]::Empty',
		[Parameter(ParameterSetName = 'CimSession',
		HelpMessage = 'Specifies one or more existing CIM Session(s) to use')]
		[Microsoft.Management.Infrastructure.CimSession[]]$CimSession
	)

	PROCESS {
		if ($PSBoundParameters['CimSession']) {
			foreach ($Cim in $CimSession) {
				$CIMComputer = $($Cim.ComputerName).ToUpper()

				try {
					# Parameters for Get-CimInstance
					$CIMSplatting = @{
						Class         = 'Win32_TerminalServiceSetting'
						NameSpace     = 'root\cimv2\terminalservices'
						CimSession    = $Cim
						ErrorAction   = 'Stop'
						ErrorVariable = 'ErrorProcessGetCimInstance'
					}

					# Parameters for Invoke-CimMethod
					$CIMInvokeSplatting = @{
						MethodName    = 'SetAllowTSConnections'
						Arguments     = @{
							AllowTSConnections      = 0
							ModifyFirewallException = 0
						}
						ErrorAction   = 'Stop'
						ErrorVariable = 'ErrorProcessInvokeCim'
					}

					# Be verbose
					Write-Verbose -Message (Get-DefaultMessage -Message "$CIMComputer - CIMSession - disable Remote Desktop (and Modify Firewall Exception")

					Get-CimInstance @CIMSplatting | Invoke-CimMethod @CIMInvokeSplatting
				} catch {
					Write-Warning -Message (Get-DefaultMessage -Message "$CIMComputer - CIMSession - Something wrong happened")

					if ($ErrorProcessGetCimInstance) {
						Write-Warning -Message (Get-DefaultMessage -Message "$CIMComputer - Issue with Get-CimInstance")
					}
					if ($ErrorProcessInvokeCim) {
						Write-Warning -Message (Get-DefaultMessage -Message "$CIMComputer - Issue with Invoke-CimMethod")
					}

					Write-Warning -Message $Error[0].Exception.Message
				} finally {
					$CIMSplatting.Clear()
					$CIMInvokeSplatting.Clear()
				}
			}
		}

		foreach ($Computer in $ComputerName) {
			# Set a variable with the computername all upper case
			Set-Variable -Name 'Computer' -Value $($Computer.ToUpper())

			try {
				# Be verbose
				Write-Verbose -Message (Get-DefaultMessage -Message "$Computer - Test-Connection")

				if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
					$Splatting = @{
						Class         = 'Win32_TerminalServiceSetting'
						NameSpace     = 'root\cimv2\terminalservices'
						ComputerName  = $Computer
						ErrorAction   = 'Stop'
						ErrorVariable = 'ErrorProcessGetWmi'
					}

					if ($PSBoundParameters['Credentials']) {
						$Splatting.credential = $Credentials
					}

					# Be verbose
					Write-Verbose -Message (Get-DefaultMessage -Message "$Computer - Get-WmiObject - disable Remote Desktop")

					# disable Remote Desktop
					[void](Get-WmiObject @Splatting).SetAllowTsConnections(0, 0)

					# Disable requirement that user must be authenticated
					#(Get-WmiObject -Class Win32_TSGeneralSetting @Splatting -Filter TerminalName='RDP-tcp').SetUserAuthenticationRequired(0)  Out-Null
				}
			} catch {
				Write-Warning -Message (Get-DefaultMessage -Message "$Computer - Something wrong happened")

				if ($ErrorProcessGetWmi) {
					Write-Warning -Message (Get-DefaultMessage -Message "$Computer - Issue with Get-WmiObject")
				}

				Write-Warning -Message $Error[0].Exception.Message
			} finally {
				$Splatting.Clear()
			}
		}
	}
}

function Enable-RemoteDesktop {
	<#
			.SYNOPSIS
			The function Enable-RemoteDesktop will enable RemoteDesktop on a
			local or remote machine.

			.DESCRIPTION
			The function Enable-RemoteDesktop will enable RemoteDesktop on a
			local or remote machine.

			.PARAMETER ComputerName
			Specifies the computername

			.PARAMETER Credentials
			Specifies the Credentials to use

			.PARAMETER CimSession
			Specifies one or more existing CIM Session(s) to use

			.EXAMPLE
			PS C:\> Enable-RemoteDesktop -ComputerName 'DC01'

			Description
			-----------
			Enables RDP on 'DC01'

			.EXAMPLE
			PS C:\> Enable-RemoteDesktop -ComputerName DC01 -Credentials (Get-Credentials -cred "FX\SuperAdmin")

			Description
			-----------
			Enables RDP on 'DC01' and use the Domain (FX) Credentials for
			'SuperAdmin', The password will be queried.

			.EXAMPLE
			PS C:\> Enable-RemoteDesktop -CimSession $Session

			Description
			-----------
			Enable RDP for the host where the CIM Session '$Session' is open.

			.EXAMPLE
			PS C:\> Enable-RemoteDesktop -CimSession $Session1,$session2,$session3

			Description
			-----------
			Enable RDP for the host where the CIM Sessions
			'$Session1,$session2,$session3' are open.

			.NOTES
			Based on an idea of Francois-Xavier Cat
	#>

	[CmdletBinding(DefaultParameterSetName = 'CimSession',
			ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ParameterSetName = 'Main',
				ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Specifies the computername')]
		[Alias('CN', '__SERVER', 'PSComputerName')]
		[String[]]$ComputerName = "$env:COMPUTERNAME",
		[Parameter(ParameterSetName = 'Main',
		HelpMessage = 'Specifies the credential to use')]
		[System.Management.Automation.Credential()]
		[Alias('RunAs')]
		[pscredential]$Credentials = '[System.Management.Automation.PSCredential]::Empty',
		[Parameter(ParameterSetName = 'CimSession',
		HelpMessage = 'Specifies one or more existing CIM Session(s) to use')]
		[Microsoft.Management.Infrastructure.CimSession[]]$CimSession
	)

	PROCESS {
		if ($PSBoundParameters['CimSession']) {
			foreach ($Cim in $CimSession) {
				# Create a Variable with an all upper case computer name
				Set-Variable -Name 'CIMComputer' -Value $($($Cim.ComputerName).ToUpper())

				try {
					# Parameters for Get-CimInstance
					$CIMSplatting = @{
						Class         = 'Win32_TerminalServiceSetting'
						NameSpace     = 'root\cimv2\terminalservices'
						CimSession    = $Cim
						ErrorAction   = 'Stop'
						ErrorVariable = 'ErrorProcessGetCimInstance'
					}

					# Parameters for Invoke-CimMethod
					$CIMInvokeSplatting = @{
						MethodName    = 'SetAllowTSConnections'
						Arguments     = @{
							AllowTSConnections      = 1
							ModifyFirewallException = 1
						}
						ErrorAction   = 'Stop'
						ErrorVariable = 'ErrorProcessInvokeCim'
					}

					# Be verbose
					Write-Verbose -Message (Get-DefaultMessage -Message "$CIMComputer - CIMSession - Enable Remote Desktop (and Modify Firewall Exception")

					#
					Get-CimInstance @CIMSplatting | Invoke-CimMethod @CIMInvokeSplatting
				} CATCH {
					# Whoopsie!
					Write-Warning -Message (Get-DefaultMessage -Message "$CIMComputer - CIMSession - Something wrong happened")

					if ($ErrorProcessGetCimInstance) {
						Write-Warning -Message (Get-DefaultMessage -Message "$CIMComputer - Issue with Get-CimInstance")
					}

					if ($ErrorProcessInvokeCim) {
						Write-Warning -Message (Get-DefaultMessage -Message "$CIMComputer - Issue with Invoke-CimMethod")
					}

					Write-Warning -Message $Error[0].Exception.Message
				} FINALLY {
					# Cleanup
					$CIMSplatting.Clear()
					$CIMInvokeSplatting.Clear()
				}
			}
		}

		foreach ($Computer in $ComputerName) {
			# Creatre a Variable with the all upper case Computername
			Set-Variable -Name 'Computer' -Value $($Computer.ToUpper())

			try {
				Write-Verbose -Message (Get-DefaultMessage -Message "$Computer - Test-Connection")
				if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
					$Splatting = @{
						Class         = 'Win32_TerminalServiceSetting'
						NameSpace     = 'root\cimv2\terminalservices'
						ComputerName  = $Computer
						ErrorAction   = 'Stop'
						ErrorVariable = 'ErrorProcessGetWmi'
					}

					if ($PSBoundParameters['Credentials']) {
						$Splatting.credential = $Credentials
					}

					# Be verbose
					Write-Verbose -Message (Get-DefaultMessage -Message "$Computer - Get-WmiObject - Enable Remote Desktop")

					# Enable Remote Desktop
					$null = (Get-WmiObject @Splatting).SetAllowTsConnections(1, 1)

					# Disable requirement that user must be authenticated
					#(Get-WmiObject -Class Win32_TSGeneralSetting @Splatting -Filter TerminalName='RDP-tcp').SetUserAuthenticationRequired(0)  Out-Null
				}
			} catch {
				# Whoopsie!
				Write-Warning -Message (Get-DefaultMessage -Message "$Computer - Something wrong happened")

				if ($ErrorProcessGetWmi) {
					Write-Warning -Message (Get-DefaultMessage -Message "$Computer - Issue with Get-WmiObject")
				}

				Write-Warning -Message $Error[0].Exception.Message
			} finally {
				# Cleanup
				$Splatting.Clear()
			}
		}
	}
}

# Reload-Module
function Reload-Module {
	<#
			.SYNOPSIS
			Reloads one, or more, PowerShell Module(s)

			.DESCRIPTION
			This function forces an unload and then load the given PowerShell
			Module again.

			There is no build-in Re-Load function in PowerShell, at least yet!

			If you want to reload more then one Module at the time,
			just separate them by comma (Usual in PowerShell for multiple-values)

			.PARAMETER Module
			Name one, or more, PowerShell Module(s) to reload

			.NOTES
			Needs to be documented

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Name of the Module to reload')]
		[ValidateNotNullOrEmpty()]
		[Alias('ModuleName')]
		[System.String[]]$Module
	)

	PROCESS {
		foreach ($SingleModule in $Module) {
			#Check if the Module is loaded
			if (((Get-Module -Name $SingleModule -All | Measure-Object).count) -gt 0) {
				# Unload the Module
				(Remove-Module -Name $SingleModule -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

				# Make sure it is unloaded!
				(Remove-Module -Name $SingleModule -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1
			} else {
				Write-Warning "The Module $SingleModule was not loaded..."
			}

			if (((Get-Module -Name $SingleModule -ListAvailable | Measure-Object).count) -gt 0) {
				# Load the module
				try {
					(Import-Module -Name $SingleModule -DisableNameChecking -Force -Verbose:$false -ErrorAction:Stop -WarningAction:SilentlyContinue)
				} catch {
					Write-Warning "Unable to load $SingleModule"
				}
			} else {
				Write-Warning "Sorry, the Module $SingleModule was not found!"
			}
		}
	}
}

function Remove-ItemSafely {
	<#
			.SYNOPSIS
			Deletes files and folders into the Recycle Bin

			.DESCRIPTION
			Deletes the file or folder as if it had been done via File Explorer.

			.PARAMETER Path
			The path to the file/files or folder/folders

			.PARAMETER DeletePermanently
			Bypasses the recycle bin, deleting the file or folder permanently

			.NOTES
			Early Beta Version

			.LINK
			Based on http://stackoverflow.com/a/502034/2688

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'The path to the file or folder')]
		[System.String[]]$Path,
		[Parameter(HelpMessage = 'Bypasses the recycle bin, deleting the file or folder permanently')]
		[switch]$DeletePermanently
	)

	PROCESS {
		foreach ($SingleItem in $Path) {
			try {
				if ($DeletePermanently) {
					try {
						# Bypasses the recycle bin, deleting the file or folder permanently
						(Remove-Item -Path:$SingleItem -Force)
					} catch {
						Write-Warning "Unable to Delete $SingleItem, please check!"
					}

					# Done!
					return
				}

				# Soft Delete
				$item = (Get-Item $SingleItem)
				$directoryPath = (Split-Path $item -Parent)
				$shell = (New-Object -ComObject 'Shell.Application')
				$shellFolder = ($shell.Namespace($directoryPath))
				$shellItem = ($shellFolder.ParseName($item.Name))
				$shellItem.InvokeVerb('delete')
			} catch {
				Write-Warning "Unable to Delete $SingleItem, please check!"
			}
		}
	}
}

function Remove-TempFiles {
	<#
			.SYNOPSIS
			Removes all temp files older then a given time period

			.DESCRIPTION
			Removes all temp files older then a given time period from the system or the user environment.

			.PARAMETER Month
			Remove temp files older then X month.
			The default is 1

			.PARAMETER Context
			Remove the System or User Temp Files?
			The default is All.

			.EXAMPLE
			PS C:\> Remove-TempFiles -Confirm:$false

			TotalSize                     Retrieved                   TotalSizeMB                   RetrievedMB
			---------                     ---------                   -----------                   -----------
			518485778                     417617315                         494,5                         398,3

			Description
			-----------
			Removes all 'User' and 'System' temp file older then one month,
			without asking if you are sure! This could be dangerous...

			.EXAMPLE
			PS C:\> Remove-TempFiles -Confirm:$false
			WARNING: The process cannot access the file 'C:\Users\josh\AppData\Local\Temp\FXSAPIDebugLogFile.txt' because it is being used by another process. - Line Number: 96

			TotalSize                       Retrieved                     TotalSizeMB                     RetrievedMB
			---------                       ---------                     -----------                     -----------
			264147489                       214105710                           251,9                           204,2

			Description
			-----------
			Removes all 'User' and 'System' temp file older then one month,
			without asking if you are sure! This could be dangerous...

			One file is locked by another process! Just a warning will show up,
			the cleanup will continue.

			.EXAMPLE
			PS C:\> Remove-TempFiles -Month 3 -Context 'System'
			[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y")

			TotalSize                       Retrieved                     TotalSizeMB                     RetrievedMB
			---------                       ---------                     -----------                     -----------
			264147489                       214105710                           251,9                           204,2

			Description
			-----------
			Removes all 'System' temp files older then 3 month

			.EXAMPLE
			PS C:\> Remove-TempFiles -Month 3 -Context 'User'
			[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y")

			TotalSize                       Retrieved                     TotalSizeMB                     RetrievedMB
			---------                       ---------                     -----------                     -----------
			151519609                       145693231                           144,5                           138,9

			Description
			-----------
			Removes all 'User' temp files older then 3 month.

			.NOTES
			Adopted from a snippet found on Powershell.com

			.LINK
			Source http://powershell.com/cs/blogs/tips/archive/2016/05/27/cleaning-week-deleting-temp-files.aspx
	#>

	[CmdletBinding(ConfirmImpact = 'High',
	SupportsShouldProcess = $true)]
	[OutputType([System.Object])]
	param
	(
		[Parameter(Position = 1,
		HelpMessage = 'Remove temp files older then X month.')]
		[System.Int64]$Month = 1,
		[Parameter(ValueFromPipeline = $true,
				Position = 2,
		HelpMessage = 'Remove the System or User Temp Files?')]
		[ValidateSet('System', 'User', 'All', IgnoreCase = $true)]
		[System.String]$context = 'All'
	)

	#requires -Version 3
	#Requires -RunAsAdministrator

	BEGIN {
		# Look at temp files older than given period
		$cutoff = ((Get-Date).AddMonths(- $Month))

		# Use an ordered hash table to store logging info
		$sizes = [Ordered]@{ }
	}

	PROCESS {
		if ($context -eq 'System') {
			$Target = "$env:windir\temp"
		} elseif ($context -eq 'User') {
			$Target = "$env:temp"
		} elseif ($context -eq 'All') {
			$Target = "$env:windir\temp", $env:temp
		} else {
			Write-Error -Message "I have no idea what to clean: $($Target)" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the hard way...
			exit 1
		}

		if ($pscmdlet.ShouldProcess("$($context)", "Remove Temp file older then $($Month)")) {
			<#
					Mind the Pipes. All in a very long command :-)
			#>
			# Find all files in both temp folders recursively
			Get-ChildItem $Target -Recurse -Force -File |
			# calculate total size before cleanup
			ForEach-Object {
				$sizes['TotalSize'] += $_.Length
				$_
			} |
			# take only outdated files
			Where-Object { $_.LastWriteTime -lt $cutoff } |
			# Try to delete. Add retrieved file size only if the file could be deleted
			ForEach-Object {
				try {
					$fileSize = ($_.Length)

					Remove-Item -Path $_.FullName -Force -Confirm:$false -ErrorAction Stop -WarningAction SilentlyContinue

					$sizes['Retrieved'] += $fileSize
				} catch [System.Exception] {
					Write-Warning "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
				} catch {
					# Did not see this one coming!
					Write-Warning "Unable to remove $($_.FullName)"
				}
			}
		}
	}

	END {
		# Turn bytes into MB
		$sizes['TotalSizeMB'] = [Math]::Round(($sizes['TotalSize']/1MB), 1)
		$sizes['RetrievedMB'] = [Math]::Round(($sizes['Retrieved']/1MB), 1)

		# Dump the info
		New-Object -TypeName PSObject -Property $sizes
	}
}

function Repair-DotNetFrameWorks {
	<#
			.SYNOPSIS
			Optimize all installed NET Frameworks

			.DESCRIPTION
			Optimize all installed NET Frameworks by executing NGEN.EXE for each.

			This could be useful to improve the performance and sometimes the
			installation of new NET Frameworks, or even patches, makes them use
			a single (the first) core only.

			Why Microsoft does not execute the NGEN.EXE with each installation...

			no idea!

			.EXAMPLE
			PS C:\> Repair-DotNetFrameWorks
			C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe executeQueuedItems
			C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe executeQueuedItems

			Description
			-----------
			Optimize all installed NET Frameworks

			.NOTES
			The Function name is changed!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		# Cleanup
		Remove-Variable frameworks -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Get all NET framework paths and build an array with it
		$frameworks = @("$env:SystemRoot\Microsoft.NET\Framework")

		# If we run on an 64Bit system (what we should), we add these frameworks to
		If (Test-Path "$env:SystemRoot\Microsoft.NET\Framework64") {
			# Add the 64Bit Path to the array
			$frameworks += "$env:SystemRoot\Microsoft.NET\Framework64"
		}

		# Loop over all NET frameworks that we found.
		ForEach ($framework in $frameworks) {
			# Find the latest version of NGEN.EXE in the current framework path
			$ngen_path = Join-Path (Join-Path $framework -ChildPath (Get-ChildItem $framework |
					Where-Object { ($_.PSIsContainer) -and (Test-Path (Join-Path $_.FullName -ChildPath 'ngen.exe')) } |
					Sort-Object Name -Descending |
			Select-Object -First 1).Name) -ChildPath 'ngen.exe'

			# Execute the optimization command and suppress the output, we also prevent a new window
			Write-Output "$ngen_path executeQueuedItems"
			Start-Process $ngen_path -ArgumentList 'executeQueuedItems' -NoNewWindow -Wait -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue -LoadUserProfile:$false -RedirectStandardOutput null
		}
	}

	END {
		# Cleanup
		Remove-Variable frameworks -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Reset-Prompt {
	<#
			.SYNOPSIS
			Restore the Default Prompt

			.DESCRIPTION
			Restore the Default Prompt

			.EXAMPLE
			Josh@fra1w7vm01 /scripts/PowerShell/functions $ Reset-Prompt
			PS C:\scripts\PowerShell\functions>

			Description
			-----------
			If you modified the prompt before, this command restores the
			PowerShell default for you

			.NOTES
			Just a quick helper!

			Reset the prompt and the window title back to the defaults

			.LINK
			Set-LinuxPrompt
			Set-PowerPrompt

			.LINK
			Set-DefaultPrompt
			Set-ServicePrompt
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		if ($pscmdlet.ShouldProcess('Prompt', 'Restore the default')) {
			function Prompt {
				<#
						.SYNOPSIS
						Set a default prompt

						.DESCRIPTION
						Set a default prompt

						.EXAMPLE
						PS C:\> prompt

						# Set a default prompt
				#>

				# Create a default prompt
				Write-Host ('PS ' + (Get-Location) + '> ')

				# Blank
				Return ' '
			}

			<#
					Also Reset the Window Title
			#>
			# Are we elevated or administrator?
			if ((New-Object Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
				# Administrator Session!
				$Host.ui.RawUI.WindowTitle = 'Administrator: Windows PowerShell'
			} else {
				# User Session!
				$Host.ui.RawUI.WindowTitle = 'Windows PowerShell'
			}
		}
	}

	END {
		if ($pscmdlet.ShouldProcess('Prompt', 'Restore the default')) {
			# Execute!
			Prompt
		}
	}
}

function Get-EncryptSecretText {
	<#
			.SYNOPSIS
			Encrypts a given string with a given certificate

			.DESCRIPTION
			Sometimes you might need to transfer a password (or another secret)
			via Mail (or any other insecure media) here a strong encryption is
			very handy.
			Get-EncryptSecretText uses a given Certificate to encrypt a given String

			.PARAMETER CertificatePath
			Path to the certificate that you would like to use

			.PARAMETER plaintext
			Plain text string that you would like to encrypt with the certificate

			.EXAMPLE
			PS C:\> Get-EncryptSecretText -CertificatePath "Cert:\CurrentUser\My\XYZ" -PlainText "My Secret Text"
			MIIB9QYJKoZIhvcNAQcDoIIB5jCCAeICAQAxggGuMIIBqgIBADCBkTB9MQswCQYDVQQGEwJHQjEbnBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8
			gQ0EgTGltaXRlZDEjMCEGA1UEAxMaQ09NT0RPIFJTQSBDb2RlIFNpZ25pbmcgQ0ECEBbU91MdmxgnT/ImczrRgFwwDQYJKoZIhvcNAQEBBQAEggEAi5M7w7k/siGdGiYW8z8izVUNfI15HaHqHJs/t3VIZkgfSc
			GAKUpZjwJW7xMZHoKppw0eL/mUZr4823M276swiktXnpRbol8g8Kqvy2c7dUx2lNJm/+s8YLG0rsK70EhSPzAEbNtFAqlWj5ETnskTlfuEiJdB2tFjC42oweWKRokQ0exyztY1sN7V7vImkMtCS7JHeJF23SyNv
			PbFw0hE0QtiKVdu8DESO2CB9H1bVYIxVWTvpvT71yDQCFFOwg0JdGJpCI6l+YxPqHqKhFcdWZtuP8JMvNZ8UbxveNVmBOrasM5ZTHfHljWIT6V6tDxy5jOd9cTiuayh/X1A2eKA/DArBgkqhkiG9w0BBwEwFAYI
			KoZIhvcNAwcECFjYhWLX5qsEgAgjq1toxGP5GQ==

			Description
			-----------
			In this example the Certificate with the Fingerprint "XYZ" from the
			certificate store of the user is used.

			.LINK
			Get-DecryptSecretText

			.NOTES
			You need Get-DecryptSecretText to make it human readable again

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Path to the certificate that you would like to use')]
		[ValidateNotNullOrEmpty()]
		[System.String]$CertificatePath,
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Plain text string that you would like to encyt with the certificate')]
		[ValidateNotNullOrEmpty()]
		[System.String]$PlainText
	)

	BEGIN {
		[void][System.Reflection.Assembly]::LoadWithPartialName('System.Security') > $null 2>&1 3>&1
	}

	PROCESS {
		#Get the certificate
		Set-Variable -Name 'Certificate' -Value $(Get-Item $CertificatePath)

		# GetBytes .NET
		Set-Variable -Name 'ContentInfo' -Value $(New-Object Security.Cryptography.Pkcs.ContentInfo -ArgumentList ( , [Text.Encoding]::Unicode.GetBytes($PlainText)))

		# Set the secured envelope infos
		Set-Variable -Name 'SecureEnvelope' -Value $(New-Object Security.Cryptography.Pkcs.EnvelopedCms -ArgumentList $ContentInfo)
		$SecureEnvelope.Encrypt((New-Object System.Security.Cryptography.Pkcs.CmsRecipient -ArgumentList ($Certificate)))

		# And here is the secured string
		Set-Variable -Name 'SecretText' -Value $([Convert]::ToBase64String($SecureEnvelope.Encode()))
	}

	END {
		# Dump it
		Write-Output $SecretText
	}
}

function Get-DecryptSecretText {
	<#
			.SYNOPSIS
			Decrypts a given String, encrypted by Get-EncryptSecretText

			.DESCRIPTION
			Get-DecryptSecretText makes a string encrypted by Get-EncryptSecretText
			decrypts it to and human readable again.

			.PARAMETER EncryptedText
			The encrypted test string

			.EXAMPLE
			PS C:\> $Foo = (Get-EncryptSecretText -CertificatePath "Cert:\CurrentUser\My\XYZ" -PlainText "My Secret Text")
			PS C:\> Get-DecrypSecretText -EncryptedText $Foo
			My Secret Text

			Description
			-----------
			Get-DecryptSecretText makes a string encrypted by Get-EncryptSecretText
			human readable again.
			In this example the Certificate with the Fingerprint "XYZ" from the
			certificate store of the user is used.

			.NOTES
			You need the certificate that was used with Get-EncryptSecretText to
			encrypt the string

			.LINK
			Get-EncryptSecretText

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'The encrypted test string')]
		[ValidateNotNullOrEmpty()]
		[System.String]$EncryptedText
	)

	BEGIN {
		[void][System.Reflection.Assembly]::LoadWithPartialName('System.Security') > $null 2>&1 3>&1
	}

	PROCESS {
		# Decode the Base64 encoded string back
		Set-Variable -Name 'SecretText' -Value $([Convert]::FromBase64String($EncryptedText))

		# the secured envelope infos
		Set-Variable -Name 'SecureEnvelope' -Value $(New-Object Security.Cryptography.Pkcs.EnvelopedCms)
		$SecureEnvelope.Decode($SecretText)
		$SecureEnvelope.Decrypt()

		# And here is the human readable string again!
		Set-Variable -Name 'UnicodeContent' -Value $([text.encoding]::Unicode.GetString($SecureEnvelope.ContentInfo.Content))
	}

	END {
		# Dump it
		Write-Output $UnicodeContent
	}
}

function Send-HipChat {
	<#
			.SYNOPSIS
			Send a notification message to a HipChat room.

			.DESCRIPTION
			Send a notification message to a HipChat room via a RESTful Call to
			the HipChat API V2 Atlassian requires a separate token for each room
			within HipChat!

			So please note, that the Room and the Token parameter must match.

			.PARAMETER Token
			HipChat Auth Token

			.PARAMETER Room
			HipChat Room Name that get the notification.
			The Token has to fit to the Room!

			.PARAMETER notify
			Whether this message should trigger a user notification
			(change the tab color, play a sound, notify mobile phones, etc).
			Each recipient's notification preferences are taken into account.

			.PARAMETER color
			Background color for message.

			Valid is
			- yellow
			- green
			- red
			- purple
			- gray
			-random

			.PARAMETER Message
			The message body itself. Please see the HipChat API V2 documentation

			.PARAMETER Format
			Determines how the message is treated by our server and rendered
			inside HipChat applications

			.EXAMPLE
			PS C:\> Send-HipChat -Message "This is just a BuildServer Test" -color "gray" -Room "Testing" -notify $true

			Description
			-----------
			Sent a HipChat Room notification "This is just a BuildServer Test" to
			the Room "Testing".
			It uses the Color "gray", and it sends a notification to all users
			in the room.
			It uses a default Token to do so!

			.EXAMPLE
			PS C:\> Send-HipChat -Message "Hello @JoergHochwald" -color "Red" -Room "DevOps" -Token "1234567890" -notify $false

			Description
			-----------
			Sent a HipChat Room notification "Hello @JoergHochwald" to the
			Room "DevOps".
			The @ indicates a user mention, this is supported like in a regular
			chat from user 2 User.
			It uses the Color "red", and it sends no notification to users in
			the room.
			It uses a Token "1234567890" to do so! The Token must match the Room!

			.NOTES
			We use the API V2 now ;-)

			.LINK
			API: https://www.hipchat.com/docs/apiv2

			.LINK
			Docs: https://www.hipchat.com/docs/apiv2/method/send_room_notification

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(HelpMessage = 'HipChat Auth Token')]
		[Alias('AUTH_TOKEN')]
		[System.String]$token = '8EWA77eidxEJG5IFluWjD9794ft8WSzfKhjBCKpv',
		[Parameter(HelpMessage = 'HipChat Room Name that get the notification')]
		[Alias('ROOM_ID')]
		[System.String]$Room = 'Testing',
		[Parameter(HelpMessage = 'Whether this message should trigger a user notification.')]
		[boolean]$notify = $false,
		[Parameter(HelpMessage = 'Background color for message.')]
		[ValidateSet('yellow', 'green', 'red', 'purple', 'gray', 'random', IgnoreCase = $true)]
		[System.String]$color = 'gray',
		[Parameter(HelpMessage = 'The message body')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Message,
		[Parameter(HelpMessage = 'Determines how the message is treated by our server and rendered inside HipChat applications')]
		[ValidateSet('html', 'text', IgnoreCase = $true)]
		[Alias('message_format')]
		[System.String]$Format = 'text'
	)

	BEGIN {
		# Cleanup all variables...
		Remove-Variable -Name 'headers' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'myMethod' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'post' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Set the Header Variable
		Set-Variable -Name 'headers' -Value $(@{
				'Authorization' = "Bearer $($token)"
				'Content-type' = 'application/json'
		})

		# Make the content of the Variable all lower case
		$color = $color.ToLower()
		$Format = $Format.ToLower()

		# Set the Body Variable, will be converted to JSON then
		Set-Variable -Name 'body' -Value $(@{
				'color'        = "$color"
				'message_format' = "$Format"
				'message'      = "$Message"
				'notify'       = "$notify"
		})

		# Convert the Body Variable to JSON Check if the Server understands Compression, could reduce bandwidth
		# Be careful with the Depth Parameter, bigger values means less performance
		Set-Variable -Name 'myBody' -Value $(ConvertTo-Json $body -Depth 2 -Compress:$false)

		# Set the URI Variable based on the Atlassian HipChat API V2 documentation
		Set-Variable -Name 'uri' -Value $('https://api.hipchat.com/v2/room/' + $Room + '/notification')

		# Method to use for the RESTful Call
		Set-Variable -Name 'myMethod' -Value $('POST' -as ([System.String] -as [type]))

		# Use the API via RESTful call
		try {
			# We fake the User Agent here!
			(Invoke-RestMethod -Uri $uri -Method $myMethod -Headers $headers -Body $myBody -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts WindowsPowerShell Service $CoreVersion" -ErrorAction:Stop -WarningAction:SilentlyContinue)
		} catch [System.Exception] {
			<#
					Argh! Catched an Exception...
			#>

			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		} catch {
			# Whoopsie!
			# That should not happen...
			Write-Warning -Message "Could not send notification to your HipChat Room $Room"
			<#
					I use Send-HipChat a lot within automated tasks.
					I post updates from my build server and info from customers Mobile Device Management systems.
					So I decided to use a warning instead of an error here.

					You might want to change this to fit you needs.

					Remember: If you throw an terminating error, you might want to add a "finally" block to this try/catch Block here.
			#>
		} finally {
			# Cleanup all variables...
			Remove-Variable -Name 'headers' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'myMethod' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'post' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Send-Packet {
	<#
			.SYNOPSIS
			Send a packet via IP, TCP or UDP

			.DESCRIPTION
			Send a packet via IP, TCP or UDP
			Found this useful to test firewall configurations and routing.
			Or even to test some services.

			.PARAMETER Target
			Target name or IP

			.PARAMETER Protocol
			protocol to use, default is IP

			.PARAMETER TargetPort
			Target Port (against the target)

			.PARAMETER SourcePort
			Fake Source port (Default is random)

			.PARAMETER Ttl
			The Time To Life (Default is 128)

			.PARAMETER Count
			The count, how many packets? (Default is one)

			.EXAMPLE
			PS C:\> Send-Packet -Target '10.10.16.29' -Protocol 'TCP' -TargetPort '4711'

			Description
			-----------
			Send a 'TCP' packet on port '4711' to target '10.10.16.29'

			.EXAMPLE
			PS C:\> Send-Packet -Target '10.10.16.29' -Protocol 'UDP' -TargetPort '4711' -Count '10'

			Description
			-----------
			Send 10 'UDP' packets on port '4711' to target '10.10.16.29'

			.EXAMPLE
			PS C:\> Send-Packet -Target '10.10.16.29' -Protocol 'TCP' -TargetPort '4711' -SourcePort '14712'

			Description
			-----------
			Send a 'TCP' packet on port '4711' to target '10.10.16.29' and it
			uses a fake source port '14712'
			This could be useful for port knocking or to check Firewall behaviors

			.NOTES
			Based on an idea of JohnLaska

			.LINK
			Source: https://github.com/JohnLaska/PowerShell/blob/master/Send-Packet.ps1
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Target name or IP')]
		[System.String]$Target,
		[Parameter(Position = 1,
		HelpMessage = 'protocol to use, default is IP')]
		[ValidateSet('IP', 'TCP', 'UDP')]
		[System.String]$Protocol = 'IP',
		[Parameter(Mandatory = $true,
				Position = 2,
		HelpMessage = 'Target Port (against the target)')]
		[ValidateRange(0, 65535)]
		[System.Int32]$TargetPort,
		[Parameter(Position = 3,
		HelpMessage = 'Fake Source port (Default is random)')]
		[ValidateRange(0, 65535)]
		[System.Int32]$SourcePort = (Get-Random -Minimum 0 -Maximum 65535),
		[Parameter(Position = 4,
		HelpMessage = 'The Time To Life (Default is 128)')]
		[System.Int32]$TTL = 128,
		[Parameter(Position = 5,
		HelpMessage = 'The count, how many packets? (Default is one)')]
		[System.Int32]$count = 1
	)

	PROCESS {
		$packet = New-Object System.Net.Sockets.Socket -ArgumentList (
			[System.Net.Sockets.AddressFamily]::InterNetwork,
			[System.Net.Sockets.SocketType]::Raw,
			[System.Net.Sockets.ProtocolType]::$Protocol
		)

		$packet.Ttl = ($TTL)
	}
}

function Send-Prowl {
	<#
			.SYNOPSIS
			Prowl is the Growl client for iOS.

			.DESCRIPTION
			Prowl is the Growl client for iOS. Push to your iPhone, iPod touch,
			or iPad notifications from a Mac or Windows computer,
			or from a multitude of apps and services.
			Easily integrate the Prowl API into your applications.

			.PARAMETER Event
			The Text of the Prowl Message

			.PARAMETER Description
			Description of the Prowl Message

			.PARAMETER ApplicationName
			Name your Application, e.g. BuildBot. Default is PowerShell

			.PARAMETER Priority
			Priority of the Prowl Message (0, 1,2), default is 0

			.PARAMETER url
			URL you would like to attach to the Prowl Message

			.PARAMETER apiKey
			Prowl API Key (Required)

			.EXAMPLE
			Send-Prowl -apiKey "1234567890" -Event "Hello World!"

			Description
			-----------
			Send the Prowl message "Hello World!"

			.EXAMPLE
			Send-Prowl -apiKey "1234567890" -Event "Call the Helpdesk!" -Priority "2" -Description "Call the Helpdesk, we need your feedback!!!" -url "tel:1234567890"

			Description
			-----------
			Send Prowl event "Call the Helpdesk!" with priority 2 and the
			description "Call the Helpdesk, we need your feedback!!!".

			It attaches the URL "tel:1234567890"

			.EXAMPLE
			Send-Prowl -apiKey "1234567890" -Event "Your Ticket is updated" -Priority 1 -Description "The Helpdesk Team updated your ticket!" -url "http://support.NET-Experts.net/"

			Description
			-----------
			Send Prowl event "Your Ticket is updated" with priority 2 and the
			description "The Helpdesk Team updated your ticket!".

			It attaches the URL "http://support.NET-Experts.net/"

			.NOTES
			Additional information about the function.

			.LINK
			Info: http://www.prowlapp.com

			.LINK
			API: http://www.prowlapp.com/api.php

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(Mandatory = $true,
		HelpMessage = 'The Text of the Prowl Message')]
		[ValidateNotNullOrEmpty()]
		[ValidateLength(1, 1024)]
		[System.String]$Event,
		[Parameter(HelpMessage = 'Description of the Prowl Message')]
		[ValidateLength(0, 10000)]
		[System.String]$Description = '',
		[Parameter(HelpMessage = 'Name your Application, e.g. BuildBot')]
		[ValidateLength(1, 256)]
		[System.String]$ApplicationName = 'PowerShell',
		[Parameter(HelpMessage = 'Priority of the Prowl Message (0, 1,2), defaul is 0')]
		[ValidateRange(1, 2)]
		[System.Int32]$priority = 0,
		[Parameter(HelpMessage = 'URL you would like to attach to the Prowl Message')]
		[ValidateLength(0, 512)]
		[System.String]$url,
		[Parameter(Mandatory = $true,
		HelpMessage = 'Prowl API Key (Required)')]
		[ValidateScript({ $_.Length -ge 40 })]
		[System.String]$apiKey
	)

	BEGIN {
		# URL-encode some strings
		$null = [Reflection.Assembly]::LoadWithPartialName('System.Web')
		$Event = [web.httputility]::urlencode($Event.Trim())
		$Description = [web.httputility]::urlencode($Description.Trim())
		$ApplicationName = [web.httputility]::urlencode($ApplicationName.Trim())
		$url = [web.httputility]::urlencode($url.Trim())

		# Compose the complete URL
		$apiBaseUrl = 'https://prowl.weks.net/publicapi/add'
		$ProwlUrl = "$($apiBaseUrl)?apikey=$($apiKey)&application=$($ApplicationName)&event=$($Event)&Description=$($Description)&priority=$($priority)&url=$($url)"

		# Be Verbose
		Write-Verbose "Complete URL: $($ProwlUrl)"
	}

	PROCESS {
		# Try to send message
		try {
			# Fire it up!
			$webReturn = ([System.String] (New-Object Net.WebClient).DownloadString($ProwlUrl))
		} catch {
			# Be Verbose
			Write-Verbose "Error sending Prowl Message: $($Error[0])"

			Return $false
		}

		# Output what comes back from the API
		Write-Verbose $webReturn

		If (([xml]$webReturn).prowl.success.code -eq 200) {
			# Be Verbose
			Write-Verbose 'Prowl message sent OK'

			Return $true
		} else {
			# Be Verbose
			Write-Verbose "Error sending Prowl Message: $((1$webReturn).prowl.error.code) - $((1$webReturn).prowl.error.innerXml)"

			Return $false
		}
	}
}

function Send-SlackChat {
	<#
			.SYNOPSIS
			Sends a chat message to a Slack organization

			.DESCRIPTION
			The Post-ToSlack cmdlet is used to send a chat message to a Slack
			channel, group, or person.

			Slack requires a token to authenticate to an organization within Slack.

			.PARAMETER Channel
			Slack Channel to post to

			.PARAMETER Message
			Chat message to post

			.PARAMETER token
			Slack API token

			.PARAMETER BotName
			Optional name for the bot

			.EXAMPLE
			PS C:\> Send-SlackChat -channel '#general' -message 'Hello everyone!' -botname 'The Borg' -token '1234567890'

			Description
			-----------
			This will send a message to the "#General" channel using a specific
			token 1234567890, and the bot's name will be "The Borg".

			.EXAMPLE
			PS C:\> Send-SlackChat -channel '#general' -message 'Hello everyone!' -token '1234567890'

			Description
			-----------
			This will send a message to the "#General" channel using a specific t
			oken 1234567890, and the bot's name will be default ("Build Bot").

			.NOTES
			Based on an idea of @ChrisWahl
			Please note the Name change and the removal of some functions

			.LINK
			Info: https://api.slack.com/tokens

			.LINK
			API: https://api.slack.com/web

			.LINK
			Info: https://api.slack.com/bot-users

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'Slack Channel to post to')]
		[ValidateNotNullOrEmpty()]
		[System.String]$channel,
		[Parameter(Mandatory = $true,
				Position = 1,
		HelpMessage = 'Chat message to post')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Message,
		[Parameter(Position = 2,
		HelpMessage = 'Slack API token')]
		[ValidateNotNullOrEmpty()]
		[System.String]$token,
		[Parameter(Position = 3,
		HelpMessage = 'Optional name for the bot')]
		[Alias('Name')]
		[System.String]$BotName = 'Build Bot'
	)

	BEGIN {
		# Cleanup all variables...
		Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		Set-Variable -Name 'uri' -Value $('https://slack.com/api/chat.postMessage')

		# Build the body as per https://api.slack.com/methods/chat.postMessage
		# We convert this to JSON then...
		Set-Variable -Name 'body' -Value $(@{
				token    = $token
				channel  = $channel
				text     = $Message
				username = $BotName
				parse    = 'full'
		})

		# Convert the Body Variable to JSON Check if the Server understands Compression,
		# could reduce bandwidth Be careful with the Depth Parameter, bigger values means less performance
		Set-Variable -Name 'myBody' -Value $(ConvertTo-Json $body -Depth 2 -Compress:$false)

		# Method to use for the RESTful Call
		Set-Variable -Name 'myMethod' -Value $('POST' -as ([System.String] -as [type]))

		# Use the API via RESTful call
		try {
			(Invoke-RestMethod -Uri $uri -Method $myMethod -Body $body -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts WindowsPowerShell Service $CoreVersion" -ErrorAction:Stop -WarningAction:SilentlyContinue)
		} catch [System.Exception] {
			<#
					Argh!
					That was an Exception...
			#>

			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		} catch {
			# Whoopsie!
			# That should not happen...
			Write-Warning -Message "Could not send notification to your Slack $channel"
		} finally {
			# Cleanup all variables...
			Remove-Variable -Name 'uri' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'body' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			Remove-Variable -Name 'myBody' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Set-AcceptProtocolViolation {
	<#
			.SYNOPSIS
			Workaround for servers with SSL header problems

			.DESCRIPTION
			Workaround for the following Exception "DownloadString" with "1"
			argument(s):
			"The underlying connection was closed: Could not establish trust
			relationship for the SSL/TLS secure channel."

			.EXAMPLE
			PS C:\> Set-AcceptProtocolViolation

			Description
			-----------
			Establish the workaround (Be careful)

			.NOTES
			Be careful:
			This is just a workaround for servers that have a problem with
			SSL headers.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param ()

	PROCESS {
		# Set the SSL Header unsafe parser based on the value from the configuration
		if ($AcceptProtocolViolation) {
			# Be Verbose
			Write-Verbose -Message:'Set the SSL Header unsafe parser based on the value from the configuration'

			# Read the existing settings to a variable
			Set-Variable -Name 'netAssembly' -Value $([Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection]))

			# Check if we have something within the Variable
			if ($netAssembly) {
				# Set some new values
				Set-Variable -Name 'bindingFlags' -Value $([Reflection.BindingFlags] 'Static,GetProperty,NonPublic')
				Set-Variable -Name 'settingsType' -Value $($netAssembly.GetType('System.Net.Configuration.SettingsSectionInternal'))
				Set-Variable -Name 'instance' -Value $($settingsType.InvokeMember('Section', $bindingFlags, $null, $null, @()))

				# Check for the Instance variable
				if ($instance) {
					# Change the values if they exist
					$bindingFlags = 'NonPublic', 'Instance'
					Set-Variable -Name 'useUnsafeHeaderParsingField' -Value $($settingsType.GetField('useUnsafeHeaderParsing', $bindingFlags))

					# Check for the unsafe HEader Variable
					if ($useUnsafeHeaderParsingField) {
						# Looks like the variable exists, set the value...
						$useUnsafeHeaderParsingField.SetValue($instance, $true)
					}
				}
			}
		}
	}
}

function Set-Culture {
	<#
			.SYNOPSIS
			Set the PowerShell culture to a given culture

			.DESCRIPTION
			Set the PowerShell culture to a given culture

			.PARAMETER culture
			Culture to use

			.EXAMPLE
			PS C:\> Set-Culture -culture "en-US" | ConvertFrom-UnixDate -Date 1458205878
			Thursday, March 17, 2016 9:11:18 AM

			Description
			-----------
			Returns the date in the given culture (en-US) format instead of
			the system culture.

			.NOTES
			Inspired by Use-Culture.ps1 by Lee Holmes

			.LINK
			Use-Culture http://poshcode.org/2226
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Culture to use')]
		[ValidateNotNullOrEmpty()]
		[System.Globalization.CultureInfo]$culture = 'en-US'
	)

	PROCESS {
		$OldCulture = [System.Threading.Thread]::CurrentThread.CurrentUICulture

		[System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
		[System.Threading.Thread]::CurrentThread.CurrentCulture = $culture

		$TheCulture = [System.Threading.Thread]::CurrentThread.CurrentUICulture
	}

	END {
		# Be Verbose
		Write-Verbose -Message "Old: $OldCulture"
		Write-Verbose -Message "New: $TheCulture"
	}
}

function Set-DebugOn {
	<#
			.SYNOPSIS
			Turn Debug on

			.DESCRIPTION
			Turn Debug on

			.NOTES
			Just an internal function to make our life easier!

			.EXAMPLE
			PS C:\> Set-DebugOn

			Description
			-----------
			Turn Debug on

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		Set-Variable -Name DebugPreference -Scope:Global -Value:'Continue' -Option AllScope -Visibility Public -Confirm:$false
		Set-Variable -Name NETXDebug -Scope:Global -Value:"$true" -Option AllScope -Visibility Public -Confirm:$false
	}

	END {
		Write-Output 'Debug enabled'
	}
}

function Set-DebugOff {
	<#
			.SYNOPSIS
			Turn Debug off

			.DESCRIPTION
			Turn Debug off

			.NOTES
			Just an internal function to make our life easier!

			.EXAMPLE
			PS C:\> Set-DebugOff

			Description
			-----------
			Turn Debug off
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		Set-Variable -Name DebugPreference -Scope:Global -Value:'SilentlyContinue' -Option AllScope -Visibility Public -Confirm:$false
		Set-Variable -Name NETXDebug -Scope:Global -Value:"$false" -Option AllScope -Visibility Public -Confirm:$false
	}

	END {
		Write-Output 'Debug disabled'
	}
}

function Set-Encoding {
	<#
			.SYNOPSIS
			Converts Encoding of text files

			.DESCRIPTION
			Allows you to change the encoding of files and folders.
			It supports file extension agnostic

			Please note: Overwrites original file if destination equals the path

			.PARAMETER path
			Folder or file to convert

			.PARAMETER dest
			If you want so save the newly encoded file/files to a new location

			.PARAMETER encoding
			Encoding method to use for the Patch or File

			.EXAMPLE
			PS C:\> Set-Encoding -path "c:\windows\temps\folder1" -encoding "UTF8"

			Description
			-----------
			Converts all Files in the Folder c:\windows\temps\folder1 in the UTF8 format

			.EXAMPLE
			PS C:\> Set-Encoding -path "c:\windows\temps\folder1" -dest "c:\windows\temps\folder2" -encoding "UTF8"

			Description
			-----------
			Converts all Files in the Folder c:\windows\temps\folder1 in the UTF8
			format and save them to c:\windows\temps\folder2

			.EXAMPLE
			PS C:\> (Get-Content -path "c:\temp\test.txt") | Set-Content -Encoding UTF8 -Path "c:\temp\test.txt"

			Description
			-----------
			This converts a single File via hardcore PowerShell without a Script.
			Might be useful if you want to convert this script after a transfer!

			.NOTES
			BETA!!!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('PathName')]
		[System.String]$Path,
		[Alias('Destination')]
		[System.String]$dest = $Path,
		[Parameter(Mandatory = $true)]
		[Alias('enc')]
		[System.String]$encoding
	)

	BEGIN {
		# ensure it is a valid path
		if (-not (Test-Path -Path $Path)) {
			# Aw, Snap!
			throw 'File or directory not found at {0}' -f $Path
		}
	}

	PROCESS {
		# if the path is a file, else a directory
		if (Test-Path $Path -PathType Leaf) {
			# if the provided path equals the destination
			if ($Path -eq $dest) {
				# get file extension
				Set-Variable -Name ext -Value $([System.IO.Path]::GetExtension($Path))

				#create destination
				Set-Variable -Name dest -Value $($Path.Replace([System.IO.Path]::GetFileName($Path), ('temp_encoded{0}' -f $ext)))

				# output to file with encoding
				Get-Content $Path | Out-File -FilePath $dest -Encoding $encoding -Force

				# copy item to original path to overwrite (note move-item loses encoding)
				Copy-Item -Path $dest -Destination $Path -Force -PassThru | ForEach-Object { Write-Output -InputObject ('{0} encoded {1}' -f $encoding, $_) }

				# remove the extra file
				Remove-Item $dest -Force -Confirm:$false
			} else {
				# output to file with encoding
				Get-Content $Path | Out-File -FilePath $dest -Encoding $encoding -Force
			}

		} else {
			# get all the files recursively
			foreach ($i in Get-ChildItem -Path $Path -Recurse) {
				if ($i.PSIsContainer) {
					continue
				}

				# get file extension
				Set-Variable -Name ext -Value $([System.IO.Path]::GetExtension($i))

				# create destination
				Set-Variable -Name dest -Value $("$Path\temp_encoded{0}" -f $ext)

				# output to file with encoding
				Get-Content $i.FullName | Out-File -FilePath $dest -Encoding $encoding -Force

				# copy item to original path to overwrite (note move-item loses encoding)
				Copy-Item -Path $dest -Destination $i.FullName -Force -PassThru | ForEach-Object { Write-Output -InputObject ('{0} encoded {1}' -f $encoding, $_) }

				# remove the extra file
				Remove-Item $dest -Force -Confirm:$false
			}
		}
	}
}

function Set-FolderDate {
	<#
			.SYNOPSIS
			Change one folder, or more, last-write time based on the latest
			last-write of the included files

			.DESCRIPTION
			Change one folder, or more, folder last-write time based on the
			latest last-write of the included files
			Makes windows a lot more Uni* like and have some Convenience.

			.PARAMETER Path
			One folder, or more, you would like to update

			Default is C:\scripts\PowerShell\log

			.EXAMPLE
			Set-FolderDate -Path "D:\temp"

			Description
			-----------
			Change "D:\temp" last-write time based on the latest last-write
			of the included files

			.NOTES
			We intercept all Errors! This is the part in the "BEGIN" block.
			You might want to change that to a warning...

			We use this function in bulk operations and from scheduled scripts,
			so we do not want that!!!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'The Path you would like to update, default is C:\scripts\PowerShell\log')]
		[ValidateNotNullOrEmpty()]
		[System.String[]]$Path = 'C:\scripts\PowerShell\log'
	)

	BEGIN {
		# Suppress all error messages!
		Trap [Exception] {
			Write-Verbose $('TRAPPED: ' + $_.Exception.Message)

			# Be Verbose
			Write-Verbose 'Could not change date on folder (Folder open in explorer?)'

			# Ignore what happened and just continue with what you are doing...
			Continue
		}
	}

	PROCESS {
		# Get latest file date in folder
		$LatestFile = (Get-ChildItem $Path |
			Sort-Object LastWriteTime -Descending |
		Select-Object -First 1)

		# Change the date, if needed
		$Folder = Get-Item $Path

		if ($LatestFile.LastWriteTime -ne $Folder.LastWriteTime) {
			# Be Verbose
			Write-Verbose "Changing date on folder '$($Path)' to '$($LatestFile.LastWriteTime)' taken from '$($LatestFile)'"

			$Folder.LastWriteTime = ($LatestFile.LastWriteTime)
		}
	}

	END {
		Write-Output $Folder
	}
}

function Set-LinuxPrompt {
	<#
			.SYNOPSIS
			Make the Prompt more Linux (bash) like

			.DESCRIPTION
			Make the Prompt more Linux (bash) like

			.EXAMPLE
			PS C:\Windows\system32> Set-LinuxPrompt
			Josh@fra1w7vm01 /Windows/system32 #

			Description
			-----------
			The user 'Josh' executes the 'Set-LinuxPrompt' on the system
			'fra1w7vm01', the '#' shows that he did that in an
			elevated (started as Administrator) session.

			.EXAMPLE
			PS C:\Users\Josh> Set-LinuxPrompt
			Josh@fra1w7vm01 ~ $

			Description
			-----------
			The user 'Josh' executes the 'Set-LinuxPrompt' on the system
			'fra1w7vm01', the '$' shows that this is a non elevated (User) session.

			.NOTES
			Based on an idea of Tommy Maynard
			If you want a more colorful Prompt, take a look at the
			Set-PowerPrompt command

			.LINK
			Source http://tommymaynard.com/quick-learn-duplicate-the-linux-prompt-2016/

			.LINK
			Support https://github.com/jhochwald/NETX/issues

			.LINK
			Set-PowerPrompt
			Reset-Prompt

			.LINK
			Set-DefaultPrompt
			Set-ServicePrompt
	#>

	[CmdletBinding()]
	param ()

	BEGIN {
		(Get-PSProvider -PSProvider FileSystem).Home = $env:USERPROFILE
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess('Prompt', 'Set it to a Bash styled one')) {
			function Prompt {
				# Are we elevated or administrator?
				if ((New-Object Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
					# Administrator Session!
					$Symbol = '#'
				} else {
					# User Session!
					$Symbol = '$'
				}

				if ($PWD.Path -eq $env:USERPROFILE) {
					$Location = '~'
				} elseif ($PWD.Path -like "*$env:USERPROFILE*") {
					$Location = ($PWD.Path -replace ($env:USERPROFILE -replace '\\', '\\'), '~' -replace '\\', '/')
				} else {
					$Location = "$(($PWD.Path -replace '\\', '/' -split ':')[-1])"
				}

				$Prompt = "$(${env:UserName}.ToLower())@$($env:COMPUTERNAME.ToLower()) $Location $Symbol "

				# Mirror the Prompt to the window title
				$Host.UI.RawUI.WindowTitle = ($Prompt)
				$Prompt
			}
		}
	}

	END {
		if ($pscmdlet.ShouldProcess('Prompt', 'Set it to a Bash styled one')) {
			# Execute!
			Prompt
		}
	}
}

function Set-PowerPrompt {
	<#
			.SYNOPSIS
			Multicolored prompt with marker for windows started as Admin and
			marker for providers outside file system

			.DESCRIPTION
			Multicolored prompt with marker for windows started as Admin and
			marker for providers outside file system

			.EXAMPLE
			[Admin] C:\Windows\System32>

			Description
			-----------
			Multicolored prompt with marker for windows started as Admin and
			marker for providers outside file system

			.EXAMPLE
			[Registry] HKLM:\SOFTWARE\Microsoft\Windows>

			Description
			-----------
			Multicolored prompt with marker for windows started as Admin and
			marker for providers outside file system

			.EXAMPLE
			[Admin] [Registry] HKLM:\SOFTWARE\Microsoft\Windows>

			Description
			-----------
			Multicolored prompt with marker for windows started as Admin and
			marker for providers outside file system

			.NOTES
			Just an internal function to make my life easier!

			.LINK
			Source: http://www.snowland.se/2010/02/23/nice-powershell-prompt/

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues

			.LINK
			Set-LinuxPrompt
			Reset-Prompt

			.LINK
			Set-DefaultPrompt
			Set-ServicePrompt
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		if ($pscmdlet.ShouldProcess('Prompt', 'Set Multicolored')) {
			function Prompt {
				[CmdletBinding()]
				[OutputType([System.String])]
				param ()

				# New nice WindowTitle
				$Host.UI.RawUI.WindowTitle = 'PowerShell v' + (Get-Host).Version.Major + '.' + (Get-Host).Version.Minor + ' (' + $PWD.Provider.Name + ') ' + $PWD.Path

				# Are we elevated or administrator?
				if ((New-Object Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
					# Admin-mark in WindowTitle
					$Host.UI.RawUI.WindowTitle = '[Admin] ' + $Host.UI.RawUI.WindowTitle

					# Admin-mark on prompt
					Write-Host '[' -NoNewline -ForegroundColor DarkGray
					Write-Host 'Admin' -NoNewline -ForegroundColor Red
					Write-Host '] ' -NoNewline -ForegroundColor DarkGray
				}

				# Show provider name if you are outside FileSystem
				if ($PWD.Provider.Name -ne 'FileSystem') {
					Write-Host '[' -NoNewline -ForegroundColor DarkGray
					Write-Host $PWD.Provider.Name -NoNewline -ForegroundColor Gray
					Write-Host '] ' -NoNewline -ForegroundColor DarkGray
				}

				# Split path and write \ in a gray
				$PWD.Path.Split('\') | ForEach-Object {
					Write-Host $_ -NoNewline -ForegroundColor Yellow
					Write-Host '\' -NoNewline -ForegroundColor Gray
				}

				# Backspace last \ and write >
				Write-Host "`b>" -NoNewline -ForegroundColor Gray

				Return ' '
			}
		}
	}

	END {
		if ($pscmdlet.ShouldProcess('Prompt', 'Set Multicolored')) {
			# Execute!
			Prompt
		}
	}
}

function Set-VisualEditor {
	<#
			.SYNOPSIS
			Set the VisualEditor variable

			.DESCRIPTION
			Setup the VisualEditor variable. Checks if the free (GNU licensed)
			Notepad++ is installed,
			if so it uses this great free editor.

			If not the fall back is the PowerShell ISE.

			.EXAMPLE
			PS C:\> Set-VisualEditor

			Description
			-----------
			Set the VisualEditor variable. Nothing is returned, no parameter,
			no nothing ;-)

			.EXAMPLE
			PS C:\> $VisualEditor
			C:\Program Files (x86)\Notepad++\notepad++.exe

			Description
			-----------
			Show the variable (Notepad++ in this case)

			.EXAMPLE
			PS C:\> $VisualEditor
			PowerShell_ISE.exe

			Description
			-----------
			Show the variable (PowerShell ISE in this case)
			So no Sublime (our favorite) or Notepad++ (Fallback) installed.
			looks like a plain vanilla PowerShell box.
			But hey, since PowerShell 4, ISE is great!

			.NOTES
			This is just a little helper function to make the shell more flexible

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param ()

	PROCESS {
		# Do we have the Sublime Editor installed?
		Set-Variable -Name SublimeText -Value $(Resolve-Path (Join-Path (Join-Path "$env:PROGRAMW6432*" -ChildPath 'Sublime*') -ChildPath 'Sublime_text*'))

		# Check if the GNU licensed Note++ is installed
		Set-Variable -Name NotepadPlusPlus -Value $(Resolve-Path (Join-Path (Join-Path "$env:PROGRAMW6432*" -ChildPath 'notepad*') -ChildPath 'notepad*'))

		# Do we have it?
		(Resolve-Path "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe" -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)

		# What Editor to use?
		if (($SublimeText) -and (Test-Path $SublimeText)) {
			# We have Sublime Editor installed, so we use it
			Set-Variable -Name VisualEditor -Scope:Global -Value $($SublimeText.Path)
		} elseif (($NotepadPlusPlus) -and (Test-Path $NotepadPlusPlus)) {
			# We have Notepad++ installed, Sublime Editor is not here... use Notepad++
			Set-Variable -Name VisualEditor -Scope:Global -Value $($NotepadPlusPlus.Path)
		} else {
			# No fancy editor, so we use ISE instead
			Set-Variable -Name VisualEditor -Scope:Global -Value $('PowerShell_ISE.exe')
		}
	}

	END {
		# Be Verbose
		Write-Verbose "$VisualEditor"
	}
}

function Get-ShortDate {
	<#
			.SYNOPSIS
			Get the Date as short String

			.DESCRIPTION
			Get the Date as short String

			.PARAMETER FilenameCompatibleFormat
			Make sure it is compatible to File Dates

			.EXAMPLE
			PS C:\> Get-ShortDate
			19.03.16

			Description
			-----------
			Get the Date as short String

			.EXAMPLE
			PS C:\> Get-ShortDate -FilenameCompatibleFormat
			19-03-16

			Description
			-----------
			Get the Date as short String and replace the '.' with '-'.
			Useful is you want to append this to filenames.

			The dots are bad for such use cases!

			.NOTES
			Helper Function based on an idea of Robert D. Biddle

			.LINK
			Source https://github.com/RobBiddle/Get-ShortDateTime/blob/master/Get-ShortDateTime.psm1
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Position = 0,
		HelpMessage = 'Make sure it is compatible to File Dates')]
		[Switch]$FilenameCompatibleFormat
	)

	PROCESS {
		if ($FilenameCompatibleFormat) {
			$Date = (Get-Date)

			# Dump
			Return (($Date.ToShortDateString()).Replace('/', '-'))
		} else {
			$Date = (Get-Date)

			# Dump
			Return ($Date.ToShortDateString())
		}
	}
}

function Get-ShortTime {
	<#
			.SYNOPSIS
			Get the Time as short String

			.DESCRIPTION
			Get the Time as short String

			.PARAMETER FilenameCompatibleFormat
			Make sure it is compatible to File Timestamp

			.EXAMPLE
			PS C:\> Get-ShortTime
			16:17

			Description
			-----------
			Get the Time as short String

			.EXAMPLE
			PS C:\> Get-ShortTime -FilenameCompatibleFormat
			16-17

			Description
			-----------
			Get the Time as short String and replace the ':' with '-'.
			Useful is you want to append this to filenames.
			The dash could be bad for such use cases!

			.NOTES
			Helper Function based on an idea of Robert D. Biddle

			.LINK
			Source https://github.com/RobBiddle/Get-ShortDateTime/blob/master/Get-ShortDateTime.psm1
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Position = 0,
		HelpMessage = 'Make sure it is compatible to File Timestamp')]
		[Switch]$FilenameCompatibleFormat
	)

	PROCESS {
		if ($FilenameCompatibleFormat) {
			$time = (Get-Date)

			# Dump
			Return (($time.ToShortTimeString()).Replace(':', '-').Replace(' ', '-'))
		} else {
			$time = (Get-Date)

			# Dump
			Return ($time.ToShortTimeString())
		}
	}
}

# Uni* like SuDo
function Invoke-WithElevation {
	<#
			.SYNOPSIS
			Uni* like Superuser Do (Sudo)

			.DESCRIPTION
			This is not a hack or something:
			You still to have the proper access rights (permission) to execute
			something with elevated rights (permission)!
			Windows will tell you (and ask for confirmation) that the given
			command is executes with administrative rights.

			The command opens another window and you can still use your existing
			shell with you regular permissions.

			Keep that in mind when you execute it...

			.PARAMETER file
			Script/Program to run

			.EXAMPLE
			PS C:\> sudo 'C:\scripts\PowerShell\profile.ps1'

			Description
			-----------
			Try to execute 'C:\scripts\PowerShell\profile.ps1' with elevation
			We use the Uni* like alias here

			.EXAMPLE
			PS C:\> Invoke-WithElevation 'C:\scripts\PowerShell\profile.ps1'

			Description
			-----------
			Try to execute 'C:\scripts\PowerShell\profile.ps1' with elevation

			.NOTES
			Still a internal Beta function!
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = ' Script/Program to run')]
		[Alias('FileName')]
		[System.String]$File
	)

	PROCESS {
		# Define some defaults
		$sudo = (New-Object System.Diagnostics.ProcessStartInfo)
		$sudo.Verb = 'runas'
		$sudo.FileName = "$pshome\PowerShell.exe"
		$sudo.windowStyle = 'Normal'
		$sudo.WorkingDirectory = (Get-Location)

		# What to execute?
		if ($File) {
			if (Test-Path $File) {
				$sudo.Arguments = "-executionpolicy unrestricted -NoExit -noprofile -Command $File"
			} else {
				Write-Error -Message:"Error: File does not exist - $File" -ErrorAction:Stop
			}
		} else {
			# No file given, so we open a plain Shell (Console window)
			$sudo.Arguments = "-executionpolicy unrestricted -NoExit -Command  &{Set-Location '" + (Get-Location).Path + "'}"
		}
	}

	END {
		# NET call to execute SuDo
		if ($pscmdlet.ShouldProcess("$sudo", 'Execute elevated')) {
			$null = [System.Diagnostics.Process]::Start($sudo)
		}
	}
}

function tail {
	<#
			.SYNOPSIS
			Make the PowerShell a bit more *NIX like

			.DESCRIPTION
			Wrapper for the PowerShell command Get-Content. It opens a given
			file and shows the content...
			Get-Content normally exists as soon as the end of the given file is
			reached, this wrapper keeps it open and display every new informations
			as soon as it appears. This could be very useful for parsing log files.

			Everyone ever used Unix or Linux known tail ;-)

			.PARAMETER f
			Follow

			.PARAMETER file
			File to open

			.EXAMPLE
			PS C:\> tail C:\scripts\PowerShell\logs\create_new_OU_Structure.log

			Description
			-----------
			Opens the given Log file
			(C:\scripts\PowerShell\logs\create_new_OU_Structure.log) and shows
			every new entry until you break it (CTRL + C)

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(HelpMessage = 'Follow')]
		[switch]$f,
		[Parameter(Mandatory = $true,
		HelpMessage = 'File to open')]
		[ValidateNotNullOrEmpty()]
		$File
	)

	PROCESS {
		if ($f) {
			# Follow is enabled, dump the last 10 lines and follow the stream
			Get-Content $File -Tail 10 -Wait
		} else {
			# Follow is not enabled, just dump the last 10 lines
			Get-Content $File -Tail 10
		}
	}
}

<#
		This is the former version...
		Deprecated and will be removed soon!
#>
function tail2 {
	<#
			.SYNOPSIS
			Make the PowerShell a bit more *NIX like

			.DESCRIPTION
			Wrapper for the PowerShell command Get-Content. It opens a given file
			and shows the content...
			Get-Content normally exists as soon as the end of the given file is
			reached, this wrapper keeps it open and display every new informations a
			s soon as it appears. This could be very useful for parsing log files.

			Everyone ever used Unix or Linux known tail ;-)

			.PARAMETER file
			File to open

			.EXAMPLE
			PS C:\> tail2 C:\scripts\PowerShell\logs\create_new_OU_Structure.log

			Description
			-----------
			Opens the given Log file
			(C:\scripts\PowerShell\logs\create_new_OU_Structure.log) and shows
			every new entry until you break it (CTRL + C)

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
		HelpMessage = 'File to open')]
		[ValidateNotNullOrEmpty()]
		[Alias('FileName')]
		$File
	)

	PROCESS {
		# Is the File given?
		if (-not ($File)) {
			# Aw SNAP! That sucks...
			Write-Error -Message:'Error: File to tail is missing...' -ErrorAction:Stop
		} else {
			# tailing the file for you, Sir! ;-)
			Get-Content $File -Wait
		}
	}
}

function Test-Method {
	<#
			.SYNOPSIS
			Check if the given Function is loaded from a given Module

			.DESCRIPTION
			Check if the given Function is loaded from a given Module

			.PARAMETER Module
			Name of the Module

			.PARAMETER Function
			Name of the function

			.EXAMPLE
			PS C:\> Test-Method -Module 'NETX.AD' -Function 'Add-AdThumbnailPhoto'
			True

			Description
			-----------
			Check if the given Function 'Add-AdThumbnailPhoto' is loaded from a
			given Module 'NETX.AD', what it IS.

			.EXAMPLE
			PS C:\> Test-Method -Module 'NETX.AD' -Function 'Test-TCPPort'
			True

			Description
			-----------
			Check if the given Function 'Test-TCPPort' is loaded from a given
			Module 'NETX.AD', what it is NOT.

			.NOTES
			Quick helper function to shortcut things. / MBE

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Name of the Module')]
		[Alias('moduleName')]
		[System.String]$Module,
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 2,
		HelpMessage = 'Name of the function')]
		[Alias('functionName')]
		[System.String]$Function
	)

	PROCESS {
		if ($pscmdlet.ShouldProcess("$Function", "Check if loaded from $Module")) {
			((Get-Command -Module $Module |
					Where-Object { $_.Name -eq "$Function" } |
			Measure-Object).Count -eq 1)
		}
	}
}

function Test-ModuleAvailableToLoad {
	<#
			.SYNOPSIS
			Test if the given Module exists

			.DESCRIPTION
			Test if the given Module exists

			.PARAMETER modname
			Name of the Module to check

			.EXAMPLE
			PS C:\> Test-ModuleAvailableToLoad EXISTINGMOD
			True

			Description
			-----------
			This module exists

			.EXAMPLE
			PS C:\> Test-ModuleAvailableToLoad WRONGMODULE
			False

			Description
			-----------
			This Module does not exists

			.EXAMPLE
			$MSOLModname = "MSOnline"
			$MSOLTrue = (Test-ModuleAvailableToLoad $MSOLModName)

			Description
			-----------
			Bit more complex example that put the Boolean in a variable
			for later use.

			.NOTES
			Quick helper function
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
		Position = 0)]
		[string[]]$modname
	)

	BEGIN {
		# Easy, gust check if it exists
		$modtest = (Get-Module -ListAvailable $modname -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)
	}

	PROCESS {
		if (-not ($modtest)) {
			Return $false
		} else {
			Return $true
		}
	}
}

function Test-ProxyBypass {
	<#
			.SYNOPSIS
			Testing URLs for Proxy Bypass

			.DESCRIPTION
			If you'd like to find out whether a given URL goes through a proxy or
			is accessed directly

			.PARAMETER url
			URL to check for Proxy Bypass

			.EXAMPLE
			PS C:\> Test-ProxyBypass -url 'https://outlook.office.com'
			True

			Description
			-----------
			Check if the given URL 'https://outlook.office.com' is directly
			accessible, what it IS!

			.EXAMPLE
			PS C:\> Test-ProxyBypass -url 'http://technet.microsoft.com'
			False

			Description
			-----------
			Check if the given URL 'http://technet.microsoft.com' is directly
			accessible, what it is NOT!

			.NOTES
			Initial version of the function

			.Link
			Source: http://powershell.com/cs/blogs/tips/archive/2012/08/14/testing-urls-for-proxy-bypass.aspx

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'URL to check for Proxy Bypass')]
		[ValidateNotNullOrEmpty()]
		[Alias('uri')]
		[System.String]$url = 'http://support.NET-Experts.net'
	)

	BEGIN {
		# Cleanup
		$webclient = $null
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$url", 'Check if direct access is possible')) {
			$webclient = (New-Object System.Net.WebClient)

			Write-Output "$($webclient.Proxy.IsBypassed($url))"
		}
	}

	END {
		# Cleanup
		$webclient = $null
	}
}

function Test-RemotePOSH {
	<#
			.SYNOPSIS
			Check if PSRemoting (Remote execution of PowerShell) is enabled on
			a given Host

			.DESCRIPTION
			Check if PSRemoting (Remote execution of PowerShell) is enabled on
			a given Host

			.PARAMETER ComputerName
			Hostname of the System to perform, default is the local system

			.PARAMETER POSHcred
			The credentials to use!

			Default is the credentials that we use for Azure, Exchange...

			.EXAMPLE
			PS C:\> Enable-RemotePOSH -ComputerName 'NXLIMCLN01'
			WARNING: Unable to establish remote session with NXLIMCLN01.

			Description
			-----------
			Check if PSRemoting (Remote execution of PowerShell) is enabled on
			'NXLIMCLN01'. It uses the default credentials (Same that we use to
			administer Exchange Online and Azue)

			.EXAMPLE
			PS C:\> Enable-RemotePOSH -ComputerName 'NXLIMCLN02' -POSHcred (Get-Credential)
			NXLIMCLN02

			Description
			-----------
			Check if PSRemoting (Remote execution of PowerShell) is enabled on
			'NXLIMCLN02'.

			And is asks for the credentials to use.

			.NOTES
			Initial Beta based on an idea of Adrian Rodriguez (adrian@rdrgz.net)

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Hostname of the System to perform, default is the local system')]
		[string[]]$Computer = ($env:COMPUTERNAME),
		[Parameter(HelpMessage = 'The credentials to use! Default is the centials that we use for Azure, Exchange...')]
		[pscredential]$POSHcred
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name 'ScriptBlock' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'InvokeArgs' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'Failures' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'Item' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		# Define a dummy ScriptBlock
		$ScriptBlock = { $env:COMPUTERNAME }

		# Define the Argument List
		$InvokeArgs = @{
			ComputerName = $Computer
			ScriptBlock  = $ScriptBlock
		}

		# Do we have credentials?
		If ($null -ne $POSHcred) {
			# Yeah!
			$InvokeArgs.Credential = $POSHcred
		}

		# Try to connect
		Invoke-Command @InvokeArgs -ErrorAction:SilentlyContinue -ErrorVariable Failures

		# Loop over the Problems, if we have one... or more?
		ForEach ($Failure in $Failures) {
			# Warn the user
			Write-Warning -Message "Unable to establish remote session with $($Failure.TargetObject)."
		}
	}

	END {
		# Cleanup
		Remove-Variable -Name 'ScriptBlock' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'InvokeArgs' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'Failures' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name 'Item' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}

function Test-TCPPort {
	<#
			.SYNOPSIS
			TCP Port Ping

			.DESCRIPTION
			This function is used to see if a TCP Port is answering

			.PARAMETER target
			Please specify an EndPoint (Host or IP Address)

			.PARAMETER Port
			Please specify a Port

			.PARAMETER TimeOut
			Timeout value (Default is 1.000)

			.EXAMPLE
			Test-TCPPort -target '127.0.0.1' -Port '445'
			False

			Description
			-----------
			This function is used to see if a TCP Port is answering

			.EXAMPLE
			Test-TCPPort -target '110.10..16.10' -Port '445'
			True

			Description
			-----------
			This function is used to see if a TCP Port is answering

			.NOTES
			This function will be replaced soon: We will build a new one soon that
			supports other protocols to (Not only TCP)

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'Please specify an EndPoint (Host or IP Address)')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Target,
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
				Position = 1,
		HelpMessage = 'Please specify a Port')]
		[ValidateNotNullOrEmpty()]
		[System.String]$Port,
		[Parameter(ValueFromPipeline = $true,
				Position = 2,
		HelpMessage = 'Timeout value (Default is 1.000)')]
		[ValidateNotNullOrEmpty()]
		[System.Int32]$TimeOut = 1000
	)

	BEGIN {
		# Cleanup
		$Address = $null
		$Socket = $null
		$Connect = $null
		$Wait = $null
	}

	PROCESS {
		Try {
			$IP = ([System.Net.Dns]::GetHostAddresses($Target))
			$Address = ([System.Net.IPAddress]::Parse($IP))
			$Socket = (New-Object System.Net.Sockets.TCPClient)
			$Connect = ($Socket.BeginConnect($Address, $Port, $null, $null))
		} catch {
			Write-Warning -Message 'Host unreachable'
		}

		# Wait a few ticks (Just a few!!!)
		Start-Sleep -Milliseconds 10

		if ($Connect.IsCompleted) {
			$Wait = ($Connect.AsyncWaitHandle.WaitOne($TimeOut, $false))

			if ($Wait) {
				$Socket.EndConnect($Connect)
				$Socket.Close()
				Return $true
			} else {
				$Socket.Close()
				Return $false
			}
		} else {
			Return $false
		}
	}

	END {
		# Cleanup
		$Address = $null
		$Socket = $null
		$Connect = $null
		$Wait = $null
	}
}

function Get-Time {
	<#
			.SYNOPSIS
			Timing How Long it Takes a Script or Command to Run

			.DESCRIPTION
			This is a quick wrapper for Measure-Command Cmdlet

			Make the PowerShell a bit more *NIX like

			Everyone ever used Unix or Linux known time ;-)

			.PARAMETER file
			Script or command to execute

			.EXAMPLE
			PS C:\> time new-Bulk-devices.ps1

			Description
			-----------
			Runs the script new-Bulk-devices.ps1 and shows how log it takes
			to execute

			We use the well known Uni* alias here!

			.EXAMPLE
			PS C:\> time Get-Service | Export-Clixml c:\scripts\test.xml

			Description
			-----------
			When you run this command, service information will be saved to
			the file Test.xml

			It also shows how log it takes to execute
			We use the well known Uni* alias here!

			.EXAMPLE
			PS C:\> Get-Time new-Bulk-devices.ps1

			Description
			-----------
			Runs the script new-Bulk-devices.ps1 and shows how log it takes to
			execute

			Makes no sense, instead of Measure-Command we use Get-Time,
			but we need to use this name to make it right ;-)

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
		HelpMessage = 'Script or command to execute')]
		[ValidateNotNullOrEmpty()]
		[Alias('Command')]
		$File
	)

	PROCESS {
		# Does the file exist?
		if (-not ($File)) {
			# Aw SNAP! That sucks...
			Write-Error -Message:'Error: Input is missing but mandatory...' -ErrorAction:Stop
		} else {
			# Measure the execution for you, Sir! ;-)
			Measure-Command { $File }
		}
	}
}

function Set-FileTime {
	<#
			.SYNOPSIS
			Change file Creation + Modification + Last Access times

			.DESCRIPTION
			The touch utility sets the Creation + Modification + Last Access
			times of files.

			If any file does not exist, it is created with default permissions by
			default.

			To prevent this, please use the -NoCreate parameter!

			.PARAMETER Path
			Path to the File that we would like to change

			.PARAMETER AccessTime
			Change the Access Time Only

			.PARAMETER WriteTime
			Change the Write Time Only

			.PARAMETER CreationTime
			Change the Creation Time Only

			.PARAMETER NoCreate
			Do not create a new file, if the given one does not exist.

			.PARAMETER Date
			Date to set

			.EXAMPLE
			touch foo.txt

			Description
			-----------
			Change the Creation + Modification + Last Access Date/time and if the
			file does not already exist, create it with the default permissions.
			We use the alias touch instead of Set-FileTime to make it more *NIX like

			.EXAMPLE
			Set-FileTime foo.txt -NoCreate

			Description
			-----------
			Change the Creation + Modification + Last Access Date/time if this
			file exists.

			The -NoCreate makes sure, that the file will not be created!

			.EXAMPLE
			Set-FileTime foo.txt -only_modification

			Description
			-----------
			Change only the modification time

			.EXAMPLE
			Set-FileTime foo.txt -only_access

			Description
			-----------
			Change only the last access time

			.EXAMPLE
			dir . -recurse -filter "*.xls" | Set-FileTime

			Description
			-----------
			Change multiple files

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues

			.LINK
			Based on this: http://ss64.com/ps/syntax-touch.html
	#>

	[CmdletBinding(ConfirmImpact = 'Medium',
	SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
		HelpMessage = 'Path to the File')]
		[System.String[]]$Path,
		[Parameter(HelpMessage = 'Change the Access Time Only')]
		[switch]$AccessTime,
		[Parameter(HelpMessage = 'Change the Write Time Only')]
		[switch]$WriteTime,
		[Parameter(HelpMessage = 'Change the Creation Time Only')]
		[switch]$CreationTime,
		[switch]$NoCreate,
		[Parameter(HelpMessage = 'Date to set')]
		[datetime]$Date
	)

	PROCESS {
		# Let us test if the given file exists
		if (Test-Path $Path) {
			if ($Path -is [System.IO.FileSystemInfo]) {
				Set-Variable -Name 'FileSystemInfoObjects' -Value $($Path)
			} else {
				Set-Variable -Name 'FileSystemInfoObjects' -Value $($Path |
					Resolve-Path -ErrorAction:SilentlyContinue |
				Get-Item)
			}

			# Now we loop over all objects
			foreach ($fsInfo in $FileSystemInfoObjects) {

				if (($Date -eq $null) -or ($Date -eq '')) {
					$Date = Get-Date
				}

				# Set the Access time
				if ($AccessTime) {
					$fsInfo.LastAccessTime = $Date
				}

				# Set the Last Write time
				if ($WriteTime) {
					$fsInfo.LastWriteTime = $Date
				}

				# Set the Creation time
				if ($CreationTime) {
					$fsInfo.CreationTime = $Date
				}

				# On, no parameter given?
				# We set all time stamps!
				if (-not ($AccessTime -and $ModificationTime -and $CreationTime)) {
					$fsInfo.CreationTime = $Date
					$fsInfo.LastWriteTime = $Date
					$fsInfo.LastAccessTime = $Date
				}
			}
		} elseif (-not $NoCreate) {
			# Let us create the file for ya!
			Set-Content -Path $Path -Value $null
			Set-Variable -Name 'fsInfo' -Value $($Path |
				Resolve-Path -ErrorAction:SilentlyContinue |
			Get-Item)

			# OK, now we set the date to the given one
			# We ignore all given parameters here an set all time stamps!
			# If you want to change it, re-run the command!
			if (($Date -ne $null) -and ($Date -ne '')) {
				Set-Variable -Name 'Date' -Value $(Get-Date)
				$fsInfo.CreationTime = $Date
				$fsInfo.LastWriteTime = $Date
				$fsInfo.LastAccessTime = $Date
			}
		}
	}
}

function ConvertTo-UnixDate {
	<#
			.SYNOPSIS
			Convert from DateTime to Unix date

			.DESCRIPTION
			Convert from DateTime to Unix date

			.PARAMETER Date
			Date to convert

			.PARAMETER Utc
			Default behavior is to convert Date to universal time.
			Set this to false to skip this step.

			.EXAMPLE
			PS C:\> ConvertTo-UnixDate -Date (Get-date)
			1458205878

			Description
			-----------
			Convert from UTC DateTime to Unix date

			.EXAMPLE
			PS C:\> ConvertTo-UnixDate -Date (Get-date) -UTC $false
			1458209488

			Description
			-----------
			Convert from non UTC DateTime to Unix date

			.NOTES
			Adopted parts of Warren F. (RamblingCookieMonster)

			.LINK
			Source http://stackoverflow.com/questions/10781697/convert-unix-time-with-powershell
			Source http://powershell.com/cs/blogs/tips/archive/2012/03/09/converting-unix-time.aspx
	#>

	[CmdletBinding()]
	[OutputType([System.Int32])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Date to convert')]
		[System.DateTime]$Date = (Get-Date),
		[Parameter(Position = 1,
		HelpMessage = 'Default behavior is to convert Date to universal time. Set this to false to skip this step.')]
		[System.Boolean]$UTC = $true
	)

	BEGIN {
		# Do we use UTC as Time-Zone?
		if ($UTC) {
			$Date = $Date.ToUniversalTime()
		}
	}

	PROCESS {
		$unixEpochStart = (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc))
		[System.Int32]($Date - $unixEpochStart).TotalSeconds
	}
}

function ConvertFrom-UnixDate {
	<#
			.SYNOPSIS
			Convert from Unix time to DateTime

			.DESCRIPTION
			Convert from Unix time to DateTime and make it human readable again

			.PARAMETER Date
			Date to convert, in Unix / Epoch format

			.PARAMETER Utc
			Default behavior is to convert Date to universal time.
			Set this to false to Return local time.

			.EXAMPLE
			PS C:\> ConvertFrom-UnixDate -Date 1458205878
			17. März 2016 09:11:18

			Description
			-----------
			Convert from a given Unix time string to a UTC DateTime format
			Formated based on the local PowerShell Culture!

			.EXAMPLE
			PS C:\> ConvertFrom-UnixDate -Date 1458205878 -UTC $false
			17. März 2016 10:11:18

			Description
			-----------
			Convert from a given Unix time string to a non UTC DateTime format
			Formated based on the local PowerShell Culture!

			.EXAMPLE
			PS C:\> Set-Culture -culture "en-US" | ConvertFrom-UnixDate -Date 1458205878
			Thursday, March 17, 2016 9:11:18 AM

			Description
			-----------
			Use our Set-Culture to dump the info in US English

			.EXAMPLE
			PS C:\> Set-Culture -culture "en-GB" | ConvertFrom-UnixDate -Date 1458205878
			17 March 2016 09:11:18

			Description
			-----------
			Use our Set-Culture to dump the info in plain (UK) English

			.EXAMPLE
			PS C:\>  Set-Culture -culture "fr-CA" | ConvertFrom-UnixDate -Date 1458205878
			17 mars 2016 09:11:18

			Description
			-----------
			Use our Set-Culture to dump the info in Canadian French

			.EXAMPLE
			PS C:\> ConvertFrom-UnixDate -Date (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' | Select-Object -ExpandProperty InstallDate)
			20. Juli 2015 13:24:00

			Description
			-----------
			Read the Install date of the local system (Unix time string)
			and converts it to a human readable string

			Formated based on the local PowerShell Culture!

			.EXAMPLE
			PS C:\> ConvertFrom-UnixDate -Date (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion' | Select-Object -ExpandProperty InstallDate) | New-TimeSpan | Select-Object -ExpandProperty Days
			240

			Description
			-----------
			Read the Install date (Unix time string) and converts it to DateTime,
			extracts the days

			.NOTES
			Adopted parts of Warren F. (RamblingCookieMonster)

			.LINK
			Source http://stackoverflow.com/questions/10781697/convert-unix-time-with-powershell
			Source http://powershell.com/cs/blogs/tips/archive/2012/03/09/converting-unix-time.aspx
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				Position = 0,
		HelpMessage = 'Date to convert, in Unix / Epoch format')]
		[System.Int32]$Date,
		[Parameter(Position = 1,
		HelpMessage = 'Default behavior is to convert Date to universal time. Set this to false to Return local time.')]
		[System.Boolean]$UTC = $true
	)

	BEGIN {
		# Create the Object
		$unixEpochStart = (New-Object DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc))

		# Default is UTC
		$output = ($unixEpochStart.AddSeconds($Date))
	}

	PROCESS {
		# Convert to non UTC?
		if (-not $UTC) {
			# OK, let us use the local time
			$output = ($output.ToLocalTime())
		}
	}

	END {
		# Dump
		Write-Output $output
	}
}

function ConvertFrom-UrlEncoded {
	<#
			.SYNOPSIS
			Decodes a UrlEncoded string.

			.DESCRIPTION
			Decodes a UrlEncoded string.

			Input can be either a positional or named parameters of type string or
			an array of strings.

			The Cmdlet accepts pipeline input.

			.PARAMETER InputObject
			A description of the InputObject parameter.

			.EXAMPLE
			PS C:\> ConvertFrom-UrlEncoded 'http%3a%2f%2fwww.d-fens.ch'
			http://www.d-fens.ch

			Description
			-----------
			Encoded string is passed as a positional parameter to the Cmdlet.

			.EXAMPLE
			PS C:\> ConvertFrom-UrlEncoded -InputObject 'http%3a%2f%2fwww.d-fens.ch'
			http://www.d-fens.ch

			Description
			-----------
			Encoded string is passed as a named parameter to the Cmdlet.

			.EXAMPLE
			PS C:\>  ConvertFrom-UrlEncoded -InputObject 'http%3a%2f%2fwww.d-fens.ch', 'http%3a%2f%2fwww.dfch.biz%2f'
			http://www.d-fens.ch
			http://www.dfch.biz/

			Description
			-----------
			Encoded strings are passed as an implicit array to the Cmdlet.

			.EXAMPLE
			PS C:\> ConvertFrom-UrlEncoded -InputObject @("http%3a%2f%2fwww.d-fens.ch", "http%3a%2f%2fwww.dfch.biz%2f")
			http://www.d-fens.ch
			http://www.dfch.biz/

			Description
			-----------
			Encoded strings are passed as an explicit array to the Cmdlet.

			.EXAMPLE
			PS C:\> @("http%3a%2f%2fwww.d-fens.ch", "http%3a%2f%2fwww.dfch.biz%2f") | ConvertFrom-UrlEncoded
			http://www.d-fens.ch
			http://www.dfch.biz/

			Description
			-----------
			Encoded strings are piped as an explicit array to the Cmdlet.

			.EXAMPLE
			PS C:\> "http%3a%2f%2fwww.dfch.biz%2f" | ConvertFrom-UrlEncoded
			http://www.dfch.biz/

			Description
			-----------
			Encoded string is piped to the Cmdlet.

			.EXAMPLE
			PS C:\> $r = @("http%3a%2f%2fwww.d-fens.ch", 0, "http%3a%2f%2fwww.dfch.biz%2f") | ConvertFrom-UrlEncoded
			PS C:\> $r
			http://www.d-fens.ch
			0
			http://www.dfch.biz/

			Description
			-----------
			In case one of the passed strings is not a UrlEncoded encoded string,
			the plain string is returned. The pipeline will continue to execute
			and all strings are returned.

			.LINK
			Online Version: http://dfch.biz/biz/dfch/PS/System/Utilities/ConvertFrom-UrlEncoded/
	#>

	[CmdletBinding(ConfirmImpact = 'None',
			HelpUri = 'http://dfch.biz/biz/dfch/PS/System/Utilities/ConvertFrom-UrlEncoded/',
	SupportsShouldProcess = $true)]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				ValueFromPipeline = $true,
		Position = 0)]
		[ValidateNotNullOrEmpty()]
		$InputObject
	)

	BEGIN {
		$datBegin = [datetime]::Now
		[System.String]$fn = ($MyInvocation.MyCommand.Name)
		$OutputParameter = $null
	}

	PROCESS {
		foreach ($Object in $InputObject) {
			$fReturn = $false
			$OutputParameter = $null

			$OutputParameter = [System.Web.HttpUtility]::UrlDecode($InputObject)
			$OutputParameter
		}
		$fReturn = $true
	}

	END {
		$datEnd = [datetime]::Now
	}
}

function ConvertTo-UrlEncoded {
	[CmdletBinding(ConfirmImpact = 'None',
			HelpUri = 'http://dfch.biz/biz/dfch/PS/System/Utilities/ConvertTo-UrlEncoded/',
	SupportsShouldProcess = $true)]
	[OutputType([System.String])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				ValueFromPipelineByPropertyName = $true,
		Position = 0)]
		[System.String]$InputObject
	)

	BEGIN {
		$datBegin = [datetime]::Now
		[System.String]$fn = $MyInvocation.MyCommand.Name
	}

	PROCESS {
		$fReturn = $false
		$OutputParameter = $null

		$OutputParameter = [System.Web.HttpUtility]::UrlEncode($InputObject)
		Write-Output $OutputParameter
	}

	END {
		$datEnd = [datetime]::Now
	}
}

function Get-TinyURL {
	<#
			.SYNOPSIS
			Get a Short URL

			.DESCRIPTION
			Get a Short URL using the TINYURL.COM Service

			.PARAMETER URL
			Long URL

			.EXAMPLE
			PS C:\> Get-TinyURL -URL 'http://net-experts.net'
			http://tinyurl.com/yc63nbh

			Description
			-----------
			Request the TINYURL for http://net-experts.net.
			In this example the Return is http://tinyurl.com/yc63nbh

			.NOTES
			Still a beta Version!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'Long URL')]
		[ValidateNotNullOrEmpty()]
		[Alias('URL2Tiny')]
		[System.String]$url
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name 'tinyURL' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		try {
			# Request
			Set-Variable -Name 'tinyURL' -Value $(Invoke-WebRequest -Uri "http://tinyurl.com/api-create.php?url=$url" | Select-Object -ExpandProperty Content)

			# Do we have the TinyURL?
			if (($tinyURL)) {
				# Dump to the Console
				Write-Output "$tinyURL"
			} else {
				# Aw Snap!
				throw
			}
		} catch {
			# Something bad happed
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		} finally {
			# Cleanup
			Remove-Variable tinyURL -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Get-IsGdURL {
	<#
			.SYNOPSIS
			Get a Short URL

			.DESCRIPTION
			Get a Short URL using the IS.GD Service

			.PARAMETER URL
			Long URL

			.EXAMPLE
			PS C:\> Get-IsGdURL -URL 'http://net-experts.net'
			http://is.gd/FkMP5v

			Description
			-----------
			Request the IS.GD for http://net-experts.net.
			In this example the Return is http://is.gd/FkMP5v

			.NOTES
			Additional information about the function.

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'Long URL')]
		[ValidateNotNullOrEmpty()]
		[Alias('URL2GD')]
		[System.String]$url
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name 'isgdURL' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		try {
			# Request
			Set-Variable -Name 'isgdURL' -Value $(Invoke-WebRequest -Uri "http://is.gd/api.php?longurl=$url" | Select-Object -ExpandProperty Content)

			# Do we have the short URL?
			if (($isgdURL)) {
				# Dump to the Console
				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
			} else {
				# Aw Snap!
				throw
			}
		} catch {
			# Something bad happed
			Write-Output 'Whoopsie... Houston, we have a problem!'
		} finally {
			# Cleanup
			Remove-Variable isgdURL -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Get-TrImURL {
	<#
			.SYNOPSIS
			Get a Short URL

			.DESCRIPTION
			Get a Short URL using the TR.IM Service

			.PARAMETER URL
			Long URL

			.EXAMPLE
			PS C:\> Get-TrImURL -URL 'http://net-experts.net'

			Description
			-----------
			Request the tr.im for http://net-experts.net.

			.NOTES
			The service is off line at the moment!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'Long URL')]
		[ValidateNotNullOrEmpty()]
		[Alias('URL2Trim')]
		[System.String]$url
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name 'trimURL' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		try {
			# Request
			Set-Variable -Name 'trimURL' -Value $(Invoke-WebRequest -Uri "http://api.tr.im/api/trim_simple?url=$url" | Select-Object -ExpandProperty Content)

			# Do we have a trim URL?
			if (($trimURL)) {
				# Dump to the Console
				Write-Output "$trimURL"
			} else {
				# Aw Snap!
				throw
			}
		} catch {
			# Something bad happed
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		} finally {
			# Cleanup
			Remove-Variable trimURL -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function Get-LongURL {
	<#
			.SYNOPSIS
			Expand a Short URL

			.DESCRIPTION
			Expand a Short URL via the untiny.me
			This service supports all well known short URL services!

			.PARAMETER URL
			Short URL

			.EXAMPLE
			PS C:\> Get-LongURL -URL 'http://cutt.us/KX5CD'
			http://net-experts.net

			Description
			-----------
			Get the Long URL (http://net-experts.net) for a given Short URL

			.NOTES
			This service supports all well known short URL services!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $true,
				Position = 0,
		HelpMessage = 'Short URL')]
		[ValidateNotNullOrEmpty()]
		[Alias('URL2Exapnd')]
		[System.String]$url
	)

	BEGIN {
		# Cleanup
		Remove-Variable -Name 'longURL' -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}

	PROCESS {
		try {
			# Request
			Set-Variable -Name 'longURL' -Value $(Invoke-WebRequest -Uri "http://untiny.me/api/1.0/extract?url=$url&format=text" | Select-Object -ExpandProperty Content)

			# Do we have the long URL?
			if (($longURL)) {
				# Dump to the Console
				Write-Output "$longURL"
			} else {
				# Aw Snap!
				throw
			}
		} catch {
			# Something bad happed
			Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
		} finally {
			# Cleanup
			Remove-Variable longURL -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		}
	}
}

function wc {
	<#
			.SYNOPSIS
			Word, line, character, and byte count

			.DESCRIPTION
			The wc utility displays the number of lines, words, and bytes
			contained in each input file, or standard input (if no file is
			specified) to the standard output.
			A line is defined as a string of characters delimited by a <newline>
			character.
			Characters beyond the final <newline> character will not be
			included in the line count.

			.PARAMETER object
			The input File, Object, or Array

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.Int32])]
	param
	(
		[Alias('File')]
		$Object
	)

	BEGIN {
		# initialize counter for counting number of data from
		$counter = 0
	}

	# Process is invoked for every pipeline input
	PROCESS {
		if ($_) { $counter++ }
	}

	END {
		# if "wc" has an argument passed, ignore pipeline input
		if ($Object) {
			if (Test-Path $Object) {
				(Get-Content $Object | Measure-Object).Count
			} else {
				($Object | Measure-Object).Count
			}
		} else {
			$counter
		}
	}
}

function which {
	<#
			.SYNOPSIS
			Locate a program file in the user's path

			.DESCRIPTION
			Make PowerShell more Uni* like by set an alias to the existing
			Get-Command command let

			.PARAMETER command
			Locate a program file in the path

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
		HelpMessage = 'Locate a program file in the path')]
		[ValidateNotNullOrEmpty()]
		$command
	)

	PROCESS {
		# Easy: Just use Get-Command ;-)
		(Get-Command -All $command).Definition
	}
}

function whoami {
	<#
			.SYNOPSIS
			Shows the windows login info

			.DESCRIPTION
			Make PowerShell a bit more like *NIX! Shows the Login info as you
			might know it from Unix/Linux

			.EXAMPLE
			PS C:\> whoami
			BART\josh

			Description
			-----------
			Login (User) Josh on the system named BART

			.NOTES
			Make PowerShell a bit more like *NIX!

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	[OutputType([System.String])]
	param ()

	PROCESS {
		# Call the NET function
		[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	}
}

function Write-ToLog {
	<#
			.SYNOPSIS
			Write Log to file and screen

			.DESCRIPTION
			Write Log to file and screen
			Each line has a UTC Time-stamp

			.PARAMETER LogFile
			Name of the Log-file

			.NOTES
			Early Beta Version...
			Based on an idea/script of Michael Bayer

			.LINK
			NET-Experts http://www.net-experts.net

			.LINK
			Support https://github.com/jhochwald/NETX/issues
	#>

	[CmdletBinding()]
	param
	(
		[Parameter(HelpMessage = 'Name of the Logfile')]
		[Alias('Log')]
		[System.String]$LogFile
	)

	BEGIN {
		# No Logfile?
		If ($LogFile -ne '') {
			# UTC Time-stamp
			Set-Variable -Name 'UtcTime' -Value $((Get-Date).ToUniversalTime() | Get-Date -UFormat '%Y-%m-%d %H:%M (UTC)')

			# Check for the LogFile
			If (Test-Path $LogFile) {
				# OK, we have a LogFile
				Write-Warning -Message "$LogFile already exists"
				Write-Output "Logging will append to $LogFile"
			} Else {
				# Create a brand new LogFile
				Write-Output "Logfile: $LogFile"
				$null = New-Item -Path $LogFile -ItemType file
			}

			# Here is our LogFile
			Set-Variable -Name 'MyLogFileName' -Scope:Script -Value $($LogFile)

			# Create a start Header
			Add-Content $Script:MyLogFileName -Value "Logging start at $UtcTime `n"
		}

		# Have a buffer?
		If (-not ($Script:MyLogBuffer)) {
			# Nope!
			$Script:MyLogBuffer = @()
		}
	}

	PROCESS {
		# UTC Time-stamp
		Set-Variable -Name 'UtcTime' -Value $((Get-Date).ToUniversalTime() | Get-Date -UFormat '%Y-%m-%d %H:%M:%S')

		# Create the Message Array
		$messages = @()

		# Fill the messages
		$messages += ('' + ($_ | Out-String)).TrimEnd().Split("`n")

		# Loop over the messages
		foreach ($Message in $messages) {
			# Write a line
			Set-Variable -Name 'LogMsg' -Value $($UtcTime + ': ' + ($Message -replace "`n|`r", '').TrimEnd())

			# Inform
			Write-Output $LogMsg
			$Script:MyLogBuffer += $LogMsg
		}
	}

	END {
		try {
			# Dump the buffers
			$Script:MyLogBuffer | Add-Content $Script:MyLogFileName
		} catch {
			# Whoopsie!
			Write-Error -Message "Cannot write log into $MyLogFileName" -ErrorAction:Stop
		}

		# Remove the Variable
		Remove-Variable -Name 'MyLogBuffer' -Scope:Script -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}
#endregion Functions

#region ExportModuleStuff

# Get public function definition files.
if (Test-Path -Path (Join-Path $PSScriptRoot -ChildPath 'Public')) {
	$Public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot -ChildPath 'Public') -Exclude '*.tests.*' -Recurse -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)

	# Dot source the files
	foreach ($Import in @($Public)) {
		try {
			. $Import.fullname
		} catch {
			Write-Error "Failed to import Public function $($Import.fullname): $_"
		}
	}
}

if ($LoadingModule) {
	Export-ModuleMember -Function '*' -Alias '*' -Cmdlet '*' -Variable '*'
}

if (Test-Path -Path (Join-Path $PSScriptRoot -ChildPath 'Private')) {
	# Get public and private function definition files.
	$Private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot -ChildPath 'Private') -Exclude '*.tests.*' -Recurse -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)

	foreach ($Import in @($Private)) {
		try {
			. $Import.fullname
		} catch {
			Write-Error "Failed to import Private function $($Import.fullname): $_"
		}
	}
}

# End the Module Loading Mode
$LoadingModule = $false

# Return to where we are before we start loading the Module
Pop-Location

#endregion ExportModuleStuff

<#
		Execute some stuff here
#>

# SIG # Begin signature block
# MIIYpQYJKoZIhvcNAQcCoIIYljCCGJICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhIiFI8gidXNykksYPssWBq93
# qFagghPNMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggVMMIIENKADAgECAhAW1PdTHZsYJ0/yJnM0UYBcMA0GCSqGSIb3DQEBCwUAMH0x
# CzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV
# BAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSMwIQYDVQQD
# ExpDT01PRE8gUlNBIENvZGUgU2lnbmluZyBDQTAeFw0xNTA3MTcwMDAwMDBaFw0x
# ODA3MTYyMzU5NTlaMIGQMQswCQYDVQQGEwJERTEOMAwGA1UEEQwFMzU1NzYxDzAN
# BgNVBAgMBkhlc3NlbjEQMA4GA1UEBwwHTGltYnVyZzEYMBYGA1UECQwPQmFobmhv
# ZnNwbGF0eiAxMRkwFwYDVQQKDBBLcmVhdGl2U2lnbiBHbWJIMRkwFwYDVQQDDBBL
# cmVhdGl2U2lnbiBHbWJIMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# ryMOYXRM7T2omd0n14YWqtrWV/Xg0OEzzAhPxwVxn8BfZfOsTrNv/yQTmwvj90yG
# 5M6n5Iy3S0j9I43oFjfbTy/82UMjt+jMCod+a8+Etfqn9O0OSZIfWwPwAjKtMf1v
# bvAM1fisL3XgprgQEjywa1nBk5CTBB2VXqAIGZp1qv7tiRWEBsgiRJrMT3LJFO59
# +J2a0dXj0Mc+v6qXiOI0n8rbtkVlvAzqQYGUMEFKAtQq+58xj5c9S6SnN0JoDRTP
# KAZR0N+DLSG1JKnwxH1GerhYwvS399PQhm+avEKuHs1eRBcAKTbG2eSrRtdQgLof
# RmiWd+Xh9qe9VjK8PzyogQIDAQABo4IBsjCCAa4wHwYDVR0jBBgwFoAUKZFg/4pN
# +uv5pmq4z/nmS71JzhIwHQYDVR0OBBYEFJ5Ubj/1S9WOa/xJPLh/uQYe5xKGMA4G
# A1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MBEGCWCGSAGG+EIBAQQEAwIEEDBGBgNVHSAEPzA9MDsGDCsGAQQBsjEBAgEDAjAr
# MCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21vZG8ubmV0L0NQUzBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9SU0FD
# b2RlU2lnbmluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPgYIKwYBBQUHMAKGMmh0
# dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET1JTQUNvZGVTaWduaW5nQ0EuY3J0
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wIwYDVR0RBBww
# GoEYaG9jaHdhbGRAa3JlYXRpdnNpZ24ubmV0MA0GCSqGSIb3DQEBCwUAA4IBAQBJ
# JmTEqjcTIST+pbRkKzsIMMcpPHdRyoTGKCxpjQNGj19taCpbKci2yp3AWS5BgnHO
# SeqbYky/AgroG19ZzrhZmHLQG0jdLeHHNgfEONUMEsHL3WSP+Z10+N6frRb4vrqg
# 0ReIG4iw5wn17u0fpWf14URSO6rl6ygkzoVX4wgq/+M8VYynkHoS1fgsMcSliktF
# VCe7GhzfyaZ341+NwPb+j/zVu7ouYEV6AcBoYOlOEZ/weTc1XLQZylDe2uqYfp7c
# KmbxS3lSShI41l2RhbCvOSbMWAnKgzaudMxOHh+JzEFCkHsiS/hUSesdFF6KFnTP
# A34eRc7VcSd3eGb7TyMvMIIF4DCCA8igAwIBAgIQLnyHzA6TSlL+lP0ct800rzAN
# BgkqhkiG9w0BAQwFADCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENB
# IExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkwHhcNMTMwNTA5MDAwMDAwWhcNMjgwNTA4MjM1OTU5WjB9MQswCQYDVQQG
# EwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxm
# b3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEjMCEGA1UEAxMaQ09NT0RP
# IFJTQSBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCmmJBjd5E0f4rR3elnMRHrzB79MR2zuWJXP5O8W+OfHiQyESdrvFGRp8+e
# niWzX4GoGA8dHiAwDvthe4YJs+P9omidHCydv3Lj5HWg5TUjjsmK7hoMZMfYQqF7
# tVIDSzqwjiNLS2PgIpQ3e9V5kAoUGFEs5v7BEvAcP2FhCoyi3PbDMKrNKBh1SMF5
# WgjNu4xVjPfUdpA6M0ZQc5hc9IVKaw+A3V7Wvf2pL8Al9fl4141fEMJEVTyQPDFG
# y3CuB6kK46/BAW+QGiPiXzjbxghdR7ODQfAuADcUuRKqeZJSzYcPe9hiKaR+ML0b
# tYxytEjy4+gh+V5MYnmLAgaff9ULAgMBAAGjggFRMIIBTTAfBgNVHSMEGDAWgBS7
# r34CPfqm8TyEjq3uOJjs2TIy1DAdBgNVHQ4EFgQUKZFg/4pN+uv5pmq4z/nmS71J
# zhIwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAww
# CgYIKwYBBQUHAwMwEQYDVR0gBAowCDAGBgRVHSAAMEwGA1UdHwRFMEMwQaA/oD2G
# O2h0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0NPTU9ET1JTQUNlcnRpZmljYXRpb25B
# dXRob3JpdHkuY3JsMHEGCCsGAQUFBwEBBGUwYzA7BggrBgEFBQcwAoYvaHR0cDov
# L2NydC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQWRkVHJ1c3RDQS5jcnQwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AgEAAj8COcPu+Mo7id4MbU2x8U6ST6/COCwEzMVjEasJY6+rotcCP8xvGcM91hoI
# lP8l2KmIpysQGuCbsQciGlEcOtTh6Qm/5iR0rx57FjFuI+9UUS1SAuJ1CAVM8bdR
# 4VEAxof2bO4QRHZXavHfWGshqknUfDdOvf+2dVRAGDZXZxHNTwLk/vPa/HUX2+y3
# 92UJI0kfQ1eD6n4gd2HITfK7ZU2o94VFB696aSdlkClAi997OlE5jKgfcHmtbUIg
# os8MbAOMTM1zB5TnWo46BLqioXwfy2M6FafUFRunUkcyqfS/ZEfRqh9TTjIwc8Jv
# t3iCnVz/RrtrIh2IC/gbqjSm/Iz13X9ljIwxVzHQNuxHoc/Li6jvHBhYxQZ3ykub
# Ua9MCEp6j+KjUuKOjswm5LLY5TjCqO3GgZw1a6lYYUoKl7RLQrZVnb6Z53BtWfht
# Kgx/GWBfDJqIbDCsUgmQFhv/K53b0CDKieoofjKOGd97SDMe12X4rsn4gxSTdn1k
# 0I7OvjV9/3IxTZ+evR5sL6iPDAZQ+4wns3bJ9ObXwzTijIchhmH+v1V04SF3Awpo
# bLvkyanmz1kl63zsRQ55ZmjoIs2475iFTZYRPAmK0H+8KCgT+2rKVI2SXM3CZZgG
# ns5IW9S1N5NGQXwH3c/6Q++6Z2H/fUnguzB9XIDj5hY5S6cxggRCMIIEPgIBATCB
# kTB9MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAw
# DgYDVQQHEwdTYWxmb3JkMRowGAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEjMCEG
# A1UEAxMaQ09NT0RPIFJTQSBDb2RlIFNpZ25pbmcgQ0ECEBbU91MdmxgnT/ImczRR
# gFwwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwIwYJKoZIhvcNAQkEMRYEFJH0/N3DdhJNPx9DLIpjXzTNytM1MA0GCSqGSIb3
# DQEBAQUABIIBAIdLc1pBvzpd17pA6OXrjdt8XnzG5ZfVhFV2mNkaDrHwlK1035v5
# 04LtoiEswzSoxxUioHtXRl7z6xXcL0B3v1b261ht2Tyhy6Y4Y2io8GkBgK6qyAGa
# WFuGaQVRhvhipxUajI9fh/svd0doQIkYz/sR/TFmy9E7F0r+H3SJSIYvGsBWrxe/
# FNBbFMdGvAV31qKXg72+J83xtYV82JICxA6W4Tq4NjPG08Raz5RfkeoX6yu6B1zr
# QvjpcREvZlz1TPntnNC00Ex3FyqS6tLPguspxg6J3bGeO+T6KUNQX8OxTx/ir/oq
# LihiS9FKJNPnNqp5BhiV0pwno18y4Bf8snKhggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwNjA5MTk1MTI2
# WjAjBgkqhkiG9w0BCQQxFgQUdiTpqRfwh6Uo0ohx6Cr2B+jOFhwwDQYJKoZIhvcN
# AQEBBQAEggEAmoPTFFTAb4UKhF12YOvz0loZz6cXCa/DB2jO92RsUsXYoP+6Znh4
# 4q5Ww9MW6gLDzo2XN/a5icnynt9n7ijJnPxIYK6LR0ccIcWIKd+04yMJo+jFdlDU
# pOyJ1PY5HUdxu/QjGzGfEmvIEsJv4jZ3fIS8SHLweNbee4aZU+i8TEsiSyI/x4qN
# nwKGRKqEku+2bNgvVSXn70aMPX6KxwenSVQfV3I7oYmcItMAxRDTiX+tjfuMQts3
# iZrOpy8Jg++OrSsIgYziC/Gu/0MbQf5XNewhcsCLtuK+Eir+W7+NSZHJlHW2xXFU
# 6Q7caRhDT4l8tRzBiHqXmqgOirDiFtkVCg==
# SIG # End signature block
