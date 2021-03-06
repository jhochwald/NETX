﻿#requires -Version 3.0

#region Info
<#
		Support: https://github.com/jhochwald/NETX/issues
#>
#endregion Info

#region License
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

<#
		This is a third-party Software!

		The developer of this Software is NOT sponsored by or affiliated with
		Microsoft Corp (MSFT) or any of its subsidiaries in any way

		The Software is not supported by Microsoft Corp (MSFT)!

		More about Quality Software Ltd. http://www.q-soft.co.uk
#>
#endregion License

<#
		.SYNOPSIS
		PowerShell Profile Example

		.DESCRIPTION
		NET-Experts example Profile Script for PowerShell Session Login

		Again, this is just an example,
		you might want to adopt a few things for yourself.

		.NOTES
		This is just an example!
		It contains some stuff that we at NET-Experts find useful to have,
		you can and should customize this profile to fit to your custom needs!

		Please note:
		If you get the NET-Experts PowerShell Toolbox distribution, you will
		get this file with every release, so please rename yours!

		.LINK
		Support Site https://github.com/jhochwald/NETX/issues
#>

param ()

function global:Get-IsWin10 {
	# For some Workarounds!
	if ([Environment]::OSVersion.Version -ge (New-Object -TypeName 'Version' -ArgumentList 10, 0)) {
		Return $True
	} else {
		Return $False
	}
}

# Make this Shell clean!
function Clear-AllVariables {
	# Delete all variables that exists
	$null = (Remove-Variable -Name * -Scope Local -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
	$null = (Remove-Variable -Name * -Scope Local -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

	$null = (Remove-Variable -Name * -Scope Script -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
	$null = (Remove-Variable -Name * -Scope Script -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

	$null = (Remove-Variable -Name * -Scope Global -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
	$null = (Remove-Variable -Name * -Scope Global -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
}

Clear-AllVariables

# By default, when you import Microsoft's ActiveDirectory PowerShell module which
# ships with Server 2008 R2 (or later) and is a part of the free RSAT tools,
# it will import AD command lets and also install an AD: PowerShell drive.
#
# If you do not want to install that drive set the variable to 0
$env:ADPS_LoadDefaultDrive = 1

# Resetting Console Colors
[Console]::ResetColor()

# Get the Mode?
if ((Get-Command -Name Set-RunEnv -ErrorAction SilentlyContinue)) {
	# Use our Core Module command
	Set-RunEnv
} else {
	# Enforce Terminal as Mode!
	Set-Variable -Name RunEnv -Scope Global -Value $('Terminal')
}

# This is our Base location
Set-Variable -Name BasePath -Scope Global -Value $('c:/scripts/PowerShell')

$IsNewModuleAvailable = (Get-Module -Name 'enatec.OpenSource' -ListAvailable)

if ($IsNewModuleAvailable) {
	if ((Get-Module -Name 'enatec.OpenSource')) {
		$null = (Remove-Module -Name 'enatec.OpenSource' -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
	}

	$null = (Import-Module -Name 'enatec.OpenSource' -Force -DisableNameChecking -NoClobber -Global)
} else {
	# Helper Function, see below
	function script:LoadScripts {
		PROCESS {
			# Load all the NET-Experts PowerShell functions from *.ps1 files
			Set-Variable -Name ToolsPath -Value $(('{0}\functions\*.ps1' -f $BasePath))

			# Exclude (Pester) Test scripts
			Set-Variable -Name ExcludeName -Value $('.Tests.')

			# Load them all
			$null = (Get-ChildItem -Path $ToolsPath -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
				Where-Object -FilterScript { $_.psIsContainer -eq $False } |
				Where-Object -FilterScript { $_.Name -like '*.ps1' } |
				Where-Object -FilterScript { $_.Name -ne $ExcludeName } |
			ForEach-Object -Process { .$_.FullName })
		}
	}

	# Load the Functions from each file in the "functions" directory
	LoadScripts
}

# Make em English!
if ((Get-Command -Name Set-Culture -ErrorAction SilentlyContinue)) {
	try {
		Set-Culture -Culture 'en-US'
	} catch {
		# Do nothing!
		Write-Debug -Message 'We had an Error'
	}
}

#region WorkAround

# Search for all NET-Experts Modules
$MyModules = @((Get-Module -Name NETX.* -ListAvailable).Name)

# Loop over the List of modules
foreach ($MyModule in $MyModules) {
	# Search for Modules not exported correct
	if ((((Get-Module -Name $MyModule -ListAvailable).ModuleType) -eq 'Manifest') -and ((((Get-Module -Name $MyModule -ListAvailable).Version).ToString()) -eq '0.0')) {
		$null = (Import-Module -Name $MyModule -DisableNameChecking -Force -Scope Global -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
		$null = (Remove-Module -Name $MyModule -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
	}
}

$null = (Remove-Module -Name 'NETX.Core' -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)

#endregion WorkAround

# Gets back the default colors parameters
[console]::ResetColor()

# Change the Window
function global:Set-WinStyle {
	PROCESS {
		Set-Variable -Name console -Value $($host.UI.RawUI)
		Set-Variable -Name buffer -Value $($console.BufferSize)

		$buffer.Width = 128
		$buffer.Height = 2000
		$console.BufferSize = ($buffer)

		Set-Variable -Name size -Value $($console.WindowSize)

		$size.Width = 128
		$size.Height = 50
		$console.WindowSize = ($size)
	}
}

# Make the Windows dark blue
function global:Set-RegularMode {
	BEGIN {
		# Reformat the Windows
		if ((Get-Command -Name Set-WinStyle -ErrorAction SilentlyContinue)) {
			$null = (Set-WinStyle)
			$null = (Set-WinStyle)
		}
	}

	PROCESS {
		# Change Color
		Set-Variable -Name console -Value $($host.UI.RawUI)
		$console.ForegroundColor = 'Gray'
		$console.BackgroundColor = 'DarkBlue'
		$console.CursorSize = 10

		# Text
		Set-Variable -Name colors -Value $($host.PrivateData)
		$colors.VerboseForegroundColor = 'Yellow'
		$colors.VerboseBackgroundColor = 'DarkBlue'
		$colors.WarningForegroundColor = 'Yellow'
		$colors.WarningBackgroundColor = 'DarkBlue'
		$colors.ErrorForegroundColor = 'Red'
		$colors.ErrorBackgroundColor = 'DarkBlue'
	}

	END {
		# Clean screen
		[Console]::Clear()
		[Console]::SetWindowPosition(0, [Console]::CursorTop)
	}
}

# Make the window white
function global:Set-LightMode {
	BEGIN {
		# Reformat the Windows
		if ((Get-Command -Name Set-WinStyle -ErrorAction SilentlyContinue)) {
			$null = (Set-WinStyle)
			$null = (Set-WinStyle)
		}
	}

	PROCESS {
		# Change Color
		Set-Variable -Name console -Value $($host.UI.RawUI)
		$console.ForegroundColor = 'black'
		$console.BackgroundColor = 'white'
		$console.CursorSize = 10

		# Text
		Set-Variable -Name colors -Value $($host.PrivateData)
		$colors.VerboseForegroundColor = 'blue'
		$colors.VerboseBackgroundColor = 'white'
		$colors.WarningForegroundColor = 'Magenta'
		$colors.WarningBackgroundColor = 'white'
		$colors.ErrorForegroundColor = 'Red'
		$colors.ErrorBackgroundColor = 'white'
	}

	END {
		# Clean screen
		[Console]::Clear()
		[Console]::SetWindowPosition(0, [Console]::CursorTop)
	}
}

# Include this to the PATH
if ((Get-Command -Name Add-AppendPath -ErrorAction SilentlyContinue)) {
	try {
		Add-AppendPath -Pathlist $BasePath
	} catch {
		# Do nothing!
		Write-Warning -Message ('Could not append {0} to the Path!' -f $BasePath)
	}
}

# Configure the CONSOLE itself
if ($host.Name -eq 'ConsoleHost') {
	# Console Mode

	# Set the Environment variable
	if (-not ($RunEnv)) { Set-Variable -Name RunEnv -Scope Global -Value $('Terminal') }

	# Style the Window
	if ((Get-Command -Name Set-RegularMode -ErrorAction SilentlyContinue)) {
		# Set the Default Mode!
		$null = (Set-RegularMode)
	}
} elseif (($host.Name -eq 'Windows PowerShell ISE Host') -and ($psISE)) {
	# Yeah, we run within the ISE

	# Set the Environment variable
	if (-not ($RunEnv)) {
		# We are in a Console!
		Set-Variable -Name RunEnv -Scope Global -Value $('Terminal')
	}

	# Style the Window
	if ((Get-Command -Name Set-LightMode -ErrorAction SilentlyContinue)) {
		# Set the Default Mode!
		$null = (Set-RegularMode)
	}
} elseif ($host.Name -eq 'PrimalScriptHostImplementation') {
	# Oh, we running in a GUI - Ask yourself why you run the profile!
	Write-Debug -Message 'Running a a GUI based Environment and execute a Console Profile!'

	# Set the Environment variable
	if (-not ($RunEnv)) { Set-Variable -Name RunEnv -Scope Global -Value $('GUI') }
} else {
	# Not in the Console, not ISE... Where to hell are we?
	Write-Debug -Message 'Unknown!'
}

# Set the Defaults
Set-DefaultPrompt

# Where the windows Starts
Set-Location -Path $BasePath

# Display some infos
function info {
	PROCESS {
		''
		('Today is: ' + $((Get-Date -Format 'yyyy-MM-dd') + ' ' + (Get-Date -Format 'HH:mm:ss')))
		''
		if ((Get-Command -Name Get-NETXCoreVer -ErrorAction SilentlyContinue)) {
			#Dump the Version info
			Get-NETXPoshVer
		}
		''
	}
}

# The Message of the Day (MOTD) function
function motd {
	PROCESS {
		# Display Disk Informations
		# We try to display regular Disk only, no fancy disk drives
		foreach ($HD in (Get-WmiObject -Query 'SELECT * from win32_logicaldisk where DriveType = 3')) {
			# Free Disk Space function
			Set-Variable -Name Free -Value $($HD.FreeSpace / 1GB -as [int])
			Set-Variable -Name Total -Value $($HD.Size / 1GB -as [int])

			# How much Disk Space do we have here?
			if ($Free -le 5) {
				# Less then 5 GB available - WARN!
				Write-Host -Object ('Drive {0} has {1}GB of {2}GB available' -f $HD.DeviceID, ($Free), ($Total)) -ForegroundColor 'Yellow'
			} elseif ($Free -le 2) {
				# Less then 2 GB available - WARN a bit more aggressive!!!
				Write-Host -Object ('Drive {0} has {1}GB of {2}GB available' -f $HD.DeviceID, ($Free), ($Total)) -ForegroundColor 'Red'
			} else {
				# Regular Disk Free Space- GREAT!
				# With more then 5 GB available
				Write-Host -Object ('Drive {0} has {1}GB of {2}GB available' -f $HD.DeviceID, ($Free), ($Total))
			}
		}

		Write-Host -Object ''

		if ((Get-Command -Name Get-Uptime -ErrorAction SilentlyContinue)) {
			# Get the Uptime...
			Get-Uptime
		}

		Write-Host -Object ''
	}
}

# unregister events, in case they weren't unregistered properly before.
# Just error silently if they don't exist
Unregister-Event -SourceIdentifier ConsoleStopped -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier FileCreated -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier FileChanged -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier TimerTick -ErrorAction SilentlyContinue

# Try the new auto connect feature or authenticate manual via Invoke-AuthO365
if (Get-Command -Name tryAutoLogin -ErrorAction SilentlyContinue) {
	# Lets try the new command
	(Get-tryAutoLogin)
} elseif (Get-Command -Name Invoke-AuthO365 -ErrorAction SilentlyContinue) {
	# Fall-back to the old and manual way
	(Invoke-AuthO365)
}

# Enable strict mode
<#
		Set-StrictMode -Version Latest
#>

# Where are we?
if ($host.Name -eq 'ConsoleHost') {
	# Console Mode - Make a clean screen
	[Console]::Clear()
	[Console]::SetWindowPosition(0, [Console]::CursorTop)

	# Is this a user or an Admin account?
	# This has nothing to do with the user / User rights!
	# We look for the Session: Is it started as Admin, or not!
	if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
		# Make the Name ALL Lower case
		$MyUserInfo = ($env:Username.ToUpper())

		# This is a regular user Account!
		Write-Host -Object ('Entering PowerShell as {0} with User permissions on {1}' -f $MyUserInfo, $env:COMPUTERNAME) -ForegroundColor 'White'
	} else {
		# Make the Name ALL Lower case
		$MyUserInfo = ($env:Username.ToUpper())

		# This is an elevated session!
		Write-Host -Object ('Entering PowerShell as {0} with Admin permissions on {1}' -f $MyUserInfo, $env:COMPUTERNAME) -ForegroundColor 'Green'
	}

	# Show infos
	if (Get-Command -Name info -ErrorAction SilentlyContinue) { info }

	# Show message of the day
	if (Get-Command -Name motd -ErrorAction SilentlyContinue) {
		# This is the function from above.
		# If you want, you might use Get-MOTD here.
		motd
	}
} elseif (($host.Name -eq 'Windows PowerShell ISE Host') -and ($psISE)) {
	# Yeah, we run within the ISE
	# We do not support this Environment :)
	Write-Debug -Message 'ISE Found!'
} elseif ($host.Name -eq 'PrimalScriptHostImplementation') {
	# Oh, we running in a GUI
	# We do not support this Environment :)
	Write-Debug -Message 'GUI App'
} elseif ($host.Name -eq 'DefaultHost') {
	# Look who is using our PowerShell Web Proxy Server...
	# We do not support this Environment :)
	Write-Debug -Message 'Default Host!'
} elseif ($host.Name -eq 'ServerRemoteHost') {
	Clear-Host

	if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
		# Make the Name ALL Lower case
		$MyUserInfo = ($env:Username.ToUpper())

		# This is a regular user Account!
		Write-Host -Object ('Entering PowerShell as {0} with User permissions on {1}' -f $MyUserInfo, $env:COMPUTERNAME) -ForegroundColor 'White'
	} else {
		# Make the Name ALL Lower case
		$MyUserInfo = ($env:Username.ToUpper())

		# This is an elevated session!
		Write-Host -Object ('Entering PowerShell as {0} with Admin permissions on {1}' -f $MyUserInfo, $env:COMPUTERNAME) -ForegroundColor 'Green'
	}

	# Support for Remote was added a while ago.
	if (Get-Command -Name Get-MOTD -ErrorAction SilentlyContinue) { Get-MOTD }

	# Use this to display the Disk Info
	if (Get-Command -Name motd -ErrorAction SilentlyContinue) {
		# Blank Line
		Write-Output -InputObject ''

		motd
	}
} else {
	# Not in the Console, not ISE... Where to hell are we right now?
	Write-Debug -Message 'Unknown!'
}

if (Get-Command -Name Get-Quote -ErrorAction SilentlyContinue) {
	# Print a Quote
	(Get-Quote)
}

# Try to check the Credentials
if ((Get-Command -Name Test-Credential -ErrorAction SilentlyContinue)) {
	try {
		$IsCredValid = (Test-Credential)
	} catch {
		# Prevent "The server could not be contacted." Error
		Write-Debug -Message 'We had an Error'
	}

	if (($IsCredValid -eq $False) -and (-not ($Environment -eq 'Development'))) {
		Write-Warning -Message 'Looks like your Credentials are not correct!!!'

		try {
			# Remove saved credentials!
			if (Get-Command -Name Remove-PSCredential -ErrorAction SilentlyContinue) { $null = (Remove-PSCredential) }

			# Ask for Credentials...
			(Invoke-AuthO365)

			try {
				if (Get-Command -Name Export-PSCredential -ErrorAction SilentlyContinue) { $null = (Export-PSCredential) }
			} catch { Write-Debug -Message 'Could not export Credentials!' }
		} catch { Write-Debug -Message 'Houston we have a problem!' }
	}
}

# Do a garbage collection
if (Get-Command -Name Invoke-GC -ErrorAction SilentlyContinue) { (Invoke-GC) }

# SIG # Begin signature block
# MIIfOgYJKoZIhvcNAQcCoIIfKzCCHycCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbvBOUwHr0lYetQ18of29xZ3Y
# mlagghnLMIIEFDCCAvygAwIBAgILBAAAAAABL07hUtcwDQYJKoZIhvcNAQEFBQAw
# VzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNV
# BAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw0xMTA0
# MTMxMDAwMDBaFw0yODAxMjgxMjAwMDBaMFIxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSgwJgYDVQQDEx9HbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBDQSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO9l
# +LVXn6BTDTQG6wkft0cYasvwW+T/J6U00feJGr+esc0SQW5m1IGghYtkWkYvmaCN
# d7HivFzdItdqZ9C76Mp03otPDbBS5ZBb60cO8eefnAuQZT4XljBFcm05oRc2yrmg
# jBtPCBn2gTGtYRakYua0QJ7D/PuV9vu1LpWBmODvxevYAll4d/eq41JrUJEpxfz3
# zZNl0mBhIvIG+zLdFlH6Dv2KMPAXCae78wSuq5DnbN96qfTvxGInX2+ZbTh0qhGL
# 2t/HFEzphbLswn1KJo/nVrqm4M+SU4B09APsaLJgvIQgAIMboe60dAXBKY5i0Eex
# +vBTzBj5Ljv5cH60JQIDAQABo4HlMIHiMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBRG2D7/3OO+/4Pm9IWbsN1q1hSpwTBHBgNV
# HSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLm5ldC9yb290LmNybDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQ
# L30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEATl5WkB5GtNlJMfO7FzkoG8IW
# 3f1B3AkFBJtvsqKa1pkuQJkAVbXqP6UgdtOGNNQXzFU6x4Lu76i6vNgGnxVQ380W
# e1I6AtcZGv2v8Hhc4EvFGN86JB7arLipWAQCBzDbsBJe/jG+8ARI9PBw+DpeVoPP
# PfsNvPTF7ZedudTbpSeE4zibi6c1hkQgpDttpGoLoYP9KOva7yj2zIhd+wo7AKvg
# IeviLzVsD440RZfroveZMzV+y5qKu0VN5z+fwtmK+mWybsd+Zf/okuEsMaL3sCc2
# SI8mbzvuTXYfecPlf5Y1vC0OzAGwjn//UYCAp5LUs0RGZIyHTxZjBzFLY7Df8zCC
# BJ8wggOHoAMCAQICEhEh1pmnZJc+8fhCfukZzFNBFDANBgkqhkiG9w0BAQUFADBS
# MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
# AxMfR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBHMjAeFw0xNjA1MjQwMDAw
# MDBaFw0yNzA2MjQwMDAwMDBaMGAxCzAJBgNVBAYTAlNHMR8wHQYDVQQKExZHTU8g
# R2xvYmFsU2lnbiBQdGUgTHRkMTAwLgYDVQQDEydHbG9iYWxTaWduIFRTQSBmb3Ig
# TVMgQXV0aGVudGljb2RlIC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCwF66i07YEMFYeWA+x7VWk1lTL2PZzOuxdXqsl/Tal+oTDYUDFRrVZUjtC
# oi5fE2IQqVvmc9aSJbF9I+MGs4c6DkPw1wCJU6IRMVIobl1AcjzyCXenSZKX1GyQ
# oHan/bjcs53yB2AsT1iYAGvTFVTg+t3/gCxfGKaY/9Sr7KFFWbIub2Jd4NkZrItX
# nKgmK9kXpRDSRwgacCwzi39ogCq1oV1r3Y0CAikDqnw3u7spTj1Tk7Om+o/SWJMV
# TLktq4CjoyX7r/cIZLB6RA9cENdfYTeqTmvT0lMlnYJz+iz5crCpGTkqUPqp0Dw6
# yuhb7/VfUfT5CtmXNd5qheYjBEKvAgMBAAGjggFfMIIBWzAOBgNVHQ8BAf8EBAMC
# B4AwTAYDVR0gBEUwQzBBBgkrBgEEAaAyAR4wNDAyBggrBgEFBQcCARYmaHR0cHM6
# Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCQYDVR0TBAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3Js
# Lmdsb2JhbHNpZ24uY29tL2dzL2dzdGltZXN0YW1waW5nZzIuY3JsMFQGCCsGAQUF
# BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNv
# bS9jYWNlcnQvZ3N0aW1lc3RhbXBpbmdnMi5jcnQwHQYDVR0OBBYEFNSihEo4Whh/
# uk8wUL2d1XqH1gn3MB8GA1UdIwQYMBaAFEbYPv/c477/g+b0hZuw3WrWFKnBMA0G
# CSqGSIb3DQEBBQUAA4IBAQCPqRqRbQSmNyAOg5beI9Nrbh9u3WQ9aCEitfhHNmmO
# 4aVFxySiIrcpCcxUWq7GvM1jjrM9UEjltMyuzZKNniiLE0oRqr2j79OyNvy0oXK/
# bZdjeYxEvHAvfvO83YJTqxr26/ocl7y2N5ykHDC8q7wtRzbfkiAD6HHGWPZ1BZo0
# 8AtZWoJENKqA5C+E9kddlsm2ysqdt6a65FDT1De4uiAO0NOSKlvEWbuhbds8zkSd
# wTgqreONvc0JdxoQvmcKAjZkiLmzGybu555gxEaovGEzbM9OuZy5avCfN/61PU+a
# 003/3iCOTpem/Z8JvE3KGHbJsE2FUPKA0h0G9VgEB7EYMIIFTDCCBDSgAwIBAgIQ
# FtT3Ux2bGCdP8iZzNFGAXDANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQGEwJHQjEb
# MBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxmb3JkMRow
# GAYDVQQKExFDT01PRE8gQ0EgTGltaXRlZDEjMCEGA1UEAxMaQ09NT0RPIFJTQSBD
# b2RlIFNpZ25pbmcgQ0EwHhcNMTUwNzE3MDAwMDAwWhcNMTgwNzE2MjM1OTU5WjCB
# kDELMAkGA1UEBhMCREUxDjAMBgNVBBEMBTM1NTc2MQ8wDQYDVQQIDAZIZXNzZW4x
# EDAOBgNVBAcMB0xpbWJ1cmcxGDAWBgNVBAkMD0JhaG5ob2ZzcGxhdHogMTEZMBcG
# A1UECgwQS3JlYXRpdlNpZ24gR21iSDEZMBcGA1UEAwwQS3JlYXRpdlNpZ24gR21i
# SDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8jDmF0TO09qJndJ9eG
# Fqra1lf14NDhM8wIT8cFcZ/AX2XzrE6zb/8kE5sL4/dMhuTOp+SMt0tI/SON6BY3
# 208v/NlDI7fozAqHfmvPhLX6p/TtDkmSH1sD8AIyrTH9b27wDNX4rC914Ka4EBI8
# sGtZwZOQkwQdlV6gCBmadar+7YkVhAbIIkSazE9yyRTuffidmtHV49DHPr+ql4ji
# NJ/K27ZFZbwM6kGBlDBBSgLUKvufMY+XPUukpzdCaA0UzygGUdDfgy0htSSp8MR9
# Rnq4WML0t/fT0IZvmrxCrh7NXkQXACk2xtnkq0bXUIC6H0Zolnfl4fanvVYyvD88
# qIECAwEAAaOCAbIwggGuMB8GA1UdIwQYMBaAFCmRYP+KTfrr+aZquM/55ku9Sc4S
# MB0GA1UdDgQWBBSeVG4/9UvVjmv8STy4f7kGHucShjAOBgNVHQ8BAf8EBAMCB4Aw
# DAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzARBglghkgBhvhCAQEE
# BAMCBBAwRgYDVR0gBD8wPTA7BgwrBgEEAbIxAQIBAwIwKzApBggrBgEFBQcCARYd
# aHR0cHM6Ly9zZWN1cmUuY29tb2RvLm5ldC9DUFMwQwYDVR0fBDwwOjA4oDagNIYy
# aHR0cDovL2NybC5jb21vZG9jYS5jb20vQ09NT0RPUlNBQ29kZVNpZ25pbmdDQS5j
# cmwwdAYIKwYBBQUHAQEEaDBmMD4GCCsGAQUFBzAChjJodHRwOi8vY3J0LmNvbW9k
# b2NhLmNvbS9DT01PRE9SU0FDb2RlU2lnbmluZ0NBLmNydDAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuY29tb2RvY2EuY29tMCMGA1UdEQQcMBqBGGhvY2h3YWxkQGty
# ZWF0aXZzaWduLm5ldDANBgkqhkiG9w0BAQsFAAOCAQEASSZkxKo3EyEk/qW0ZCs7
# CDDHKTx3UcqExigsaY0DRo9fbWgqWynItsqdwFkuQYJxzknqm2JMvwIK6BtfWc64
# WZhy0BtI3S3hxzYHxDjVDBLBy91kj/mddPjen60W+L66oNEXiBuIsOcJ9e7tH6Vn
# 9eFEUjuq5esoJM6FV+MIKv/jPFWMp5B6EtX4LDHEpYpLRVQnuxoc38mmd+NfjcD2
# /o/81bu6LmBFegHAaGDpThGf8Hk3NVy0GcpQ3trqmH6e3Cpm8Ut5UkoSONZdkYWw
# rzkmzFgJyoM2rnTMTh4ficxBQpB7Ikv4VEnrHRReihZ0zwN+HkXO1XEnd3hm+08j
# LzCCBdgwggPAoAMCAQICEEyq+crbY2/gH/dO2FsDhp0wDQYJKoZIhvcNAQEMBQAw
# gYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAO
# BgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMSswKQYD
# VQQDEyJDT01PRE8gUlNBIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTEwMDEx
# OTAwMDAwMFoXDTM4MDExODIzNTk1OVowgYUxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoT
# EUNPTU9ETyBDQSBMaW1pdGVkMSswKQYDVQQDEyJDT01PRE8gUlNBIENlcnRpZmlj
# YXRpb24gQXV0aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# kehUktIKVrGsDSTdxc9EZ3SZKzejfSNwAHG8U9/E+ioSj0t/EFa9n3Byt2F/yUsP
# F6c947AEYe7/EZfH9IY+Cvo+XPmT5jR62RRr55yzhaCCenavcZDX7P0N+pxs+t+w
# gvQUfvm+xKYvT3+Zf7X8Z0NyvQwA1onrayzT7Y+YHBSrfuXjbvzYqOSSJNpDa2K4
# Vf3qwbxstovzDo2a5JtsaZn4eEgwRdWt4Q08RWD8MpZRJ7xnw8outmvqRsfHIKCx
# H2XeSAi6pE6p8oNGN4Tr6MyBSENnTnIqm1y9TBsoilwie7SrmNnu4FGDwwlGTm0+
# mfqVF9p8M1dBPI1R7Qu2XK8sYxrfV8g/vOldxJuvRZnio1oktLqpVj3Pb6r/SVi+
# 8Kj/9Lit6Tf7urj0Czr56ENCHonYhMsT8dm74YlguIwoVqwUHZwK53Hrzw7dPamW
# oUi9PPevtQ0iTMARgexWO/bTouJbt7IEIlKVgJNp6I5MZfGRAy1wdALqi2cVKWlS
# ArvX31BqVUa/oKMoYX9w0MOiqiwhqkfOKJwGRXa/ghgntNWutMtQ5mv0TIZxMOmm
# 3xaG4Nj/QN370EKIf6MzOi5cHkERgWPOGHFrK+ymircxXDpqR+DDeVnWIBqv8mqY
# qnK8V0rSS527EPywTEHl7R09XiidnMy/s1Hap0flhFMCAwEAAaNCMEAwHQYDVR0O
# BBYEFLuvfgI9+qbxPISOre44mOzZMjLUMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
# Af8EBTADAQH/MA0GCSqGSIb3DQEBDAUAA4ICAQAK8dVGhLeuUbtssk1BFACTTJzL
# 5cBUz6AljgL5/bCiDfUgmDwTLaxWorDWfhGS6S66ni6acrG9GURsYTWimrQWEmla
# jOHXPqQa6C8D9K5hHRAbKqSLesX+BabhwNbI/p6ujyu6PZn42HMJWEZuppz01yfT
# ldo3g3Ic03PgokeZAzhd1Ul5ACkcx+ybIBwHJGlXeLI5/DqEoLWcfI2/LpNiJ7c5
# 2hcYrr08CWj/hJs81dYLA+NXnhT30etPyL2HI7e2SUN5hVy665ILocboaKhMFrEa
# mQroUyySu6EJGHUMZah7yyO3GsIohcMb/9ArYu+kewmRmGeMFAHNaAZqYyF1A4CI
# im6BxoXyqaQt5/SlJBBHg8rN9I15WLEGm+caKtmdAdeUfe0DSsrw2+ipAT71VpnJ
# Ho5JPbvlCbngT0mSPRaCQMzMWcbmOu0SLmk8bJWx/aode3+Gvh4OMkb7+xOPdX9M
# i0tGY/4ANEBwwcO5od2mcOIEs0G86YCR6mSceuEiA6mcbm8OZU9sh4de826g+XWl
# m0DoU7InnUq5wHchjf+H8t68jO8X37dJC9HybjALGg5Odu0R/PXpVrJ9v8dtCpOM
# pdDAth2+Ok6UotdubAvCinz6IPPE5OXNDajLkZKxfIXstRRpZg6C583OyC2mUX8h
# wTVThQZKXZ+tuxtfdDCCBeAwggPIoAMCAQICEC58h8wOk0pS/pT9HLfNNK8wDQYJ
# KoZIhvcNAQEMBQAwgYUxCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1h
# bmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBM
# aW1pdGVkMSswKQYDVQQDEyJDT01PRE8gUlNBIENlcnRpZmljYXRpb24gQXV0aG9y
# aXR5MB4XDTEzMDUwOTAwMDAwMFoXDTI4MDUwODIzNTk1OVowfTELMAkGA1UEBhMC
# R0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9y
# ZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxIzAhBgNVBAMTGkNPTU9ETyBS
# U0EgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAppiQY3eRNH+K0d3pZzER68we/TEds7liVz+TvFvjnx4kMhEna7xRkafPnp4l
# s1+BqBgPHR4gMA77YXuGCbPj/aJonRwsnb9y4+R1oOU1I47Jiu4aDGTH2EKhe7VS
# A0s6sI4jS0tj4CKUN3vVeZAKFBhRLOb+wRLwHD9hYQqMotz2wzCqzSgYdUjBeVoI
# zbuMVYz31HaQOjNGUHOYXPSFSmsPgN1e1r39qS/AJfX5eNeNXxDCRFU8kDwxRstw
# rgepCuOvwQFvkBoj4l8428YIXUezg0HwLgA3FLkSqnmSUs2HD3vYYimkfjC9G7WM
# crRI8uPoIfleTGJ5iwIGn3/VCwIDAQABo4IBUTCCAU0wHwYDVR0jBBgwFoAUu69+
# Aj36pvE8hI6t7jiY7NkyMtQwHQYDVR0OBBYEFCmRYP+KTfrr+aZquM/55ku9Sc4S
# MA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMBEGA1UdIAQKMAgwBgYEVR0gADBMBgNVHR8ERTBDMEGgP6A9hjto
# dHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5LmNybDBxBggrBgEFBQcBAQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9j
# cnQuY29tb2RvY2EuY29tL0NPTU9ET1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIB
# AAI/AjnD7vjKO4neDG1NsfFOkk+vwjgsBMzFYxGrCWOvq6LXAj/MbxnDPdYaCJT/
# JdipiKcrEBrgm7EHIhpRHDrU4ekJv+YkdK8eexYxbiPvVFEtUgLidQgFTPG3UeFR
# AMaH9mzuEER2V2rx31hrIapJ1Hw3Tr3/tnVUQBg2V2cRzU8C5P7z2vx1F9vst/dl
# CSNJH0NXg+p+IHdhyE3yu2VNqPeFRQevemknZZApQIvfezpROYyoH3B5rW1CIKLP
# DGwDjEzNcweU51qOOgS6oqF8H8tjOhWn1BUbp1JHMqn0v2RH0aofU04yMHPCb7d4
# gp1c/0a7ayIdiAv4G6o0pvyM9d1/ZYyMMVcx0DbsR6HPy4uo7xwYWMUGd8pLm1Gv
# TAhKeo/io1Lijo7MJuSy2OU4wqjtxoGcNWupWGFKCpe0S0K2VZ2+medwbVn4bSoM
# fxlgXwyaiGwwrFIJkBYb/yud29AgyonqKH4yjhnfe0gzHtdl+K7J+IMUk3Z9ZNCO
# zr41ff9yMU2fnr0ebC+ojwwGUPuMJ7N2yfTm18M04oyHIYZh/r9VdOEhdwMKaGy7
# 5Mmp5s9ZJet87EUOeWZo6CLNuO+YhU2WETwJitB/vCgoE/tqylSNklzNwmWYBp7O
# SFvUtTeTRkF8B93P+kPvumdh/31J4LswfVyA4+YWOUunMYIE2TCCBNUCAQEwgZEw
# fTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
# A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxIzAhBgNV
# BAMTGkNPTU9ETyBSU0EgQ29kZSBTaWduaW5nIENBAhAW1PdTHZsYJ0/yJnM0UYBc
# MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MCMGCSqGSIb3DQEJBDEWBBS0GZ2jntJfIeSDLdJedpbJs5Ef7TANBgkqhkiG9w0B
# AQEFAASCAQBD9DXJTU5xWRg9Za5dx6KP/rwaWmWwR8fcwaHM9GRaFO5IgBIhghVT
# cBj8otRj6w0JVLDEhiMdB+5TEQnwevbIsNVKt8Z6PPb6XkbQU2Z9Esv85ZGxktdS
# hZAPEZRr0ceIZAUyjdUHaAxcCFxBJrJzv2C8F4tWhhFTxo0YWqyPYohJhh6vxNZl
# 0TfOSxyzD1MuxHKDWo5pEC23+2A34J3i+ezP1/z68FssIJb+YjCXpZfqxqFJ3IPj
# 2zycbOVo0nNUbqn3/iR0xWGbUbCxo+gkjhUP/xgP70uXje8QggT5wWEiFFMmaBdk
# uTlfNhKckP547Bdiev4UGdFj+PrRuxOloYICojCCAp4GCSqGSIb3DQEJBjGCAo8w
# ggKLAgEBMGgwUjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYt
# c2ExKDAmBgNVBAMTH0dsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gRzICEhEh
# 1pmnZJc+8fhCfukZzFNBFDAJBgUrDgMCGgUAoIH9MBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MTAxMjEzMTMwOFowIwYJKoZIhvcN
# AQkEMRYEFJ7f9C/JHOFQGpyo7EQwUH+nhBWbMIGdBgsqhkiG9w0BCRACDDGBjTCB
# ijCBhzCBhAQUY7gvq2H1g5CWlQULACScUCkz7HkwbDBWpFQwUjELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMTH0dsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gRzICEhEh1pmnZJc+8fhCfukZzFNBFDANBgkq
# hkiG9w0BAQEFAASCAQAX4PwqC5cH3PwFZXH587C6atcr+ZWixMuJKmndxMEqI5j4
# rqjIHREBFR2jqupYln4JwU6RAlL/bfU1tS7EMBVA6Sb3TtVzXQNyLNpsBfXu6t5u
# s6IvJbTZNQt5I9SuQl2f0oKIeBOLyybhv925091qQM3y3LXNUy0MlqeM9GaCjfkJ
# 1HBdQPErjdC+bfK5bO3Cxv8UVbkTfL0hc3ws+MMmyoCrv2BDDxS+HQQ1NSXSwMGO
# Ki7dMyP3dYkDDbSm1kdDV5Ca8CHSuF3UAdX9SRF+/VAcbn35rjSDDJY4FhwNrua/
# DRo1+SoMJPI4NpCHOLkGMu7IH+Iv/IjQJTRAJb6r
# SIG # End signature block
