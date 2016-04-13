<#
	.SYNOPSIS
		NET-Experts PowerShell Support for JetBrains YouTrack Rest API

	.DESCRIPTION
		Easy way to access the JetBrains YouTrack API from PowerShell

		This is just the initial version that we published!
		We have a lot more functions, but we need to test them a bit more before we release them to the public!

		Some of the commands/functions might make no sense if you look at them!
		We wrote them cause we use them from out other modules and out our support portal.
		Due to the fact that we run everything from a central Portal, we need to automate everything.

	.NOTES
		This is the first Module that we release as Open Source and under the terms of the BSD license terms.
		Our other Modules will not be published under this terms (at least not yet!)

		Some commands used within here are not published as Open Source, they are part of our commercial PowerShell ToolBox!
		We tried to make the commands as independent as possible, so everything should work without the rest of our stuff.

		If you find any problems, please let use know via the GitHub Tracker: https://github.com/jhochwald/NETX/issues

		Feel free to contribute by give some feedback :-)

		BuildNumber = "1.2.3.0"

		modified by     : Joerg Hochwald
		last modified   : 2016-04-13

	.LINK
		NET-Experts http:/www.net-experts.net

	.LINK
		Support https://github.com/jhochwald/NETX/issues

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/YouTrack+REST+API+Reference

	.EXTERNALHELP
		NETX.Tools.psm1-Help.xml
#>

#.EXTERNALHELP NETX.YouTrack.psm1-Help.xml

#region License

<#
	Copyright (c) 2012-2016, NET-Experts <http:/www.net-experts.net>.
	All rights reserved.

	Redistribution and use in source and binary forms, with or without modification,
	are permitted provided that the following conditions are met:

	1. Redistributions of source code must retain the above copyright notice, this list of
	   conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright notice,
	   this list of conditions and the following disclaimer in the documentation and/or
	   other materials provided with the distribution.

	3. Neither the name of the copyright holder nor the names of its contributors may
	   be used to endorse or promote products derived from this software without
	   specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
	IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
	AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
	OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.

	By using the Software, you agree to the License, Terms and Conditions above!
#>

#endregion License

#region ModuleDefaults

# Temp Change to the Module Directory
Push-Location $PSScriptRoot

# Start the Module Loading Mode
$LoadingModule = $true

#endregion ModuleDefaults

#region Externals

#endregion Externals

#region Functions

function Get-NETXYouTrackVersion {
<#
	.SYNOPSIS
		Internal Function to display the version string of the Module

	.DESCRIPTION
		This function displays the Module version!

	.PARAMETER s
		Displays the Version Number

	.EXAMPLE
		PS C:\> Get-NETXYouTrackVersion
		NET-Experts PowerShell Support for JetBrains YouTrack Rest API Version 1.2.3.0

		Description
		-----------
		Internal function to display the version string of the Tools Module

	.EXAMPLE
		PS C:\> Get-NETXYouTrackVersion -s
		1.2.3.0

		Description
		-----------
		Displays the Version Number

	.NOTES
		For internal Support
		Version/Build will be updated by the NETX Build Server!
#>
	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	[OutputType([System.String])]
	param
	(
		[Parameter(Mandatory = $false,
				   Position = 0,
				   HelpMessage = 'Displays just the Version Number')]
		[Alias('short')]
		[switch]$s
	)

	BEGIN {
		# Module Build number
		# DO NOT EDIT THIS FIELD!!!
		$BuildNumber = "1.2.3.0"
	}

	PROCESS {
		# Long or short output?
		if ($s) {
			if ($pscmdlet.ShouldProcess("Version", "Get Version Number")) {
				# This is just the Build/Version
				Write-Output "$BuildNumber"
			}
		} else {
			if ($pscmdlet.ShouldProcess("Version", "Get Version Number and details")) {
				# This is the full String
				Write-Output "NET-Experts PowerShell Support for JetBrains YouTrack Rest API Version $BuildNumber"
			}
		}
	}
}

function Initialize-YouTrackConnection {
<#
	.SYNOPSIS
		Connect to the given YouTrack service

	.DESCRIPTION
		This function connects to a given YouTrack service using the REST API to authenticate and returns the web request session object.

	.PARAMETER YouTrackUser
		Specify the user to use for authenticating with JetBrains YouTrack REST API.

	.PARAMETER YouTrackPassword
		Specify the password to use for authenticating with JetBrains YouTrack REST API.

	.PARAMETER YouTrackURI
		Specify the Uri of the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Initialize-YouTrackConnection -YouTrackUser 'john.doe' -YouTrackPassword 'P@55Word!' -YouTrackURI 'https://issues.contoso.com:8443'

		Description
		-----------
		This will establish a connection to the JetBrains YouTrack API 'https://issues.contoso.com:8443' and connects with the login credentials of the given account.
		It will save the authorization inf o in the Variable 'YouTrackWebSession'. You can re-Use this by '$YouTrackWebSession' as long as the session is active.
		If you close the session, or the Timeout hits, just run this function again!

	.NOTES
		The JetBrains Example regarding the Auth is a bit wired! They append the User and password to the request URL and everybody who can see the traffic can see this info!
		So I changed it to "x-www-form-urlencoded" and put the User and password in the body. Still not cool (secure), but if you use SSL it should be OK because then it is still in the body and this is never transfered in clear text.
		They do the same in some of the examples theypublished and I think this is much better!

		JetBrains wants us to use OAuth 2.0 with the Hub instance, but this was to complicated for me right now. I will do that later cause I do not have the standalone Hub yet :-)

	.LINK
		LoginInfo https://confluence.jetbrains.com/display/YTD65/Log+in+to+YouTrack

	.LINK
		OAuthInfo https://www.jetbrains.com/help/hub/1.0/OAuth-2.0-Authorization.html?origin=old_help

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/YouTrack+REST+API+Reference
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'Specify the user to use for authenticating with JetBrains YouTrack REST API.')]
		[Alias('User')]
		[System.String]$YouTrackUser,
		[Parameter(ValueFromPipeline = $true,
				   Position = 2,
				   HelpMessage = 'Specify the password to use for authenticating with JetBrains YouTrack REST API.')]
		[Alias('Password')]
		[System.String]$YouTrackPassword,
		[Parameter(ValueFromPipeline = $true,
				   Position = 3,
				   HelpMessage = 'Specify the Uri of the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Scope:Global -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Does our default Auth variable exist?
		if ($Credentials) {
			# Read the User from the existing variable
			Set-Variable -Name "YouTrackUser" -Value $(($Credentials.GetNetworkCredential()).UserName -replace "@$localDomain", "")

			# Do we have the UPN here?
			if ($YouTrackUser -like "*@*") {
				# OK, this is a UPN! We remove the Domain Part...
				Set-Variable -Name "YouTrackUser" -Value $((($Credentials.GetNetworkCredential()).UserName).Split("@")[0])
			}

			# Read the Password from the existing variable
			Set-Variable -Name "YouTrackPassword" -Value $(($Credentials.GetNetworkCredential()).Password)
		} elseif ((Get-Command Invoke-AuthO365 -ErrorAction:SilentlyContinue)) {
			# Get the credentials
			try {
				# Try the new auto connect feature for your convenience
				if (Get-Command tryAutoLogin -ErrorAction:SilentlyContinue) {
					# Lets try the new command
					(Get-tryAutoLogin)
				}

				# Use our internal function to get the credentials
				Invoke-AuthO365
			} catch {
				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		} else {
			Write-Error -Message "Credentials are mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri/rest/user/login", "Login")) {
			try {
				# Cleanup
				Remove-Variable -Name "YouTrackWebSessionTemp" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
				Remove-Variable -Name "YouTrackWebSession" -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

				# Build the Body
				Set-Variable -Name "YouTrackWebBody" -Value "login=$YouTrackUser&password=$YouTrackPassword"

				# Remove the Clear text password
				Remove-Variable -Name "YouTrackPassword" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

				# Fire it up!
				$null = (Invoke-RestMethod -Method "Post" -Uri "$YouTrackUri/rest/user/login" -Body $YouTrackWebBody -SessionVariable "YouTrackWebSessionTemp" -ContentType "application/x-www-form-urlencoded" -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)

				# Save the Session as persistant info for all other calls
				if ($YouTrackWebSessionTemp) {
					Set-Variable -Name "YouTrackWebSession" -Scope:Global -Value $($YouTrackWebSessionTemp)

					# Remove the temp variable
					Remove-Variable -Name "YouTrackWebSessionTemp" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
				} else {
					Write-Error "Unable to Autheticate" -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} finally {
				# Remove the Clear text password
				Remove-Variable -Name "YouTrackWebBody" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
				Remove-Variable -Name "YouTrackPassword" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
			}
		}
	}

	END {
		# Cleanup
		Remove-Variable -Name "YouTrackWebBody" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name "YouTrackPassword" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Remove-Variable -Name "YouTrackUser" -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue

		# Save the URI for other calls!
		Remove-Variable -Name "YouTrackURIGlobal" -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
		Set-Variable -Name "YouTrackURIGlobal" -Scope:Global -Value $($YouTrackURI)
	}
}
# Set a compatibility Alias
(Set-Alias Initialize-YTCon Initialize-YouTrackConnection -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function New-YouTrackItem {
<#
	.SYNOPSIS
		Creates a new item in a given JetBrains YouTrack project.

	.DESCRIPTION
		Creates a new item in a given JetBrains YouTrack project.
		Open an Issue, Bug Report or whatever you like to do with it.

	.PARAMETER YouTrackProject
		Specify the name of the project to create the item.

	.PARAMETER YouTrackSummary
		Specify the summary information for the item.

	.PARAMETER YouTrackDescription
		Specify the description information for the item.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackURI
		Specify the Uri of the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> New-YouTrackItem -YouTrackProject "WEBSUPPORT" -YouTrackSummary "CSS Problem" -YouTrackDescription "Some Styles are wrong when I access the site via my Edge browser. Works fine in IE."
		WEBSUPPORT-4711

		Description
		-----------
		Generates an Issue in the YouTrack Project 'WEBSUPPORT'. The Issue has the Title 'CSS Problem' and the Description 'Some Styles are wrong when I access the site via my Edge browser. Works fine in IE.'.
		The Issue generated is 'WEBSUPPORT-4711'

	.EXAMPLE
		PS C:\> $MyNewTicket = (New-YouTrackItem -YouTrackProject "WEBSUPPORT" -YouTrackSummary "CSS Problem" -YouTrackDescription "Some Styles are wrong when I access the site via my Edge browser. Works fine in IE.")
		WEBSUPPORT-4711

		Description
		-----------
		Generates an Issue in the YouTrack Project 'WEBSUPPORT'. The Issue has the Title 'CSS Problem' and the Description 'Some Styles are wrong when I access the site via my Edge browser. Works fine in IE.'.
		The Issue number is saved in the variable '$MyNewTicket' (e.g. something like WEBSUPPORT-4711), so you can reuse it to modify the new issue right after it is created!

	.NOTES
		The Call of this function is based on an idea of Dean Grant <https://deangrant.wordpress.com/tag/powershell/>
		I needed to adopt his Invoke-WebRequest based call cause my favorite Invoke-RestMethod returned 0 bytes all the time.

	.Link
		Source https://github.com/dean1609/PowerShell/blob/master/Functions/New-YouTrackItem.ps1
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	[OutputType([System.String])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'Specify the name of the project to create the item.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Project')]
		[System.String]$YouTrackProject,
		[Parameter(ValueFromPipeline = $true,
				   Position = 2,
				   HelpMessage = 'Specify the summary information for the item.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Summary')]
		[System.String]$YouTrackSummary,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the description information for the item.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Description')]
		[System.String]$YouTrackDescription,
		[Parameter(Position = 4,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession),
		[Parameter(HelpMessage = 'Specify the Uri of the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackURI", "Create Item $YouTrackSummary in $YouTrackProject")) {
			try {
				$YouTrackNewItemCall = (Invoke-WebRequest -Method "Put" -Uri "$YouTrackURI/rest/issue?project=$YouTrackProject&summary=$YouTrackSummary&description=$YouTrackDescription" -WebSession $YouTrackSession -UseBasicParsing -ErrorAction:Stop -WarningAction:SilentlyContinue)

				# Regular expression pattern match from the response header information to return the project item issue number.
				$YouTrackNewItem = ([regex]::Matches($YouTrackNewItemCall.Headers.Location, '[^/]+$')).Value
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Returns the value of the project item issue number.
		Return $YouTrackNewItem
	}
}
# Set a compatibility Alias
(Set-Alias New-YTItem New-YouTrackItem -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Approve-YouTrackItemExists {
<#
	.SYNOPSIS
		Check if the Item exists in YouTrack

	.DESCRIPTION
		Helper function to do a basic check if a given issue exists in YouTrack or not.
		It return a simple Boolean as indicator.

	.PARAMETER YouTrackItem
		YouTrack item that should be checked

	.PARAMETER YouTrackURI
		Specify the Uri of the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Approve-YouTrackItemExists -YouTrackItem 'SUPPORT-4711' -YouTrackURI 'https://support.contoso.com:8443'
		True

		Description
		-----------
		Check if the Item "SUPPORT-4711" exists. The Return (True) indicates that this item exists.

	.EXAMPLE
		PS C:\> Approve-YouTrackItemExists -YouTrackItem 'SUPPORT-4711'
		False

		Description
		-----------
		Check if the Item "SUPPORT-4711" exists. The Return (False) indicates that this item doesn't exists.
		We leave the URI and YouTrackSession variables empty, that indicates that the defaults are used and the URI is set via the Initialize-YouTrackConnection command

	.EXAMPLE
		$MyIssue = 'SUPPORT-4711'
		if ((Approve-YouTrackItemExists -YouTrackItem $MyIssue) -eq $true) {
			# So something with this issue
		} else {
			Write-Error "Sorry, but $MyIssue was not found"
		}

		Description
		-----------
		Simple example that checks if a given Issue exists. If not it drops an Error. Within the IF you can do something useful.

	.NOTES
		Simple Call that I use within my other calls. So I make sure that the issue exists before I go any further and try to do something with it.

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Check+that+an+Issue+Exists
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'YouTrack Iten that should be checked')]
		[ValidateNotNullOrEmpty()]
		[Alias('Item')]
		[System.String]$YouTrackItem,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the Uri of the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession)
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if it exists")) {
			try {
				$null = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackURI/rest/issue/$YouTrackItem/exists" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue) > $null 2>&1 3>&1
				Return $true
			} catch {
				Return $false
			}
		}
	}

	END {
		# Cleanup
		Remove-Variable -Name "YouTrackItem" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}
# Set a compatibility Alias
(Set-Alias Approve-YTItem Approve-YouTrackItemExists -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItemList {
<#
	.SYNOPSIS
		Get a list of all Items in YouTrack

	.DESCRIPTION
		Get a list of all Items in YouTrack

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Get-YouTrackItemList -YouTrackURI 'https://support.contoso.com:8443'

		Description
		-----------
		Get a list of all existing items in YouTrack and dumps it to the console.

	.EXAMPLE
		PS C:\> $YTReport = @(Get-YouTrackItemList -YouTrackURI 'https://support.contoso.com:8443')

		Description
		-----------
		Get a list of all existing items in YouTrack and put it to the '$YTReport' object, so you can re use it within other functions, scripts, whatever.

	.NOTES
		The Call supports a lot of filters, nice, but I filter everything in PowerShell later. So I don't use them here.
		Take a look at there documentation if you like to use the filters within the call.

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Get+the+List+of+Issues
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Position = 1,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession)
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri", "List items")) {
			try {
				$YouTrackItemList = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackUri/rest/issue" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Dump The info
		Return ($YouTrackItemList).issueCompacts.issue
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTItemList Get-YouTrackItemList -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItemListInProject {
<#
	.SYNOPSIS
		Get a list of all Items in a given YouTrack Project

	.DESCRIPTION
		Get a list of all Items in a given YouTrack Project

	.PARAMETER YouTrackProject
		ProjectID of a project to get issues from.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER wikify
		Issue description in the response should be formatted.

	.EXAMPLE
		PS C:\> Get-YouTrackItemListInProject -YouTrackProject 'SUPPORT' -YouTrackURI 'https://support.contoso.com:8443'

		Description
		-----------
		Get a list of all existing items in YouTrack Project 'SUPPORT' and dumps it to the console.

	.EXAMPLE
		PS C:\> $YTReport = @(Get-YouTrackItemListInProject -YouTrackProject 'SUPPORT' -YouTrackURI 'https://support.contoso.com:8443')

		Description
		-----------
		Get a list of all existing items in YouTrack Project 'SUPPORT' and put it to the '$YTReport' object, so you can re use it within other functions, scripts, whatever.

	.EXAMPLE
		PS C:\> $YTReport = @(Get-YouTrackItemListInProject -YouTrackProject 'SUPPORT' -YouTrackURI 'https://support.contoso.com:8443' -wikify)

		Description
		-----------
		Get a list of all existing items in YouTrack Project 'SUPPORT' and puty it to the '$YTReport' object, so you can re use it within other functions, scripts, whatever.
		Issue description in the response should be formatted while the 'wikify' switch is used.

	.NOTES
		The Call supports a lot of filters, nice, but I filter everything in PowerShell later. So I don't use them here.
		Take a look at there documentation if you like to use the filters within the call.

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Get+the+List+of+Issues
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'ProjectID of a project to get issues from.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Project')]
		[System.String]$YouTrackProject,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession),
		[Parameter(HelpMessage = 'Issue description in the response should be formatted.')]
		[Alias('wikifyDescription')]
		[switch]$wikify
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri", "List items in $YouTrackProject")) {
			try {
				if ($wikify) {
					$YouTrackItemList = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackUri/rest/issue/byproject/$YouTrackProject/?wikifyDescription=true" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
				} else {
					$YouTrackItemList = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackUri/rest/issue/byproject/$YouTrackProject/" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
				}
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Dump the info
		Return ($YouTrackItemList).issues.issue
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTProjectItems Get-YouTrackItemListInProject -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItem {
<#
	.SYNOPSIS
		Get details about a given YouTrackItem

	.DESCRIPTION
		Get details about a given YouTrackItem

	.PARAMETER YouTrackItem
		The YouTrack item to search for.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER wikify
		Issue description in the response should be formatted.

	.EXAMPLE
		PS C:\> Get-YouTrackItem -YouTrackItem 'Value1' -YouTrackURI 'Value2'

		Description
		-----------
		Get details about a given YouTrackItem

	.NOTES
		You need to Filter it in PowerShell to make this useful!
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'The YouTrack item to search for.')]
		[Alias('Item')]
		[System.String]$YouTrackItem,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession,
		[Parameter(HelpMessage = 'Issue description in the response should be formatted.')]
		[switch]$wikify
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Now we check that the given item exists in YouTrack
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if exists")) {
			if ((Approve-YouTrackItemExists -YouTrackItem $YouTrackItem) -eq $false) {
				Write-Error -Message "Looks like $YouTrackItem does not exist" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Get details")) {
			try {
				if ($wikify) {
					$YouTrackItemDetails = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackURI/rest/issue/$YouTrackItem/?wikifyDescription=true" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
				} else {
					$YouTrackItemDetails = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackURI/rest/issue/$YouTrackItem" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
				}
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Dump the info
		Return ($YouTrackItemDetails).issue
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTItem Get-YouTrackItem -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1


function Get-YouTrackItemHistory {
<#
	.SYNOPSIS
		Get history details about a given YouTrackItem

	.DESCRIPTION
		Get History details about a given YouTrackItem

	.PARAMETER YouTrackItem
		The YouTrack item to search for.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Get-YouTrackItemHistory -YouTrackItem 'Value1' -YouTrackURI 'Value2'

		Description
		-----------
		Get history details about a given YouTrackItem

	.NOTES
		You need to Filter it in PowerShell to make this useful!
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'The YouTrack item to search for.')]
		[Alias('Item')]
		[System.String]$YouTrackItem,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Now we check that the given item exists in YouTrack
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if exists")) {
			if ((Approve-YouTrackItemExists -YouTrackItem $YouTrackItem) -eq $false) {
				Write-Error -Message "Looks like $YouTrackItem does not exist" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Get history details")) {
			try {
				$YouTrackItemHistory = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackURI/rest/issue/$YouTrackItem/history" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Dump the info
		Return ($YouTrackItemHistory).issues.issue
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTItemHistory Get-YouTrackItemHistory -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItemChanges {
<#
	.SYNOPSIS
		Get historical changes of an YouTrack Item

	.DESCRIPTION
		Get historical changes of an YouTrack Item

	.PARAMETER YouTrackItem
		The YouTrack item to search for.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Get-YouTrackItemChanges -YouTrackItem 'Value1' -YouTrackURI 'Value2'

		Description
		-----------
		Get historical changes of an YouTrack Item

	.NOTES
		You need to Filter it in PowerShell to make this useful!
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'The YouTrack item to search for.')]
		[Alias('Item')]
		[System.String]$YouTrackItem,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Now we check that the given item exists in YouTrack
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if exists")) {
			if ((Approve-YouTrackItemExists -YouTrackItem $YouTrackItem) -eq $false) {
				Write-Error -Message "Looks like $YouTrackItem does not exist" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Get a list of changes")) {
			try {
				$YouTrackItemChanges = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackURI/rest/issue/$YouTrackItem/changes" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Dump the info
		Return ($YouTrackItemChanges).changes.change
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTItemChanges Get-YouTrackItemChanges -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Remove-YouTrackItem {
<#
	.SYNOPSIS
		Delete a specified YouTrack Item

	.DESCRIPTION
		Delete a specified YouTrack Item

	.PARAMETER YouTrackItem
		The YouTrack item to delete.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Remove-YouTrackItem -YouTrackItem $value1 -YouTrackURI $value2

		Description
		-----------
		Delete a specified YouTrack Item

	.NOTES
		Mind the Gap! Delete an Item is dangerous... And it might be something you should avoid doing!

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Delete+an+Issue
#>

	[CmdletBinding(ConfirmImpact = 'Medium',
				   SupportsShouldProcess = $true)]
	[OutputType([System.String])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'The YouTrack item to delete.')]
		[Alias('Item')]
		[System.String]$YouTrackItem,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Now we check that the given item exists in YouTrack
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if exists")) {
			if ((Approve-YouTrackItemExists -YouTrackItem $YouTrackItem) -eq $false) {
				Write-Error -Message "Looks like $YouTrackItem does not exist" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Delete")) {
			try {
				$YouTrackItemToDelete = (Invoke-RestMethod -Method "Delete" -Uri "$YouTrackURI/rest/issue/$YouTrackItem" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
				return "$YouTrackItem deleted"
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}
}
# Set a compatibility Alias
(Set-Alias Remove-YTItem Remove-YouTrackItem -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Update-YouTrackItem {
<#
	.SYNOPSIS
		Update summary and description for an specified YouTrack Item.

	.DESCRIPTION
		Update summary and description for an specified YouTrack Item.

	.PARAMETER YouTrackItem
		The YouTrack item to delete.

	.PARAMETER YouTrackSummary
		Specify the summary information for the item.

	.PARAMETER YouTrackDescription
		Specify the description information for the item.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Update-YouTrackItem -YouTrackItem 'SUPPORT-4711' -YouTrackSummary 'New Summary' -YouTrackURI 'https://support.contoso.com:8443'

		Description
		-----------
		Will update the Item 'SUPPORT-4711' and change the summary/title to 'New Summary'

	.EXAMPLE
		PS C:\> Update-YouTrackItem -YouTrackItem 'SUPPORT-4711' -YouTrackSummary 'Not working on PowerShell 5' -YouTrackDescription 'Tried the function on Windows 10 (PowerShell 5) and it soe nothing. There is no error message, just did nothing.'

		Description
		-----------
		Will update the Item 'SUPPORT-4711' and change the summary/title to 'Not working on PowerShell 5' and it also updates the description field of the item.

	.NOTES
		Please note that this POST method allows updating issue summary and/or description, only. To update issue fields, please use method to Apply Command to an Issue.

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Update+an+Issue
#>

	[CmdletBinding(ConfirmImpact = 'Medium',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'The YouTrack item to delete.')]
		[Alias('Item')]
		[System.String]$YouTrackItem,
		[Parameter(ValueFromPipeline = $true,
				   Position = 2,
				   HelpMessage = 'Specify the summary information for the item.')]
		[Alias('Summary')]
		[System.String]$YouTrackSummary,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the description information for the item.')]
		[Alias('Description')]
		[System.String]$YouTrackDescription,
		[Parameter(Position = 4,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 5,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Now we check that the given item exists in YouTrack
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if exists")) {
			if ((Approve-YouTrackItemExists -YouTrackItem $YouTrackItem) -eq $false) {
				Write-Error -Message "Looks like $YouTrackItem does not exist" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}

		# What to call
		$YouTrackUpdateURIInitial = "$YouTrackURI/rest/issue/$YouTrackItem"

		# Set a new variable with the original value
		$YouTrackUpdateURI = ($YouTrackUpdateURIInitial)

		# Do we have the info?
		if ($YouTrackSummary) {
			$YouTrackUpdateURI = ($YouTrackUpdateURI + "?summary=$YouTrackSummary")
		} else {
			Write-Warning -Message "You must specify a Summary, even if do not change it. The API rejects updates without a Summary (Throws an error 400 - Bad Request.)"

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Do we have a description?
		if ($YouTrackDescription) {
			$YouTrackUpdateURI = ($YouTrackUpdateURI + "&description=$YouTrackDescription")

		}

		# Check the URI by comparing it with the original
		if ($YouTrackUpdateURI -eq $YouTrackUpdateURIInitial) {
			Write-Warning -Message "Nothing to Update"

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Update")) {
			try {
				$YouTrackItemToUpdate = (Invoke-RestMethod -Method "Post" -Uri $YouTrackUpdateURI -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}
}
# Set a compatibility Alias
(Set-Alias Update-YTItem Update-YouTrackItem -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItemCount {
<#
	.SYNOPSIS
		Get a list of all Items in YouTrack

	.DESCRIPTION
		Get a list of all Items in YouTrack

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER ReturnObject
		Return the values of oesolved and open as Object and not a human readable dump.

	.EXAMPLE
		PS C:\> Get-YouTrackItemCount -YouTrackURI 'https://support.contoso.com:8443'
		Resolved: 56
		Open: 24

		Description
		-----------
		Get a list of all Items in YouTrack, in this case 56 where solved/closed and 24 are open

	.EXAMPLE
		PS C:\> $YTItemStatus = @(Get-YouTrackItemCount -YouTrackURI 'https://support.contoso.com:8443' -ReturnObject)

		Description
		-----------
		Get a list of all Items in YouTrack and put the Object(!) to a Variable

	.NOTES
		The Call supports more parameters, but I stay with the default. Check out the API if you think you need some more options.

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Get+Number+of+Issues+for+Several+Queries
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Position = 1,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession),
		[Parameter(HelpMessage = 'Return the values of oesolved and open as Object and not a human readable dump.')]
		[switch]$ReturnObject
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Build the XML Body for this Request
		$YouTrackItemCountBody = @"
<queries>
 <query>#Resolved</query>
 <query>#Unresolved</query>
</queries>
"@
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri", "List items")) {
			try {
				# Fire up the Rest Request, this time we use ab Bit XML
				# Note: Convert this to  Json to get rid of XML soon - JH
				$YouTrackItemCount = (Invoke-RestMethod -Method "Post" -Uri "$YouTrackUri/rest/issue/counts" -ContentType "application/xml" -Body $YouTrackItemCountBody -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		if ($ReturnObject) {
			# Dump the info
			Return ($YouTrackItemCount).counts
		} else {
			# Dump the info human readable
			Write-Output "Resolved: $(($YouTrackItemCount).counts.count[0])"
			Write-Output "Open: $(($YouTrackItemCount).counts.count[1])"
		}
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTItemCount Get-YouTrackItemCount -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItemProjectCount {
<#
	.SYNOPSIS
		Get a list of all Items in YouTrack Project

	.DESCRIPTION
		Get a list of all Items in YouTrack Project

	.PARAMETER YouTrackProject
		ProjectID of a project to get issues from.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Get-YouTrackItemProjectCount -YouTrackProject 'SUPPORTWEB' -YouTrackURI 'https://support.contoso.com:8443'
		callback({"value":4})

		Description
		-----------
		Get a list of all Items in YouTrack project 'SUPPORTWEB', in this case 56 where solved/closed and 24 are open

	.EXAMPLE
		PS C:\> $YTItemStatus = @(Get-YouTrackItemProjectCount -YouTrackProject 'SUPPORTWEB' -YouTrackURI 'https://support.contoso.com:8443' -ReturnObject)

		Description
		-----------
		Get a list of all Items in YouTrack project 'SUPPORTWEB' and put the Object(!) to a Variable

	.NOTES
		The Call supports more parameters, but I stay with the default. Check out the API if you think you need some more options.

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Get+a+Number+of+Issues
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'ProjectID of a project to get issues from.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Project')]
		[System.String]$YouTrackProject,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession)
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		$YouTrackItemCountFilter = "project: $YouTrackProject"
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri", "List items")) {
			try {
				# Fire up the Rest Request, this time we use ab Bit XML
				$YouTrackItemCount = (Invoke-RestMethod -Method "GET" -Uri "$YouTrackUri/rest/issue/count?filter=$YouTrackItemCountFilter" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Dump the info
		Return ($YouTrackItemCount)
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTProjectCount Get-YouTrackItemProjectCount -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItemFiltered {
<#
	.SYNOPSIS
		Get a list of all Items in YouTrack selected by a given filter

	.DESCRIPTION
		Get a list of all Items in YouTrack selected by a given filter
		Very intelligent filtering is what makes JetBrains YouTrack so powerful!
		Just copy what you filtered in the "Enter search request" field of the Web interface and use it here with the YouTrackFilter parameter

	.PARAMETER YouTrackFilter
		ProjectID of a project to get issues from.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackCount
		Just a Number instead of the Object willed with the items.

	.EXAMPLE
		PS C:\> Get-YouTrackItemFiltered -YouTrackFilter 'project: SUPPORTWEB by: me'

		Description
		-----------
		Get a list of all Items in YouTrack project 'SUPPORTWEB' that you created

	.EXAMPLE
		PS C:\> $myTickets = (Get-YouTrackItemFiltered -YouTrackFilter 'project: SUPPORTWEB by: me')

		Description
		-----------
		Save a list of all Items in YouTrack project 'SUPPORTWEB' that you created in the variable "myTickets"

	.EXAMPLE
		PS C:\> Get-YouTrackItemFiltered -YouTrackFilter 'by: me' -YouTrackCount
		103

		Description
		-----------
		Get a number of all Items in YouTrack that you created

	.EXAMPLE
		PS C:\> Get-YouTrackItemFiltered -YouTrackFilter 'Subsystem: Deployment' -YouTrackCount
		16

		Description
		-----------
		Get a number of all Items in the YouTrack Subsystem "Deployment"

	.NOTES
		Very intelligent filtering is what makes JetBrains YouTrack so powerful! We use them here :-)
		Just copy what you filtered in the "Enter search request" field of the Web interface and use it here with the YouTrackFilter parameter

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Get+the+List+of+Issues
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'ProjectID of a project to get issues from.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Filter')]
		[System.String]$YouTrackFilter,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession),
		[Parameter(HelpMessage = 'Just a Number instead of the Object willed with the items.')]
		[switch]$YouTrackCount
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri", "List items")) {
			try {
				# Fire up the Rest Request, this time we use ab Bit XML
				$YouTrackItemCount = (Invoke-RestMethod -Method "GET" -Uri "$YouTrackUri/rest/issue?$YouTrackItemCountFilter" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		if ($YouTrackCount) {
			# Dump the info (Counter)
			Return ($YouTrackItemCount).issueCompacts.issue.Count
		} else {
			# Dump the info
			Return ($YouTrackItemCount).issueCompacts.issue
		}
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTFilterItem Get-YouTrackItemFiltered -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackItemIntellisense {
<#
	.SYNOPSIS
		Get highlight and suggestions for item filter query

	.DESCRIPTION
		Get highlight and suggestions for item filter query
		Very intelligent filtering is what makes JetBrains YouTrack so powerful!
		Just copy what you filtered in the "Enter search request" field of the Web interface and use it here with the YouTrackFilter parameter

	.PARAMETER YouTrackFilter
		ProjectID of a project to get issues from.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackCount
		Just a Number instead of the Object willed with the items.

	.EXAMPLE
		PS C:\> Get-YouTrackItemIntellisense -YouTrackFilter 'project: SUPPORTWEB by: me'

		Description
		-----------
		Get highlight and suggestions for items filter query in YouTrack project 'SUPPORTWEB' that you created

	.EXAMPLE
		PS C:\> $myTickets = (Get-YouTrackItemIntellisense -YouTrackFilter 'project: SUPPORTWEB by: me')

		Description
		-----------
		Save highlight and suggestions of all Items in YouTrack project 'SUPPORTWEB' that you created in the variable "myTickets"

	.EXAMPLE
		PS C:\> Get-YouTrackItemIntellisense -YouTrackFilter 'by: me' -YouTrackCount
		103

		Description
		-----------
		Get a number of highlight and suggestions for all Items in YouTrack that you created

	.EXAMPLE
		PS C:\> Get-YouTrackItemIntellisense -YouTrackFilter 'Subsystem: Deployment' -YouTrackCount
		16

		Description
		-----------
		Get a number of highlight and suggestions for all Items in the YouTrack Subsystem "Deployment"

	.NOTES
		Very intelligent filtering is what makes JetBrains YouTrack so powerful! We use them here :-)
		Just copy what you filtered in the "Enter search request" field of the Web interface and use it here with the YouTrackFilter parameter

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Intellisense+for+issue+search
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'ProjectID of a project to get issues from.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Filter')]
		[System.String]$YouTrackFilter,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession),
		[Parameter(HelpMessage = 'Just a Number instead of the Object willed with the items.')]
		[switch]$YouTrackCount
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri", "List items")) {
			try {
				# Fire up the Rest Request, this time we use ab Bit XML
				$YouTrackItemIntellisense = (Invoke-RestMethod -Method "GET" -Uri "$YouTrackUri/rest/issue/intellisense?$YouTrackItemCountFilter" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		if ($YouTrackCount) {
			# Dump the info (Counter)
			Return ($YouTrackItemIntellisense).IntelliSense.suggest.ChildNodes.Count
		} else {
			# Dump the info
			Return ($YouTrackItemIntellisense).IntelliSense.suggest
		}
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTItemIntelli Get-YouTrackItemIntellisense -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Set-YouTrackItemCommand {
<#
	.SYNOPSIS
		Apply a command to an YouTrack Item

	.DESCRIPTION
		Apply a command to an YouTrack Item

	.PARAMETER YouTrackItem
		The YouTrack item to search for.

	.PARAMETER YouTrackCommand
		A command to apply. A command might content a string of attributes and their values, that is: You can change multiple fields with one complex command. For example, the following command will set an issue's Type=Bug, Priority=Critical, Fix version=5.1, and will add tag regression

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Set-YouTrackItemCommand -YouTrackItem 'ISUP-28' -YouTrackCommand 'Priority Minor Type Task'

		Description
		-----------
		Set the Priority of the Item 'ISUP-28' to minor and set the Type to 'Task'.

	.NOTES
		You need to Filter it in PowerShell to make this useful!
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'The YouTrack item to search for.')]
		[Alias('Item')]
		[System.String]$YouTrackItem,
		[Parameter(Mandatory = $true,
				   Position = 2,
				   HelpMessage = 'A command to apply. A command might content a string of attributes and their values.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Command')]
		[System.String]$YouTrackCommand,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 4,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Now we check that the given item exists in YouTrack
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if exists")) {
			if ((Approve-YouTrackItemExists -YouTrackItem $YouTrackItem) -eq $false) {
				Write-Error -Message "Looks like $YouTrackItem does not exist" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}

		# Create the body for the x-www-form-urlencoded call
		$YouTrackWebBody = "command=$YouTrackCommand"
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Apply command $YouTrackCommand")) {
			try {
				$YouTrackItemCommand = (Invoke-RestMethod -Method "Post" -Uri "$YouTrackURI/rest/issue/$YouTrackItem/execute" -Body $YouTrackWebBody -WebSession $YouTrackWebSession -ContentType "application/x-www-form-urlencoded" -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	END {
		# Return Boolean (True)
		Return $true
	}
}
# Set a compatibility Alias
(Set-Alias Set-YTItemCmd Set-YouTrackItemCommand -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackStatus {
<#
	.SYNOPSIS
		Get telemetry parameters of YouTrack server

	.DESCRIPTION
		Get telemetry parameters of YouTrack server

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER Info
		Dump Info about Memory usage

	.PARAMETER User
		Dump Info about active users

	.PARAMETER All
		Dump all Infos

	.EXAMPLE
		PS C:\> Get-YouTrackStatus -YouTrackURI 'https://support.contoso.com:8443'
		availableMemory : 910.5 MB
		allocatedMemory : 345.0 MB
		uptime          : 19 hours, 8 minutes, 5 seconds and 84 milliseconds
		usedMemory      : 262.7 MB
		databaseSize    : 7.9 MB

		Description
		-----------
		Get telemetry parameters of YouTrack server

	.EXAMPLE
		PS C:\> Get-YouTrackStatus -User
		users    : 1
		sessions : 1
		windows  : 2

		Description
		-----------
		Get telemetry parameters of YouTrack server

	.EXAMPLE
		PS C:\> Get-YouTrackStatus -YouTrackURI 'https://support.contoso.com:8443'
		availableMemory : 910.5 MB
		allocatedMemory : 336.0 MB
		uptime          : 20 hours, 27 minutes, 19 seconds and 738 milliseconds
		usedMemory      : 251.2 MB
		databaseSize    : 8.2 MB

		users    : 1
		sessions : 1
		windows  : 2

		Description
		-----------
		Get telemetry parameters of YouTrack server

	.NOTES
		TDB

	.LINK
		https://confluence.jetbrains.com/display/YTD65/GET+Telemetry
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Position = 1,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession),
		[Parameter(HelpMessage = 'Dump Info about Memory usage')]
		[switch]$Info,
		[switch]$User,
		[switch]$All
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackUri", "Telemetry")) {
			try {
				$YouTrackTelemetry = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackUri/rest/admin/statistics/telemetry" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}

		# Save the infos to new variables
		$YouTrackTelemetry1 = (($YouTrackTelemetry).telemetry | Select-Object availableMemory, allocatedMemory, uptime, usedMemory, databaseSize)
		$YouTrackTelemetry2 = (($YouTrackTelemetry).telemetry.onlineUsers | Format-List)
	}

	END {
		# Dump The info
		if (($Info) -and (-not ($All))) {
			Write-Output -InputObject $YouTrackTelemetry1
		}

		if (($User) -and (-not ($All))) {
			Write-Output -InputObject $YouTrackTelemetry2
		}

		if (($All)) {
			Write-Output -InputObject $YouTrackTelemetry1
			Write-Output -InputObject $YouTrackTelemetry2
		}

		if ((-not ($Info)) -and (-not ($User)) -and (-not ($All))) {
			Write-Output -InputObject $YouTrackTelemetry1
		}

		# Cleanup
		$YouTrackTelemetry1 = $null
		$YouTrackTelemetry2 = $null
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTStatus Get-YouTrackStatus -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function New-YouTrackSubsystem {
<#
	.SYNOPSIS
		Add a Subsystem to a given JetBrains YouTrack project.

	.DESCRIPTION
		Add a Subsystem to a given JetBrains YouTrack project.

	.PARAMETER YouTrackProject
		Specify the name of the project to create the Subsystem.

	.PARAMETER YouTrackSubsystem
		Specify the Subsystem to add.

	.PARAMETER YouTrackDefaultAssignee
		Specify the default assignee for the new Subsystem.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackURI
		Specify the Uri of the JetBrains YouTrack API.

	.EXAMPLE
		New-YouTrackSubsystem -YouTrackProject 'dummy' -YouTrackSubsystem 'Test1'
		True

		Description
		-----------
		Generates the Subsystem 'Test1' in the YouTrack Project 'dummy'

	.EXAMPLE
		New-YouTrackSubsystem -YouTrackProject 'dummy' -YouTrackSubsystem 'Test1'
		New-YouTrackSubsystem : Error: The remote server returned an error: (409) Conflict. - Line Number: 86

		Description
		-----------
		Subsystem 'Test1' in the YouTrack Project 'dummy' exists!

	.EXAMPLE
		New-YouTrackSubsystem -YouTrackProject 'dummy' -YouTrackSubsystem 'Test1' -YouTrackDefaultAssignee 'John'

		Description
		-----------
		Generates the Subsystem 'Test1' in the YouTrack Project 'dummy' and use 'John' as default assignee

	.NOTES
		If the "-YouTrackDefaultAssignee" parameters is used, we use a x-www-form-urlencoded call

	.Link
		Source https://confluence.jetbrains.com/display/YTD65/REST+Import+Sample#RESTImportSample-Addfirstsubsystem
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'Specify the name of the project to create the item.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Project')]
		[System.String]$YouTrackProject,
		[Parameter(ValueFromPipeline = $true,
				   Position = 2,
				   HelpMessage = 'Specify the name of the project to create the Subsystem.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Subsystem')]
		[System.String]$YouTrackSubsystem,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the Subsystem to add.')]
		[ValidateNotNullOrEmpty()]
		[Alias('DefaultAssignee')]
		[System.String]$YouTrackDefaultAssignee,
		[Parameter(Position = 4,
				   HelpMessage = 'Specify the default assignee for the new Subsystem.')]
		[ValidateNotNullOrEmpty()]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession),
		[Parameter(HelpMessage = 'Specify the Uri of the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackURI", "Create Subsystem $YouTrackSubsystem in $YouTrackProject")) {
			try {
				if ($YouTrackDefaultAssignee) {
					# Create the body for the x-www-form-urlencoded call
					$YouTrackWebBody = "defaultAssignee=$YouTrackDefaultAssignee"

					# Fire up!
					$YouTrackNewItemCall = (Invoke-RestMethod -Method "Put" -Uri "$YouTrackURI/rest/admin/project/$YouTrackProject/subsystem/$YouTrackSubsystem" -Body $YouTrackWebBody -WebSession $YouTrackWebSession -ContentType "application/x-www-form-urlencoded" -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
				} else {
					# Fire up!
					$YouTrackNewItemCall = (Invoke-RestMethod -Method "Put" -Uri "$YouTrackURI/rest/admin/project/$YouTrackProject/subsystem/$YouTrackSubsystem" -WebSession $YouTrackSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
				}

				# Return
				Return $true
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}
}
# Set a compatibility Alias
(Set-Alias New-YTSubsystem New-YouTrackSubsystem -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Approve-YouTrackProjectExists {
<#
	.SYNOPSIS
		Check if the Project exists in YouTrack

	.DESCRIPTION
		Helper function to do a basic check if a Project issue exists in YouTrack or not.
		It return a simple Boolean as indicator.

	.PARAMETER YouTrackProject
		YouTrack item that should be checked

	.PARAMETER YouTrackURI
		Specify the Uri of the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Approve-YouTrackProjectExists -YouTrackProject 'SUPPORT' -YouTrackURI 'https://support.contoso.com:8443'
		True

		Description
		-----------
		Check if the Item "SUPPORT" exists. The Return (True) indicates that this item exists.

	.EXAMPLE
		PS C:\> Approve-YouTrackProjectExists -YouTrackProject 'SUPPORT'
		False

		Description
		-----------
		Check if the Item "SUPPORT-4711" exists. The Return (False) indicates that this item doesn't exists.
		We leave the URI and YouTrackSession variables empty, that indicates that the defaults are used and the URI is set via the Initialize-YouTrackConnection command

	.EXAMPLE
		$MyIssue = 'SUPPORT-4711'
		if ((Approve-YouTrackProjectExists -YouTrackProject $MyIssue) -eq $true) {
			# So something with this issue
		} else {
			Write-Error "Sorry, but $MyIssue was not found"
		}

		Description
		-----------
		Simple example that checks if a given Issue exists. If not it drops an Error. Within the IF you can do something useful.

	.NOTES
		Simple Call that I use within my other calls. So I make sure that the issue exists before I go any further and try to do something with it.

	.LINK
		API https://confluence.jetbrains.com/display/YTD65/Check+that+an+Issue+Exists
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	[OutputType([System.Boolean])]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'YouTrack Project that should be checked')]
		[ValidateNotNullOrEmpty()]
		[Alias('Project')]
		[System.String]$YouTrackProject,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the Uri of the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession = ($YouTrackWebSession)
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackProject", "Check if it exists")) {
			try {
				$null = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackURI/rest/admin/project/$YouTrackProject" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue) > $null 2>&1 3>&1
				Return $true
			} catch {
				Return $false
			}
		}
	}

	END {
		# Cleanup
		Remove-Variable -Name "YouTrackItem" -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
	}
}
# Set a compatibility Alias
(Set-Alias Approve-YTProjectExists Approve-YouTrackProjectExists -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

function Get-YouTrackProject {
<#
	.SYNOPSIS
		Get details about a given YouTrack Project

	.DESCRIPTION
		Get details about a given YouTrack Project

	.PARAMETER YouTrackProject
		The YouTrack project to search for.

	.PARAMETER YouTrackURI
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.PARAMETER YouTrackSession
		Specify the web request session value to use for authentication against the JetBrains YouTrack API.

	.EXAMPLE
		PS C:\> Get-YouTrackProject YouTrackProject 'dummy' -YouTrackURI 'https://support.contoso.com:8443'

		name        : dummy
		id          : DUMMY
		description : Dummy Project
		archived    : false
		lead        : john

		Description
		-----------
		Get details about a given YouTrack Project

	.NOTES
		You need to Filter it in PowerShell to make this useful!
#>

	[CmdletBinding(ConfirmImpact = 'None',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(ValueFromPipeline = $true,
				   Position = 1,
				   HelpMessage = 'The YouTrack project to search for.')]
		[Alias('Project')]
		[System.String]$YouTrackProject,
		[Parameter(Position = 2,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('URI')]
		[System.String]$YouTrackURI,
		[Parameter(Position = 3,
				   HelpMessage = 'Specify the web request session value to use for authentication against the JetBrains YouTrack API.')]
		[Alias('Session')]
		$YouTrackSession
	)

	BEGIN {
		# Does we have a URI set?
		if ($YouTrackURIGlobal) {
			Set-Variable -Name "YouTrackURI" -Value $($YouTrackURIGlobal)
		} elseif (-not ($YouTrackURI)) {
			Write-Error -Message "The URL is mandatory!" -ErrorAction:Stop

			# Still here? Make sure we are done!
			break

			# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
			exit 1
		}

		# Are we authenticated?
		if (-not ($YouTrackSession)) {
			if ($pscmdlet.ShouldProcess("YouTrack API", "Login")) {
				try {
					Initialize-YouTrackConnection -YouTrackURI "$YouTrackURI"
				} catch {
					Write-Error -Message "Unable to Authenticate! Please call Initialize-YouTrackConnection to do so." -ErrorAction:Stop

					# Still here? Make sure we are done!
					break

					# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
					exit 1
				}
			}
		}

		# Now we check that the given item exists in YouTrack
		if ($pscmdlet.ShouldProcess("$YouTrackItem", "Check if exists")) {
			if ((Approve-YouTrackProjectExists -YouTrackProject $YouTrackProject) -eq $false) {
				Write-Error -Message "Looks like $YouTrackProject does not exist" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}
	}

	PROCESS {
		if ($pscmdlet.ShouldProcess("$YouTrackProject", "Get details")) {
			try {
				$YouTrackProjectDetails = (Invoke-RestMethod -Method "Get" -Uri "$YouTrackURI/rest/admin/project/$YouTrackProject" -WebSession $YouTrackWebSession -UserAgent "Mozilla/5.0 (Windows NT; Windows NT 6.1; en-US) NET-Experts PowerShell Service $(Get-NETXYouTrackVersion -s)" -ErrorAction:Stop -WarningAction:SilentlyContinue)
			} catch [System.Management.Automation.PSArgumentException] {
				# Something is wrong with the command-line
				Write-Debug -Message "Caught a Argument Exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch [system.exception] {
				# This is a system exception
				Write-Debug -Message "Caught a System exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			} catch {
				# Did not see this one coming!
				Write-Debug -Message "Caught a Unknown exception"

				Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction:Stop

				# Still here? Make sure we are done!
				break

				# Aw Snap! We are still here? Fix that the Bruce Willis way: DIE HARD!
				exit 1
			}
		}

		$YouTrackProjectDetailsPrint = (($YouTrackProjectDetails).project | Select-Object name, id, description, archived, lead)
	}

	END {
		# Dump the info
		Return ($YouTrackProjectDetailsPrint)
	}
}
# Set a compatibility Alias
(Set-Alias Get-YTProject Get-YouTrackProject -option:AllScope -Scope:Global -Force -Confirm:$false -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue) > $null 2>&1 3>&1

#endregion Functions

#region ExportModuleStuff

# Get public function definition files.
if (Test-Path -Path (Join-Path $PSScriptRoot 'Public')) {
	$Public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Exclude "*.tests.*" -Recurse -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)

	# Dot source the files
	foreach ($import in @($Public)) {
		Try {
			. $import.fullname
		} Catch {
			Write-Error -Message "Failed to import Public function $($import.fullname): $_"
		}
	}
}

if ($loadingModule) {
	Export-ModuleMember -Function "*" -Alias "*" -Cmdlet "*" -Variable "*"
}

if (Test-Path -Path (Join-Path $PSScriptRoot 'Private')) {
	# Get public and private function definition files.
	$Private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Exclude "*.tests.*" -Recurse -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)

	foreach ($import in @($Private)) {
		Try {
			. $import.fullname
		} Catch {
			Write-Error -Message "Failed to import Private function $($import.fullname): $_"
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
