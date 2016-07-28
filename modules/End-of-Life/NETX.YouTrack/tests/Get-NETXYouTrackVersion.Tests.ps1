<#
	.SYNOPSIS
		Pester Unit Test

	.DESCRIPTION
		Pester is a BDD based test runner for PowerShell.

	.EXAMPLE
		PS C:\> Invoke-Pester

	.NOTES
		PESTER PowerShell Module must be installed!

		modified by     : Joerg Hochwald
		last modified   : 2016-04-11

	.LINK
		Pester https://github.com/pester/Pester
#>

# Where are we?
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$moduleName = Split-Path -Leaf $modulePath
$moduleCall = $modulePath + "\" + $moduleName + ".psm1"

# Reload the Module
Remove-Module $moduleName -Force -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
Import-Module $moduleCall -DisableNameChecking -Force -Scope Global -ErrorAction:Stop -WarningAction:SilentlyContinue

Describe "Get-NETXYouTrackVersion" {
	InModuleScope NETX.YouTrack {
		Context "Must pass" {
			It "Long Version" {
				(Get-NETXYouTrackVersion) | Should Match "NET-Experts PowerShell Support for JetBrains YouTrack Rest API Version"
			}
			It "Short Version" {
				(Get-NETXYouTrackVersion -s) | Should not Match "NET-Experts PowerShell Support for JetBrains YouTrack Rest API Version"
			}
		}
	}
}
