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

Describe 'Check function' {
	InModuleScope $moduleName {
		$ModuleCommandList = ((Get-Command -Module NETX.YouTrack).Name)

		foreach ($ModuleCommand in $ModuleCommandList) {
			# Cleanup
			$help = $null

			# Get the Help
			$help = (Get-Help $ModuleCommand -Detailed)

			Context "Check $ModuleCommand Help" {
				It "Check $ModuleCommand Name" {
					$help.name | Should Not BeNullOrEmpty
				}

				It "Check $ModuleCommand Description" {
					$help.description | Should Not BeNullOrEmpty
				}

<#

				It "Check $ModuleCommand Links" {
					$help.relatedLinks | Should Not BeNullOrEmpty
				}

#>

				It "Check $ModuleCommand Examples" {
					$help.examples | Should Not BeNullOrEmpty
				}
			}
		}
	}
}
