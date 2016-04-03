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
		last modified   : 2016-03-31

	.LINK
		Pester https://github.com/pester/Pester
#>

$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$moduleName = Split-Path -Leaf $modulePath
$manifestPath = Join-Path -Path $modulePath -Child "$moduleName.psd1"

Describe 'Manifest' {
	Context 'Manifest' {

		$manifestHash = (Invoke-Expression (Get-Content $manifestPath -Raw))
<#
		It 'Has a valid manifest' { { $null = Test-ModuleManifest -Path $manifestPath -ErrorAction:Stop -WarningAction:SilentlyContinue } | Should Not Throw
		}
#>
		It 'Has no more ModuleToProcess entry (Old PowerShell Style)' {
			$manifestHash.ModuleToProcess | Should BeNullOrEmpty
		}

		It 'Has a valid description' {
			$manifestHash.Description | Should Not BeNullOrEmpty
		}

		It 'Has a valid PowerShell Version Requirement' {
			$manifestHash.PowerShellVersion | Should Not BeNullOrEmpty
		}

		It 'Has a valid author' {
			$manifestHash.Author | Should Not BeNullOrEmpty
		}

		It 'Has a valid Company' {
			$manifestHash.CompanyName | Should Not BeNullOrEmpty
		}

		It 'Has a valid guid' { {
				[guid]::Parse($manifestHash.Guid)
			} | Should Not throw
		}

		It 'Has a valid copyright' {
			$manifestHash.CopyRight | Should Not BeNullOrEmpty
		}

		It 'Has a valid Version' {
			$manifestHash.ModuleVersion | Should Not BeNullOrEmpty
		}

		It 'Exports the Cmdlets' {
			$manifestHash.CmdletsToExport | Should Not BeNullOrEmpty
		}

		It 'Exports the Functions' {
			$manifestHash.FunctionsToExport | Should Not BeNullOrEmpty
		}

		It 'Has a valid Root Module' {
			$manifestHash.RootModule | Should Be "$moduleName.psm1"
		}
	}
}
