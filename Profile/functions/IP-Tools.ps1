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

Function Global:Convert-IPToBinary {
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

	[OutputType([psobject])]
	param
	(
		[Parameter(ValueFromPipeline,
		Position = 1)]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')]
		[Alias('IPAddress')]
		[String]$IP
	)

	BEGIN {
		$Binary = $null
		$Result = $null
		$SingleIP = $null
	}

	PROCESS {
		foreach ($SingleIP in $IP) {
			try {
				$SingleIP.split('.') | ForEach-Object -Process { $Binary = $Binary + $([convert]::toString($_, 2).padleft(8, '0')) }
			} catch [System.Exception] {
				Write-Error -Message "$($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)" -ErrorAction Stop

				# Capture any failure and display it in the error section
				# The Exit with Code 1 shows any calling App that there was something wrong
				exit 1
			} catch {
				Write-Error -Message "Could not convert $SingleIP!" -ErrorAction Stop

				# Still here? Make sure we are done!
				break
			}

			$Result = New-Object -TypeName PSObject -Property @{
				IPAddress = $SingleIP
				Binary    = $Binary
			}
		}
	}

	END {
		Write-Output -InputObject $Result
	}
}

function global:Convert-IPtoDecimal {
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

	[OutputType([psobject])]
	param
	(
		[Parameter(Mandatory,
				ValueFromPipeline,
				Position = 0,
		HelpMessage = 'An IP Address you want to check')]
		[Alias('IP')]
		[string]$IPAddress
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
				'Decimal' = [long](
					([int]::Parse($IP[0]) * [Math]::Pow(2, 24) +
						([int]::Parse($IP[1]) * [Math]::Pow(2, 16) +
							([int]::Parse($IP[2]) * [Math]::Pow(2, 8) +
								([int]::Parse($IP[3])
								)
							)
						)
					)
				)
		})
	}

	END {
		# Dump the info to the console
		Write-Output -InputObject $Object
	}
}

function global:Check-IPaddress {
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

	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory,
				ValueFromPipelineByPropertyName,
				Position = 0,
		HelpMessage = 'An IP Address you want to check')]
		[ValidateScript({
					$_ -match [IPAddress]
					$_
		})]
		[Alias('IP')]
		[string]$IPAddress
	)

	PROCESS {
		# Use the .NET Call to figure out if the given address is valid or not.
		Set-Variable -Name 'IsValid' -Scope Script -Value $(($IPAddress -As [IPAddress]) -As [Bool])
	}

	END {
		# Dump the bool value to the console
		Write-Output -InputObject $IsValid
	}
}

function global:Get-NtpTime {
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
			port 13 â€" although this is an old protocol and is not supported
			by all NTP servers.

			.LINK
			Source: https://chrisjwarwick.wordpress.com/2012/08/26/getting-ntpsntp-network-time-with-powershell/
	#>

	[OutputType([datetime])]
	param
	(
		[Alias('NETServer')]
		[string]$Server = 'de.pool.ntp.org'
	)

	PROCESS {
		# Construct client NTP time packet to send to specified server
		# (Request Header: [00=No Leap Warning; 011=Version 3; 011=Client Mode]; 00011011 = 0x1B)
		[Byte[]]$NtpData = , 0 * 48
		$NtpData[0] = 0x1B

		# Create the connection
		$Socket = New-Object -TypeName Net.Sockets.Socket -ArgumentList ([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)

		# Configure the connection
		$Socket.Connect($Server, 123)
		$null = $Socket.Send($NtpData)

		# Returns length â€" should be 48
		$null = $Socket.Receive($NtpData)

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
		(New-Object -TypeName DateTime -ArgumentList (1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddMilliseconds($Milliseconds).ToLocalTime()
	}
}
# Set a compatibility Alias
(Set-Alias -Name Get-AtomicTime -Value Get-NtpTime -Option AllScope -Scope Global -Force -Confirm:$False -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) > $null 2>&1 3>&1

# SIG # Begin signature block
# MIIfOgYJKoZIhvcNAQcCoIIfKzCCHycCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUS3LYCPiivP8MQ9UlKpjPrYDg
# jJ6gghnLMIIEFDCCAvygAwIBAgILBAAAAAABL07hUtcwDQYJKoZIhvcNAQEFBQAw
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
# MCMGCSqGSIb3DQEJBDEWBBRl+XtWnDUTLMq8ePaW+7l66KfVWzANBgkqhkiG9w0B
# AQEFAASCAQB7GvM/lQf2hY518RpXfRJj2Hkr/4K21My0Udq8Lvvkd4ifaQCjWiY4
# Oz6Mzqg2kbuIFEXxv2t8eYxkeye+rADIFlmypVcdFHf1IP7w2+IO8fJs+E46tXv6
# WZ6EkzjBuYIjS5VLqSMXbGFCuowymACerXOkH9GMVpt7BwVNtMOOdmC8fCPjNyhR
# ReUfTXtvx2tWWi9k/ras1WrhwSxsLy5/Fpd4tDZv4cjn+aCFsR6Zj62082xrsle3
# n07+1XjjRY6zgEr3B0NONU35t66V/uiVMjeUSoSQd1wlG8l8Ndsn7soSI2AlPHGQ
# ONUdWK+4mIGfNReFVT259ZAlXFgnr6ejoYICojCCAp4GCSqGSIb3DQEJBjGCAo8w
# ggKLAgEBMGgwUjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYt
# c2ExKDAmBgNVBAMTH0dsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gRzICEhEh
# 1pmnZJc+8fhCfukZzFNBFDAJBgUrDgMCGgUAoIH9MBgGCSqGSIb3DQEJAzELBgkq
# hkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MTAxMjEzMTM0NFowIwYJKoZIhvcN
# AQkEMRYEFFcls9tjXUFFdgTOge+xaCwOZIGpMIGdBgsqhkiG9w0BCRACDDGBjTCB
# ijCBhzCBhAQUY7gvq2H1g5CWlQULACScUCkz7HkwbDBWpFQwUjELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKDAmBgNVBAMTH0dsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gRzICEhEh1pmnZJc+8fhCfukZzFNBFDANBgkq
# hkiG9w0BAQEFAASCAQAModSxQv3gjroOwmQS0dnz6oY9ZCEKT/4+6i7Lu1ftQSeK
# IgVZTNBXsQJ0tCJe7f/Lc+8JJqWw5bu/BVyPwhQCmHuoE5xzhDc6mwBXEXfiIS7F
# uJ0V3liNJKhpG/iCuD5puzpbKdbfMseDX4GTXEeWyjz+Dni3dOffA6WGqOH23GuW
# xElrTmWvVKGfaonkyOY3VJPJBeAa6dU7AlH3q7b4QCtspvt2mIf9rJkzjXKBqS77
# UIiDBEd9aO0HwfsMcS6YUbGHM70zNUuGYlNvVKk2a+rVTvlTJkCX3Wjg4fmVC1EC
# s1FYeo+lMKmoFPBnvDO9Gri4FXqk7Pvn+znfL9Ty
# SIG # End signature block
