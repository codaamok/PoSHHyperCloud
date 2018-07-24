<#
.SYNOPSIS
  A PowerShell script used to back up Hyper-V virtual machines. Rclone is used to upload and 7zip is used to archive. Options are configurable via XML.
.DESCRIPTION
  https://github.com/codaamok/HyperBackup
.PARAMETER ConfigFile
  Path to XML configuration file, if not passed then assumes "Settings.xml" exists in same directory as this script
.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None>
.NOTES
  Version:        1.0
  Author:         Adam Cook
  Creation Date:  July 2018
  Purpose/Change: Initial commit
.EXAMPLE
  <Example explanation goes here>
  <Example goes here. Repeat this attribute for more than one example>
#>

Param (
	[Parameter(Mandatory=$false)]
	[ValidateScript({
		If (-Not ($_ | Test-Path)) {
			throw "Can't find Settings.xml in current directory"
		}
		If (-Not ($_ | Test-Path -PathType Leaf)) {
			throw "Please specify an XML file"
		}
		If ($_ -notmatch ".xml") {
			throw "The file specified must be of XML type"
		}
		return $true 
	})]
	[System.IO.FileInfo]$ConfigFile
)

#requires -version 5.1

$ProgressPreference = "SilentlyContinue"

If (!($ConfigFile)) { 
	$ConfigFile = ((Split-Path -Parent $MyInvocation.MyCommand.Path) + "\Settings.xml")
    [xml]$ConfigFileXML = Get-Content ((Split-Path -Parent $MyInvocation.MyCommand.Path) + "\Settings.xml")
}
Else {
    [xml]$ConfigFileXML = Get-Content $ConfigFile
}

#----------------------------------------------------------[Validate XML]----------------------------------------------------------

#---------------------------------------------------------[Validate Rclone]--------------------------------------------------------

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

$Date = "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"

# XML 

$VMSettings = $ConfigFileXML.Settings.VM
$ExcludedVMs = $ConfigFileXML.Settings.VM | ? { ($_.id -ne "all" ) } | ? { ($_.Exclude -eq $true) }
$SkipRemoteVerificationVMs = $ConfigFileXML.Settings.VM | ? { ($_.id -ne "all") } | ? { ($_.SkipRemoteVerification -eq $true) }
$SkipLocalChecksumVMs = $ConfigFileXML.Settings.VM | ? { ($_.id -ne "all") } | ? { ($_.SkipLocalChecksum -eq $true) }
$AppRclone = $ConfigFileXML.Settings.Applications.Rclone 
$App7zip = $ConfigFileXML.Settings.Applications.SevenZip
$LocalTarget = $ConfigFileXML.Settings.Targets.Local
$RemoteTarget = $ConfigFileXML.Settings.Targets.Remote
$Notifications = $ConfigFileXML.Settings.Notifications
$Log = $ConfigFileXML.Settings.Log

# Other

$MailArgs = @{
	From       = $ConfigFileXML.Settings.Notifications.Email.From
	To         = $ConfigFileXML.Settings.Notifications.Email.To
	SmtpServer = $ConfigFileXML.Settings.Notifications.Email.SMTPServer
	Port       = $ConfigFileXML.Settings.Notifications.Email.SMTPPort
	UseSsl     = [bool]$ConfigFileXML.Settings.Notifications.Email.UseSSL
	Credential = New-Object pscredential $ConfigFileXML.Settings.Notifications.Email.Username,("$($ConfigFileXML.Settings.Notifications.Email.Password)" | ConvertTo-SecureString -AsPlainText -Force)
}

$VerificationCheck = @{}
$NewFolders = "$($LocalTarget.ExportPath)\${Date}","$($LocalTarget.Path)\${Date}","$($Log.Path)"


#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function LogWrite {
	Param (
		[string]$Message
	)
	$Time = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
	Add-Content "$($Log.Path)\${Date}.log" -value "${Time} - $Message"
	Write-Host "${Time} - $Message"
}

function Send-Notification {
	Param (
		[hashtable]$EmailArguments,
		[string]$Enabled
	)
	If ($Enabled -eq $true) {
		Send-MailMessage @EmailArguments -Subject "${env:computername} - Backup Notification" -Body "$(Get-Content -Path "$($Log.Path)\${Date}.log" -Raw)"
	}
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

clear

ForEach ($Folder in $NewFolders) {
	If (!(Test-Path $Folder)) {
		New-Item -ItemType Container -Path $Folder > $null
	}
}

LogWrite "Started"

LogWrite "Using XML: ${ConfigFile}"

switch ($true) {
	(((($VMSettings | ? { ($_.id -eq "all") }).BackupRunningOnly) -eq $true) -And ((Get-VM | ? { ($_.State -eq "Running") }).count -eq 0)) {
		LogWrite "Configured to back up running VMs only, no VMs currently running"
		LogWrite "Finished"
		Send-Notification -EmailArguments $MailArgs -Enabled $Notifications.Email.Enabled
		Exit
	}
	((($VMSettings | ? { ($_.id -eq "all") }).BackupRunningOnly) -eq $true) {
		$VMs = Get-VM | ? { ((($ExcludedVMs).id -notcontains ($_.id)) -And ($_.State -eq "Running")) }
		break
	}
	default {
		$VMs = Get-VM | ? { (($ExcludedVMs).id -notcontains ($_.id)) }
	}
}

LogWrite "Exporting started"

ForEach ($VM in $VMs) {
	LogWrite "Exporting $($VM.Name) ($($VM.id))"
	Get-VM -ID $VM.id | Export-VM -Path "$($LocalTarget.ExportPath)\${Date}\$($VM.Name)_$($VM.id)"
}

LogWrite "Archiving started"

ForEach ($VMExport in (ls "$($LocalTarget.ExportPath)\${Date}")) {
	$File = "$($VMExport.Name).$($App7zip.FileExtension)"
	$Destination = "$($LocalTarget.Path)\${Date}\${File}"
	LogWrite "Archiving $($VMExport.Name) to ${Destination}"
	Start-Process -WindowStyle Hidden -FilePath $App7zip.Path -ArgumentList "a","${Destination}","$($VMExport.FullName)","-mhe=on","-mx=9","-p$($App7zip.Password)" -Wait
}

LogWrite "Archive checksum started"

If ((($VMSettings | ? { ($_.id -eq "all") }).SkipLocalChecksum) -eq $true) {
	LogWrite "Configured to skip calculating checksum for local archives, skipping step"
}
Else {
	ForEach ($Archive in (ls "$($LocalTarget.Path)\${Date}")) {
		# Not a pretty solution, I know...
		# Split the archive's file name to grab the VM ID portion in the name
		If ($SkipLocalChecksumVMs.id -notcontains (($Archive.Name).Split("_")[1]).Split(".")[0]) {
			$Hash = (Get-FileHash $Archive.FullName -Algorithm SHA256).Hash
			LogWrite "SHA256: ${Hash} $($Archive.Name)"
			Add-Content "$($LocalTarget.Path)\${Date}\$($Archive.Name).txt" -Value "SHA256: ${Hash} $($Archive.Name)"
		}
		Else {
			LogWrite "Configured to skip calculating checksum for $($Archive.Name), skipping"
		}
	}
}

LogWrite "Uploading started"

ForEach ($Archive in (ls "$($LocalTarget.Path)\${Date}")) {
	ForEach ($Remote in $RemoteTarget) {
		LogWrite "Uploading $($Archive.Name) to $($Remote.RcloneRemoteName) ($($Remote.RcloneType))"
		Start-Process -WindowStyle Hidden -FilePath $AppRclone.Path -ArgumentList "copy","$($Archive.FullName)","$($Remote.RcloneRemoteName):$($Remote.Path)/${Date}","--stats=10s","--bwlimit `"17:00,0.5M 23:00,off`"","-v" -Wait
	}
}

LogWrite "Verification started"

If ((($VMSettings | ? { ($_.id -eq "all") }).SkipRemoteVerification) -eq $true) {
	LogWrite "Configured to skip verifying remote archives, skipping step"
}
Else {
	ForEach ($Archive in (ls "$($LocalTarget.Path)\${Date}")) {
		ForEach ($Remote in $RemoteTarget) {
			# Not a pretty solution, I know...
			# Split the archive's file name to grab the VM ID portion in the name
			If ($SkipRemoteVerificationVMs.id -notcontains (($Archive.Name).Split("_")[1]).Split(".")[0]) {
				LogWrite "Verifying $($Archive.Name) on $($Remote.RcloneRemoteName) ($($Remote.RcloneType))"
				$rc = Start-Process -WindowStyle Hidden -FilePath $AppRclone.Path -ArgumentList "check","$($Archive.FullName)","$($Remote.RcloneRemoteName):$($Remote.Path)/${Date}/" -PassThru -Wait
				If ($rc.ExitCode -ne 0) {
					LogWrite "Verification failed for $($Archive.Name) on $($Remote.RcloneRemoteName) ($($Remote.RcloneType))"
					$VerificationCheck.$($Archive.Name) = $false
				} 
				Else {
					LogWrite "Verification successful for $($Archive.Name) on $($Remote.RcloneRemoteName) ($($Remote.RcloneType))"
					$VerificationCheck.$($Archive.Name) = $true
				}
			}
			Else {
				LogWrite "Configured to skip verification for $($Archive.Name), skipping"
			}
		}
	}
}

LogWrite "Rotation started"

If ($VerificationCheck.ContainsValue($false)) {
	LogWrite "Not going to rotate due to a verification failure, skipping step"
}
Else {
	ForEach ($Remote in $RemoteTarget) {
		Start-Process -WindowStyle Hidden -FilePath $AppRclone.Path -ArgumentList "lsjson","$($Remote.RcloneRemoteName):$($Remote.Path)" -Wait -RedirectStandardOutput "$($LocalTarget.ExportPath)\${Date}\output.txt"
		$BackupsJSON = ((Get-Content "$($LocalTarget.ExportPath)\${Date}\output.txt" | ConvertFrom-Json) | Sort Name -Descending )
		If ($BackupsJSON.count -gt $Remote.Retention) {
			ForEach ($Backup in $BackupsJSON) {
				If (($BackupsJSON.IndexOf($Backup)) -ge $Remote.Retention) {
					LogWrite "Deleting $($Backup.Name) from $($Remote.RcloneRemoteName) ($($Remote.RcloneType))"
					Start-Process -WindowStyle Hidden -File $AppRclone.Path -ArgumentList "purge","$($Remote.RcloneRemoteName):$($Remote.Path)/$($Backup.Name)"
				}
			}
		}
		Else {
			LogWrite "No old backups to delete from $($Remote.RcloneRemoteName) ($($Remote.RcloneType))"
		}
	}
	# Excluded "exported" from directory listing in case users set <ExportPath> to be a folder that's a sub folder of $LocalTarget.Path
	If ((ls $LocalTarget.Path | ? { ( $_.Name -ne "exported" ) } ).count -gt $LocalTarget.Retention) {
		ForEach ($LocalBackup in ($dir = ls $LocalTarget.Path | ? { ( $_.Name -ne "exported" ) } | Sort Name -Descending)) {
			If ($dir.IndexOf($LocalBackup) -ge $LocalTarget.Retention) {
				LogWrite "Deleting $($LocalBackup.Name) from $($LocalTarget.Path) (local)"
				Remove-Item "$($LocalBackup.FullName)" -Force -Recurse
			}
		}
		$dir.clear()
	}
	Else {
		LogWrite "No old backups to delete from $($LocalTarget.Path) (local)"
	}
}

LogWrite "Deleting exported VMs"

Remove-Item "$($LocalTarget.ExportPath)" -Force -Recurse

LogWrite "Finished"

Send-Notification -EmailArguments $MailArgs -Enabled $Notifications.Email.Enabled

Exit