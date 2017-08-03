<#
.SYNOPSIS
Test script to test the different functionalities of the vfCheckpointFirewall module
This script is ment as a testing script and is not intended to be run as a whole!!
#>
#Requires -Version 4


#Set current path
$baseScriptPath = $psScriptRoot
if (($psEditor -ne $null) -and ([string]::IsNullOrEmpty($baseScriptPath)))
{
    $baseScriptPath = ([Io.FileInfo]$psEditor.GetEditorContext().CurrentFile.Path).Directory.FullName
}
elseif (($psISE -ne $null) -and (Tes-Path -Path $psISE.CurrentFile.FullPath))
{
    $baseScriptPath = ([Io.FileInfo]$psISE.CurrentFile.FullPath).Directory.FullName
}

# Load Module
Get-Module -Name vfCheckpointFirewall | Remove-Module -Force
Import-Module -Name $baseScriptPath\vfCheckpointFirewall.psd1


# Login
$userCredential = Get-Credential -UserName apiadmin
$HostName = "10.221.4.6"
Connect-ckpSession -HostName $HostName -Credential $userCredential -ContinueLastSession


#region session tests
$sessions = Get-ckpSession -Limit 500 -GetAll
$sessions.Count
$sessions | Undo-ckpSession
$sessions.Count

Switch-ckpSession -Uid 'e72455c5-07e5-4b07-9e91-162e2a33bd8c'
Reset-ckpSessionTimeout
Disconnect-ckpSession
Undo-ckpSession -Uid 6d8aff8d-b242-4848-9c71-8becc8b77be8

Publish-ckpSession
#endregion session tests

#region Gateaway servers
Get-ckpGateway -GetAll
Get-ckpServer

$d = Get-ckpCommand -Name 'show'
Get-ckpObject -Type 'application-site'
#end region gateways


#region networks
$networks = Get-ckpNetwork -Limit 500 -GetAll
Get-ckpObjectUsage -Uid $networks[0].uid
$networks | Select-Object -First 50 | Format-Table name, subnet4, mask-length4, subnet-mask -AutoSize

Remove-ckpNetwork -Uid $lastNetwork.uid
#endregion networks

#region groups
$groupName = 'azure_public_we'
$group = Get-ckpGroup -Name $groupName
if (-Not $group)
{
    $member = $networks | Where-Object {$_.name -ilike 'azure_public_europewest*'} | Select-Object -ExpandProperty uid
    Add-ckpGroup -Name $groupName -Member $member
}
$group.members.Count
#Set-ckpGroup -Name $groupName -Member $newMember
#endregion groups
