#Requires -Version 4
$userCredential = Get-Credential -UserName apiadmin

$baseScriptPath = $psScriptRoot
if (($psEditor -ne $null) -and ([string]::IsNullOrEmpty($baseScriptPath)))
{
    $baseScriptPath = ([Io.FileInfo]$psEditor.GetEditorContext().CurrentFile.Path).Directory.FullName
}
elseif (($psISE -ne $null) -and (Tes-Path -Path $psISE.CurrentFile.FullPath))
{
    $baseScriptPath = ([Io.FileInfo]$psISE.CurrentFile.FullPath).Directory.FullName
}

Get-Module -Name vfCheckpointFirewall | Remove-Module -Force
Import-Module -Name $baseScriptPath\vfCheckpointFirewall.psd1

$HostName = "10.221.4.6"
Connect-ckpSession -HostName $HostName -Credential $userCredential -ContinueLastSession

#region session tests
$sessions = Get-ckpSession -Limit 500 -GetAll

$sessions | % { Undo-ckpSession -Uid $_}

$sessions.Count
$sessions[0] | fl

Switch-ckpSession -Uid 'e72455c5-07e5-4b07-9e91-162e2a33bd8c'
Reset-ckpSessionTimeout
Disconnect-ckpSession
#endregion

Get-ckpGateway -GetAll
Get-ckpServer

$d = Get-ckpCommand -Name 'show'
Get-ckpObject -Type 'application-site'

$networks = Get-ckpNetwork -Limit 500 -GetAll

Get-ckpObjectUsage -Uid $networks[0].uid

$networks | Select -First 50 | Format-Table name, subnet4, mask-length4, subnet-mask -AutoSize

$azurePath = Join-Path -Path $env:USERPROFILE -ChildPath "desktop/PublicIPs_20170731.xml"
[xml]$azureXml = Get-Content -Path $azurePath
$nets = @()
$azureXml.AzurePublicIpAddresses.Region | Where-Object {$_.Name -ilike 'europe*'} | Foreach-Object {
    $region = $_
    Foreach ($range in $region.IpRange)
    {
        $match = $range.Subnet | Select-String -Pattern '(\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})\/(\d{2})?'
        $nets += [PsCustomObject]@{
            name       = "azure_public_$($region.name)_$($match.matches.Groups[1].value)"
            Subnet     = $match.matches.Groups[1].value
            MaskLength = $match.matches.Groups[2].value
        }
    }
}

$missingNetworks = Compare-Object -ReferenceObject $nets -DifferenceObject (
    $networks | Select-Object name, @{n = "Subnet";e = {$_subnet4}}, @{n = "MaskLenght";e = {$_.'mask-length4'}}
)
$missingNetworks.Count

Foreach ($missingNet in $missingNetworks)
{
    $missingNet.InputObject | Add-ckpNetwork
}

$groupName = 'azure_public_we'
$group = Get-ckpGroup -Name $groupName

if (-Not $group)
{
    $member = $networks | Where-Object {$_.name -ilike 'azure_public_europewest*'} | Select-Object -ExpandProperty uid
    Add-ckpGroup -Name $groupName -Member $member
}
$group.members.Count




Publish-ckpSession

Disconnect-ckpSession


$lastNetwork = $networks[-1]

$lastNetwork

$member = $group.members.uid
$newMember = $member[1..$($member.count - 1)]
$lastMember = $member[-1]

Set-ckpGroup -Name $groupName -Member $newMember


$sess = Get-ckpSession

$sess[0]

Undo-ckpSession -Uid 6d8aff8d-b242-4848-9c71-8becc8b77be8

Remove-ckpNetwork -Uid $lastNetwork.uid


Get-ckpPackage
