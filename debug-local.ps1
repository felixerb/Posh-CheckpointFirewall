#Requires -Version 4
$userCredential = [PSCredential]::new(
    'apiadmin',
    (ConvertTo-SecureString -String 'RHrMU84*0d99' -AsPlainText -Force)
)

$baseScriptPath = $psScriptRoot
if (($psEditor -ne $null) -and ([string]::IsNullOrEmpty($baseScriptPath)))
{
    $baseScriptPath = ([Io.FileInfo]$psEditor.GetEditorContext().CurrentFile.Path).Directory.FullName
}

Get-Module -Name vfCheckpointFirewall | Remove-Module
Import-Module -Name $baseScriptPath\vfCheckpointFirewall.psd1

$HostName = "10.221.4.6"
Connect-ckpSession -HostName $HostName -Credential $userCredential

$networks = Get-ckpNetwork -Limit 500 -GetAll


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


Undo-ckpSession

Publish-ckpSession

Disconnect-ckpSession


$lastNetwork = $networks[-1]

$lastNetwork

$member = $group.members.uid
$newMember = $member[1..$($member.count - 1)]
$lastMember = $member[-1]

Set-ckpGroup -Name $groupName -Member $newMember


Remove-ckpNetwork -Uid $lastNetwork.uid

#Invoke-WebRequest -Uri 'https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/' -OutFile "huhu.xml"