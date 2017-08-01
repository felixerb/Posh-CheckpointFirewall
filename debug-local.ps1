#Requires -Version 4
$userCredential = [PSCredential]::new(
    'apiadmin',
    (ConvertTo-SecureString -String 'password' -AsPlainText -Force)
)
Get-Module -Name vfCheckpointFirewall | Remove-Module
Import-Module -Name .\vfCheckpointFirewall.psd1


$HostName = "10.221.4.6"

Register-ckpSession -HostName $HostName -Credential $userCredential

$d = Get-ckpNetwork

$d.objects[0].name

Get-ckpNetwork -NetworkName $d.objects[0].name
