Remove-Module vfCheckpointFirewall -ErrorAction Ignore
$Script:Module = Import-Module "$PSScriptRoot\vfCheckpointFirewall.psd1" -Force -DisableNameChecking -PassThru

Describe "Module" -Tags "Unit", "Build" {
    $moduleCommands = Get-Command -Module ($Script:Module.Name)
    Foreach ($moduleCommand in $moduleCommands)
    {
        if ($moduleCommand.CommandType -ne 'Function')
        {
            continue
        }
        Context $moduleCommand.Name {

            It "$($moduleCommand.Name) should be an advanced function" {
                $moduleCommand.CmdletBinding | Should Be $true
            }

            It "$($moduleCommand.Name) should have an approved verb" {
                $approvedVerbs = (Get-Verb | Select-Object -ExpandProperty Verb)
                ($approvedVerbs -icontains $moduleCommand.Verb) | Should Be $true
            }

            It "$($moduleCommand.Name) should have a doc-comment block" {
                $moduleCommand.Definition | Should Match '<#'
                $moduleCommand.Definition | Should Match '#>'
            }

            It "$($moduleCommand.Name) is valid PowerShell code" {
                $errors = $null
                $null = [System.Management.Automation.PSParser]::Tokenize($moduleCommand.Definition, [ref]$errors)
                $errors.Count | Should Be 0
            }

            $helpText = Get-Help -Name $moduleCommand -Full
            It "$($moduleCommand.Name) should have a description doc comment" {
                ($helpText.Description | Out-String) | Should Not BeNullOrEmpty
            }

            It "$($moduleCommand.Name) should have at least one example as doc comment" {
                ($helpText.examples | Out-String) | Should Not BeNullOrEmpty
            }

            It "$($moduleCommand.Name) should have a synopsis doc comment" {
                ($helpText.Synopsis | Out-String) | Should Not Match "^\r.*"
            }
        }
    }
}

InModuleScope $Script:Module {
    Describe 'Get-internalObject' {
        Mock -CommandName Invoke-ckpWebRequest -ModuleName $Script:Module -MockWith {
            $returnValues = @()
            1..5 | ForEach-Object {
                $returnValues += @{
                    Name = "Name$($_)"
                    Uid  = "$($_)-$($_)-$($_)"
                }
            }
            return $returnValues
        }

        It 'should throw an error if not logged in' {
            { Get-internalObject -CommandSingularName network -CommandPluralName networks } | Should throw
        }
    }

    Describe 'Connect-ckpSession' {
        Mock -CommandName Invoke-ckpWebRequest -ModuleName $Script:Module -MockWith {
            @{
                sid = (New-Guid).ToString()
                uid = (New-Guid).ToString()
            }
        }

        It "should set the internal session object after successfull login" {
            $credential = [PSCredential]::new('someuser', (ConvertTo-SecureString -String 'somePassword' -AsPlainText -Force))
            $null = Connect-ckpSession -HostName 'someHost' -Credential $credential
            Get-ckpInternalSession | Should Not BeNullOrEmpty
        }

    }

    Describe 'Disconnect-ckpSession' {
        Mock -CommandName Invoke-ckpWebRequest -ModuleName $Script:Module -MockWith {
            @{
                sid = (New-Guid).ToString()
                uid = (New-Guid).ToString()
            }
        }
        It 'should not throw an error if no session is available' {
            { Disconnect-ckpSession } | Should Not Throw
        }

        It 'should reset the internal session object to null' {
            $credential = [PSCredential]::new('someuser', (ConvertTo-SecureString -String 'somePassword' -AsPlainText -Force))
            $null = Connect-ckpSession -HostName 'someHost' -Credential $credential
            Disconnect-ckpSession
            Get-ckpInternalSession | Should BeNullOrEmpty
        }
    }
}