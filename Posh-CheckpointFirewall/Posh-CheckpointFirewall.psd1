@{
    RootModule        = 'vfCheckpointFirewall.psm1'
    ModuleVersion     = '1.1.3.3'
    GUID              = 'ef3c886d-72a2-4a6d-9720-1158504d3d79'
    Author            = 'Felix Erb and contributors'
    Copyright         = '(c) 2017. Felix Erb and contributors'
    Description       = 'Module wraps REST API Calls to Checkpoint Firewall Management Servers'
    PowerShellVersion = '4.0'
    # DotNetFrameworkVersion = ''
    # CLRVersion = ''
    # RequiredModules = @()
    # RequiredAssemblies = @()
    # ScriptsToProcess = @()
    # TypesToProcess = @()
    # FormatsToProcess = @()

    # NestedModules = @()
    FunctionsToExport = @(
        'Add-ckpGroup'
        ,'Add-ckpNetwork'
        ,'Connect-ckpSession'
        ,'Disconnect-ckpSession'
        ,'Get-ckpCommand'
        ,'Get-ckpGateway'
        ,'Get-ckpGroup'
        ,'Get-ckpNetwork'
        ,'Get-ckpObject'
        ,'Get-ckpSession'
        ,'Publish-ckpSession'
        ,'Remove-ckpNetwork'
        ,'Reset-ckpSessionTimeout'
        ,'Set-ckpGroup'
        ,'Switch-ckpSession'
        ,'Undo-ckpSession'
        ,'Get-ckpObjectUsage'
        ,'Get-ckpValidation'
        ,'Get-ckpPackage'
        ,'Install-ckpPolicy'
        ,'Get-ckpTask'
        ,'Get-ckpHost'
        ,'Add-ckpHost'
        ,'Add-ckpGroupWithExclusion'
        ,'Set-ckpGroupWithExclusion'
    )
    CmdletsToExport   = @()
    # VariablesToExport = @()
    AliasesToExport   = @('Get-ckpServer')
    # DscResourcesToExport = @()
    # ModuleList = @()
    # FileList = @()
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            # ProjectUri = ''

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

            # External dependent modules of this module
            # ExternalModuleDependencies = ''
        } # End of PSData hashtable
    } # End of PrivateData hashtable
}
