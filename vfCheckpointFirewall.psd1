@{
    RootModule        = 'vfCheckpointFirewall.psm1'
    ModuleVersion     = '1.1.3.3'
    GUID              = '3dda1a1f-521a-4fec-acc1-c68a983b84fd'
    Author            = 'VAP TEAM'

    CompanyName       = 'Vattenfall'

    Copyright         = 'Vattenfall (c) 2017 . All rights reserved.'

    Description       = 'Module wrapping VSTS REST API Calls and includes commonly used helper functions for VSTS build and release pipelines'

    PowerShellVersion = '4.0'



    # Die für dieses Modul mindestens erforderliche Microsoft .NET Framework-Version. Diese erforderliche Komponente ist nur f�r die PowerShell Desktop-Edition g�ltig.

    # DotNetFrameworkVersion = ''



    # Die für dieses Modul mindestens erforderliche Version der CLR (Common Language Runtime). Diese erforderliche Komponente ist nur f�r die PowerShell Desktop-Edition g�ltig.

    # CLRVersion = ''



    # Die Module, die vor dem Importieren dieses Moduls in die globale Umgebung geladen werden m�ssen

    # RequiredModules = @()



    # Die Assemblys, die vor dem Importieren dieses Moduls geladen werden m�ssen

    # RequiredAssemblies = @()



    # Die Skriptdateien (PS1-Dateien), die vor dem Importieren dieses Moduls in der Umgebung des Aufrufers ausgef�hrt werden.

    # ScriptsToProcess = @()



    # Die Typdateien (.ps1xml), die beim Importieren dieses Moduls geladen werden sollen

    # TypesToProcess = @()



    # Die Formatdateien (.ps1xml), die beim Importieren dieses Moduls geladen werden sollen

    # FormatsToProcess = @()



    # Die Module, die als geschachtelte Module des in "RootModule/ModuleToProcess" angegebenen Moduls importiert werden sollen.

    # NestedModules = @()

    FunctionsToExport = '*'

    # Aus diesem Modul zu exportierende Cmdlets. Um optimale Leistung zu erzielen, verwenden Sie keine Platzhalter und l�schen den Eintrag nicht. Verwenden Sie ein leeres Array, wenn keine zu exportierenden Cmdlets vorhanden sind.

    CmdletsToExport   = @()



    # Die aus diesem Modul zu exportierenden Variablen

    # VariablesToExport = @()



    # Aus diesem Modul zu exportierende Aliase. Um optimale Leistung zu erzielen, verwenden Sie keine Platzhalter und l�schen den Eintrag nicht. Verwenden Sie ein leeres Array, wenn keine zu exportierenden Aliase vorhanden sind.

    AliasesToExport   = @()



    # Aus diesem Modul zu exportierende DSC-Ressourcen

    # DscResourcesToExport = @()



    # Liste aller Module in diesem Modulpaket

    # ModuleList = @()



    # Liste aller Dateien in diesem Modulpaket

    # FileList = @()



    # Die privaten Daten, die an das in "RootModule/ModuleToProcess" angegebene Modul �bergeben werden sollen. Diese k�nnen auch eine PSData-Hashtabelle mit zus�tzlichen von PowerShell verwendeten Modulmetadaten enthalten.

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
