$Script:HostName = $null
$Script:SessionID = $null

Function Invoke-ckpWebRequest
{
    [CmdletBinding(DefaultParameterSetName = "Session")]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $HostName

        ,[Parameter(Mandatory)]
        [ValidateNotNull()]
        [string[]] $Commands

        ,[Parameter(Mandatory)]
        [ValidateSet("POST","GET")]
        [string] $Method

        ,[Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Credential')]
        [Object] $Body

        ,[Parameter(Mandatory, ParameterSetName = 'Session')]
        [ValidateNotNullOrEmpty()]
        [string] $SessionID

        ,[Parameter(Mandatory, ParameterSetName = "Credential")]
        [ValidateNotNullOrEmpty()]
        [PSCredential] $Credential
    )
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    $requestUri = [System.UriBuilder] @{
        Host   = $HostName
        Scheme = "https"
        Port   = "443"
        Path   = "web_api/" + ($Commands -join "/")
    }

    $requestParams = @{
        Method      = $Method
        Uri         = ($requestUri.ToString())
        ContentType = 'application/json'
    }

    if (-Not([string]::IsNullOrEmpty($SessionID)))
    {
        $requestParams['Headers'] = @{
            "X-chkp-sid" = $SessionID
        }
    }
    else
    {
        Write-Debug "Using Credential Authentication"
        $Body = @{
            user     = $Credential.UserName
            password = $Credential.GetNetworkCredential().Password
        }
    }

    if (($Body -ne $null))
    {
        $jsonBody = ConvertTo-Json -Depth 99 -InputObject $Body
        $requestParams['Body'] = $jsonBody
        Write-Debug "JsonBody: `n $jsonBody"
    }
    Write-Debug ($requestParams | Format-Table -AutoSize | Out-String).Trim()
    Write-Debug "REST CALL: '$($requestUri.ToString())'"
    $response = Invoke-RestMethod @requestParams -Verbose:$VerbosePreference -Debug:$DebugPreference
    return $response
}

Function Register-ckpSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $HostName

        ,[Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCredential] $Credential
    )

    $requestParams = @{
        HostName   = $HostName
        Method     = 'POST'
        Commands   = @('login')
        Credential = $Credential
    }
    $response = Invoke-ckpWebRequest @requestParams
    $Script:HostName = $HostName
    $Script:SessionID = $response.sid
    return $response
}


Function Get-ckpNetwork
{
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    Param(
        [Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $NetworkName

        ,[Parameter(ParameterSetName = 'UID')]
        [string] $NetworkUID

        ,[Parameter(ParameterSetName = 'Name')]
        [Parameter(ParameterSetName = 'UID')]
        [ValidateNotNullOrEmpty()]
        [string]$SessionID = $Script:SessionID

        ,[Parameter(ParameterSetName = 'Name')]
        [Parameter(ParameterSetName = 'UID')]
        [ValidateNotNullOrEmpty()]
        [string]$HostName = $Script:HostName
    )

    if ([string]::IsNullOrEmpty($SessionID) -or [string]::IsNullOrEmpty($HostName))
    {
        throw "You are not logged in please run 'Register-ckpSession'"
    }
    $command = 'show-networks'
    $body = @{
        limit = 100
    }

    if (-Not([string]::IsNullOrEmpty($NetworkName)))
    {
        $command = 'show-network'
        $body = @{
            name = $NetworkName
        }
    }

    $requestParams = @{
        HostName  = $HostName
        Method    = 'POST'
        Commands  = @($command)
        SessionID = $SessionID
        Body      = $body
    }
    $networks = Invoke-ckpWebRequest @requestParams
    return $networks
}


