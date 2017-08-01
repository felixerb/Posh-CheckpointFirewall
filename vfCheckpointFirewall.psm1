[string] $Script:HostName = $null
[string] $Script:SessionID = $null

Function Invoke-ckpWebRequest
{
    [CmdletBinding(DefaultParameterSetName = "Session")]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $HostName

        ,[Parameter(Mandatory)]
        [ValidateNotNull()]
        [string] $Command

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
        Path   = "web_api/" + $Command
    }

    $requestParams = @{
        Method      = 'POST'
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

Function Get-ckpInternalSession
{
    if ([string]::IsNullOrEmpty($SessionID) -or [string]::IsNullOrEmpty($Script:HostName))
    {
        return $null
    }

    return @{
        HostName  = $Script:HostName
        SessionID = $Script:SessionID
    }
}

Function Get-ckpSession
{
    [CmdletBinding()]
    Param(

    )
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

Function Unregister-ckpSession
{
    [CmdletBinding()]
}

Function Get-ckpNetwork
{
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    Param(
        [Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(ParameterSetName = 'UID')]
        [string] $UID
    )

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        throw "You are not logged in please run 'Register-ckpSession'"
    }
    $command = 'show-networks'
    $body = @{
        limit = 100
    }

    if (-Not([string]::IsNullOrEmpty($Name)))
    {
        $command = 'show-network'
        $body = @{
            name = $Name
        }
    }

    $requestParams = @{
        HostName  = $HostName
        Command   = $command
        SessionID = $SessionID
        Body      = $body
    }
    $networks = Invoke-ckpWebRequest @requestParams
    return $networks
}


