[string] $Script:HostName = $null
[string] $Script:SessionID = $null
[string] $Script:SessionUID = $null

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
    #[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


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
    }else{
        $requestParams['Body'] = '{}'
    }
    Write-Debug ($requestParams | Format-Table -AutoSize | Out-String).Trim()
    Write-Debug "REST CALL: '$($requestUri.ToString())'"
    try
    {
        return Invoke-RestMethod @requestParams -Verbose:$VerbosePreference -Debug:$DebugPreference
    }
    catch [System.Net.WebException]
    {
        $httpError = $_
        if ($httpError.Exception.Response.StatusCode -eq [Net.HttpStatusCode]::NotFound)
        {
            return $null
        }
        else
        {
            throw $httpError
        }
    }
}

Function Get-ckpInternalSession
{
    if ([string]::IsNullOrEmpty($SessionID) -or [string]::IsNullOrEmpty($Script:HostName))
    {
        return $null
    }

    return @{
        HostName   = $Script:HostName
        SessionID  = $Script:SessionID
        SessionUID = $Script:SessionUID
    }
}

Function Get-ckpSession
{
    [CmdletBinding(DefaultParameterSetName = 'Generic')]
    Param(
        [Parameter(ParameterSetName = 'UID')]
        [string] $UID

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateNotNull()]
        [int] $Offset

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateRange(1,500)]
        [int] $Limit

        ,[Parameter(ParameterSetName = 'Generic')]
        [switch] $GetAll

    )
    return Get-internalObject @PSBoundParameters -CommandSingularName 'session' -CommandPluralName 'sessions'
}

Function Connect-ckpSession
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
        Command    = 'login'
        Credential = $Credential
    }
    $response = Invoke-ckpWebRequest @requestParams
    $Script:HostName = $HostName
    $Script:SessionID = $response.sid
    $Script:SessionUID = $response.uid
    $Script:SessionStartTime = (Get-Date)
    return $response
}

Function Disconnect-ckpSession
{
    [CmdletBinding()]
    Param()

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        return
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'logout'
        SessionID = $session.SessionID
    }
    $response = Invoke-ckpWebRequest @requestParams
    return $response
}

Function Publish-ckpSession
{
    [CmdletBinding()]
    Param()

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        return
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'publish'
        SessionID = $session.SessionID
    }
    return Invoke-ckpWebRequest @requestParams
}

Function Undo-ckpSession
{
    [CmdletBinding()]
    Param()

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        return
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'discard'
        SessionID = $session.SessionID
    }
    return Invoke-ckpWebRequest @requestParams
}


Function Get-internalObject
{
    [CmdletBinding(DefaultParameterSetName = 'Generic')]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CommandSingularName

        ,[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CommandPluralName

        ,[Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(ParameterSetName = 'UID')]
        [string] $UID

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateNotNull()]
        [int] $Offset

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateRange(1,500)]
        [int] $Limit

        ,[Parameter(ParameterSetName = 'Generic')]
        [switch] $GetAll
    )

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        throw "You are not logged in please run 'Connect-ckpSession'"
    }
    $command = "show-$($CommandPluralName.ToLower())"
    $body = @{
        limit = 100
    }

    if ($PSBoundParameters.Count -gt 0)
    {
        if ($PSCmdlet.ParameterSetName -ne 'Generic')
        {
            $command = "show-$($CommandSingularName.ToLower())"
            Foreach ($boundParam in $PSBoundParameters.GetEnumerator())
            {
                if ($boundParam.Key -notin @('Name','UID'))
                {
                    continue
                }
                $body = @{
                    "$(([string]$boundParam.Key).ToLower())" = $boundParam.Value
                }
            }
        }
        else
        {
            if ($Offset -ne $null)
            {
                $body['offset'] = $Offset
            }
            if ($Limit -ne $null)
            {
                $body['limit'] = $Limit
            }
        }
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = $command
        SessionID = $session.SessionID
        Body      = $body
    }
    $response = Invoke-ckpWebRequest @requestParams
    $returnValue = $response
    if (($response -ne $null) -and (($response | Get-Member -MemberType NoteProperty -Name objects) -ne $null))
    {
        $returnValue = $response.objects
        while (
            ($GetAll) -and
            (
                (($Limit -ne $null) -and ($response.objects.Count -ge $Limit)) -or
                (($Limit -eq $null) -and ($response.objects.Count -ge 50))
            )
        )
        {
            $requestParams['Body']['offset'] = $response.objects.Count
            $requestParams['Body']['limit'] = 500
            $Limit = 500
            $response = Invoke-ckpWebRequest @requestParams
            $returnValue += $response.objects
        }
    }
    return $returnValue
}

Function Get-ckpNetwork
{
    [CmdletBinding(DefaultParameterSetName = 'Generic')]
    Param(
        [Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(ParameterSetName = 'UID')]
        [string] $UID

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateNotNull()]
        [int] $Offset

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateRange(1,500)]
        [int] $Limit

        ,[Parameter(ParameterSetName = 'Generic')]
        [switch] $GetAll

    )
    return Get-internalObject @PSBoundParameters -CommandSingularName 'network' -CommandPluralName 'networks'
}

Function Add-ckpNetwork
{
    [CmdletBinding(DefaultParameterSetName = 'Generic')]
    Param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Generic')]
        [string] $Subnet

        ,[Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Generic')]
        [string] $MaskLength

        ,[Parameter(Mandatory, ParameterSetName = 'v4')]
        [string] $SubentV4

        ,[Parameter(Mandatory, ParameterSetName = 'v4')]
        [string] $MaskLengthV4

        ,[Parameter(Mandatory, ParameterSetName = 'v6')]
        [string] $SubentV6

        ,[Parameter(Mandatory, ParameterSetName = 'v6')]
        [string] $MaskLengthV6

        ,[Parameter(ParameterSetName = 'Generic')]
        [Parameter(ParameterSetName = 'v4')]
        [Parameter(ParameterSetName = 'v6')]
        [string[]] $Tags

        ,[Parameter(ParameterSetName = 'Generic')]
        [Parameter(ParameterSetName = 'v4')]
        [Parameter(ParameterSetName = 'v6')]
        [ValidateSet('disallow','allow')]
        [string] $Broadcast
    )
    Begin
    {
        $session = Get-ckpInternalSession
        if (-Not $session)
        {
            throw "You are not logged in please run 'Connect-ckpSession'"
        }
    }

    Process
    {
        $body = @{
            name = $name
        }

        if ($PSCmdlet.ParameterSetName -eq 'Generic')
        {
            $body += @{
                subnet        = $Subnet
                "mask-length" = $MaskLength
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'v4')
        {
            $body += @{
                subnet4        = $SubnetV4
                "mask-length4" = $MaskLengthV4
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'v6')
        {
            $body += @{
                subnet6        = $SubnetV6
                "mask-length6" = $MaskLengthV6
            }
        }

        if (-Not ([string]::IsNullOrEmpty($Broadcast)))
        {
            $body['broadcast'] = $Broadcast
        }

        if (($Tags -ne $null) -and ($Tags.Count -gt 0))
        {
            $body['tags'] = $Tags
        }

        $requestParams = @{
            HostName  = $session.HostName
            Command   = 'add-network'
            SessionID = $session.SessionID
            Body      = $body
        }
        return Invoke-ckpWebRequest @requestParams
    }
}

Function Remove-ckpNetwork
{
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'Name', ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(Mandatory, ParameterSetName = 'Uid')]
        [ValidateNotNullOrEmpty()]
        [string] $Uid
    )

    Begin
    {
        $session = Get-ckpInternalSession
        if (-Not $session)
        {
            throw "You are not logged in please run 'Connect-ckpSession'"
        }
    }

    Process
    {
        $body = @{
           "$($PSCmdlet.ParameterSetName.ToLower())" = (Get-Variable -Name $($PSCmdlet.ParameterSetName) -ValueOnly)
        }

        $requestParams = @{
            HostName  = $session.HostName
            Command   = 'delete-network'
            SessionID = $session.SessionID
            Body      = $body
        }
        return Invoke-ckpWebRequest @requestParams
    }
}

Function Get-ckpGroup
{
    [CmdletBinding(DefaultParameterSetName = 'Generic')]
    Param(
        [Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(ParameterSetName = 'UID')]
        [string] $UID

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateNotNull()]
        [int] $Offset

        ,[Parameter(ParameterSetName = 'Generic')]
         [ValidateRange(1,500)]
        [int] $Limit

        ,[Parameter(ParameterSetName = 'Generic')]
        [switch] $GetAll
    )

    return Get-internalObject @PSBoundParameters -CommandSingularName 'group' -CommandPluralName 'groups'
}

Function Add-ckpGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [string[]] $Member

        ,[Parameter()]
        [ValidateNotNull()]
        [string[]] $Tags
    )
    Begin
    {
        $session = Get-ckpInternalSession
        if (-Not $session)
        {
            throw "You are not logged in please run 'Connect-ckpSession'"
        }
    }

    Process
    {
        $body = @{
            name = $Name
            members = $Member
        }

        if (($Tags -ne $null) -and ($Tags.Count -gt 0))
        {
            $body['tags'] = $Tags
        }

        $requestParams = @{
            HostName  = $session.HostName
            Command   = 'add-group'
            SessionID = $session.SessionID
            Body      = $body
        }
        return Invoke-ckpWebRequest @requestParams
    }
}

Function Set-ckpGroup
{
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    Param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name

       ,[Parameter(Mandatory, ParameterSetName = 'Uid')]
        [ValidateNotNullOrEmpty()]
        [string] $Uid

       ,[Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Name')]
        [Parameter(ParameterSetName = 'Uid')]
        [ValidateNotNull()]
        [string[]] $Member

       ,[Parameter(ParameterSetName = 'Name')]
        [Parameter(ParameterSetName = 'Uid')]
        [ValidateNotNull()]
        [string] $NewName

        ,[Parameter(ParameterSetName = 'Name')]
        [Parameter(ParameterSetName = 'Uid')]
        [ValidateNotNull()]
        [string[]] $Tags
    )
    Begin
    {
        $session = Get-ckpInternalSession
        if (-Not $session)
        {
            throw "You are not logged in please run 'Connect-ckpSession'"
        }
    }

    Process
    {
        $body = @{
            "$($PSCmdlet.ParameterSetName.ToLower())" = (Get-Variable -Name $($PSCmdlet.ParameterSetName) -ValueOnly)
        }

        if ($Member -ne $null)
        {
            $body['members'] = $Member
        }

        if (-Not ([string]::IsNullOrEmpty($NewName)))
        {
            $body['new-name'] = $NewName
        }

        if (($Tags -ne $null) -and ($Tags.Count -gt 0))
        {
            $body['tags'] = $Tags
        }

        $requestParams = @{
            HostName  = $session.HostName
            Command   = 'set-group'
            SessionID = $session.SessionID
            Body      = $body
        }
        return Invoke-ckpWebRequest @requestParams
    }
}
