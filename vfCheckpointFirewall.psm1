[string] $Script:HostName = $null
[string] $Script:SessionID = $null
[string] $Script:SessionUID = $null

Function Invoke-ckpWebRequest
{
    <#
    .SYNOPSIS
    Wrapper for webrequest against checkpoint web api

    .DESCRIPTION
    Wrapper function to create a web request against the checkpoint api
    it creates a webrequest according the pattern of the checkpoint web api
    only body and command has to be provided

    .PARAMETER HostName
    The hostname or ip to which the request will be adressed to

    .PARAMETER Command
    The api command

    .PARAMETER Body
    Hashtable containing the body properties

    .PARAMETER SessionID
    The Session ID to authenticate against the server

    .PARAMETER Credential
    Username and Password to create a session

    .EXAMPLE
    Invoke-ckpWebRequest -HostName $hostName -Command 'show-networks' -SessionId $sessId

    .EXAMPLE
    Invoke-ckpWebRequest  -HostName $hostName -Command 'login' -Credential $cred

    .EXAMPLE
    Invoke-ckpWebRequest -HostName $hostName -Command 'show-networks' -SessionId $sessId -Body @{limit = 500}
    #>
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
    #Allow invalid ssl certificates (e.g. self signed)
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
        $Body += @{
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
        $response = Invoke-RestMethod @requestParams -Verbose:$false -Debug:$DebugPreference
        return $response
    }
    catch [System.Net.WebException]
    {
        $httpError = $_

        #Retrieve the error response to get error details
        $errorStream = $httpError.Exception.Response.GetResponseStream()
        $errorReader = New-Object System.IO.StreamReader($errorStream)
        $errorReader.BaseStream.Position = 0
        $errorReader.DiscardBufferedData()
        $errorResponse = ($errorReader.ReadToEnd())
        if (-Not([string]::IsNullOrEmpty($errorResponse)))
        {
            try{
                $errorResponseContent = $errorResponse | ConvertFrom-Json
            }catch{

            }
        }

        if ($httpError.Exception.Response.StatusCode -eq [Net.HttpStatusCode]::NotFound)
        {
            return $null
        }
        elseif ($errorResponseContent -ne $null)
        {
            throw "Error ($([int]$httpError.Exception.Response.StatusCode) - $($httpError.Exception.Response.StatusCode.ToString())): Code '$($errorResponseContent.code)' Message: '$($errorResponseContent.message)'"
        }else{
            throw $httpError
        }
    }
}

Function Get-ckpInternalSession
{
    <#
    .SYNOPSIS
    Returns information about the current web session

    .DESCRIPTION
    Returns, Hostname, SessionID and SessionUID of the current websession
    If no session is available it returns null

    .EXAMPLE
    Get-ckpInternalSession
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(

    )

    if ([string]::IsNullOrEmpty($SessionID) -or [string]::IsNullOrEmpty($Script:HostName))
    {
        return $null
    }

    return @{
        HostName     = $Script:HostName
        SessionID    = $Script:SessionID
        SessionUID   = $Script:SessionUID
        SessionStart = $Script:SessionStart
    }
}

Function Get-ckpSession
{
    <#
    .SYNOPSIS
    Returns information about all available sessions or a specifc session

    .DESCRIPTION
    Rertieves session information from the checkpoint firewall
    All sessions of the current user can be displayed or an indivual one by specifying the
    session uid

    .PARAMETER UID
    The session uid, if specified detailed information about the session is returned

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .EXAMPLE
    Get-ckpSession

    .EXAMPLE
    Get-ckpSession -Limit 500 -Offset 200

    .EXAMPLE
    Get-ckpSession -Limit 500 -GetAll

    .EXAMPLE
    Get-ckpSession -Uid $sessUid

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-sessions~v1.1
    #>
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
    <#
    .SYNOPSIS
    Creates a new session to checkpoint firewall and saves session info

    .DESCRIPTION
    Login to checkpoint firewall returned session id is saved in module variable

    .PARAMETER HostName
    The hostname / ip of the checkpoint management server

    .PARAMETER Credential
    Username and password used to authenticate to checkpoint

    .PARAMETER ContinueLastSession
    If set the last inactive session will be reactivated instead of creating a new session
    This will cause an error if there are multiple inactive sessions

    .PARAMETER Timeout
    Set the session timeout in seconds
    The default timeout is 600 seconds

    .EXAMPLE
    Connect-ckpSession -HostName $HostName -Credential $cred

    .EXAMPLE
    Connect-ckpSession -HostName $HostName -Credential $cred -ContinueLastSession

    .EXAMPLE
    Connect-ckpSession -HostName $HostName -Credential $cred -Timeout 100

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/login~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $HostName

        ,[Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCredential] $Credential

        ,[Parameter()]
        [switch] $ContinueLastSession

        ,[Parameter()]
        [ValidateRange(1,800)]
        [int] $Timeout
    )

    $requestParams = @{
        HostName   = $HostName
        Command    = 'login'
        Credential = $Credential
        Body       = @{
            "session-name" = "ps-${env:COMPUTERNAME}-$($Credential.UserName)"
        }
    }

    if ($ContinueLastSession)
    {
        $requestParams['Body'] += @{
            "continue-last-session" = $true
        }
    }

    if ($Timeout -gt 0)
    {
        $requestParams['Body'] += @{
            "session-timeout" = $Timeout
        }
    }

    $response = Invoke-ckpWebRequest @requestParams
    $Script:HostName = $HostName
    $Script:SessionID = $response.sid
    $Script:SessionUID = $response.uid
    $Script:SessionStart = (Get-Date)
    return $response
}

Function Disconnect-ckpSession
{
    <#
    .SYNOPSIS
    Logout of a current checkpoint session

    .DESCRIPTION
    Terminates an open session with a checkpoint management server
    If no current session is open, function will just exit

    .EXAMPLE
    Disconnect-ckpSession

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/logout~v1.1
    #>
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
    $Script:HostName = $null
    $Script:SessionID = $null
    $Script:SessionUID = $null
    return $response
}

Function Publish-ckpSession
{
    <#
    .SYNOPSIS
    Publishes all changes made in the current session

    .DESCRIPTION
    All changes in the current session will be published to the server
    Only after a publish changes will be visible for others
    Function will do nothing if no session is currently open

    .PARAMETER Uid
    The uid of a 'different' session whose changes shall be published.
    If obmittet the current session will be published.

    .EXAMPLE
    Publish-ckpSession

    .EXAMPLE
    Publish-ckpSession -Uid 6d8aff8d-b242-4848-9c71-8becc8b77be8

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/publish~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Uid
    )
    Begin
    {
        $session = Get-ckpInternalSession
        if (-Not $session)
        {
            return
        }
    }

    Process
    {
        $requestParams = @{
            HostName  = $session.HostName
            Command   = 'publish'
            SessionID = $session.SessionID
        }
        if (-Not([string]::IsNullOrEmpty($Uid)))
        {
            $requestParams['Body'] = @{
                uid = $Uid
            }
        }
        return Invoke-ckpWebRequest @requestParams
    }
}

Function Undo-ckpSession
{
    <#
    .SYNOPSIS
    Discards all changes made in the specified session

    .DESCRIPTION
    Discards all changes made in the current session
    Resets the session, opposite of publish changes
    Function will do nothing if no session is currently open
    If Uid parameter is provied changes of the specified session will be discarded.
    If other session is inactive it will be closed if all changes have been discarded.

    .PARAMETER Uid
    The uid of a 'different' session whose changes shall be discarded
    If obmitted the changes of the current session will be discarded

    .EXAMPLE
    Undo-ckpSession

    .EXAMPLE
    Undo-ckpSession -Uid 6d8aff8d-b242-4848-9c71-8becc8b77be8

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/discard~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Uid
    )
    Begin
    {
        $session = Get-ckpInternalSession
        if (-Not $session)
        {
            return
        }
    }

    Process
    {
        $requestParams = @{
            HostName  = $session.HostName
            Command   = 'discard'
            SessionID = $session.SessionID
        }
        if (-Not([string]::IsNullOrEmpty($Uid)))
        {
            $requestParams['Body'] = @{
                uid = $Uid
            }
        }

        return Invoke-ckpWebRequest @requestParams
    }
}

Function Reset-ckpSessionTimeout
{
    <#
    .SYNOPSIS
    Extends the session timeout of the current session

    .DESCRIPTION
    If the session will expire in less than 30 seconds a command will be sent to the api
    to extend the session by the timeout intervall of the session
    If session will not expire in less then 30 seconds no request will be made unless the Force flag is set

    .PARAMETER Force
    Will force to extend the session even if the session will not expire for more than 30 seconds

    .EXAMPLE
    Reset-ckpSessionTimeout

    .EXAMPLE
    Reset-ckpSessionTimeout -Force

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/keepalive~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [switch] $Force
    )
    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        return
    }
    if ((-Not($Force)) -and (((Get-Date) - $session.SessionStart).TotalSeconds -lt 530))
    {
        return
    }
     $requestParams = @{
        HostName  = $session.HostName
        Command   = 'keepalive'
        SessionID = $session.SessionID
    }
    return Invoke-ckpWebRequest @requestParams
}

Function Switch-ckpSession
{
    <#
    .SYNOPSIS
    Switches from the current session to the provided session

    .DESCRIPTION
    Switches from the current session to another inactive session of the same user
    If source session has no changes it will disappear after the switch.
    Source session will persist as inactive session if changes where made on the session that have not been published yet.

    .PARAMETER Uid
    The Uid of the session to switch to

    .EXAMPLE
    Switch-ckpSession -Uid 6d8aff8d-b242-4848-9c71-8becc8b77be8

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/switch-session~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Uid
    )

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        return
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'switch-session'
        SessionID = $session.SessionID
        Body      = @{
            uid = $Uid
        }
    }

    $response =  Invoke-ckpWebRequest @requestParams
    $Script:SessionUID = $response.uid
    return $response
}

Function Get-internalObject
{
    <#
    .SYNOPSIS
    Wrapper for building a show-* request against the checkpoint api

    .DESCRIPTION
    Generic wrapper for all get object request against the check point firewall
    All Objects can be retrieved with the command pattern show-objects for all objects of the type
    or show-object with a specifc name or uid.
    This function handles the different command builds in a generic wrapper that will be called
    from a different function for each object type

    .PARAMETER CommandSingularName
    The command name in singular form (e.g. network, service-tcp)

    .PARAMETER CommandPluralName
    The command name in plural form (e.g. networks, hosts, services-tcp)

    .PARAMETER Name
    The name of the specific object to retrieve

    .PARAMETER UID
    The uid of the specific object to retrieve

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .PARAMETER AdditionalProperties
    Hashtable with additional properties that shall be passed to the request

    .EXAMPLE
    Get-internalObject -CommandSingularName 'network' -CommandPluralName 'networks' -GetAll

    .EXAMPLE
    Get-internalObject -CommandSingularName 'network' -CommandPluralName 'networks' -Name 'someNetwork'
    #>
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

        ,[Parameter(ParameterSetName = 'Generic')]
        [Parameter(ParameterSetName = 'Name')]
        [Parameter(ParameterSetName = 'UID')]
        [ValidateNotNull()]
        [hashtable] $AdditionalProperties

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

    if ($AdditionalProperties -ne $null)
    {
        $body += $AdditionalProperties
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = $command
        SessionID = $session.SessionID
        Body      = $body
    }
    $response = Invoke-ckpWebRequest @requestParams
    $returnValue = $response
    if ($response -eq $null)
    {
        # if response is null then get-member will cause an error therefore return the empty response
        return $returnValue
    }

    $childrenNode = $response | Get-Member -MemberType NoteProperty |
                    Where-Object {($_.Name -ieq 'objects') -or ($_.Name -ieq $CommandPluralName)} |
                    Select-Object -First 1 | Select-Object -ExpandProperty Name

    #if a single object of a specific type will be returned it will always have a sub element of the plural name
    #therefore we need to check if the $resposne.type is the command singluar name then it is not an object array but a single return
    if (($response -ne $null) -and ($childrenNode -ne $null) -and $($response.type -ne $CommandSingularName))
    {
        $returnValue = $response.$($childrenNode)
        while (
            ($GetAll) -and
            (
                (($Limit -ne $null) -and ($response.$($childrenNode).Count -ge $Limit)) -or
                (($Limit -eq $null) -and ($response.$($childrenNode).Count -ge 50))
            )
        )
        {
            $requestParams['Body']['offset'] = $response.$($childrenNode).Count
            $requestParams['Body']['limit'] = 500
            $Limit = 500
            $response = Invoke-ckpWebRequest @requestParams
            $returnValue += $response.$($childrenNode)
        }
    }
    return $returnValue
}

Function Get-ckpNetwork
{
    <#
    .SYNOPSIS
    Get all available networks or get a specifc network

    .DESCRIPTION
    Retrieves all network objects or a specific network object
    Request can max retrieve 500 objects at a time, use offest and limit or the Getall switch
    to retrieve all

    .PARAMETER Name
    The name of the specific network to retrieve

    .PARAMETER UID
    The uid of the specific network to retrieve

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .EXAMPLE
    Get-ckpNetwork

    .EXAMPLE
    Get-ckpNetwork -Name 'someNetwork'

    .EXAMPLE
    Get-ckpNetwork -Limit 500 -GetAll

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-networks~v1.1
    #>
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
    <#
    .SYNOPSIS
    Creates a new network object

    .DESCRIPTION
    Creates a new network given a name and an IP range and a subnetmask or subnetmaks length
    When using the Subnet and MaskLength checkpoint automatically decides on v4 or v6.
    If needed you can specify v4 or v6 or both directly

    .PARAMETER Name
    The name of the network object

    .PARAMETER Subnet
    The IP Range of the subnet / net adress

    .PARAMETER MaskLength
    The subnet mask length (e.g. 16, 32 etc.)

    .PARAMETER SubentV4
    The IP Range of the v4 subnet / net adress v4

    .PARAMETER MaskLengthV4
    The subnet mask length v4 (e.g. 16, 32 etc.)

    .PARAMETER SubentV6
    The IP Range of the v6 subnet / net adress v6

    .PARAMETER MaskLengthV6
    The subnet mask length v6

    .PARAMETER Tags
    Assign one or more tags to the network object

    .EXAMPLE
    Add-ckpNetwork -Name 'someNet' -Subnet '10.221.0.1' -MaskLength 28

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/add-network~v1.1
    #>

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
    <#
    .SYNOPSIS
    Removes a network object from the firewall given the name or the uid of the network

    .DESCRIPTION
    Removes the network object by uid or name
    Changes must be published before they take effekt

    .PARAMETER Name
    The name of the network

    .PARAMETER Uid
    The uid of the network

    .EXAMPLE
    Remove-ckpNetwork -Name 'NetworkName'

    .EXAMPLE
    Remove-ckpNetwork -Uid $networkId

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/delete-network~v1.1
    #>
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
    <#
    .SYNOPSIS
    Get all group objects or specific group by name or uid

    .DESCRIPTION
    Retrieves all group objects or specific one by name or id
    Detailed information are returned only when requesting specific object

    .PARAMETER Name
    The name of the specific group to retrieve

    .PARAMETER UID
    The uid of the specific group to retrieve

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .EXAMPLE
    Get-ckpGroup -Limit 500 -GetAll

    .EXAMPLE
    Get-ckpGroup -Name azure_public_westeurope

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-groups~v1.1
    #>
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
    <#
    .SYNOPSIS
    Creates a new group object

    .DESCRIPTION
    Creates a new gorup object by specifying a name and a list of object uids as members of this group
    Changes need to be pulished to take affect.

    .PARAMETER Name
    The name of the group to be created

    .PARAMETER Member
    List of object uids which will be part of the group

    .PARAMETER Tags
    One or more tags which will be assigend to the group

    .EXAMPLE
    Add-ckpGroup -Name azure_public_westeurope -Member $id1,$id2

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/add-group~v1.1
    #>
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
            name    = $Name
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
    <#
    .SYNOPSIS
    Change properties of a given group object

    .DESCRIPTION
    Long description

    .PARAMETER Name
    The name of the group to change

    .PARAMETER Uid
    The uid of the group to change

    .PARAMETER AddMember
    The list of members (names or uids) to add to the group

    .PARAMETER RemoveMember
    The list of members (names or uids) to remove from the group

    .PARAMETER Tags
    The list of tags to assign to the group

    .EXAMPLE
    Set-ckpGroup -Name azure_public_ips -NetName azure_public_2

    .EXAMPLE
    Set-ckpGroup -Name azure_public_ips -AddMember $id1,$id2

    .EXAMPLE
    Set-ckpGroup -Name azure_public_ips -AddMember $id1,$id2 -RemoveMember $id3,$id4

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/set-group~v1.1
    #>
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
        [string[]] $AddMember

       ,[Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Name')]
        [Parameter(ParameterSetName = 'Uid')]
        [string[]] $RemoveMember

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

        if (($AddMember -ne $null) -and ($AddMember.Count -gt 0))
        {
            $body['members'] += @{
                add = $AddMember
            }
        }

        if (($RemoveMember -ne $null) -and ($RemoveMember.Count -gt 0))
        {
            $body['members'] += @{
                remove = $RemoveMember
            }
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

Function Get-ckpHost
{
    <#
    .SYNOPSIS
    Get all host objects or specific host by name or uid

    .DESCRIPTION
    Retrieves all host objects or specific one by name or id
    Detailed information are returned only when requesting specific object

    .PARAMETER Name
    The name of the specific host to retrieve

    .PARAMETER UID
    The uid of the specific host to retrieve

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .EXAMPLE
    Get-ckpHost -Limit 500 -GetAll

    .EXAMPLE
    Get-ckpHost -Name azure_public_westeurope

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-hosts~v1.1
    #>
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

    return Get-internalObject @PSBoundParameters -CommandSingularName 'host' -CommandPluralName 'hosts'
}

Function Add-ckpHost
{
    <#
    .SYNOPSIS
    Creates a new host object

    .DESCRIPTION
    Creates a new host object by specifying a name and a ip address
    Changes need to be pulished to take affect.

    .PARAMETER Name
    The name of the host to be created

    .PARAMETER IpAddress
    The Ip Address of the host to be added

    .PARAMETER Tags
    One or more tags which will be assigend to the host

    .EXAMPLE
    Add-ckpHost -Name 'sdeurvf7892.eur.corp.vattenfall.com' -IpAddress '144.27.132.71'

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/add-host~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $IpAddress

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
            name         = $Name
            "ip-address" = $IpAddress
        }

        if (($Tags -ne $null) -and ($Tags.Count -gt 0))
        {
            $body['tags'] = $Tags
        }

        $requestParams = @{
            HostName  = $session.HostName
            Command   = 'add-host'
            SessionID = $session.SessionID
            Body      = $body
        }
        return Invoke-ckpWebRequest @requestParams
    }
}
Function Get-ckpObject
{
    <#
    .SYNOPSIS
    Return a specific firewall object or all firewall objects
    Return firewall objects of a specific type

    .DESCRIPTION
    Generic function to return any firewall object. Function can filter by type, name etc.

    .PARAMETER Name
    The name of the object to return

    .PARAMETER UID
    The uid of the object to return

    .PARAMETER Type
    The object type on which shall be filtered
    If specified only objects of the specified type will be returned

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .EXAMPLE
    Get-ckpObject

    .EXAMPLE
    Get-ckpObject -Type 'application-site'

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-objects~v1.1
    #>
    [CmdletBinding(DefaultParameterSetName = 'Generic')]
    Param(
        [Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name

        ,[Parameter(ParameterSetName = 'UID')]
        [string] $UID

        ,[Parameter(ParameterSetName = 'Generic')]
        [Parameter(ParameterSetName = 'UID')]
        [Parameter(ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Type

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateNotNull()]
        [int] $Offset

        ,[Parameter(ParameterSetName = 'Generic')]
        [ValidateRange(1,500)]
        [int] $Limit

        ,[Parameter(ParameterSetName = 'Generic')]
        [switch] $GetAll

    )
    $params = @{}
    Foreach ($boundParam in $PSBoundParameters.GetEnumerator())
    {
        if ($boundParam.Key -ieq 'Type')
        {
            $params['AdditionalProperties'] = @{
                type = $boundParam.Value
            }
            continue
        }
        $params[$boundParam.Key] = $boundParam.Value
    }
    return Get-internalObject @params -CommandSingularName 'object' -CommandPluralName 'objects'
}

Function Get-ckpCommand
{
    <#
    .SYNOPSIS
    Returns all rest api commands which are supported by the api

    .DESCRIPTION
    Returns all the api commands wich are supported by the management api.
    The name parameter can be used to filter the request with a prefix, Name is not a wildcard search but only a prefix match

    .PARAMETER Name
    The prefix to filter the command list by (e.g. get or show)

    .EXAMPLE
    Get-ckpCommand

    .EXAMPLE
    Get-ckpCommand -Name show

     .EXAMPLE
    Get-ckpCommand -Name show-networks

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-commands~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        throw "You are not logged in please run 'Connect-ckpSession'"
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'show-commands'
        SessionID = $session.SessionID
    }
    if (-Not([string]::IsNullOrEmpty($Name)))
    {
        $requestParams['Body'] = @{
            prefix = $Name
        }
    }
    $response = Invoke-ckpWebRequest @requestParams
    if (($response -ne $null) -and (($response | Get-Member -MemberType NoteProperty -Name 'commands') -ne $null))
    {
        return $response.commands
    }
    return $response
}

Function Get-ckpGateway
{
    <#
    .SYNOPSIS
    Returns a list of all firewall servers and gateways

    .DESCRIPTION
    Returns a list of all firewall servers and gateways

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .EXAMPLE
    Get-ckpGateway -Limit 10

    .EXAMPLE
    Get-ckpGateway -GetAll

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-gateways-and-servers~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [ValidateNotNull()]
        [int] $Offset

        ,[Parameter()]
        [ValidateRange(1,500)]
        [int] $Limit

        ,[Parameter()]
        [switch] $GetAll
    )

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        throw "You are not logged in please run 'Connect-ckpSession'"
    }
    $body = @{
        limit = 100
    }

    if ($Offset -ne $null)
    {
        $body['offset'] = $Offset
    }
    if ($Limit -ne $null)
    {
        $body['limit'] = $Limit
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'show-gateways-and-servers'
        SessionID = $session.SessionID
        Body      = $body
    }
    $response = Invoke-ckpWebRequest @requestParams
    $returnValue = $response

    #Get All Logic to retrieve all objects even if greater than 500 limit
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

New-Alias -Name Get-ckpServer -Value Get-ckpGateway

Function Get-ckpObjectUsage
{
    <#
    .SYNOPSIS
    Searches if the provided object is used in other objects (groups, rules) etc.

    .DESCRIPTION
    Searches for direct and inderect dependencies to the provided object
    If object is part of a group or specific rules etc.
    Usefull for checking if an object can be deleted without causing a conflict.

    .PARAMETER Name
    The name of the object for which the dependencies shall be found

    .PARAMETER Uid
    The uid of the object for which the depenencies shall be found

    .EXAMPLE
    Get-ckpObjectUsage -Uid 6d8aff8d-b242-4848-9c71-8becc8b77be8

    .EXAMPLE
    Get-ckpObjectUsage -Name 'someObject'

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/where-used~v1.1
    #>
    [CmdletBinding(DefaultParameterSetName = 'Uid')]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'Name')]
        [ValidateNotNullOrEmpty()]
        [string] $Name

       ,[Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Uid')]
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
            Command   = 'where-used'
            SessionID = $session.SessionID
            Body      = $body
        }
        return Invoke-ckpWebRequest @requestParams
    }
}

Function Get-ckpValidation
{
    <#
    .SYNOPSIS
    Returns a list of all validations and inicdents

    .DESCRIPTION
    Returns a list of all validations and inicdents

    .EXAMPLE
    Get-ckpValidation

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-validations~v1.1
    #>
    [CmdletBinding()]
    Param()

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        throw "You are not logged in please run 'Connect-ckpSession'"
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'show-validations'
        SessionID = $session.SessionID
    }
    return Invoke-ckpWebRequest @requestParams
}

Function Get-ckpPackage
{
    <#
    .SYNOPSIS
    Get a list of all policy package or a specific policy package

    .DESCRIPTION
    Retrieves a list of firewall policy packages or a specific policy package identified by name or uid.

    .PARAMETER Name
    Name of the policy package to retrieve

    .PARAMETER UID
    Uid of the policy package to retrieve

    .PARAMETER Offset
    The offset of itmes to retrieve, can be used to retrieve objects beyond the limit of
    500 objects per call

    .PARAMETER Limit
    The maximal amount of objects to return which one call

    .PARAMETER GetAll
    Switch if set, multiple api calls with the specified limit are made
    until all available objects are retrieved.

    .EXAMPLE
    Get-ckpPackage

     .EXAMPLE
    Get-ckpPackage -Name Standard

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-packages~v1.1
    #>
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

    $response = Get-internalObject @PSBoundParameters -CommandSingularName 'package' -CommandPluralName 'packages'
    if (($response -ne $null) -and (($response | Get-Member -MemberType NoteProperty -Name 'tasks') -ne $null))
    {
        return $response.tasks
    }
    return $response
}

Function Get-ckpTask
{
    <#
    .SYNOPSIS
    Shows the current status of a firewall background task

    .DESCRIPTION
    Returns information and the status of a given background task
    e.g. the publish operation of a session is excecuted in the backgorund and its status can be retrieved
    with this command

    .PARAMETER Id
    The ID of the task

    .EXAMPLE
    Get-ckpTask -Id $taskId

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/show-task~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Id
    )

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        throw "You are not logged in please run 'Connect-ckpSession'"
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'show-task'
        SessionID = $session.SessionID
        Body      = @{
            "task-id" = $Id
        }
    }

    $response = Invoke-ckpWebRequest @requestParams
    if (($response -ne $null) -and (($response | Get-Member -MemberType NoteProperty -Name 'tasks') -ne $null))
    {
        return $response.tasks
    }
    return $response
}

Function Install-ckpPolicy
{
    <#
    .SYNOPSIS
    Installs a given policy package on a given target

    .DESCRIPTION
    Installs all rules on the firewalls itself. A policy package and a target can be specified

    .PARAMETER Package
    The name of the policy package which shall be installed (e.g. standard)

    .PARAMETER Target
    A list of target servers to which the policy package shall be installed to

    .EXAMPLE
    Install-ckpPolicy -Package Standard -Target 'corporate-gateway'

    .LINK
    https://sc1.checkpoint.com/documents/latest/APIs/#web/install-policy~v1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Package

       ,[Parameter()]
        [ValidateNotNull()]
        [string[]] $Target
    )

    $session = Get-ckpInternalSession
    if (-Not $session)
    {
        throw "You are not logged in please run 'Connect-ckpSession'"
    }

    $requestParams = @{
        HostName  = $session.HostName
        Command   = 'install-policy'
        SessionID = $session.SessionID
    }

    if (-Not([string]::IsNullOrEmpty($Package)))
    {
        $requestParams['Body'] += @{
            "policy-package" = $Package
        }
    }
    if (($Target -ne $null) -and ($Target.Count -gt 0))
    {
        $requestParams['Body'] += @{
            "targets" = $Target
        }
    }

    return Invoke-ckpWebRequest @requestParams
}