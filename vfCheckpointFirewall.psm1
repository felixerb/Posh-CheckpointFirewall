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
        HostName   = $Script:HostName
        SessionID  = $Script:SessionID
        SessionUID = $Script:SessionUID
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

    .EXAMPLE
    Connect-ckpSession -HostName $HostName -Credential $cred
    #>
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
    <#
    .SYNOPSIS
    Logout of a current checkpoint session

    .DESCRIPTION
    Terminates an open session with a checkpoint management server
    If no current session is open, function will just exit

    .EXAMPLE
    Disconnect-ckpSession
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

    .EXAMPLE
    Publish-ckpSession
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
        Command   = 'publish'
        SessionID = $session.SessionID
    }
    return Invoke-ckpWebRequest @requestParams
}

Function Undo-ckpSession
{
    <#
    .SYNOPSIS
    Discards all changes made in the current session

    .DESCRIPTION
    Discards all changes made in the current session
    Resets the session, opposite of publish changes
    Function will do nothing if no session is currently open

    .EXAMPLE
    Undo-ckpSession
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
        Command   = 'discard'
        SessionID = $session.SessionID
    }
    return Invoke-ckpWebRequest @requestParams
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
    <#
    .SYNOPSIS
    Change properties of a given group object

    .DESCRIPTION
    Long description

    .PARAMETER Name
    The name of the group to change

    .PARAMETER Uid
    The uid of the group to change

    .PARAMETER Member
    The list of members the group shall have

    .PARAMETER NewName
    The new name for the group to be set

    .PARAMETER Tags
    The list of tags to assign to the group

    .EXAMPLE
    Set-ckpGroup -Name azure_public_ips -NetName azure_public_2

    .EXAMPLE
    Set-ckpGroup -Name azure_public_ips -Members $id1,$id2
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
