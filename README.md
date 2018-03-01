# Posh-CheckpointFirewall Powershell Module

A Powershell module to interact with Checkpoint Firewall management servers.
Module is a wrapper for the *REST* API of Checkpoint Management API.
> Required Checkpoint Version >= **R80**

## Checkpoint Management API

* [Checkpoint Management API Reference](https://sc1.checkpoint.com/documents/R80/APIs/#ws%20)
* **Requirements**
  * API Management musst be acivated
  * User Credential must be allowed for management API
  * User Credentail does not need to be global admin!
* **Authentication**
  * Interaction is session based
  * Login is required against management endpoint
  * Login will return a session id which will be used in subsequent API calls for authentication
    * Session expires after 10 minutes by default
    * Sessions can be extended

## Powershell Module

The module only implements a subset of the available commands in the API.
A list of all implemented Cmdlets can be retrieved by inspecting the module
(The module must already be imported for this).

```powershell
Get-Command -Module Posh-CheckpointFirewall
```

Each Powershell Cmdlet has help configured to get details of the usage of the cmdlet.

```powershell
Get-Help -Name CmdletName
```

You can open the mangement reference of the api command the cmdlet is based on by issuing:

```powershell
Get-Help -Name Get-ckpSession -Online
```

A list of all _REST_ commands that are provided by the management API can be found on the website or by using the following Cmdlet:

```powershell
Get-ckpCommand
```

### Module Prefix

All Cmdlets of the module have the _ckp_ prefix to distinguish them from other modules. (e.g. `Get-ckpNetwork`, `Get-ckpSession`)

### Basic Usage

* Login to the API
* Query API, Perform Changes
* Publish the changes!
  * If you do not publish the changes they will not be available for others and can not be installed on the firewalls/servers/gateways.
* Install the policy on the firewalls

Example

```powershell
Import-Module -Name Posh-CheckpointFirewall
$firewallCredential = Get-Credential
$firewallHost = 'someHostName'

# Login to firewall
Connect-ckpSession -HostName $firewallHost -Credential $firewallCredential

# Get networks
Get-ckpNetwork -Limit 10 | Format-Table name, subnet4, mask-length4, subnet-mask -AutoSize

# Add network
Add-ckpNetwork -Name 'someNetowrk' -Subnet '10.221.255.0' -MaskLength 24

# Publish changes
Publish-ckpSession

# Install Policy
Install-ckpPolicy

#Logout
Disconnect-ckpSession
```

### About Sessions and Locks

Changes are only visible for others if changes are published, but modified objects can have be locked by other sessions that have not been published yet.

One user can have multiple sessions, if changes have been made to the session it will persist even if the session is timed out. That means your own older sessions can block your actions in the current session. Therefore it is important to manage sessions.

Show me all my sessions:

```powershell
Get-ckpSession
```

You can either publish the changes of other sessions (only sessions from your user) or discard/undo the changes of the session. If you publish/discard an inactive session it will dissapear after the operation successfully finishes.

Undo all operations of my sessions

```powershell
Get-ckpSession | Undo-ckpSession
```

To avoid locking objects with your own session you should always logout of your session at the end with `Disconnect-ckpSession`.
Additionally you can specify when logging in that you want to reconnect to an inactive session if one sill exits.

```powershell
Connect-ckpSession -HostName $firewallHost -Credential $firewallCredential -ContinueLastSession
```

This ensures that you will reconnect to your last session if you accidentally did not close the session.
This will hower **cause an Error** if you have more then one inactive session. In that case you need to discard or publish your inactive sessions.

### Modifying Objects

The API usually offers only show, add, delete and **set** object.
If you want to add objects to an existing object (e.g. adding networks to a group) you need to 'set' the group:

```powershell
# Creating new network
$newNetwork = Add-ckpNetwork -Name 'someNetowrk' -Subnet '10.221.255.0' -MaskLength 24

# Add new network to group
Set-ckpGroup -Name 'someGroup' -AddMember $newNetwork.uid
```

## Powershell Basics

### Loading Modules

```powershell
Get-Help about_modules
```

Modules can be loaded in two different ways:

* implicit loading (since version 4, not in strict mode)
  * When a cmdlet is called, powershell searches in his module path for a module that contains the cmdlet and loads the module behind the covers
* explicit loading
  * Load module by invoking the Cmdlet `Import-Module`
  * Loading by module name with the name of the module will let powershell search its module path for a module with matching name.
  * Loading by module path where you point to the `*.psm1` or `*.psd1` file directly.

> Prefer **explicit** loading over implicit loading to make the dependency to the module more visible! This improves readability of your scripts and facilitates debugging.
>
> Prefer loading `*.psd1` over `*.psm1` when importing modules by path

#### PSModulePath

The powershell module path, is the path where powershell searches for modules by name.
In that path needs to be a subfolder with the exact name of the module and within the subfolder must be at least a `*.psm1` file or additionally a `*.psd1` file.

The Module path is a powershell environment variable much like the windows *PATH* variable. This variable contains a list of paths seperated by `;`.
You can permanantly or temporary modify the module path:

```powershell
$env:PSModulePath += ";C:\MyModules"
Import-Module -Name MyModule
```