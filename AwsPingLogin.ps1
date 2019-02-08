<#
 # Copyright (c) 2019 Atif Aziz
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy
 # of this software and associated documentation files (the "Software"), to deal
 # in the Software without restriction, including without limitation the rights
 # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 # copies of the Software, and to permit persons to whom the Software is
 # furnished to do so, subject to the following conditions:
 #
 # The above copyright notice and this permission notice shall be included in
 # all copies or substantial portions of the Software.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 # SOFTWARE.
 #>

[CmdletBinding()]
param(
    [parameter(Position=0, Mandatory=$true)]
    [Uri]$SsoUrl,
    [parameter(ParameterSetName="Profile", Mandatory=$true)]
    [string]$Account,
    [parameter(ParameterSetName="Profile", Mandatory=$true)]
    [string]$Role,
    [parameter(ParameterSetName="Profile", Mandatory=$true)]
    [string]$Profile,
    [parameter(ParameterSetName="Profile")]
    [int]$DurationMinutes = 15,
    [parameter(ParameterSetName="Profile")]
    [string]$Region,
    [parameter(ParameterSetName="Roles")]
    [switch]$ShowRoles)

$ErrorActionPreference = 'Stop'

if (!(Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Error "The AWS CLI does not appear to be installed or in the system path."
}

$samlResponse = (Invoke-RestMethod -Method Post -Uri $ssoUrl -UseDefaultCredentials).html.body.form.input.value
[xml]$saml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($samlResponse))

[array]$roles =
    $saml.Response.Assertion.AttributeStatement.Attribute |
    ? { $_.Name -like '*Role' } |
    % { $_.AttributeValue.'#text' } |
    % {
        $cn = $_ -split ',', 2
        New-Object psobject -Property @{
            Arn     = $cn[0]
            Account = ($cn[0] -split ':')[4]
            Name    = ($cn[0] -split '/', 2)[1]
            Ping    = $cn[1]
        }
    }

if ($PSCmdlet.ParameterSetName -eq 'Roles') {

    $roles | select Arn, Account, Name

} else {

    $selection = $roles | ? { $_.Account -eq $account -and $_.Name -eq $role }

    if (!$selection) {
        throw "You are not authorized to access AWS!"
    }

    Write-Verbose $selection

    $session =
        aws sts assume-role-with-saml `
            --role-arn $selection.Arn `
            --principal-arn $selection.Ping `
            --saml-assertion $samlResponse `
            --duration-seconds ($durationMinutes * 60) |
            ConvertFrom-Json

    if ($LASTEXITCODE) {
        throw "The command 'aws sts assume-role-with-saml' failed (exit code = $LASTEXITCODE)."
    }

    function Aws-SetConfig {
        param([string]$profile, [string]$name, [string]$value)

        Write-Verbose "Running: aws configure --profile $profile set $name ..."
        aws configure --profile $profile set $name $value
        if ($LASTEXITCODE) {
            throw "Failed to configure AWS profile `"$profile`" for `"$name`" (exit code = $LASTEXITCODE)."
        }

    }

    Aws-SetConfig $profile aws_access_key_id     $session.Credentials.AccessKeyId
    Aws-SetConfig $profile aws_secret_access_key $session.Credentials.SecretAccessKey
    Aws-SetConfig $profile aws_session_token     $session.Credentials.SessionToken

    if ($region) {
        Aws-SetConfig $profile region $region
    }

}
