# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

function log-info($data)
{
    write-host ($data | out-string)
}

function activate-licenseServer($licServer, $companyInfo)
{
    $licServerResult = @{}
    $licServerResult.LicenseServerActivated = $Null

    $timeoutSeconds = 300
    $startTime = Get-Date

    do {
        $wmiClass = ([wmiclass]"\\$($licServer)\root\cimv2:Win32_TSLicenseServer")
        if ($wmiClass -eq $Null) {
            Start-Sleep -Seconds 5
        }
        if ((Get-Date) - $startTime -gt (New-TimeSpan -Seconds $timeoutSeconds)) {
            throw "Timeout waiting for WMI class Win32_TSLicenseServer"
        }
    } while (-not $wmiClass)

    do {
        $wmiTSLicenseObject = Get-WMIObject Win32_TSLicenseServer -computername $licServer -ErrorAction SilentlyContinue
        if ($wmiTSLicenseObject -eq $Null) {
            Start-Sleep -Seconds 5
        }
        if ((Get-Date) - $startTime -gt (New-TimeSpan -Seconds $timeoutSeconds)) {
            throw "Timeout waiting for WMI object Win32_TSLicenseServer"
        }
    } while (-not $wmiTSLicenseObject)

    $wmiTSLicenseObject.FirstName=$companyInfo.FirstName
    $wmiTSLicenseObject.LastName=$companyInfo.LastName
    $wmiTSLicenseObject.Company=$companyInfo.Company
    $wmiTSLicenseObject.CountryRegion=$companyInfo.CountryRegion
    $wmiTSLicenseObject.Put()

    $wmiClass.ActivateServerAutomatic()

    $licServerResult.LicenseServerActivated = $wmiClass.GetActivationStatus().ActivationStatus
    log-info "activation status: $($licServerResult.LicenseServerActivated) (0 = activated, 1 = not activated)"
}

function main()
{
    $licenseServer='localhost'
    $companyInformation = @{}
    $companyInformation.FirstName="Suzy"
    $companyInformation.LastName="Sample"
    $companyInformation.Company="Independent Consolidators"
    $companyInformation.CountryRegion="United States"

    activate-licenseServer $licenseServer $companyInformation
}

main
