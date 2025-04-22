#!/usr/bin/env pwsh
# Automatic creation of ClamAV.Managed test directory
# This file is path of the ClamAV.Managed project
#
#   Copyright (c) 2014-2025 Rupert Muchembled
#   ClamAV.Managed is licensed under the GNU GPL v2 or any later version.

Write-Host "Automatic creation of ClamAV.Managed test directory"
Write-Host "  Part of the ClamAV.Managed project"
Write-Host "  Copyright (c) 2014-2025 Rupert Muchembled"
Write-Host "  ClamAV.Managed is licensed under the GNU GPL v2 or any later version."

# Create TestFiles directory if it doesn't exist
if (!(Test-Path -PathType Container "../TestFiles")) {
    Write-Host "Creating TestFiles directory..."
    New-Item -ItemType Directory "../TestFiles"
    
    if (!(Test-Path -PathType Container "../TestFiles")) {
        Write-Host "Failed to create directory ../TestFiles"
        exit 1
    }
}

# Create samples directory for test files
$samplesDir = "../TestFiles/samples"
if (!(Test-Path -PathType Container $samplesDir)) {
    Write-Host "Creating samples directory for test files..."
    New-Item -ItemType Directory $samplesDir
}

# Create nested directory for recursive scan testing
$nestedDir = "$samplesDir/nested_folder"
if (!(Test-Path -PathType Container $nestedDir)) {
    Write-Host "Creating nested directory for recursive scan testing..."
    New-Item -ItemType Directory $nestedDir
}

# Create clean test file
$cleanFile = "$samplesDir/clean_text_file.txt"
Write-Host "Creating clean test file: $cleanFile"
Set-Content -Path $cleanFile -Value @"
This is a clean text file with no virus signatures.
It's used for testing the basic scan functionality of ClamAV.Managed.
The scanner should report this file as clean.
"@

# Create EICAR test virus file
$eicarFile = "$samplesDir/eicar_test_file.txt"
Write-Host "Creating EICAR test virus file: $eicarFile"
Set-Content -Path $eicarFile -Value "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"

# Create binary-like sample file
$binaryFile = "$samplesDir/binary_sample.dat"
Write-Host "Creating binary sample file: $binaryFile"
Set-Content -Path $binaryFile -Value @"
MZ��������������������������������������������������This is a sample file with some binary-like content.
It might trigger different scanning logic compared to plain text files.
���������������������������������������������������������������������������
"@

# Create nested clean file
$nestedCleanFile = "$nestedDir/nested_clean_file.txt"
Write-Host "Creating nested clean file: $nestedCleanFile"
Set-Content -Path $nestedCleanFile -Value @"
This is a clean file in a nested folder.
It's used to test recursive directory scanning in ClamAV.Managed.
"@

# Download ClamAV database files
Write-Host "Downloading ClamAV database files..."
./FetchDatabases.ps1 "../TestFiles/db" "http://clamav.oucs.ox.ac.uk"

Write-Host "Test files setup complete!"
