$vulnerableHashes = -split $(Invoke-WebRequest https://raw.githubusercontent.com/tiktb8/CVE-2022-29072/main/sha256sums.txt -UseBasicParsing).content | ? {$_.length -eq 64} 

# Set to 1 to attempt auto mitigate
$deleteVulnerableFiles = 0

# Set Log Level ( 0 to 4)
$loggingLevel = 4

# Print local to console (0 or 1)
$localPrint = 0

# Location of logfile, give full path
$logFileName = "mitigate-cve-2022-29072.log"
$logFileLocation = "C:\logs"
$logFile = -join($logFileLocation,"\",$logFileName)

################################ NO CHANGES BELOW THIS LINE UNLESS YOU KNOW WHAT YOU'RE DOING ####################################

# STOP ON ERROR
$ErrorActionPreference = "Stop"

# Check if logfile directory exists
if (!(test-path $logFileLocation))
{
      New-Item -ItemType Directory -Force -Path $logFileLocation
}

function WriteLog
{
    Param ([string]$logString)
    $dateTime = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    $logMessage = "$dateTime $logString"
    Add-content $logFile -value $logMessage
}

# Set $vulnerablityFound = 0 to, checked at the end if no vulns found
$vulnerablityFound = 0

# Grab drives
$drives = (Get-PSDrive -PSProvider FileSystem).Root
if ($loggingLevel -ge 3)
{
    WriteLog "LogLevel3: Drives Found: $($drives)"
}

# Check each drive individually for vulnerable files
foreach($drive In $drives) 
{

    # Get all the chm files
    $chmFiles=(Get-ChildItem $Drive *.chm -file -Recurse -erroraction silentlycontinue | Get-ItemProperty).FullName | Select-Object -Unique    
    if ($loggingLevel -ge 3)
    {
    WriteLog "LogLevel3: CHM Files Found: $($chmFiles)"
    }

    # Check each chm file against hash, if the hash maches, check to 
    foreach ($chmFile in $chmFiles)
    {
        $hash = Get-FileHash -Path $chmFile -Algorithm SHA256
        if ($vulnerableHashes.Contains($hash.Hash))
        {
            if ($localPrint -eq 1)
            {
                Write-Output "Vulnerabile file found at $($chmFile)"
            }
            if($loggingLevel -ge 1)
            {
                WriteLog "LogLevel1: Vulnerable File Found: $($chmFile)"
            }
            # Set Vulnerability found, checked later for writing output
            $vulnerablityFound = 1

            # This block checks to see if auto mitigate is active, if it is, attempt removal, then test if removal successful
            # If the path still exists after remove item, print removal failed, else print a success
            if ($deleteVulnerableFiles -eq 1) 
            {
                Remove-Item $chmFile
                if ( Test-Path $chmFile ) 
                {
                    if ($localPrint -eq 1)
                    {
                    Write-Output "Failed to remove $($chmFile)"
                    }
                    if($loggingLevel -ge 1)
                    {
                        WriteLog "LogLevel1: Failed to remove: $($chmFile)"
                    }
                }

                else 
                {
                    if ($localPrint -eq 1)
                    {
                    Write-Output "Successfully removed $($chmFile)"
                    }
                    if($loggingLevel -ge 1)
                    {
                        WriteLog "LogLevel1: Successfully removed: $($chmFile)"
                    }
                }
            } 
        }
    }   

    # If vuln found isn't set to 1, print that there's no vuln on the drive.
    if ($vulnerablityFound -eq 0) 
    {
        if ($localPrint -eq 1)
        {
            Write-Output "No vulnerability found on $($drive)"
        }
        if($loggingLevel -ge 1)
        {
            WriteLog "LogLevel1: No vulnerability found on $($drive)"
        }
    }
 }
 
