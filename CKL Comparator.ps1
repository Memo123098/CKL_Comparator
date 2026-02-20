function Get-CKLFromFolder($folderName) {
    $fullPath = Join-Path -Path (Get-Location) -ChildPath $folderName
    if (-not (Test-Path $fullPath)) {
        Write-Host "Folder '$folderName' not found. Please create it and place .ckl files inside.`nExiting..." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit
    }

    $cklFiles = Get-ChildItem -Path $fullPath -Filter *.ckl
    if ($cklFiles.Count -eq 0) {
        Write-Host "No .ckl files found in '$folderName'.`nExiting..." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit
    }

    if ($cklFiles.Count -eq 1) {
        return $cklFiles[0].FullName
    }

    Write-Host "`nMultiple .ckl files found in '$folderName':" -ForegroundColor Yellow
    $cklMap = @{}
    for ($i = 0; $i -lt $cklFiles.Count; $i++) {
        $index = $i + 1
        $cklMap[$index] = $cklFiles[$i]
        Write-Host "  [$index] $($cklFiles[$i].Name)"
    }

    do {
        $selection = Read-Host "Enter the number corresponding to the file you want to use (or 'e' to exit)"
        if ($selection -eq 'e') {
            Write-Host "`nUser exited selection for folder '$folderName'." -ForegroundColor Red
            Start-Sleep -Seconds 5
            exit
        }

        $valid = $selection -as [int]

        if ($null -eq $valid -or (-not $cklMap.ContainsKey($valid))) {
            Write-Host "Invalid selection. Please choose a number from the list." -ForegroundColor Red
        }
    } while ($null -eq $valid -or (-not $cklMap.ContainsKey($valid)))

    return $cklMap[$valid].FullName
}

function Get-RULE($VulnNode) {
    return ($VulnNode.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Rule_ID' }).ATTRIBUTE_DATA
}

function Get-VulnID($VulnNode) {
    return ($VulnNode.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Num' }).ATTRIBUTE_DATA
}

function Get-CheckText($VulnNode) {
    return ($VulnNode.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Check_Content' }).ATTRIBUTE_DATA
}

function Get-Discussion($VulnNode) {
    return (($VulnNode.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Discuss' })).ATTRIBUTE_DATA
}

function Load-CKLFiles($OldCKLPath, $NewCKLPath) {
    Write-Host "`nLoading XML files, please wait..." -ForegroundColor Cyan

    $NewCKL = New-Object System.Xml.XmlDocument
    $NewCKL.PreserveWhitespace = $true
    $NewCKL.Load([string]$NewCKLPath)

    $OldCKL = New-Object System.Xml.XmlDocument
    $OldCKL.PreserveWhitespace = $true
    $OldCKL.Load([string]$OldCKLPath)

    return @($NewCKL, $OldCKL)
}


function Save-XmlUtf8NoBom($XmlDoc, $Path) {
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $false
    $settings.NewLineHandling = "None"
    $settings.OmitXmlDeclaration = $false
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)  

    $writer = [System.Xml.XmlWriter]::Create([string]$Path, $settings)
    try {
        $XmlDoc.Save($writer)
    }
    finally {
        $writer.Close()
    }
}

function Test-RuleVersionMatch($NewCKL, $OldCKL) {
    # Extract all rules from both CKLs
    $NewRules = $NewCKL.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object { Get-RULE $_ }
    $OldRules = $OldCKL.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object { Get-RULE $_ }

    # Convert to unique sorted sets for comparison
    $NewRulesSet = $NewRules | Sort-Object -Unique
    $OldRulesSet = $OldRules | Sort-Object -Unique

    # Compare both sets for equality
    if (-not ($NewRulesSet -join ',' -eq $OldRulesSet -join ',')) {
        Write-Host "`n[!] Rule_Ver mismatch detected between New CKL and Old CKL." -ForegroundColor Red
        Write-Host "    New Rules: $($NewRulesSet -join ', ')" -ForegroundColor Yellow
        Write-Host "    Old Rules: $($OldRulesSet -join ', ')" -ForegroundColor Yellow
        Write-Host "`nThese appear to be from different STIG baselines." -ForegroundColor Red
        Write-Host "Restarting file selection..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        Clear-Host
        return $false
    }

    return $true
}

function Get-VulnerabilityMismatches($NewCKL, $OldCKL, $CommentTag) {
    $NewVulns = $NewCKL.CHECKLIST.STIGS.iSTIG.VULN
    $OldVulns = $OldCKL.CHECKLIST.STIGS.iSTIG.VULN

    # Build a map of Old vulns by trimmed Vuln_Num
    $OldVulnMap = @{}
    foreach ($vuln in $OldVulns) {
        $vid = (Get-VulnID $vuln)
        if ($vid) { $vid = $vid.Trim() }

        if (-not [string]::IsNullOrWhiteSpace($vid)) {
            $OldVulnMap[$vid] = $vuln
        }
    }

    $mismatches = @()
    for ($i = 0; $i -lt $NewVulns.Count; $i++) {
        $NewVuln = $NewVulns[$i]
        $VID = (Get-VulnID $NewVuln)
        if ($VID) { $VID = $VID.Trim() }

        if ([string]::IsNullOrWhiteSpace($VID)) {
            continue
        }

        if ($OldVulnMap.ContainsKey($VID)) {
            $OldVuln = $OldVulnMap[$VID]

            # Compare STATUS via InnerText (trimmed)
            $newStatus = ($NewVuln.SelectSingleNode("STATUS").InnerText).Trim()
            $oldStatus = ($OldVuln.SelectSingleNode("STATUS").InnerText).Trim()

            if ($newStatus -ne $oldStatus) {
                $mismatches += [PSCustomObject]@{
                    Index   = $i
                    VID     = $VID
                    NewVuln = $NewVuln
                    OldVuln = $OldVuln
                }
            }
            else {
                $retainedOld = $false

                $newFindingNode  = $NewVuln.SelectSingleNode("FINDING_DETAILS")
                $oldFindingNode  = $OldVuln.SelectSingleNode("FINDING_DETAILS")

                $newCommentsNode = $NewVuln.SelectSingleNode("COMMENTS")
                $oldCommentsNode = $OldVuln.SelectSingleNode("COMMENTS")

                $newFindingText  = ""
                $oldFindingText  = ""
                $newCommentsText = ""
                $oldCommentsText = ""

                if ($newFindingNode)  { $newFindingText  = $newFindingNode.InnerText.Trim() }
                if ($oldFindingNode)  { $oldFindingText  = $oldFindingNode.InnerText.Trim() }
                if ($newCommentsNode) { $newCommentsText = $newCommentsNode.InnerText.Trim() }
                if ($oldCommentsNode) { $oldCommentsText = $oldCommentsNode.InnerText.Trim() }

                # FINDING_DETAILS: prefer new; only merge if old exists and is different
                if (-not [string]::IsNullOrWhiteSpace($oldFindingText) -and $newFindingNode) {
                    if ([string]::IsNullOrWhiteSpace($newFindingText)) {
                        $newFindingNode.InnerText = "***********************Current Finding************************`n`n***********************Previous Reference Finding***********************`n$oldFindingText"
                        $retainedOld = $true
                    }
                    elseif ($newFindingText -ne $oldFindingText) {
                        $newFindingNode.InnerText = "***********************Current Finding************************`n$newFindingText `n***********************Previous Reference Finding*********************** `n$oldFindingText"
                        $retainedOld = $true
                    }
                }

                # COMMENTS: prefer new; only merge if old exists and is different
                if (-not [string]::IsNullOrWhiteSpace($oldCommentsText) -and $newCommentsNode) {
                    if ([string]::IsNullOrWhiteSpace($newCommentsText)) {
                        $newCommentsNode.InnerText = "***********************Current Comment***********************`n`n***********************Previous Reference Comment***********************`n$oldCommentsText"
                        $retainedOld = $true
                    }
                    elseif ($newCommentsText -ne $oldCommentsText) {
                        $newCommentsNode.InnerText = "***********************Previous Reference Comment*********************** `n$oldCommentsText `n***********************Current Comment************************`n$newCommentsText"
                        $retainedOld = $true
                    }
                }

                # Append tag only if OLD info was retained (Option B: single standardized review sentence)
                if ($retainedOld -and -not [string]::IsNullOrWhiteSpace($CommentTag) -and $newCommentsNode) {
                    $reviewLine = "$CommentTag Reviewed, found to still be applicable."
                    if ($newCommentsNode.InnerText -notmatch [regex]::Escape($reviewLine)) {
                        if ([string]::IsNullOrWhiteSpace($newCommentsNode.InnerText.Trim())) {
                            $newCommentsNode.InnerText = $reviewLine
                        } else {
                            $newCommentsNode.InnerText = "$($newCommentsNode.InnerText.Trim())`n`n$reviewLine"
                        }
                    }
                }
            }
        }
    }

    return $mismatches
}

function Show-MismatchDetails($entry, $currentIndex, $totalCount) {
    $VID = $entry.VID
    $NewVuln = $entry.NewVuln
    $OldVuln = $entry.OldVuln

    Clear-Host

    # Display ticker
    Write-Host "======== Mismatch $($currentIndex + 1) of $totalCount ========" -ForegroundColor Cyan
    Write-Host "Vulnerability ID: $VID" -ForegroundColor Yellow

    Write-Host "`nDiscussion Text:" -ForegroundColor Yellow
    Write-Host "$(Get-Discussion $NewVuln)"
    Write-Host "`nCheck Text:" -ForegroundColor Yellow
    Write-Host "$(Get-CheckText $NewVuln)"

    $oldStatus = $OldVuln.STATUS
    $newStatus = $NewVuln.STATUS
    $oldFinding = $OldVuln.SelectSingleNode("FINDING_DETAILS").InnerText
    $newFinding = $NewVuln.SelectSingleNode("FINDING_DETAILS").InnerText
    $oldComments = $OldVuln.SelectSingleNode("COMMENTS").InnerText
    $newComments = $NewVuln.SelectSingleNode("COMMENTS").InnerText

    Write-Host "`nOld Status: $oldStatus" -ForegroundColor DarkGray
    Write-Host "`nOld Finding Details:`n$oldFinding" -ForegroundColor DarkGray
    Write-Host "`nOld Comments:`n$oldComments" -ForegroundColor DarkGray
    Write-Host "`nNew Status: $newStatus" -ForegroundColor Cyan
    Write-Host "`nNew Finding Details:`n$newFinding" -ForegroundColor Cyan
    Write-Host "`nNew Comments:`n$newComments" -ForegroundColor Cyan

    Write-Host "`nOptions:"
    Write-Host "  o  = use OLD values"
    Write-Host "  n  = keep NEW values"
    Write-Host "  m  = override MANUALLY"
    Write-Host "  <  = previous mismatch"
    Write-Host "  >  = next mismatch"
    Write-Host "  x  = EXIT and save"
}

function Handle-ManualOverride($NewVuln, $OldVuln, $CommentTag, $OutputCKLPath, $NewCKL) {
    $validStatuses = @{
        "NF" = "NotAFinding"
        "O"  = "Open"
        "NR" = "Not_Reviewed"
        "NA" = "Not_Applicable"
    }

    do {
        $OverrideStatus = Read-Host "Enter override STATUS [NF, O, NR, NA] or 'x' to exit"
        if ($OverrideStatus -eq 'x') {
            Write-Host "`nExiting script." -ForegroundColor Red
            Save-XmlUtf8NoBom $NewCKL $OutputCKLPath
            Write-Host "`nMerged CKL saved to: $OutputCKLPath" -ForegroundColor Green
            Start-Sleep -Seconds 3
            exit
        }
        $OverrideStatus = $validStatuses[$OverrideStatus.ToUpper()]
    } while (-not $OverrideStatus)

    $OverrideFindingInput = Read-Host "Enter override Finding Details, or 'c' to copy old, 'n' to keep new"
    $OverrideFinding = switch ($OverrideFindingInput) {
        'c' { $OldVuln.SelectSingleNode("FINDING_DETAILS").InnerText }
        'n' { $NewVuln.SelectSingleNode("FINDING_DETAILS").InnerText }
        default { $OverrideFindingInput }
    }

    $OverrideCommentsInput = Read-Host "Enter override Comments, or 'c' to copy old, 'n' to keep new"
    $OverrideComments = switch ($OverrideCommentsInput) {
        'c' {
            $OldComments = $OldVuln.SelectSingleNode("COMMENTS").InnerText
            $reviewLine = "$CommentTag Reviewed, found to still be applicable."
            if ($OldComments -match [regex]::Escape($reviewLine)) {
                "$OldComments"
            } else {
                "$OldComments`n`n$reviewLine"
            }
        }
        'n' { $NewVuln.SelectSingleNode("COMMENTS").InnerText }
        default { "$CommentTag - $OverrideStatus - $_" }
    }

    $NewVuln.STATUS = $OverrideStatus
    $NewVuln.SelectSingleNode("FINDING_DETAILS").InnerText = $OverrideFinding
    $NewVuln.SelectSingleNode("COMMENTS").InnerText = $OverrideComments

    return $true
}

function Process-Mismatches($mismatches, $CommentTag, $OutputCKLPath, $NewCKL) {
    $current = 0
    while ($current -lt $mismatches.Count) {
        $entry = $mismatches[$current]
        $VID = $entry.VID
        $NewVuln = $entry.NewVuln
        $OldVuln = $entry.OldVuln

        Show-MismatchDetails $entry $current $mismatches.Count
        $choice = Read-Host "`nEnter your choice"

        switch ($choice) {
            'o' {
                $NewVuln.STATUS = $OldVuln.STATUS
                $NewVuln.SelectSingleNode("FINDING_DETAILS").InnerText = $OldVuln.SelectSingleNode("FINDING_DETAILS").InnerText

                $OldComments = $OldVuln.SelectSingleNode("COMMENTS").InnerText
                $reviewLine = "$CommentTag Reviewed, found to still be applicable."
                if ($OldComments -match [regex]::Escape($reviewLine)) {
                    $NewVuln.SelectSingleNode("COMMENTS").InnerText = "$OldComments"
                } else {
                    $NewVuln.SelectSingleNode("COMMENTS").InnerText = "$OldComments `n`n$reviewLine"
                }

                Write-Host "Copied OLD values for $VID and appended review comment (if missing)." -ForegroundColor Green
                $current++
            }
            'n' {
                Write-Host "Kept NEW values for $VID." -ForegroundColor Green
                $current++
            }
            'm' {
                if (Handle-ManualOverride $NewVuln $OldVuln $CommentTag $OutputCKLPath $NewCKL) {
                    Write-Host "Overridden values saved for $VID." -ForegroundColor Cyan
                    $current++
                }
            }
            '>' {
                if ($current -lt $mismatches.Count - 1) { $current++ }
            }
            '<' {
                if ($current -gt 0) { $current-- }
            }
            'x' {
                Write-Host "`nExiting script." -ForegroundColor Red
                Save-XmlUtf8NoBom $NewCKL $OutputCKLPath
                Write-Host "`nMerged CKL saved to: $OutputCKLPath" -ForegroundColor Green
                Start-Sleep -Seconds 3
                exit
            }
            default {
                Write-Host "Invalid choice. Use: o, n, m, <, >, or x." -ForegroundColor Red
            }
        }
    }
}

function Start-CKLMergeProcess {
    do {
        do {
            $OldCKLPath     = Get-CKLFromFolder "PreviouslyCompletedCKL"
            $NewCKLPath     = Get-CKLFromFolder "NewCKL"
            $NewCKLFileName = [System.IO.Path]::GetFileNameWithoutExtension($NewCKLPath)
            $OutputCKLPath  = Join-Path -Path (Get-Location) -ChildPath "$($NewCKLFileName)_Merged.ckl"

            if (Test-Path $OutputCKLPath) {
                Write-Host "`n[!] Existing merged checklist found:" -ForegroundColor Yellow
                Write-Host "    $OutputCKLPath" -ForegroundColor Yellow

                Write-Host "`nChoose an option:" -ForegroundColor Cyan
                Write-Host "  [1] Resume from last save (use existing merged as NEW input)"
                Write-Host "  [2] Create a new Merged Checklist (auto-increment name)"
                Write-Host "  [3] Overwrite the existing file (start fresh)"
                Write-Host "  [e] Exit"

                do {
                    $choice = (Read-Host "Selection").Trim().ToLower()
                } while ($choice -notin @('1','2','3','e'))

                if ($choice -eq 'e') {
                    Write-Host "`nExiting..." -ForegroundColor Red
                    Start-Sleep -Seconds 3
                    exit
                }

                switch ($choice) {
                    '1' {
                        # RESUME: let user choose which existing merged file to resume from
                        $pattern = "$($NewCKLFileName)_Merged*.ckl"

                        $mergedCandidates = Get-ChildItem -Path (Get-Location) -Filter $pattern -File |
                            Sort-Object Name

                        if (-not $mergedCandidates -or $mergedCandidates.Count -eq 0) {
                            Write-Host "`n[!] No merged files found to resume from." -ForegroundColor Red
                            Start-Sleep -Seconds 3
                            exit
                        }

                        Write-Host "`nSelect a merged file to RESUME from:" -ForegroundColor Cyan
                        $map = @{}
                        for ($j = 0; $j -lt $mergedCandidates.Count; $j++) {
                            $idx = $j + 1
                            $map[$idx] = $mergedCandidates[$j]
                            Write-Host "  [$idx] $($mergedCandidates[$j].Name)"
                        }

                        do {
                            $pick = (Read-Host "Enter selection number (or 'e' to exit)").Trim()
                            if ($pick -eq 'e') {
                                Write-Host "`nExiting..." -ForegroundColor Red
                                Start-Sleep -Seconds 3
                                exit
                            }
                            $pickInt = $pick -as [int]
                            if ($null -eq $pickInt -or (-not $map.ContainsKey($pickInt))) {
                                Write-Host "Invalid selection. Choose a number from the list." -ForegroundColor Red
                            }
                        } while ($null -eq $pickInt -or (-not $map.ContainsKey($pickInt)))

                        $selectedMerged = $map[$pickInt].FullName

                        Write-Host "`nResuming from:" -ForegroundColor Cyan
                        Write-Host "    $selectedMerged" -ForegroundColor Cyan

                        # Use selected merged as NEW input, and save back to it
                        $NewCKLPath = $selectedMerged
                        $OutputCKLPath = $selectedMerged
                    }

                    '2' {
                        $found = $false
                        for ($v = 1; $v -le 9; $v++) {
                            $candidate = Join-Path -Path (Get-Location) -ChildPath "$($NewCKLFileName)_Merged$v.ckl"
                            if (-not (Test-Path $candidate)) {
                                $OutputCKLPath = $candidate
                                $found = $true
                                break
                            }
                        }

                        if (-not $found) {
                            Write-Host "`n[!] ERROR: _Merged.ckl through _Merged9.ckl already exist. Delete/rename old merged files and rerun." -ForegroundColor Red
                            Start-Sleep -Seconds 5
                            exit
                        }

                        Write-Host "`nCreating new merged checklist:" -ForegroundColor Cyan
                        Write-Host "    $OutputCKLPath" -ForegroundColor Cyan
                    }
                    '3' {
                        Write-Host "`nOverwriting existing merged checklist:" -ForegroundColor Cyan
                        Write-Host "    $OutputCKLPath" -ForegroundColor Cyan
                    }
                }
            }

            Write-Host "`nLoaded files:" -ForegroundColor Cyan
            Write-Host "  Old CKL:     $OldCKLPath"
            Write-Host "  New CKL:     $NewCKLPath"
            Write-Host "  Output CKL:  $OutputCKLPath"

            $CommentTag = Read-Host "Place your comment tag here (Ex. '<Initials> (DATE_LRU)')"

            $NewCKL, $OldCKL = Load-CKLFiles $OldCKLPath $NewCKLPath
            $rulesMatch = Test-RuleVersionMatch $NewCKL $OldCKL

        } while (-not $rulesMatch)

        $mismatches = Get-VulnerabilityMismatches $NewCKL $OldCKL $CommentTag
        Process-Mismatches $mismatches $CommentTag $OutputCKLPath $NewCKL

        Save-XmlUtf8NoBom $NewCKL $OutputCKLPath
        Write-Host "`nMerged CKL saved to: $OutputCKLPath" -ForegroundColor Green

        $rerun = Read-Host "`nDo you want to run another comparison? (y/n)"
    } while ($rerun -eq 'y')
}


Start-CKLMergeProcess
