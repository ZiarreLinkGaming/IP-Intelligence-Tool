Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- Global Variables ---
# Define this at a scope accessible by both Append-ColoredText and the screenshot button
# This array will store objects { Text = "...", Color = ... } for screenshot purposes.
$Global:outputBoxColoredSegments = New-Object System.Collections.ArrayList
# Colors
$bgColor = [System.Drawing.Color]::FromArgb(75,75,75)
$fgColor = [System.Drawing.Color]::Cyan
$inputBg = [System.Drawing.Color]::FromArgb(65,65,65)
$buttonBg = [System.Drawing.Color]::FromArgb(45,45,45)
$footerColor = [System.Drawing.Color]::FromArgb(255,165,0)

# Custom colors for output sections
$customOutputColor = [System.Drawing.ColorTranslator]::FromHtml("#0ff5bf")
$uriColor = [System.Drawing.ColorTranslator]::FromHtml("#f28b82")

$apiKey = "841fd9ac875d86891b15"
$abuseIpdbApiKey = "68d288be9e1f1c19d106a0be0b6e2991c6a8a81b7874b427d62fd456efeb59b38f70d44d55f36212"

# --- Form Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "IP Intelligence Lookup (VPN)"
$form.Size = New-Object System.Drawing.Size(620, 645)
$form.StartPosition = "CenterScreen"
$form.BackColor = $bgColor
$form.ForeColor = $fgColor
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $true

# Footer Label
$footerLabel = New-Object System.Windows.Forms.Label
$footerLabel.Text = "Script maintained by: [RACHA]"
$footerLabel.AutoSize = $true
$footerLabel.ForeColor = $footerColor
$footerLabel.BackColor = $bgColor
$footerLabel.Font = New-Object System.Drawing.Font("Segoe UI",8,[System.Drawing.FontStyle]::Italic)

# Calculate position aligned right with 10 px padding
$rightMargin = 10
$xPos = $form.ClientSize.Width - $footerLabel.PreferredWidth - $rightMargin
$yPos = $form.ClientSize.Height - 20
$footerLabel.Location = New-Object System.Drawing.Point($xPos, $yPos)

$form.Controls.Add($footerLabel)

# --- Helper Functions for UI Elements ---
function New-Label {
    param ($text, $x, $y)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $text
    $lbl.Location = New-Object System.Drawing.Point($x, $y)
    $lbl.Size = New-Object System.Drawing.Size(200, 20)
    $lbl.ForeColor = $fgColor
    $lbl.BackColor = $bgColor
    return $lbl
}

function New-Textbox {
    param ($x, $y, $width=395)
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point($x, $y)
    $tb.Size = New-Object System.Drawing.Size($width, 20)
    $tb.BackColor = $inputBg
    $tb.ForeColor = $fgColor
    $tb.BorderStyle = 'FixedSingle'
    return $tb
}

# --- Input Field Setup ---
$labelText = "Enter IPs:"
$labelFont = New-Object System.Drawing.Font("Microsoft Sans Serif", 10)
$textSize = [System.Windows.Forms.TextRenderer]::MeasureText($labelText, $labelFont)

$lblInput = New-Label $labelText 20 15
$lblInput.Size = New-Object System.Drawing.Size($textSize.Width, $textSize.Height)
$lblInput.AutoSize = $false
$lblInput.ForeColor = [System.Drawing.Color]::LightSeaGreen
$form.Controls.Add($lblInput)

$spacing = 5
$ipInputX = $lblInput.Location.X + $lblInput.Width + $spacing

$ipInputY = $lblInput.Location.Y + $lblInput.Height + 5
$ipInputX = 20

$ipInput = New-Object System.Windows.Forms.RichTextBox
$ipInput.Location = New-Object System.Drawing.Point($ipInputX, $ipInputY)
$ipInput.Size = New-Object System.Drawing.Size(565, 80)
$ipInput.Multiline = $true
$ipInput.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$ipInput.WordWrap = $true
$ipInput.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$ipInput.ForeColor = [System.Drawing.Color]::LightSeaGreen
$ipInput.ReadOnly = $false
$ipInput.Enabled = $true
$ipInput.Font = New-Object System.Drawing.Font("Consolas", 10)
$ipInput.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$form.Controls.Add($ipInput)

function Set-IpInputVisualState {
    param ([bool]$IsEnabled)

    if ($IsEnabled) {
        $ipInput.ReadOnly = $false
        $ipInput.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $ipInput.ForeColor = [System.Drawing.Color]::LightSeaGreen
        $ipInput.Cursor = [System.Windows.Forms.Cursors]::IBeam
    } else {
        $ipInput.ReadOnly = $true
        $ipInput.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
        $ipInput.ForeColor = [System.Drawing.Color]::Gray
        $ipInput.Cursor = [System.Windows.Forms.Cursors]::No
    }
}

try {
    $ipInput.Text = (Invoke-WebRequest -Uri "https://checkip.amazonaws.com").Content
} catch {
    $ipInput.Text = ""
}

$ipInput.SelectionStart = $ipInput.TextLength
$ipInput.ScrollToCaret()

$ipInput.Add_KeyDown({
    param($sender, $e)
    if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::A) {
        $sender.SelectAll()
        $e.Handled = $true
    }
})

# $ipInput.Add_TextChanged({
#     if (-not $Global:isIpInputUpdating) {
#         $Global:isIpInputUpdating = $true
        
#         $currentText = $ipInput.Text
#         $selectionStart = $ipInput.SelectionStart
#         $selectionLength = $ipInput.SelectionLength

#         $cleanedText = $currentText.Replace('[.]', '.')
#         $cleanedText = $cleanedText -replace "`r`n", " " `
#                                    -replace "`n", " " `
#                                    -replace ",", " " `
#                                    -replace ";", " " `
#                                    -replace "\s+", " "

#         $cleanedText = $cleanedText.Trim()
#         if ($cleanedText.Length -gt 0 -and -not $cleanedText.EndsWith(" ")) {
#             $cleanedText += " "
#         }
        
#         if ($ipInput.Text -ne $cleanedText) {
#             $ipInput.Text = $cleanedText
            
#             if ($selectionStart -gt $ipInput.Text.Length) {
#                 $selectionStart = $ipInput.Text.Length
#             }
#             $ipInput.SelectionStart = $selectionStart
#             $ipInput.SelectionLength = $selectionLength
#             $ipInput.ScrollToCaret()
#         }
        
#         $Global:isIpInputUpdating = $false
#     }
# })
# --- END REMOVE BLOCK ---


# --- Output Box Setup ---
$outputBox = New-Object System.Windows.Forms.RichTextBox
$outputBox.Location = New-Object System.Drawing.Point(20, 125)
$outputBox.Size = New-Object System.Drawing.Size(565, 430)
$outputBox.ReadOnly = $true
$outputBox.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$outputBox.ForeColor = [System.Drawing.Color]::LightGreen
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$outputBox.DetectUrls = $true # Enable URL detection
$outputBox.BorderStyle = [System.Windows.Forms.BorderStyle]::None

$outputBox.Add_LinkClicked({ # Handle clicks on detected URLs
    param($sender, $e)
    Start-Process $e.LinkText # Open the clicked URL in the default browser
})
$form.Controls.Add($outputBox)

# --- Buttons ---
$lookupButton = New-Object System.Windows.Forms.Button
$lookupButton.Location = New-Object System.Drawing.Point(20, 565)
$lookupButton.Size = New-Object System.Drawing.Size(100, 30)
$lookupButton.Text = "Lookup"
$lookupButton.BackColor = $buttonBg
$lookupButton.ForeColor = $fgColor
$form.Controls.Add($lookupButton)

$screenshotButton = New-Object System.Windows.Forms.Button
$screenshotButton.Location = New-Object System.Drawing.Point(125, 565)
$screenshotButton.Size = New-Object System.Drawing.Size(100, 30)
$screenshotButton.Text = "Screenshot"
$screenshotButton.BackColor = $buttonBg
$screenshotButton.ForeColor = $fgColor
$screenshotButton.Enabled = $false
$form.Controls.Add($screenshotButton)

# --- Enter key triggers lookup ---
$form.AcceptButton = $lookupButton



function Append-ColoredText {
    param (
        [System.Windows.Forms.RichTextBox]$RichTextBox,
        [string]$Text,
        [System.Drawing.Color]$Color
    )

    # Validate that $Color is a valid System.Drawing.Color object.
    # This block ensures $Color is never null before being added to the global array.
    if ($Color -eq $null -or -not ($Color -is [System.Drawing.Color])) {
        # Write-Warning "Append-ColoredText received an invalid or null color for text: '$Text'. Falling back to Black."
        $Color = [System.Drawing.Color]::Black
    }

    # Store the text and color for screenshot purposes
    # Add-in for ArrayList
    $Global:outputBoxColoredSegments.Add(@{ Text = $Text; Color = $Color }) | Out-Null

    # Set the selection start and length to the end of the current text
    $RichTextBox.SelectionStart = $RichTextBox.TextLength
    $RichTextBox.SelectionLength = 0
    
    # Attempt to set the SelectionColor; include a try-catch for extra robustness
    try {
        $RichTextBox.SelectionColor = $Color
    } catch {
        # If setting the color fails for any reason, log the error and default to Black
        $errorMsg = $_.Exception.Message
        Write-Error ("Error setting RichTextBox SelectionColor to '$Color': " + $errorMsg + ". Falling back to Black.")
        $RichTextBox.SelectionColor = [System.Drawing.Color]::Black
    }

    # Append the text to the RichTextBox
    $RichTextBox.AppendText($Text)
    
    # Always reset the SelectionColor to the default foreground color after appending
    # This ensures subsequent text without explicit coloring uses the RichTextBox's default color.
    $RichTextBox.SelectionColor = $RichTextBox.ForeColor
}


function Show-DarkAlertDialog {
    param (
        [string]$message = "Please enter at least one valid IPv4 or IPv6 address.",
        [string]$title = "Input Error"
    )

    # These are only needed if the function is called before main script,
    # but harmless if already loaded.
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $title
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $form.ForeColor = [System.Drawing.Color]::White
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.Size = New-Object System.Drawing.Size(400, 180)
    $form.TopMost = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $message
    $label.AutoSize = $false
    $label.TextAlign = 'MiddleCenter'
    $label.Dock = 'Top'
    $label.Height = 80
    $label.Font = 'Segoe UI, 10'
    $label.ForeColor = [System.Drawing.Color]::White
    $form.Controls.Add($label)

    $button = New-Object System.Windows.Forms.Button
    $button.Text = "OK"
    $button.Size = New-Object System.Drawing.Size(80, 30)
    $button.BackColor = [System.Drawing.Color]::FromArgb(70, 70, 70)
    $button.ForeColor = [System.Drawing.Color]::DarkOrange
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderColor = [System.Drawing.Color]::Cyan
    $button.FlatAppearance.BorderSize = 1
    $button.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
    $button.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $button.Font = 'Segoe UI, 9'
    $button.Location = New-Object System.Drawing.Point(
        [int](($form.ClientSize.Width - $button.Width) / 2),
        100
    )
    $button.Add_Click({ $form.Close() })
    $form.Controls.Add($button)

    $form.AcceptButton = $button
    $form.ShowDialog() | Out-Null
}


$lookupButton.Add_Click({
    $lookupButton.Enabled = $false
    $screenshotButton.Enabled = $false
    $ipInput.Enabled = $false
    Set-IpInputVisualState -IsEnabled:$false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor

    try {
        $rawInputText = $ipInput.Text

        # IPv4 pattern (solid and standard, including [.] for evasion)
        $ipv4Pattern = '\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\[\.\](?:25[0-5]|2[0-4]\d|[01]?\d\d?)\[\.\](?:25[0-5]|2[0-4]\d|[01]?\d\d?)\[\.\](?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'

        # Comprehensive IPv6 pattern covering all forms (full, compressed '::', IPv4-mapped, and optional zone index)
        # This regex is a union of various valid IPv6 patterns.
        $ipv6Pattern = '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:%\w+)?\b' + # Full form
                       '|\b((?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?)(?:%\w+)?\b' + # Compressed form (:: can be anywhere)
                       '|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?:%\w+)?\b' + # 1 '::' and 1 to 6 segments
                       '|\b[0-9a-fA-F]{1,4}:(?:[0-9a-fA-F]{1,4}:){1,5}(?:[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))(?:%\w+)?\b' + # IPv4-mapped (e.g., ::ffff:192.0.2.1)
                       '|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?:[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))(?:%\w+)?\b' # Shorter IPv4-mapped variations


        # Combine both IPv4 and IPv6 patterns
        $allIpPattern = "$ipv4Pattern|$ipv6Pattern"

        # Step 1: Use regex to extract potential IP strings from the raw input
        # This will catch both IPv4 and IPv6, and handles IPv6 zone indices.
        $extractedPotentialIps = [System.Text.RegularExpressions.Regex]::Matches($rawInputText, $allIpPattern) | ForEach-Object {
            $cleanedValue = $_.Value
            $cleanedValue = $cleanedValue -replace '%\w+$', '' # Remove any %eth0, %en1, etc.
            $cleanedValue = $cleanedValue -replace '\[\.\]', '.' # Replace [.] with . for IPv4
            $cleanedValue
        }
        
        # Step 2: Validate each extracted string using [System.Net.IPAddress]::TryParse
        # This is the crucial step to ensure only truly valid IPs (both v4 and v6) are kept,
        # filtering out false positives like time strings or other non-IP formats.
        $validIps = @()
        foreach ($potentialIp in $extractedPotentialIps) {
            $parsedIp = [System.Net.IPAddress]::None # Initialize for TryParse
            if ([System.Net.IPAddress]::TryParse($potentialIp.Trim(), [ref]$parsedIp)) {
                $validIps += $parsedIp.ToString() # Add the string representation of the validated IP
            }
        }

        # Step 3: Remove duplicates and prepare the final list of IPs for processing
        $ips = $validIps | Select-Object -Unique

        # Format the extracted IPs for the input box display (optional, but good for user feedback)
        # This updates the RichTextBox with only the cleaned, valid IPs after the button click.
        $cleanedInputForDisplay = $ips -join " "
        if ($cleanedInputForDisplay.Length -gt 0) {
            $cleanedInputForDisplay += " "
        }

        if ($ipInput.Text -ne $cleanedInputForDisplay) {
            $ipInput.Text = $cleanedInputForDisplay
            $ipInput.SelectionStart = $ipInput.TextLength
            $ipInput.ScrollToCaret()
        }
        
        # Check if any valid IPs were found before proceeding with API lookups
        if ($ips.Count -eq 0) {
            Show-DarkAlertDialog # Or a more specific message indicating no IPs were found
            # Re-enable controls before returning
            $lookupButton.Enabled = $true
            $screenshotButton.Enabled = $false # Keep screenshot disabled if no IPs
            $ipInput.Enabled = true
            Set-IpInputVisualState -IsEnabled:$true
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
            return
        }

        # Clear the output box AND the stored colored segments before new lookup
        $outputBox.Clear()
        $Global:outputBoxColoredSegments.Clear()


        $ipCounter = 0
        $foundResults = $false

        foreach ($ip in $ips) {
            $ipCounter++

            try {
                $cleanedIp = $ip.Trim()
                $ipapiUri = "https://api.ipapi.is?q=$cleanedIp&key=$apiKey"
                $ipapiResponse = Invoke-RestMethod -Uri $ipapiUri -Method Get

                if ($ipapiResponse) {
                    $data = $ipapiResponse
                    $foundResults = $true

                    $tunnels = if ($data.vpn -and $data.vpn.service) {
                        $data.vpn.service
                    } elseif ($data.tunnels) {
                        ($data.tunnels | ForEach-Object { $_.operator }) -join ", "
                    } else { "None" }

                    $risks = @()
                    if ($data.is_vpn) { $risks += "VPN" }
                    if ($data.is_proxy) { $risks += "Proxy" }
                    if ($data.is_tor) { $risks += "Tor" }
                    if ($data.is_datacenter) { $risks += "Datacenter" }
                    if ($data.is_abuser) { $risks += "Abuser" }
                    if ($data.is_crawler) { $risks += "Crawler" }
                    
                    $asn = if ($data.asn.asn) { $data.asn.asn } else { "None" }
                    $org = if ($data.asn.org) { $data.asn.org } else { "None" }
                    
                    $city = if ($data.location.city) { $data.location.city } else { "Unknown City" }
                    $state = if ($data.location.state) { $data.location.state } else { "" }
                    $country = if ($data.location.country) { $data.location.country } else { "Unknown Country" }
                    $exitLocation = if ($state -ne "") { "$city, $state, $country" } else { "$city, $country" }

                    $labelPadding = 16

                    Append-ColoredText $outputBox "=== [$ip] ===`r`n" ([System.Drawing.Color]::LightCyan)
                    Append-ColoredText $outputBox ("{0,-$labelPadding} : " -f "Tunnel/Exit") ([System.Drawing.Color]::LightGreen)
                    Append-ColoredText $outputBox "$tunnels`r`n" ([System.Drawing.Color]::LightGreen)

                    Append-ColoredText $outputBox ("{0,-$labelPadding} : " -f "Risk Flags") ([System.Drawing.Color]::Yellow)
                    if ($risks.Count -eq 0) {
                        Append-ColoredText $outputBox "None`r`n" ([System.Drawing.Color]::Green)
                    } else {
                        foreach ($risk in $risks) {
                            $color = switch ($risk.Trim()) {
                                "VPN"           { [System.Drawing.Color]::Red }
                                "Proxy"         { [System.Drawing.Color]::DarkGoldenrod }
                                "Tor"           { [System.Drawing.Color]::Magenta }
                                "Datacenter"    { [System.Drawing.Color]::DarkCyan }
                                "Abuser"        { [System.Drawing.Color]::Crimson }
                                "Crawler"       { [System.Drawing.Color]::DarkOrange }
                                default         { [System.Drawing.Color]::White }
                            }
                            Append-ColoredText $outputBox "$risk " $color
                        }
                        Append-ColoredText $outputBox "`r`n"
                    }

                    Append-ColoredText $outputBox ("{0,-$labelPadding} : " -f "ASN/Org") ([System.Drawing.Color]::LightGreen)
                    Append-ColoredText $outputBox "$asn / $org`r`n" ([System.Drawing.Color]::LightGreen)

                    Append-ColoredText $outputBox ("{0,-$labelPadding} : " -f "Location") ([System.Drawing.Color]::LightGreen)
                    Append-ColoredText $outputBox "$exitLocation`r`n" ([System.Drawing.Color]::LightGreen)

                    # --- AbuseIPDB Lookup ---
                    $maxAgeInDays = 365
                    $abuseIpdbHeaders = @{
                        "Key"    = $abuseIpdbApiKey
                        "Accept" = "application/json"
                    }
                    $abuseIpdbUri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$cleanedIp&maxAgeInDays=$maxAgeInDays&verbose"
                    try {
                        $abuseIpdbResponse = Invoke-WebRequest -Uri $abuseIpdbUri -Method Get -Headers $abuseIpdbHeaders -UseBasicParsing | ConvertFrom-Json
                        $abuseIpdbData = $abuseIpdbResponse.data

                        $abuseDomain = if ($abuseIpdbData.domain) { $abuseIpdbData.domain } else { "Unknown" }
                        $abuseConfidenceScore = $abuseIpdbData.abuseConfidenceScore
                        $reportCount = $abuseIpdbData.totalReports

                        $abuseIpdbPadding = 16

                        Append-ColoredText $outputBox "`r`nAbuseIPDB (last $($maxAgeInDays)d reports):`r`n" ([System.Drawing.Color]::LightCyan)

                        Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : {1}`r`n" -f "Domain", $abuseDomain) $customOutputColor
                        Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : {1} times`r`n" -f "Total Reports", $reportCount) $customOutputColor

                        $scoreColor = if ($abuseConfidenceScore -ge 70) {
                            [System.Drawing.Color]::Red
                        } elseif ($abuseConfidenceScore -ge 30) {
                            [System.Drawing.Color]::Orange
                        } else {
                            [System.Drawing.Color]::LightGreen
                        }
                        Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : {1}%`r`n" -f "Confidence Score", $abuseConfidenceScore) $scoreColor

                        if ($abuseIpdbData.reports -and $abuseIpdbData.reports.Count -gt 0) {
                            $sortedAbuseReports = $abuseIpdbData.reports | Sort-Object { [datetime]$_.reportedAt }

                            $firstReportDateTime = [datetime]$sortedAbuseReports[0].reportedAt
                            $recentReportDateTime = [datetime]$abuseIpdbData.lastReportedAt

                            $humanReadableFirstReport = $firstReportDateTime.ToString("MMMM dd,yyyy HH:mm:ss K")
                            $humanReadableRecentReport = $recentReportDateTime.ToString("MMMM dd,yyyy HH:mm:ss K")

                            Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : {1}`r`n" -f "First Report", $humanReadableFirstReport) $customOutputColor
                            Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : {1}`r`n" -f "Recent Report", $humanReadableRecentReport) $customOutputColor

                            $abuseIpdbWebUrl = "https://www.abuseipdb.com/check/$cleanedIp"
                            Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : {1}`r`n" -f "View on Web", $abuseIpdbWebUrl) $uriColor

                        } else {
                            Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : N/A`r`n" -f "First Report") $customOutputColor
                            Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : N/A`r`n" -f "Recent Report") $customOutputColor

                            $abuseIpdbWebUrl = "https://www.abuseipdb.com/check/$cleanedIp"
                            Append-ColoredText $outputBox ("  {0,-$abuseIpdbPadding} : {1}`r`n" -f "View on Web", $abuseIpdbWebUrl) $uriColor
                        }
                    }
                    catch {
                        $abuseErrorMsg = $_.Exception.Message
                        Append-ColoredText $outputBox "AbuseIPDB Error for IP ${ip}: $abuseErrorMsg`r`n" ([System.Drawing.Color]::Red)
                    }

                    if ($ipCounter -lt $ips.Count) {
                        Append-ColoredText $outputBox "`r`n------------------------------------------------------------`r`n" ([System.Drawing.Color]::DarkCyan)
                    }

                }
                else {
                    Append-ColoredText $outputBox "[!] No IPapi.is data found for IP: $ip`r`n" ([System.Drawing.Color]::Red)
                    if ($ipCounter -lt $ips.Count) {
                        Append-ColoredText $outputBox "`r`n------------------------------------------------------------`r`n" ([System.Drawing.Color]::DarkCyan)
                    }
                }
            }
            catch {
                $ipapiErrorMsg = $_.Exception.Message
                Append-ColoredText $outputBox "[!] IPapi.is API Error for IP: ${ip} - $ipapiErrorMsg`r`n" ([System.Drawing.Color]::Red)
                if ($ipCounter -lt $ips.Count) {
                    Append-ColoredText $outputBox "`r`n------------------------------------------------------------`r`n" ([System.Drawing.Color]::DarkCyan)
                }
            }
        }

        if ($foundResults) {
            $screenshotButton.Enabled = $true
            Set-IpInputVisualState -IsEnabled:$true # Keep the input enabled for further lookups
        }


        Append-ColoredText $outputBox "`r`n------------------------------------------------------------" ([System.Drawing.Color]::DarkCyan)
        Append-ColoredText $outputBox "`r`nLegend:`r`n" ([System.Drawing.Color]::LightSteelBlue)
        Append-ColoredText $outputBox "Red: VPN | DarkGoldenrod: Proxy | Magenta: Tor | DarkCyan: Datacenter | Crimson: Abuser | DarkOrange: Crawler`r`n" ([System.Drawing.Color]::LightSteelBlue)

    }
    finally {
        # Ensure controls are re-enabled even if an error occurs
        $lookupButton.Enabled = $true
        $ipInput.Enabled = $true
        Set-IpInputVisualState -IsEnabled:$true
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})


$screenshotButton.Add_Click({
    # Disable the button immediately
    $screenshotButton.Enabled = $false
    try {
        $scriptDirectory = $null
        if ($MyInvocation.MyCommand.Path) {
            $scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
        } else {
            $scriptDirectory = Get-Location
        }

        $mainFolderName = "IP-LookUp-Ss"
        $todayDate = (Get-Date).ToString("yyyy-MM-dd")
        $subFolderName = $todayDate

        $savePath = Join-Path (Join-Path $scriptDirectory $mainFolderName) $subFolderName

        if (-not (Test-Path $savePath)) {
            New-Item -ItemType Directory -Path $savePath -Force | Out-Null
        }

        $baseFileName = "THP-"
        $extension = ".png"
        $fileNumber = 1
        $filename = ""
        $filePath = ""

        do {
            $filename = "$baseFileName$($fileNumber.ToString('000'))$extension"
            $filePath = Join-Path $savePath $filename
            $fileNumber++
        } while (Test-Path $filePath)

        if ($Global:outputBoxColoredSegments.Count -eq 0) {
            Show-DarkAlertDialog "There is no colored content to capture." "Screenshot Error"
            # Since the lookup button will re-enable, we just return here.
            return
        }

        $font = $outputBox.Font
        $bgColor = $outputBox.BackColor
        $lineHeight = [System.Windows.Forms.TextRenderer]::MeasureText("Sample", $font).Height
        $padding = 10

        $estimatedMaxWidth = 0
        $estimatedTotalHeight = $padding
        $tempCurrentX = $padding

        foreach ($segment in $Global:outputBoxColoredSegments) {
            $text = $segment.Text
            $parts = $text.Split("`n")

            for ($i = 0; $i -lt $parts.Count; $i++) {
                $part = $parts[$i].Trim("`r")

                $partWidth = [System.Windows.Forms.TextRenderer]::MeasureText($part, $font).Width

                if ($tempCurrentX + $partWidth -gt 1500 -or ($i -lt ($parts.Count - 1))) {
                    $estimatedTotalHeight += $lineHeight
                    $tempCurrentX = $padding
                }

                if ($tempCurrentX + $partWidth -gt $estimatedMaxWidth) {
                    $estimatedMaxWidth = $tempCurrentX + $partWidth
                }

                $tempCurrentX += $partWidth
            }
        }
        $estimatedTotalHeight += $lineHeight + $padding

        $bitmapWidth = $estimatedMaxWidth + ($padding * 4)
        if ($bitmapWidth -lt $outputBox.Width) {
            $bitmapWidth = $outputBox.Width + ($padding * 2)
        }
        $bitmapHeight = $estimatedTotalHeight


        $bitmap = New-Object Drawing.Bitmap $bitmapWidth, $bitmapHeight
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.Clear($bgColor)
        
        $currentX = $padding
        $currentY = $padding
        $actualMaxContentWidth = 0
        $actualMaxContentHeight = $padding

        foreach ($segment in $Global:outputBoxColoredSegments) {
            $text = $segment.Text
            $color = $segment.Color
            $segmentBrush = New-Object Drawing.SolidBrush ([System.Drawing.Color]$color)

            $parts = $text.Split("`n")

            for ($i = 0; $i -lt $parts.Count; $i++) {
                $part = $parts[$i].Trim("`r")

                $partWidth = [System.Windows.Forms.TextRenderer]::MeasureText($part, $font).Width

                if ($currentX + $partWidth -gt ($bitmapWidth - $padding) -and $currentX -ne $padding) {
                    $currentY += $lineHeight
                    $currentX = $padding
                }

                $graphics.DrawString($part, $font, $segmentBrush, $currentX, $currentY)
                
                $currentX += $partWidth

                if (($currentX - $padding) -gt $actualMaxContentWidth) {
                    $actualMaxContentWidth = $currentX - $padding
                }

                if ($i -lt ($parts.Count - 1)) {
                    $currentY += $lineHeight
                    $currentX = $padding
                }
            }
            $segmentBrush.Dispose()
        }

        $actualMaxContentHeight = $currentY + $lineHeight + $padding

        $finalBitmapWidth = $actualMaxContentWidth + ($padding * 2)
        $finalBitmapHeight = $actualMaxContentHeight

        if ($finalBitmapWidth -lt $outputBox.Width + ($padding * 2)) {
            $finalBitmapWidth = $outputBox.Width + ($padding * 2)
        }
        
        if ($finalBitmapHeight -lt $bitmapHeight) {
            # Do nothing, use the calculated $actualMaxContentHeight
        } else {
            $finalBitmapHeight = $actualMaxContentHeight
        }
        
        $finalBitmap = New-Object Drawing.Bitmap $finalBitmapWidth, $finalBitmapHeight
        $finalGraphics = [System.Drawing.Graphics]::FromImage($finalBitmap)
        $finalGraphics.Clear($bgColor)

        $currentX = $padding
        $currentY = $padding

        foreach ($segment in $Global:outputBoxColoredSegments) {
            $text = $segment.Text
            $color = $segment.Color
            $segmentBrush = New-Object Drawing.SolidBrush ([System.Drawing.Color]$color)

            $parts = $text.Split("`n")

            for ($i = 0; $i -lt $parts.Count; $i++) {
                $part = $parts[$i].Trim("`r")
                $partWidth = [System.Windows.Forms.TextRenderer]::MeasureText($part, $font).Width

                if ($currentX + $partWidth -gt ($finalBitmapWidth - $padding) -and $currentX -ne $padding) {
                    $currentY += $lineHeight
                    $currentX = $padding
                }

                $finalGraphics.DrawString($part, $font, $segmentBrush, $currentX, $currentY)
                $currentX += $partWidth

                if ($i -lt ($parts.Count - 1)) {
                    $currentY += $lineHeight
                    $currentX = $padding
                }
            }
            $segmentBrush.Dispose()
        }

        $finalBitmap.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)

        $graphics.Dispose()
        $bitmap.Dispose()
        $finalGraphics.Dispose()
        $finalBitmap.Dispose()

        Show-DarkAlertDialog "Screenshot saved to:`n`n$filePath" "Screenshot Saved"
    }
    catch {
        Show-DarkAlertDialog "Failed to save screenshot: $($_.Exception.Message)" "Screenshot Error"
        $screenshotButton.Enabled = $true
    }
    # No finally block needed here, as the lookup button's finally block will handle re-enabling.
})

# Initial clear of outputBox AND global segments on startup
$outputBox.Clear()
$Global:outputBoxColoredSegments.Clear()

# How to use instructions at startup
Append-ColoredText $outputBox "How to use:`r`n" ([System.Drawing.Color]::LightCyan)
Append-ColoredText $outputBox "- Enter multiple IPs separated by " ([System.Drawing.Color]::LightGreen)

# Separators with colored emphasis
$separators = @("space", "comma (,)", "semicolon (;)", "slash (/)")
for ($i = 0; $i -lt $separators.Count; $i++) {
    $color = switch ($separators[$i]) {
        "space"         { [System.Drawing.Color]::Yellow }
        "comma (,)"     { [System.Drawing.Color]::Orange }
        "semicolon (;)" { [System.Drawing.Color]::OrangeRed }
        "slash (/)"     { [System.Drawing.Color]::LightSalmon }
        default         { [System.Drawing.Color]::LightGreen }
    }
    Append-ColoredText $outputBox $separators[$i] $color
    if ($i -lt $separators.Count - 1) {
        Append-ColoredText $outputBox ", " ([System.Drawing.Color]::LightGreen)
    }
}

# Additional instruction
Append-ColoredText $outputBox "`r`n`r`n- Click the 'Lookup' button or press 'Enter' to fetch threat intel data`r`n" ([System.Drawing.Color]::LightGreen)

# Initial Legend section for startup
Append-ColoredText $outputBox "`r`nLegend:`r`n" ([System.Drawing.Color]::LightSteelBlue)
Append-ColoredText $outputBox "Red: VPN | DarkGoldenrod: Proxy | Magenta: Tor | DarkCyan: Datacenter | Crimson: Abuser | DarkOrange: Crawler`r`n" ([System.Drawing.Color]::LightSteelBlue)

$form.ShowDialog()