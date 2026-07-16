<#
.SYNOPSIS
    Padzahr Security - Aoqin Dragon (G1007) Threat Hunting Script
    Optimized to eliminate false positives and execution errors.
#>
<# این اسکریپت تست شده است ولی با اینحال حتما در محیط آزمایشگاهی یکبار تست کنید #>

Write-Host "[+] Starting Padzahr Threat Hunting for Aoqin Dragon (G1007)..." -ForegroundColor Cyan

# ۱. شکار اجرای پروسس‌ها از روی درایوهای جابه‌جا شدنی (USB) فعال
$RemovableDrives = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter -ne $null }

if ($RemovableDrives) {
    Write-Host "[*] Removable drives detected. Scanning for active processes executing from these letters..." -ForegroundColor Yellow
    foreach ($Drive in $RemovableDrives) {
        $DriveLetter = "$($Drive.DriveLetter):"
        $SuspiciousProcs = Get-Process | Where-Object { $_.Path -like "$DriveLetter*" }
        
        if ($SuspiciousProcs) {
            foreach ($Proc in $SuspiciousProcs) {
                Write-Host "[CRITICAL] Process executing from USB drive: $($Proc.Name) (PID: $($Proc.Id)) - Path: $($Proc.Path)" -ForegroundColor Red
            }
        } else {
            Write-Host "[-] No active processes running from Drive $DriveLetter." -ForegroundColor Green
        }
    }
} else {
    Write-Host "[-] No active USB/Removable drives mounted." -ForegroundColor Green
}

# ۲. بررسی عمیق لایه حافظه (RAM) برای یافتن DLLهای تزریق‌شده مربوط به Aoqin Dragon
Write-Host "[*] Hunting for known Aoqin Dragon DLL payloads in memory..." -ForegroundColor Yellow

$MaliciousDlls = @("encrashrep", "DLL-test")
$FoundAlerts = $false

# دریافت پروسس‌های جاری و فیلتر کردن آن‌ها بر اساس لود ماژول‌های مشکوک
# استفاده از ErrorAction SilentlyContinue برای عبور بی‌صدا از پروسس‌های سیستمی محافظت‌شده (نویزگیری دسترسی)
$ActiveProcesses = Get-Process -ErrorAction SilentlyContinue

foreach ($Proc in $ActiveProcesses) {
    try {
        if ($Proc.Modules) {
            # بررسی اینکه آیا هیچ‌کدام از DLLهای هدف در این پروسس لود شده‌اند یا خیر
            $Match = $Proc.Modules | Where-Object { $MaliciousDlls -contains $_.ModuleName.Replace(".dll", "") }
            if ($Match) {
                Write-Host "[CRITICAL] Found Aoqin Dragon Payload loaded in: $($Proc.Name) (PID: $($Proc.Id)) - DLL: $($Match.ModuleName)" -ForegroundColor Red
                $FoundAlerts = $true
            }
        }
    }
    catch {
        # نویزگیری در صورت عدم دسترسی به ماژول‌های پروسس‌های خاص سیستمی
        continue
    }
}

if (-not $FoundAlerts) {
    Write-Host "[-] No malicious DLL loads detected in active memory." -ForegroundColor Green
}

# ۳. بررسی تکنیک Masquerading (آیکون‌ها و فایل‌های گمراه‌کننده پنهان در مسیرهای موقت)
Write-Host "[*] Scanning temp directories for suspicious executables pretending to be documents..." -ForegroundColor Yellow
$TempPaths = @("$env:TEMP", "C:\Users\Public")
foreach ($Path in $TempPaths) {
    if (Test-Path $Path) {
        # یافتن فایل‌های اجرایی که با حجم کوچک در مسیرهای موقت ساخته شده‌اند
        $SuspiciousFiles = Get-ChildItem -Path $Path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.Length -lt 2MB -and $_.CreationTime -gt (Get-Date).AddDays(-30) }
        
        if ($SuspiciousFiles) {
            foreach ($File in $SuspiciousFiles) {
                Write-Host "[WARNING] Newly created, small executable found in shared/temp path: $($File.FullName)" -ForegroundColor Yellow
            }
        }
    }
}

Write-Host "[+] Hunting Completed successfully by Padzahr Framework." -ForegroundColor Cyan
