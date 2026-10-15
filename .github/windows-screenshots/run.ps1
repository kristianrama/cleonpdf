# Throwaway: install the release MSI on a GitHub Windows runner and take screenshots.
param([string] $Msi, [string] $Pdf, [string] $Out)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$Msi = (Resolve-Path $Msi).Path
$Log = Join-Path $Out 'steps.log'
function Note([string] $m) { $line = "$(Get-Date -Format HH:mm:ss) $m"; $line; Add-Content $Log $line }

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class W {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int a, out RECT r, int s);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[void] [W]::SetProcessDPIAware()
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
Note "screen $($screen.Width)x$($screen.Height)"

function Shot([string] $Name, [IntPtr] $Hwnd = [IntPtr]::Zero) {
  Start-Sleep -Milliseconds 700
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($b.X, $b.Y, 0, 0, $b.Size)
  $g.Dispose()
  $bmp.Save((Join-Path $Out "$Name-desktop.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  if ($Hwnd -ne [IntPtr]::Zero) {
    $r = New-Object W+RECT
    if ([W]::DwmGetWindowAttribute($Hwnd, 9, [ref] $r, 16) -eq 0) {
      $rect = [System.Drawing.Rectangle]::Intersect((New-Object System.Drawing.Rectangle $r.L, $r.T, ($r.R - $r.L), ($r.B - $r.T)), $b)
      if ($rect.Width -gt 0 -and $rect.Height -gt 0) {
        $crop = $bmp.Clone($rect, $bmp.PixelFormat)
        $crop.Save((Join-Path $Out "$Name.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        $crop.Dispose()
      }
    }
  }
  $bmp.Dispose()
  Note "shot $Name"
}

# 1. The installer, through its own UI.
$wsh = New-Object -ComObject WScript.Shell
$m = Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /l*v `"$Out\install.log`"" -PassThru
$found = $false
for ($i = 0; $i -lt 60; $i++) { if ($wsh.AppActivate('CleonPDF Setup')) { $found = $true; break }; Start-Sleep 1 }
if ($found) {
  Start-Sleep 2; [void] $wsh.AppActivate('CleonPDF Setup')
  Shot '01-installer' ([W]::GetForegroundWindow())
  $wsh.SendKeys('~')
  for ($i = 0; $i -lt 240; $i++) {
    Start-Sleep 1
    if ($i -eq 1) { [void] $wsh.AppActivate('CleonPDF Setup'); Shot '02-installing' ([W]::GetForegroundWindow()) }
    if (Get-ChildItem "$env:ProgramFiles\CleonPDF\cleonpdf.exe" -ErrorAction SilentlyContinue) { if ($i -gt 3) { break } }
  }
  Start-Sleep 4; [void] $wsh.AppActivate('CleonPDF Setup')
  Shot '03-installed' ([W]::GetForegroundWindow())
  $wsh.SendKeys('~')
  if (-not $m.WaitForExit(120000)) { Note 'msiexec still running; killing'; Stop-Process -Id $m.Id -Force }
  Note "msiexec (UI) exit $($m.ExitCode)"
} else {
  Note 'installer window not found'; Stop-Process -Id $m.Id -Force -ErrorAction SilentlyContinue
}
$Exe = "$env:ProgramFiles\CleonPDF\cleonpdf.exe"
if (-not (Test-Path $Exe)) {
  Note 'UI install did not finish; installing silently'
  Start-Sleep 10
  $s = Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qn ALLUSERS=1 /l*v `"$Out\install-silent.log`"" -PassThru -Wait
  Note "msiexec (silent) exit $($s.ExitCode)"
}
if (-not (Test-Path $Exe)) { Note 'cleonpdf.exe not installed'; exit 1 }
Note "installed: $((Get-Item $Exe).VersionInfo.FileVersion)"

# 2. The desktop, with the shortcut.
(New-Object -ComObject Shell.Application).MinimizeAll()
Start-Sleep 3
Shot '04-desktop'

# 3. The app.
$work = 'C:\Documenti'
New-Item -ItemType Directory -Force $work | Out-Null
Copy-Item $Pdf (Join-Path $work 'Esempio CleonPDF.pdf')
function Scene([string] $Name, [string[]] $AppArgs, [int] $Settle = 10) {
  $p = Start-Process -FilePath $Exe -ArgumentList $AppArgs -WorkingDirectory $work -PassThru
  $h = [IntPtr]::Zero
  for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep 1; $p.Refresh()
    if ($p.HasExited) { break }
    if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $h = $p.MainWindowHandle; break }
  }
  if ($p.HasExited) { Note "scene $Name`: the app exited ($($p.ExitCode))"; return }
  if ($h -eq [IntPtr]::Zero) { Note "scene $Name`: no window" }
  Start-Sleep $Settle
  [void] [W]::SetForegroundWindow($h)
  Shot $Name $h
  [void] $p.CloseMainWindow()
  if (-not $p.WaitForExit(15000)) { Note "scene $Name`: did not close; killing"; Stop-Process -Id $p.Id -Force }
  Start-Sleep 2
}
$doc = '"Esempio CleonPDF.pdf"'
Scene '05-home' @('--language', 'it', '--theme', 'light') 12
Scene '06-viewer' @('--language', 'it', '--theme', 'light', '--panel', 'comments', '--zoom', '72', $doc)
Scene '07-dark' @('--language', 'it', '--theme', 'dark', '--panel', 'comments', '--page', '11', '--zoom', '80', $doc)
Scene '08-organize' @('--language', 'it', '--theme', 'light', '--organize', 'on', '--panel', 'none', $doc)
Scene '09-forms' @('--language', 'it', '--theme', 'light', '--page', '13', '--fields', 'on', '--zoom', '80', '--panel', 'fields', $doc)
Scene '10-about' @('--language', 'it', '--theme', 'light', '--dialog', 'about', $doc)

Get-ChildItem -Recurse -Filter 'cleonpdf*.log' "$env:APPDATA", "$env:LOCALAPPDATA" -ErrorAction SilentlyContinue |
  Select-Object -First 5 | ForEach-Object { Copy-Item $_.FullName (Join-Path $Out ("app-" + $_.Name)) }
Note 'done'
