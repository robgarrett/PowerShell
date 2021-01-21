[CmdletBinding()]Param(
    [Parameter(Mandatory = $false)][String]$key = "^+M",
    [Parameter(Mandatory = $false)][Switch]$childWindow);

Function Set-WindowFocus {
[CmdletBinding()]Param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
    [ValidateNotNullorEmpty()]
    [System.IntPtr]$WindowHandle
);
    BEGIN {
        if ($null -eq ("APIFuncs2" -as [type])) {
            Add-Type  @"
            using System;
            using System.Runtime.InteropServices;
            public class APIFuncs2 {
                [DllImport("user32.dll")]
                [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool SetForegroundWindow(IntPtr hWnd);

                [DllImport("user32.dll")]
                [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

            }
"@;     
        }
    }
    PROCESS {
        [void] [apifuncs2]::SetForegroundWindow($WindowHandle);
        [void] [apifuncs2]::ShowWindow($WindowHandle, 3);
    }
}

Function Get-ActiveWindow {
[CmdletBinding()]Param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
    [ValidateNotNullorEmpty()]
    [System.IntPtr]$WindowHandle
);
    BEGIN {
        if ($null -eq ("APIFuncs3" -as [type])) {
            Add-Type  @"
            using System;
            using System.Runtime.InteropServices;
            public class APIFuncs3 {
                [DllImport("user32.dll")]
                public static extern IntPtr GetForegroundWindow();
            }
"@;     
        }
    }
    PROCESS {
        return ([apifuncs3]::GetForegroundWindow()) -eq $WindowHandle;
    }
}

Function Get-ChildWindow {
[CmdletBinding()]Param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
    [ValidateNotNullorEmpty()]
    [System.IntPtr]$MainWindowHandle,
    [Parameter(Mandatory = $false)][ScriptBlock]$callBack
);

    BEGIN {
        Function Get-WindowName($hwnd) {
            $len = [apifuncs]::GetWindowTextLength($hwnd);
            if ($len -gt 0) {
                $sb = [System.Text.StringBuilder]::new($len + 1);
                $rtnlen = [apifuncs]::GetWindowText($hwnd, $sb, $sb.Capacity);
                $sb.ToString();
            }
        }

        if ($null -eq ("APIFuncs" -as [type])) {
            Add-Type  @"
            using System;
            using System.Runtime.InteropServices;
            using System.Collections.Generic;
            using System.Text;
            public class APIFuncs
              {
                [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
                public static extern int GetWindowText(IntPtr hwnd,StringBuilder lpString, int cch);

                [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern IntPtr GetForegroundWindow();

                [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern Int32 GetWindowThreadProcessId(IntPtr hWnd,out Int32 lpdwProcessId);

                [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern Int32 GetWindowTextLength(IntPtr hWnd);

                [DllImport("user32")]
                [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool EnumChildWindows(IntPtr window, EnumWindowProc callback, IntPtr i);
                public static List<IntPtr> GetChildWindows(IntPtr parent)
                {
                   List<IntPtr> result = new List<IntPtr>();
                   GCHandle listHandle = GCHandle.Alloc(result);
                   try
                   {
                       EnumWindowProc childProc = new EnumWindowProc(EnumWindow);
                       EnumChildWindows(parent, childProc,GCHandle.ToIntPtr(listHandle));
                   }
                   finally
                   {
                       if (listHandle.IsAllocated)
                           listHandle.Free();
                   }
                   return result;
               }
               private static bool EnumWindow(IntPtr handle, IntPtr pointer)
               {
                   GCHandle gch = GCHandle.FromIntPtr(pointer);
                   List<IntPtr> list = gch.Target as List<IntPtr>;
                   if (list == null)
                   {
                       throw new InvalidCastException("GCHandle Target could not be cast as List<IntPtr>");
                   }
                   list.Add(handle);
                   //  You can modify this to check to see if you want to cancel the operation, then return a null here
                   return true;
               }
                public delegate bool EnumWindowProc(IntPtr hWnd, IntPtr parameter);
               }
"@
        }
    }

    PROCESS {
        Write-Verbose (Get-WindowName($MainWindowHandle));
        foreach ($child in ([apifuncs]::GetChildWindows($MainWindowHandle))) {
            $childWnd = [PSCustomObject] @{
                MainWindowHandle = $MainWindowHandle
                ChildId = $child
                ChildTitle = (Get-WindowName($child))
            };
            Write-Verbose $childWnd;
            if ($null -ne $callBack) { &$callBack -InputObject $childWnd; }
        }
    }
}

Get-Process | Where-Object { $_.ProcessName -ieq 'TEAMS' -and $_.MainWindowHandle -ne [IntPtr]::Zero } | Get-ChildWindow -callBack {
    Param([Parameter(Mandatory = $true)][PSCustomObject]$InputObject);
    $sb = {
        Param([Parameter(Mandatory = $true)][IntPtr]$MainWindowHandle);
        # Wait for Teams window to become focused, we use the main app window handle.
        while (!(Get-ActiveWindow -WindowHandle $MainWindowHandle)) { Start-Sleep -Milliseconds 250; } 
        # Send the keys.
        # https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.sendkeys?view=netframework-4.7.2
        if ($null -eq ("System.Windows.Forms" -as [type])) { Add-Type -AssemblyName "System.Windows.Forms"; }
        [System.Windows.Forms.SendKeys]::SendWait($key);
    };
    if ($ChildWindow) {
        if (![string]::IsNullOrEmpty($InputObject.ChildTitle)) {
            Set-WindowFocus -WindowHandle $InputObject.ChildId; 
            &$sb -MainWindowHandle $InputObject.MainWindowHandle;
        }
    } else {
        Set-WindowFocus -WindowHandle $InputObject.MainWindowHandle; 
        &$sb -MainWindowHandle $InputObject.MainWindowHandle;
    }
}

