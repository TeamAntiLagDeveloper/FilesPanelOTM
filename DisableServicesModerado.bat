@echo off
sc config WSearch start=disabled
sc config SSDPSRV start=disabled
sc config AXInstSV start=disabled
sc config AJRouter start=disabled
sc config AppReadiness start=disabled
sc config HomeGroupListener start=disabled
sc config HomeGroupProvider start=disabled
sc config WalletService start=disabled
sc config RetailDemo start=disabled
sc config wuauserv start= disabled
sc config bits start= disabled
sc config dosvc start= disabled
net stop dosvc
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /d 2 /t REG_DWORD /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /d 0 /t REG_DWORD /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /d 1 /t REG_DWORD /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoRebootWithLoggedOnUsers /d 1 /t REG_DWORD /f
exit