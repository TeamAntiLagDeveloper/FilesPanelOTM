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
exit