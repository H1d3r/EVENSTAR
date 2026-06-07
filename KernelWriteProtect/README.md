# EVENSTAR - KernelWriteProtect

## Version

- `v3.0.0`

## Brief

- `ISA: x86`
- `Mode: Long`
- `Bitness: 64-bit`
- `CPL: 0`
- `OS: Windows`
- `Language: C`
- Sample code that demonstrates four techniques for writing into read-only pages in kernel space using `CR0.WP` manipulation, `MDL` double mapping, `PTE` manipulation, and `PFN` remapping.

## Usage

```
1: kd> vertarget
Windows 10 Kernel Version 26100 MP (2 procs) Free x64
Product: WinNt, suite: TerminalServer SingleUserTS
Edition build lab: 26100.1.amd64fre.ge_release.240331-1435
Kernel base = 0xfffff801`cb400000 PsLoadedModuleList = 0xfffff801`cc2f52d0
Debug session time: Fri Jun  5 15:50:12.936 2026 (UTC - 4:00)
System Uptime: 0 days 0:01:50.980

1: kd> g
KDFILES: Replacing '\??\C:\pub\KernelWriteProtect.sys' with 'C:\Users\winterknife\Desktop\CNO-Programs\EVENSTAR\KernelWriteProtect\Bin\x64\KernelWriteProtect.sys'.  File size 7KB.
KdPullRemoteFile(FFFFAD0304FC5040): About to overwrite \??\C:\pub\KernelWriteProtect.sys and preallocate to 1a60
KdPullRemoteFile(FFFFAD0304FC5040): Return from ZwCreateFile with status 0
..
[DBG]: +++ KernelWriteProtect.sys Loaded +++
[DBG]: KernelWriteProtect.sys Built Jun  5 2026 15:23:55
[DBG]: KernelWriteProtect: DriverObject = FFFFAD0305316E10
[DBG]: KernelWriteProtect: RegistryPath = \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\KernelWriteProtect
[DBG]: KernelWriteProtect: g_dwProtectedValue KVA = 0xFFFFF801625A4000
[DBG]: KernelWriteProtect: g_dwProtectedValue original contents = 0xDEADBEEF
[DBG]: KernelWriteProtect: g_dwProtectedValue protected by static KDP.
Break instruction exception - code 80000003 (first chance)
KernelWriteProtect_fffff801625a0000!DriverEntry+0xe0:
fffff801`625a50e0 cc              int     3

1: kd> !pte g_dwProtectedValue
                                           VA fffff801625a4000
PXE at FFFFE673399CCF80    PPE at FFFFE673399F0028    PDE at FFFFE6733E005890    PTE at FFFFE67C00B12D20
contains 00000000001D0063  contains 00000000001CF063  contains 0A0000011169D863  contains 89000001C0FDF121
pfn 1d0       ---DA--KWEV  pfn 1cf       ---DA--KWEV  pfn 11169d    ---DA--KWEV  pfn 1c0fdf    -G--A--KR-V

1: kd> dd g_dwProtectedValue L1
fffff801`625a4000  deadbeef

1: kd> g
[DBG]: KernelWriteProtect: g_dwProtectedValue modified contents = 0x41414141
Break instruction exception - code 80000003 (first chance)
KernelWriteProtect_fffff801625a0000!DriverEntry+0x10a:
fffff801`625a510a cc              int     3

1: kd> !pte g_dwProtectedValue
                                           VA fffff801625a4000
PXE at FFFFE673399CCF80    PPE at FFFFE673399F0028    PDE at FFFFE6733E005890    PTE at FFFFE67C00B12D20
contains 00000000001D0063  contains 00000000001CF063  contains 0A0000011169D863  contains 89000001BADC3121
pfn 1d0       ---DA--KWEV  pfn 1cf       ---DA--KWEV  pfn 11169d    ---DA--KWEV  pfn 1badc3    -G--A--KR-V

1: kd> dd g_dwProtectedValue L1
fffff801`625a4000  41414141
```

## Tested OS Versions

- `Windows 11 25H2 Build 26200 Revision 8457 64-bit`

## References

1. [BattlEye hypervisor detection](https://secret.club/2020/01/12/battleye-hypervisor-detection.html)
2. [ac](https://github.com/donnaskiez/ac)
3. [EfiGuard](https://github.com/Mattiwatti/EfiGuard)
4. [kernelhook](https://github.com/adrianyy/kernelhook)
5. [Exploit Development: Leveraging Page Table Entries for Windows Kernel Exploitation](https://connormcgarr.github.io/pte-overwrites/)
6. [g_CiOptions in a Virtualized World](https://trustedsec.com/blog/g_cioptions-in-a-virtualized-world)
7. [Melting Down PatchGuard: Leveraging KPTI to Bypass Kernel Patch Protection](https://www.fortinet.com/blog/threat-research/melting-down-patchguard-leveraging-kpi-to-bypass-kernel-patch-protection)
8. [The Swan Song for Driver Signature Enforcement Tampering](https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering)
9. [Code Execution against Windows HVCI](https://datafarm-cybersecurity.medium.com/code-execution-against-windows-hvci-f617570e9df0)
10. [Intel VT-rp - Part 1. remapping attack and HLAT](https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html)
11. [Intel VT-rp - Part 2. paging-write and guest-paging verification](https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html)
12. [HEXACON2023 - Bypassing the HVCI memory protection by Viviane Zwanger and Henning Braun](https://www.youtube.com/watch?v=WWvd2_jd0ZI)
13. [BusterCall](https://github.com/zer0condition/BusterCall)