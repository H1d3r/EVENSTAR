# EVENSTAR - ReadKDBGDataBlockJSExt

## Version

- `v1.0`

## Brief

- `WinDbg` `JavaScript` extension to find the _kernel debugger data block_ (`KDDEBUGGER_DATA64`) without relying on symbols and display some of its interesting members
- The purpose of this script is to highlight the importance of this data structure that holds pointers and offsets to several opaque symbols that are otherwise not easily locatable
- The script serves as a blueprint for a `C/C++` implementation and also documents two techniques to decode the _kernel debugger data block_ using nothing but an arbitrary virtual memory read primitive

## Usage

- Set up kernel-mode debugging of the target
```c
kd> vertarget
Windows 10 Kernel Version 26100 MP (1 procs) Free x64
Edition build lab: 26100.1.amd64fre.ge_release.240331-1435
Kernel base = 0xfffff806`afc00000 PsLoadedModuleList = 0xfffff806`b0af51d0
Debug session time: Tue Jul 21 15:18:54.130 2026 (UTC + 0:00)
System Uptime: 0 days 0:02:28.542

kd> .load jsprovider.dll

kd> .scriptload ReadKDBGDataBlock.js
JavaScript script successfully loaded from 'C:\Users\winterknife\Desktop\Tools\WinDbgExtensions\ReadKDBGDataBlock.js'

kd> dx Debugger.State.Scripts.ReadKDBGDataBlock.Contents.ReadKDBGDataBlock()
nt build number: 26200
nt!KeSetTimer KVA: 0xfffff806aff2c460
nt!KiWaitNever KVA: 0xfffff806b0bc5fb0
nt!KiWaitAlways KVA: 0xfffff806b0bc6290
nt image base KVA: 0xfffff806afc00000
nt image size: 0x1450000
nt!KdDecodeDataBlock KVA: 0xfffff806b01ac098
nt!KdpDataBlockEncoded KVA: 0xfffff806b0a662c0
nt!KdDebuggerDataBlock KVA: 0xfffff806b0a01040
PAE enabled: 1
Paging levels: 4
nt!PsLoadedModuleList KVA: 0xfffff806b0af51d0
nt!PsActiveProcessHead KVA: 0xfffff806b0b05aa0
nt!PspCidTable KVA: 0xfffff806b0bc5ce8
nt!MmPfnDatabase KVA: 0xfffff806b0bc5c78
nt!MmUnloadedDrivers KVA: 0xfffff806b0af5250
nt!MmLastUnloadedDriver KVA: 0xfffff806b0af5248
nt!EtwpDebuggerData KVA: 0xfffff806b0a0eb28
poi(nt!MmPteBase) KVA: 0xffff910000000000
KCET enabled: 1
FIELD_OFFSET(nt!_KTHREAD, KernelShadowStackBase): 0x418
FIELD_OFFSET(nt!_KTHREAD, KernelShadowStackLimit): 0x420
Debugger.State.Scripts.ReadKDBGDataBlock.Contents.ReadKDBGDataBlock()

kd> .scriptunload ReadKDBGDataBlock.js
JavaScript script unloaded from 'C:\Users\winterknife\Desktop\Tools\WinDbgExtensions\ReadKDBGDataBlock.js'
```

## Tested OS Versions

- `Windows 11 25H2 Build 26200 Revision 8655 64-bit`

## References

1. [KDBGDecryptor](https://github.com/Air14/KDBGDecryptor)
2. [Timer List Obfuscation](http://uninformed.org/index.cgi?v=8&a=5&p=10)
3. [DriverBase](https://github.com/ByteWhite1x1/DriverBase)
4. [PatchGuardEncryptorDriver](https://github.com/AmitMoshel1/PatchGuardEncryptorDriver)
5. [Kdrill](https://github.com/ExaTrack/Kdrill)
6. [IceBox](https://github.com/thalium/icebox)
7. [The Secret to 64-bit Windows 8 and 2012 Raw Memory Dump Forensics](https://volatility-labs.blogspot.com/2014/01/the-secret-to-64-bit-windows-8-and-2012.html)
8. [64bit Big Sized RAM Image Acquisition Problem](https://takahiroharuyama.github.io/blog/2014/01/07/64bit-big-size-ram-acquisition-problem/)
9. [Big RAM and the kernel debugger data block](https://laserkittens.com/big-ram-and-the-kernel-debugger-data-block)
10. [Guest Windows debugging and crashdumping under QEMU/KVM: elf2dmp](https://daynix.github.io/2023/05/23/Guest-Windows-debugging-and-crashdumping-under-QEMU-KVM-elf2dmp.html)
11. [Struct KDDEBUGGER_DATA64](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/Extensions/struct.KDDEBUGGER_DATA64.html)