"use strict";

// .load jsprovider.dll
// .scriptload ReadKDBGDataBlock.js
// dx Debugger.State.Scripts.ReadKDBGDataBlock.Contents.ReadKDBGDataBlock()
// .scriptunload ReadKDBGDataBlock.js
function ReadKDBGDataBlock() {
    const debugPrint = host.diagnostics.debugLog;
    const readMemory = host.memory.readMemoryValues;

    debugPrint("nt build number: ", readMemory(host.getModuleSymbolAddress("nt", "NtBuildNumber"), 1, 4)[0] & 0xFFFF, "\n");

    /*
    nt!KeSetTimer:
    fffff805`e652c460 48895c2420       mov     qword ptr [rsp+20h],rbx
    fffff805`e652c465 55               push    rbp
    fffff805`e652c466 56               push    rsi
    fffff805`e652c467 57               push    rdi
    fffff805`e652c468 4154             push    r12
    fffff805`e652c46a 4155             push    r13
    fffff805`e652c46c 4156             push    r14
    fffff805`e652c46e 4157             push    r15
    fffff805`e652c470 4881ec90000000   sub     rsp,90h
    fffff805`e652c477 488b0542e2ad00   mov     rax,qword ptr [nt!_security_cookie (fffff805`e700a6c0)]
    fffff805`e652c47e 4833c4           xor     rax,rsp
    fffff805`e652c481 4889842480000000 mov     qword ptr [rsp+80h],rax
    fffff805`e652c489 488b05209bc900   mov     rax,qword ptr [nt!KiWaitNever (fffff805`e71c5fb0)]
    fffff805`e652c490 498be8           mov     rbp,r8
    fffff805`e652c493 48332df69dc900   xor     rbp,qword ptr [nt!KiWaitAlways (fffff805`e71c6290)]
    fffff805`e652c49a 488bf9           mov     rdi,rcx
    */

    const keSetTimerKva = host.getModuleSymbolAddress("nt", "KeSetTimer"); // exported symbol
    debugPrint("nt!KeSetTimer KVA: 0x", keSetTimerKva.toString(16), "\n");

    let offsetOfRel32 = 44;
    let rel32 = readMemory(keSetTimerKva.add(offsetOfRel32), 1, 4, true)[0];
    //debugPrint("REL32: 0x", rel32.toString(16), "\n");

    let nextInstructionKva = keSetTimerKva.add(offsetOfRel32).add(4);
    //debugPrint("Next instruction KVA: 0x", nextInstructionKva.toString(16), "\n");

    const kiWaitNeverKva = nextInstructionKva.add(rel32);
    debugPrint("nt!KiWaitNever KVA: 0x", kiWaitNeverKva.toString(16), "\n");

    offsetOfRel32 = 54;
    rel32 = readMemory(keSetTimerKva.add(offsetOfRel32), 1, 4, true)[0];
    //debugPrint("REL32: 0x", rel32.toString(16), "\n");

    nextInstructionKva = keSetTimerKva.add(offsetOfRel32).add(4);
    //debugPrint("Next instruction KVA: 0x", nextInstructionKva.toString(16), "\n");

    const kiWaitAlwaysKva = nextInstructionKva.add(rel32);
    debugPrint("nt!KiWaitAlways KVA: 0x", kiWaitAlwaysKva.toString(16), "\n");

    /*
    nt!KdDecodeDataBlock:
    fffff805`e67ac098 4883ec28        sub     rsp,28h
    fffff805`e67ac09c 803d1da28b0000  cmp     byte ptr [nt!KdpDataBlockEncoded (fffff805`e70662c0)],0
    fffff805`e67ac0a3 7413            je      nt!KdDecodeDataBlock+0x20 (fffff805`e67ac0b8)
    fffff805`e67ac0a5 488d0d944f8500  lea     rcx,[nt!KdDebuggerDataBlock (fffff805`e7001040)]
    fffff805`e67ac0ac e823ffffff      call    nt!KdCopyDataBlock (fffff805`e67abfd4)
    fffff805`e67ac0b1 c60508a28b0000  mov     byte ptr [nt!KdpDataBlockEncoded (fffff805`e70662c0)],0
    fffff805`e67ac0b8 4883c428        add     rsp,28h
    fffff805`e67ac0bc c3              ret
    */

    const ntImageBaseKva = host.currentProcess.Modules.First(m => m.Name === "ntkrnlmp.exe").BaseAddress;
    debugPrint("nt image base KVA: 0x", ntImageBaseKva.toString(16), "\n");

    const ntImageSize = host.currentProcess.Modules.First(m => m.Name === "ntkrnlmp.exe").Size;
    debugPrint("nt image size: 0x", ntImageSize.toString(16), "\n");

    const buffer = readMemory(ntImageBaseKva, ntImageSize, 1);

    let kdDecodeDataBlockKva = null;
    for (let index = 0; index <= buffer.length - 13; index++) {
        // 48 83 EC 28 80 3D ?? ?? ?? ?? 00 74 13
        if (buffer[index] === 0x48 &&
            buffer[index+1] === 0x83 &&
            buffer[index+2] === 0xEC &&
            buffer[index+3] === 0x28 &&
            buffer[index+4] === 0x80 &&
            buffer[index+5] === 0x3D &&
            buffer[index+10] === 0x00 &&
            buffer[index+11] === 0x74 &&
            buffer[index+12] === 0x13
        ) {
            kdDecodeDataBlockKva = ntImageBaseKva.add(index); // non-exported symbol
            debugPrint("nt!KdDecodeDataBlock KVA: 0x", kdDecodeDataBlockKva.toString(16), "\n");
            break;
        }
    }

    offsetOfRel32 = 6;
    rel32 = readMemory(kdDecodeDataBlockKva.add(offsetOfRel32), 1, 4, true)[0];
    //debugPrint("REL32: 0x", rel32.toString(16), "\n");

    nextInstructionKva = kdDecodeDataBlockKva.add(offsetOfRel32).add(5);
    //debugPrint("Next instruction KVA: 0x", nextInstructionKva.toString(16), "\n");

    const kdpDataBlockEncodedKva = nextInstructionKva.add(rel32);
    debugPrint("nt!KdpDataBlockEncoded KVA: 0x", kdpDataBlockEncodedKva.toString(16), "\n");

    offsetOfRel32 = 16;
    rel32 = readMemory(kdDecodeDataBlockKva.add(offsetOfRel32), 1, 4, true)[0];
    //debugPrint("REL32: 0x", rel32.toString(16), "\n");

    nextInstructionKva = kdDecodeDataBlockKva.add(offsetOfRel32).add(4);
    //debugPrint("Next instruction KVA: 0x", nextInstructionKva.toString(16), "\n");

    const kdDebuggerDataBlockKva = nextInstructionKva.add(rel32);
    debugPrint("nt!KdDebuggerDataBlock KVA: 0x", kdDebuggerDataBlockKva.toString(16), "\n");

    /*
    nt!KdCopyDataBlock:
    fffff804`8bfabfd4 803de5a28b0000  cmp     byte ptr [nt!KdpDataBlockEncoded (fffff804`8c8662c0)],0
    fffff804`8bfabfdb 488d155e508500  lea     rdx,[nt!KdDebuggerDataBlock (fffff804`8c801040)]
    fffff804`8bfabfe2 4c8bc1          mov     r8,rcx
    fffff804`8bfabfe5 743d            je      nt!KdCopyDataBlock+0x50 (fffff804`8bfac024)  Branch
    fffff804`8bfabfe7 41b974000000    mov     r9d,74h
    fffff804`8bfabfed 4c2bc2          sub     r8,rdx
    fffff804`8bfabff0 488b0db99fa100  mov     rcx,qword ptr [nt!KiWaitNever (fffff804`8c9c5fb0)]
    fffff804`8bfabff7 488b02          mov     rax,qword ptr [rdx]
    fffff804`8bfabffa 4833c1          xor     rax,rcx
    fffff804`8bfabffd 48d3c0          rol     rax,cl
    fffff804`8bfac000 488d0db9a28b00  lea     rcx,[nt!KdpDataBlockEncoded (fffff804`8c8662c0)]
    fffff804`8bfac007 4833c1          xor     rax,rcx
    fffff804`8bfac00a 480fc8          bswap   rax
    fffff804`8bfac00d 4833057ca2a100  xor     rax,qword ptr [nt!KiWaitAlways (fffff804`8c9c6290)]
    fffff804`8bfac014 49890410        mov     qword ptr [r8+rdx],rax
    fffff804`8bfac018 488d5208        lea     rdx,[rdx+8]
    fffff804`8bfac01c 4183c1ff        add     r9d,0FFFFFFFFh
    fffff804`8bfac020 75ce            jne     nt!KdCopyDataBlock+0x1c (fffff804`8bfabff0)  Branch
    fffff804`8bfac022 c3              ret
    fffff804`8bfac024 b807000000      mov     eax,7
    fffff804`8bfac029 8d4879          lea     ecx,[rax+79h]
    fffff804`8bfac02c 0f1002          movups  xmm0,xmmword ptr [rdx]
    fffff804`8bfac02f 410f1100        movups  xmmword ptr [r8],xmm0
    fffff804`8bfac033 0f104a10        movups  xmm1,xmmword ptr [rdx+10h]
    fffff804`8bfac037 410f114810      movups  xmmword ptr [r8+10h],xmm1
    fffff804`8bfac03c 0f104220        movups  xmm0,xmmword ptr [rdx+20h]
    fffff804`8bfac040 410f114020      movups  xmmword ptr [r8+20h],xmm0
    fffff804`8bfac045 0f104a30        movups  xmm1,xmmword ptr [rdx+30h]
    fffff804`8bfac049 410f114830      movups  xmmword ptr [r8+30h],xmm1
    fffff804`8bfac04e 0f104240        movups  xmm0,xmmword ptr [rdx+40h]
    fffff804`8bfac052 410f114040      movups  xmmword ptr [r8+40h],xmm0
    fffff804`8bfac057 0f104a50        movups  xmm1,xmmword ptr [rdx+50h]
    fffff804`8bfac05b 410f114850      movups  xmmword ptr [r8+50h],xmm1
    fffff804`8bfac060 0f104260        movups  xmm0,xmmword ptr [rdx+60h]
    fffff804`8bfac064 410f114060      movups  xmmword ptr [r8+60h],xmm0
    fffff804`8bfac069 4c03c1          add     r8,rcx
    fffff804`8bfac06c 0f104a70        movups  xmm1,xmmword ptr [rdx+70h]
    fffff804`8bfac070 4803d1          add     rdx,rcx
    fffff804`8bfac073 410f1148f0      movups  xmmword ptr [r8-10h],xmm1
    fffff804`8bfac078 4883e801        sub     rax,1
    fffff804`8bfac07c 75ae            jne     nt!KdCopyDataBlock+0x58 (fffff804`8bfac02c)  Branch
    fffff804`8bfac07e 0f1002          movups  xmm0,xmmword ptr [rdx]
    fffff804`8bfac081 410f1100        movups  xmmword ptr [r8],xmm0
    fffff804`8bfac085 0f104a10        movups  xmm1,xmmword ptr [rdx+10h]
    fffff804`8bfac089 410f114810      movups  xmmword ptr [r8+10h],xmm1
    fffff804`8bfac08e c3              ret
    */

    /*
    nt!KiInitializeKernel+0x3b4:
    fffff800`77f59ce4 0f31            rdtsc
    fffff800`77f59ce6 48c1e220        shl     rdx,20h
    fffff800`77f59cea 480bc2          or      rax,rdx
    fffff800`77f59ced 8bc8            mov     ecx,eax
    fffff800`77f59cef 83e10f          and     ecx,0Fh
    fffff800`77f59cf2 488bd0          mov     rdx,rax
    fffff800`77f59cf5 48c1c22b        rol     rdx,2Bh
    fffff800`77f59cf9 4833d0          xor     rdx,rax
    fffff800`77f59cfc 48d3ca          ror     rdx,cl
    fffff800`77f59cff 488915aac24600  mov     qword ptr [nt!KiWaitNever (fffff800`783c5fb0)],rdx
    fffff800`77f59d06 0f31            rdtsc
    fffff800`77f59d08 48c1e220        shl     rdx,20h
    fffff800`77f59d0c 480bc2          or      rax,rdx
    fffff800`77f59d0f 8bc8            mov     ecx,eax
    fffff800`77f59d11 83e10f          and     ecx,0Fh
    fffff800`77f59d14 488bd0          mov     rdx,rax
    fffff800`77f59d17 48c1ca2f        ror     rdx,2Fh
    fffff800`77f59d1b 4833c2          xor     rax,rdx
    fffff800`77f59d1e 48d3c0          rol     rax,cl
    fffff800`77f59d21 48890568c54600  mov     qword ptr [nt!KiWaitAlways (fffff800`783c6290)],rax
    */

    /*
    nt!KdDebuggerDataBlock represents a data structure of type nt!_KDDEBUGGER_DATA64 (#include <WDBGEXTS.H>)
    0n116 QWORDs of this structure are obfuscated when nt!KdpDataBlockEncoded != 0
    These QWORDs can be deobfuscated using the following algorithm:
    DeobfuscatedQword = ObfuscatedQword ^ *(QWORD*)&nt!KiWaitNever;
    DeobfuscatedQword = _rotl64(DeobfuscatedQword, *(QWORD*)&nt!KiWaitNever & 0n63);
    DeobfuscatedQword = DeobfuscatedQword ^ &nt!KdpDataBlockEncoded;
    DeobfuscatedQword = _bswap64(DeobfuscatedQword);
    DeobfuscatedQword = DeobfuscatedQword ^ *(QWORD*)&nt!KiWaitAlways;
    */

    /*
    A known plaintext attack that does not require knowing nt!KiWaitNever, nt!KiWaitAlways, or nt!KdpDataBlockEncoded is also feasible
    ciphertext0 ^ ciphertext1 == ror(bswap(plaintext0 ^ plaintext1), shift)
    Brute force the shift value in the range 0 - 63
    plaintext = plaintext0 ^ bswap(rol(ciphertext ^ ciphertext0, shift))
    */

    debugPrint("PAE enabled: ", readMemory(kdDebuggerDataBlockKva.add(0x36), 1, 2)[0] & 0x1, "\n");
    debugPrint("Paging levels: ", (readMemory(kdDebuggerDataBlockKva.add(0x36), 1, 2)[0] >>> 2) & 0xF, "\n");
    debugPrint("nt!PsLoadedModuleList KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0x48), 1, 8)[0].toString(16), "\n");
    debugPrint("nt!PsActiveProcessHead KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0x50), 1, 8)[0].toString(16), "\n");
    debugPrint("nt!PspCidTable KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0x58), 1, 8)[0].toString(16), "\n");
    debugPrint("nt!MmPfnDatabase KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0xC0), 1, 8)[0].toString(16), "\n");
    debugPrint("nt!MmUnloadedDrivers KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0x220), 1, 8)[0].toString(16), "\n");
    debugPrint("nt!MmLastUnloadedDriver KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0x228), 1, 8)[0].toString(16), "\n");
    debugPrint("nt!EtwpDebuggerData KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0x330), 1, 8)[0].toString(16), "\n");
    debugPrint("poi(nt!MmPteBase) KVA: 0x", readMemory(kdDebuggerDataBlockKva.add(0x360), 1, 8)[0].toString(16), "\n");
    debugPrint("KCET enabled: ", readMemory(readMemory(kdDebuggerDataBlockKva.add(0x388), 1, 8)[0], 1, 1)[0], "\n");
    debugPrint("FIELD_OFFSET(nt!_KTHREAD, KernelShadowStackBase): 0x", readMemory(kdDebuggerDataBlockKva.add(0x384), 1, 4)[0].toString(16), "\n");
    debugPrint("FIELD_OFFSET(nt!_KTHREAD, KernelShadowStackLimit): 0x", readMemory(kdDebuggerDataBlockKva.add(0x380), 1, 4)[0].toString(16), "\n");
}