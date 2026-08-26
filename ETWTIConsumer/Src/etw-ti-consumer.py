#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.14"
# dependencies = ["pywintrace", "psutil"]
# ///


"""
[!] Usage: kdu.exe -prv 27 -pse "python.exe etw-ti-consumer.py [PID of process to be monitored] [output filename]"
[!] Note: Please launch from an admin shell to be able to load the driver.
"""

import sys
import etw
from etw.etw import ProviderParameters
import json
import ctypes
import psutil
from datetime import datetime, timezone, timedelta

events = []
filter_pid = 0


def event_callback(event_tufo):
    event_id = event_tufo[0]
    payload = event_tufo[1]

    calling_pid = payload["CallingProcessId"]
    if filter_pid != int(calling_pid):
        return

    calling_tid = payload["CallingThreadId"]
    target_pid = payload.get("TargetProcessId")

    user_stack = []
    for retaddr in payload["EventExtendedData"]["StackTrace64"]["Address"]:
        if retaddr > 0x7FFFFFFEFFFF:  # MM_HIGHEST_USER_ADDRESS
            continue
        user_stack.append(f"0x{retaddr:x}")

    timestamp = (
        (
            datetime(1601, 1, 1, tzinfo=timezone.utc)
            + timedelta(microseconds=payload["EventHeader"]["TimeStamp"] // 10)
        )
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )

    if event_id == 1:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE",
            "Description": "Cross-process private executable memory allocation by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Base Address": payload["BaseAddress"],
            "Region Size": payload["RegionSize"],
            "Protection Mask": hex(payload["ProtectionMask"]),
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 6:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL",
            "Description": "In-process private executable memory allocation by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Base Address": payload["BaseAddress"],
            "Region Size": payload["RegionSize"],
            "Protection Mask": hex(payload["ProtectionMask"]),
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 7:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL",
            "Description": "In-process executable virtual memory protection change by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Base Address": payload["BaseAddress"],
            "Region Size": payload["RegionSize"],
            "New Protection Mask": hex(payload["ProtectionMask"]),
            "Old Protection Mask": hex(payload["LastProtectionMask"]),
            "VAD Allocation Base": payload["VaVadAllocationBase"],
            "VAD Original Protection": hex(payload["VaVadAllocationProtect"]),
            "VAD Region Type": hex(payload["VaVadRegionType"]),
            "VAD Region Size": payload["VaVadRegionSize"],
            "VAD MMF Name": payload["VaVadMmfName"],
            "Target Address": payload["TargetAddress"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 2:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE",
            "Description": "Cross-process executable virtual memory protection change by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Base Address": payload["BaseAddress"],
            "Region Size": payload["RegionSize"],
            "New Protection Mask": hex(payload["ProtectionMask"]),
            "Old Protection Mask": hex(payload["LastProtectionMask"]),
            "VAD Allocation Base": payload["VaVadAllocationBase"],
            "VAD Original Protection": hex(payload["VaVadAllocationProtect"]),
            "VAD Region Type": hex(payload["VaVadRegionType"]),
            "VAD Region Size": payload["VaVadRegionSize"],
            "VAD MMF Name": payload["VaVadMmfName"],
            "Target Address": payload["TargetAddress"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 11:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_READVM_LOCAL",
            "Description": "In-process virtual memory read by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Base Address": payload["BaseAddress"],
            "Bytes Read": payload["BytesCopied"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 13:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_READVM_REMOTE",
            "Description": "Cross-process virtual memory read by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Base Address": payload["BaseAddress"],
            "Bytes Read": payload["BytesCopied"],
            "VAD Allocation Base": payload["VaVadAllocationBase"],
            "VAD Original Protection": hex(payload["VaVadAllocationProtect"]),
            "VAD Region Type": hex(payload["VaVadRegionType"]),
            "VAD Region Size": payload["VaVadRegionSize"],
            "VAD MMF Name": payload["VaVadMmfName"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 12:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL",
            "Description": "In-process virtual memory write by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Base Address": payload["BaseAddress"],
            "Bytes Written": payload["BytesCopied"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 14:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE",
            "Description": "Cross-process virtual memory write by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Base Address": payload["BaseAddress"],
            "Bytes Written": payload["BytesCopied"],
            "VAD Allocation Base": payload["VaVadAllocationBase"],
            "VAD Original Protection": hex(payload["VaVadAllocationProtect"]),
            "VAD Region Type": hex(payload["VaVadRegionType"]),
            "VAD Region Size": payload["VaVadRegionSize"],
            "VAD MMF Name": payload["VaVadMmfName"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 8:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL",
            "Description": "In-process executable non-image section mapping by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Base Address": payload["BaseAddress"],
            "View Size": payload["ViewSize"],
            "Protection Mask": hex(payload["ProtectionMask"]),
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 3:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE",
            "Description": "Cross-process executable non-image section mapping by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Base Address": payload["BaseAddress"],
            "View Size": payload["ViewSize"],
            "Protection Mask": hex(payload["ProtectionMask"]),
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 4:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE",
            "Description": "Cross-process normal or special user-mode APC queuing by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Target TID": payload["TargetThreadId"],
            "Target Thread Alertable": payload["TargetThreadAlertable"],
            "Normal Routine": payload["ApcRoutine"],
            "APC Argument 1": payload["ApcArgument1"],
            "APC Argument 2": payload["ApcArgument2"],
            "APC Argument 3": payload["ApcArgument3"],
            "Normal Routine VAD Allocation Base": payload[
                "ApcRoutineVadAllocationBase"
            ],
            "Normal Routine VAD Original Protection": hex(
                payload["ApcRoutineVadAllocationProtect"]
            ),
            "Normal Routine VAD Region Type": hex(payload["ApcRoutineVadRegionType"]),
            "Normal Routine VAD Region Size": payload["ApcRoutineVadRegionSize"],
            "Normal Routine VAD MMF Name": payload["ApcRoutineVadMmfName"],
            "APC Argument 1 VAD Allocation Base": payload[
                "ApcArgument1VadAllocationBase"
            ],
            "APC Argument 1 VAD Original Protection": hex(
                payload["ApcArgument1VadAllocationProtect"]
            ),
            "APC Argument 1 VAD Region Type": hex(payload["ApcArgument1VadRegionType"]),
            "APC Argument 1 VAD Region Size": payload["ApcArgument1VadRegionSize"],
            "APC Argument 1 VAD MMF Name": payload["ApcArgument1VadMmfName"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 5:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE",
            "Description": "Cross-process thread CONTEXT modification by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Target TID": payload["TargetThreadId"],
            "CONTEXT Flags": payload["ContextFlags"],
            "CONTEXT Mask": payload["ContextMask"],
            "RIP": payload["Pc"],
            "RSP": payload["Sp"],
            "RBP": payload["Fp"],
            "RAX": payload["Reg0"],
            "RCX": payload["Reg1"],
            "RDX": payload["Reg2"],
            "RBX": payload["Reg3"],
            "RSI": payload["Reg4"],
            "RDI": payload["Reg5"],
            "R8": payload["Reg6"],
            "R9": payload["Reg7"],
            "RIP VAD Allocation Base": payload["PcVadAllocationBase"],
            "RIP VAD Original Protection": hex(payload["PcVadAllocationProtect"]),
            "RIP VAD Region Type": hex(payload["PcVadRegionType"]),
            "RIP VAD Region Size": payload["PcVadRegionSize"],
            "RIP VAD MMF Name": payload["PcVadMmfName"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 15:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD",
            "Description": "In-process or cross-process thread suspension by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Target TID": payload["TargetThreadId"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 16:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_RESUME_THREAD",
            "Description": "In-process or cross-process thread resumption by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "Target TID": payload["TargetThreadId"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 17:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS",
            "Description": "In-process or cross-process multithread suspension by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 18:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_RESUME_PROCESS",
            "Description": "In-process or cross-process multithread resumption by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 19:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_FREEZE_PROCESS",
            "Description": "In-process or cross-process multithread freezing by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 20:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_THAW_PROCESS",
            "Description": "In-process or cross-process multithread thawing by user-mode caller",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Target PID": target_pid,
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 35:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_PROCESS_SYSCALL_USAGE",
            "Description": "First invocation of NtQuerySystemInformation or NtSystemDebugControl system call by non-admin process",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Session ID": payload["SessionId"],
            "System Call Enum": payload["SyscallEnum"],
            "Primary Token Sandboxed": payload["IsSandboxedToken"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 33:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_UP",
            "Description": "Thread's impersonation token changed to equal or higher integrity level",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Previous Token Type": payload["PreviousTokenType"],
            "Previous Token Elevation": payload["PreviousTokenElevation"],
            "Previous Token Elevation Type": payload["PreviousTokenElevationType"],
            "Previous Token Impersonation Level": payload[
                "PreviousTokenImpersonationLevel"
            ],
            "Previous Token User SID": payload["PreviousTokenUser"],
            "Previous Token Integrity Level RID": hex(
                payload["PreviousTokenIntegrityLevel"]
            ),
            "Previous Token Logon LUID": payload["PreviousTokenAuthenticationId"],
            "Current Token Type": payload["CurrentTokenType"],
            "Current Token Elevation": payload["CurrentTokenElevation"],
            "Current Token Elevation Type": payload["CurrentTokenElevationType"],
            "Current Token Impersonation Level": payload[
                "CurrentTokenImpersonationLevel"
            ],
            "Current Token User SID": payload["CurrentTokenUser"],
            "Current Token Integrity Level RID": hex(
                payload["CurrentTokenIntegrityLevel"]
            ),
            "Current Token Logon LUID": payload["CurrentTokenAuthenticationId"],
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 34:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_REVERT",
            "Description": "Thread stopped impersonating and reverted to its process's primary token",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "User Stack": user_stack,
        }
        events.append(event_dict)
    elif event_id == 36:
        event_dict = {
            "Keyword": "KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_DOWN",
            "Description": "Thread's impersonation token changed to lower integrity level",
            "Timestamp": timestamp,
            "Calling PID": calling_pid,
            "Calling TID": calling_tid,
            "Previous Token Type": payload["PreviousTokenType"],
            "Previous Token Elevation": payload["PreviousTokenElevation"],
            "Previous Token Elevation Type": payload["PreviousTokenElevationType"],
            "Previous Token Impersonation Level": payload[
                "PreviousTokenImpersonationLevel"
            ],
            "Previous Token User SID": payload["PreviousTokenUser"],
            "Previous Token Integrity Level RID": hex(
                payload["PreviousTokenIntegrityLevel"]
            ),
            "Previous Token Logon LUID": payload["PreviousTokenAuthenticationId"],
            "Current Token Type": payload["CurrentTokenType"],
            "Current Token Elevation": payload["CurrentTokenElevation"],
            "Current Token Elevation Type": payload["CurrentTokenElevationType"],
            "Current Token Impersonation Level": payload[
                "CurrentTokenImpersonationLevel"
            ],
            "Current Token User SID": payload["CurrentTokenUser"],
            "Current Token Integrity Level RID": hex(
                payload["CurrentTokenIntegrityLevel"]
            ),
            "Current Token Logon LUID": payload["CurrentTokenAuthenticationId"],
            "User Stack": user_stack,
        }
        events.append(event_dict)


def main():
    if len(sys.argv) != 3:
        print("[-] Invalid args.")
        print(__doc__)
        sys.exit(0)

    globals()["filter_pid"] = int(sys.argv[1])
    filename = sys.argv[2]

    try:
        file = open(filename, "w", encoding="utf-8")
    except OSError:
        print("[-] Invalid file path.")
        sys.exit(0)

    params = ProviderParameters(
        event_property=4, event_filters=[]
    )  # EVENT_ENABLE_PROPERTY_STACK_TRACE

    providers = [
        etw.ProviderInfo(
            "Microsoft-Windows-Threat-Intelligence",
            etw.GUID("{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}"),
            level=etw.evntrace.TRACE_LEVEL_INFORMATION,
            any_keywords=[
                "KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL",  # mask=0x1
                "KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE",  # mask=0x4
                "KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL",  # mask=0x10
                "KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_FILL_VAD",  # mask=0x400000000
                "KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE",  # mask=0x40
                "KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_FILL_VAD",  # mask=0x1000000000
                "KERNEL_THREATINT_KEYWORD_READVM_LOCAL",  # mask=0x10000
                "KERNEL_THREATINT_KEYWORD_READVM_REMOTE",  # mask=0x20000
                "KERNEL_THREATINT_KEYWORD_READVM_REMOTE_FILL_VAD",  # mask=0x100000000
                "KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL",  # mask=0x40000
                "KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE",  # mask=0x80000
                "KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE_FILL_VAD",  # mask=0x200000000
                "KERNEL_THREATINT_KEYWORD_READWRITEVM_NO_SIGNATURE_RESTRICTION",  # mask=0x20000000
                "KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL",  # mask=0x100
                "KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE",  # mask=0x400
                "KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE",  # mask=0x1000
                "KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_VAD_PROBE",  # mask=0x8000000
                "KERNEL_THREATINT_KEYWORD_EXECUTION_ADDRESS_MMF_NAME_PROBE",  # mask=0x10000000
                "KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE",  # mask=0x4000
                "KERNEL_THREATINT_KEYWORD_CONTEXT_PARSE",  # mask=0x4000000
                "KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD",  # mask=0x100000
                "KERNEL_THREATINT_KEYWORD_RESUME_THREAD",  # mask=0x200000
                "KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS",  # mask=0x400000
                "KERNEL_THREATINT_KEYWORD_RESUME_PROCESS",  # mask=0x800000
                "KERNEL_THREATINT_KEYWORD_FREEZE_PROCESS",  # mask=0x1000000
                "KERNEL_THREATINT_KEYWORD_THAW_PROCESS",  # mask=0x2000000
                "KERNEL_THREATINT_KEYWORD_PROCESS_SYSCALL_USAGE",  # mask=0x10000000000
                "KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_UP",  # mask=0x4000000000
                "KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_REVERT",  # mask=0x8000000000
                "KERNEL_THREATINT_KEYWORD_PROCESS_IMPERSONATION_DOWN",  # mask=0x40000000000
            ],
            all_keywords=None,
            params=params.get(),
        )
    ]

    job = etw.ETW(
        session_name="etw-ti",
        providers=providers,
        event_callback=event_callback,
        ignore_exists_error=False,
        pid_whitelist=[],
    )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=False)

    pids = [p.pid for p in psutil.process_iter()]

    buffer = ctypes.c_ulong(0x7F)

    for pid in pids:
        process_handle = kernel32.OpenProcess(
            0x0200, False, pid
        )  # PROCESS_SET_INFORMATION
        if not process_handle:
            # print(f"[-] OpenProcess error: {ctypes.get_last_error()}")
            continue

        # ProcessEnableLogging info class
        # EnableReadVmLogging (0x01)
        # EnableWriteVmLogging (0x02)
        # EnableProcessSuspendResumeLogging (0x04)
        # EnableThreadSuspendResumeLogging (0x08)
        # EnableLocalExecProtectVmLogging (0x10)
        # EnableRemoteExecProtectVmLogging (0x20)
        # EnableImpersonationLogging (0x40)
        status = ntdll.NtSetInformationProcess(
            process_handle, 0x60, ctypes.byref(buffer), ctypes.sizeof(buffer)
        )
        kernel32.CloseHandle(process_handle)
        if status != 0:
            print(f"[-] NtSetInformationProcess error: 0x{status & 0xFFFFFFFF:08X}")

    print("[+] Starting capture.")
    job.start()

    try:
        input("[+] Press Enter to stop.")
    except KeyboardInterrupt:
        pass
    finally:
        stats = job.query()
        print("[+] Buffers written: ", stats.BuffersWritten)
        print("[+] Events lost: ", stats.EventsLost)
        print("[+] Real-time buffers lost: ", stats.RealTimeBuffersLost)
        print("[+] Stopping capture.")
        job.stop()

    json.dump(events, file, indent=4, default=str, ensure_ascii=False)
    file.close()


if __name__ == "__main__":
    main()
