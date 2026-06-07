// ========================================================================
// File: DrvMain.cpp
//
// Author: winterknife
//
// Description: Source file that contains the SYS entry point
//
// Modifications:
//  2026-04-13	Created
//  2026-06-05  Updated
// ========================================================================

// ========================================================================
// Includes
// ========================================================================

#include "../Inc/Common.h"
#include "../Inc/WriteProtectBypass.h"

// ========================================================================
// Globals
// ========================================================================

#pragma region GLOBALS

// RO global variable
#pragma section(".rodata", read)
__declspec(allocate(".rodata")) DWORD g_dwProtectedValue = 0xDEADBEEF;

#pragma endregion

// ========================================================================
// Routines
// ========================================================================

#pragma region ROUTINES

/// @brief DRIVER_INITIALIZE callback routine that gets called to initialize the driver when it is loaded
/// @param pDriverObject Pointer to DRIVER_OBJECT structure representing the driver's driver object
/// @param puncRegistryPath Pointer to UNICODE_STRING structure specifying the path to the driver's registry key
/// @return STATUS_SUCCESS or an appropriate error status
_Success_(return >= 0) _Must_inspect_result_ _IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C __declspec(code_seg("INIT")) NTSTATUS __stdcall DriverEntry(
	_In_ PDRIVER_OBJECT  pDriverObject,
	_In_ PUNICODE_STRING puncRegistryPath
) {
	DEBUG_PRINT("+++ %s.sys Loaded +++\n", __MODULE__);
	DEBUG_PRINT("%s.sys Built %s %s\n", __MODULE__, __DATE__, __TIME__);
	DEBUG_PRINT("%s: DriverObject = %p\n", __MODULE__, pDriverObject);
	DEBUG_PRINT("%s: RegistryPath = %wZ\n", __MODULE__, puncRegistryPath);

	// This driver cannot be unloaded
	// /DRIVER:WDM linker switch + no DRIVER_UNLOAD routine + no MM_PROTECT_DRIVER_SECTION_ALLOW_UNLOAD flag

	DEBUG_PRINT("%s: g_dwProtectedValue KVA = 0x%p\n", __MODULE__, &g_dwProtectedValue);
	DEBUG_PRINT("%s: g_dwProtectedValue original contents = 0x%I32X\n", __MODULE__, ReadULongNoFence(&g_dwProtectedValue));

	// Mark the guest physical page containing g_dwProtectedValue as RO in the SLAT entry
	NTSTATUS status = MmProtectDriverSection(&g_dwProtectedValue, 0, 0);
	if (!NT_SUCCESS(status)) {
		DEBUG_PRINT("%s: MmProtectDriverSection error = 0x%08X\n", __MODULE__, status);
		return status;
	}
	DEBUG_PRINT("%s: g_dwProtectedValue protected by static KDP.\n", __MODULE__);
	__debugbreak();

	// Corrupt RO data page
	BYTE byarrPayload[] = { 0x41, 0x41, 0x41, 0x41 };

	//copy_memory_cr0_wp(&g_dwProtectedValue, byarrPayload, sizeof(byarrPayload));
	//DEBUG_PRINT("%s: g_dwProtectedValue modified contents = 0x%I32X\n", __MODULE__, ReadULongNoFence(&g_dwProtectedValue));

	//copy_memory_double_mapping(&g_dwProtectedValue, byarrPayload, sizeof(byarrPayload));
	//DEBUG_PRINT("%s: g_dwProtectedValue modified contents = 0x%I32X\n", __MODULE__, ReadULongNoFence(&g_dwProtectedValue));

	//copy_memory_pte(&g_dwProtectedValue, byarrPayload, sizeof(byarrPayload));
	//DEBUG_PRINT("%s: g_dwProtectedValue modified contents = 0x%I32X\n", __MODULE__, ReadULongNoFence(&g_dwProtectedValue));

	copy_memory_page_remapping(&g_dwProtectedValue, byarrPayload, sizeof(byarrPayload));
	DEBUG_PRINT("%s: g_dwProtectedValue modified contents = 0x%I32X\n", __MODULE__, ReadULongNoFence(&g_dwProtectedValue));
	__debugbreak();

	return STATUS_SUCCESS;
}

#pragma endregion