// =============================================================================
// src/arm64/loadcfg.S - IMAGE_LOAD_CONFIG_DIRECTORY64 for ARM64
// -----------------------------------------------------------------------------
// Provides _load_config_used with DependentLoadFlags = 0x0800
// (LOAD_LIBRARY_SEARCH_SYSTEM32), SecurityCookie, and ARM64 CFG stubs.
// =============================================================================

        .text
        .p2align 2
guard_check_icall_nop:
        ret

        .p2align 2
guard_dispatch_icall_nop:
        br      x15

        .data
        .p2align 3
        .globl  __security_cookie
__security_cookie:
        .quad   0x2B992DDFA232
__guard_check_icall_fptr:
        .quad   guard_check_icall_nop
__guard_dispatch_icall_fptr:
        .quad   guard_dispatch_icall_nop

        .section .rdata,"dr"
        .p2align 2
gfids_table:
        .rva    wstart

        .p2align 3
        .globl  _load_config_used
_load_config_used:
        .long   0x140                       // Size (320 bytes)
        .long   0                           // TimeDateStamp
        .short  0, 0                        // Major/MinorVersion
        .long   0                           // GlobalFlagsClear
        .long   0                           // GlobalFlagsSet
        .long   0                           // CriticalSectionDefaultTimeout
        .quad   0                           // DeCommitFreeBlockThreshold
        .quad   0                           // DeCommitTotalFreeThreshold
        .quad   0                           // LockPrefixTable
        .quad   0                           // MaximumAllocationSize
        .quad   0                           // VirtualMemoryThreshold
        .quad   0                           // ProcessAffinityMask
        .long   0                           // ProcessHeapFlags
        .short  0                           // CSDVersion
        .short  0x0800                      // DependentLoadFlags = LOAD_LIBRARY_SEARCH_SYSTEM32
        .quad   0                           // EditList
        .quad   __security_cookie           // SecurityCookie
        .quad   0                           // SEHandlerTable
        .quad   0                           // SEHandlerCount
        .quad   __guard_check_icall_fptr    // GuardCFCheckFunctionPointer
        .quad   __guard_dispatch_icall_fptr // GuardCFDispatchFunctionPointer
        .quad   gfids_table                 // GuardCFFunctionTable (VA)
        .quad   1                           // GuardCFFunctionCount
        .long   0                           // GuardFlags
        .short  0, 0                        // CodeIntegrity.Flags/Catalog
        .long   0                           // CodeIntegrity.CatalogOffset
        .long   0                           // CodeIntegrity.Reserved
        .quad   0                           // GuardAddressTakenIatEntryTable
        .quad   0                           // GuardAddressTakenIatEntryCount
        .quad   0                           // GuardLongJumpTargetTable
        .quad   0                           // GuardLongJumpTargetCount
        .quad   0                           // DynamicValueRelocTable
        .quad   0                           // CHPEMetadataPointer
        .quad   0                           // GuardRFFailureRoutine
        .quad   0                           // GuardRFFailureRoutineFunctionPointer
        .long   0                           // DynamicValueRelocTableOffset
        .short  0                           // DynamicValueRelocTableSection
        .short  0                           // Reserved2
        .quad   0                           // GuardRFVerifyStackPointerFunctionPointer
        .long   0                           // HotPatchTableOffset
        .long   0                           // Reserved3
        .quad   0                           // EnclaveConfigurationPointer
        .quad   0                           // VolatileMetadataPointer
        .quad   0                           // GuardEHContinuationTable
        .quad   0                           // GuardEHContinuationCount
        .quad   0                           // GuardXFGCheckFunctionPointer
        .quad   0                           // GuardXFGDispatchFunctionPointer
        .quad   0                           // GuardXFGTableDispatchFunctionPointer
        .quad   0                           // CastGuardOsDeterminedFailureMode
        .quad   0                           // GuardMemcpyFunctionPointer
