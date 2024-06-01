from binaryninja import (
    Architecture,
    BinaryView,
    Endianness,
    SegmentFlag,
    StructureBuilder,
    Type,
    SegmentFlag,
    SectionSemantics,
    Symbol,
    SymbolType,
    SymbolBinding,
)

from binaryninja.log import log_error, log_info

from zipfile import ZipFile
import os
import requests
import subprocess
import platform
import pathlib
import stat
import ctypes


class XBELoader(BinaryView):
    name = "XBE"
    long_name = name
    magic = b"XBEH"
    
    kernel_thunk_table_addr = 0

    def log(self, msg, error=False):
        msg = f"[XBE Loader] {msg}"
        if not error:
            log_info(msg)
        else:
            log_error(msg)

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data):
        return data.read(0x0, 0x4) == cls.magic

    def perform_get_default_endianness(self):
        return Endianness.LittleEndian

    def perform_get_address_size(self):
        return self.arch.address_size

    def perform_is_executable(self):
        return True

    def on_complete(self):
        self.define_xbe_symbols()
        self.process_imports(self.kernel_thunk_table_addr)

    def process_imports(self, address):
        '''
        Get external functional symbols via the unscrambled value of PointerToKernelThunkTable in the XBE header.

        Calculate the import addresses and their matching symbol, then define the external symbols.
        '''
        kernel_exports = [
            "",                                     # 0
            "AvGetSavedDataAddress",                # 1
            "AvSendTVEncoderOption",                # 2
            "AvSetDisplayMode",                     # 3
            "AvSetSavedDataAddress",                # 4
            "DbgBreakPoint",                        # 5
            "DbgBreakPointWithStatus",              # 6
            "DbgLoadImageSymbols",                  # 7
            "DbgPrint",                             # 8
            "HalReadSMCTrayState",                  # 9
            "DbgPrompt",                            # 10
            "DbgUnLoadImageSymbols",                # 11
            "ExAcquireReadWriteLockExclusive",      # 12
            "ExAcquireReadWriteLockShared",         # 13
            "ExAllocatePool",                       # 14
            "ExAllocatePoolWithTag",                # 15
            "ExEventObjectType",                    # 16
            "ExFreePool",                           # 17
            "ExInitializeReadWriteLock",            # 18
            "ExInterlockedAddLargeInteger",         # 19
            "ExInterlockedAddLargeStatistic",       # 20
            "ExInterlockedCompareExchange64",       # 21
            "ExMutantObjectType",                   # 22
            "ExQueryPoolBlockSize",                 # 23
            "ExQueryNonVolatileSetting",            # 24
            "ExReadWriteRefurbInfo",                # 25
            "ExRaiseException",                     # 26
            "ExRaiseStatus",                        # 27
            "ExReleaseReadWriteLock",               # 28
            "ExSaveNonVolatileSetting",             # 29
            "ExSemaphoreObjectType",                # 30
            "ExTimerObjectType",                    # 31
            "ExfInterlockedInsertHeadList",         # 32
            "ExfInterlockedInsertTailList",         # 33
            "ExfInterlockedRemoveHeadList",         # 34
            "FscGetCacheSize",                      # 35
            "FscInvalidateIdleBlocks",              # 36
            "FscSetCacheSize",                      # 37
            "HalClearSoftwareInterrupt",            # 38
            "HalDisableSystemInterrupt",            # 39
            "HalDiskCachePartitionCount",           # 40
            "HalDiskModelNumber",                   # 41
            "HalDiskSerialNumber",                  # 42
            "HalEnableSystemInterrupt",             # 43
            "HalGetInterruptVector",                # 44
            "HalReadSMBusValue",                    # 45
            "HalReadWritePCISpace",                 # 46
            "HalRegisterShutdownNotification",      # 47
            "HalRequestSoftwareInterrupt",          # 48
            "HalReturnToFirmware",                  # 49
            "HalWriteSMBusValue",                   # 50
            "InterlockedCompareExchange",           # 51
            "InterlockedDecrement",                 # 52
            "InterlockedIncrement",                 # 53
            "InterlockedExchange",                  # 54
            "InterlockedExchangeAdd",               # 55
            "InterlockedFlushSList",                # 56
            "InterlockedPopEntrySList",             # 57
            "InterlockedPushEntrySList",            # 58
            "IoAllocateIrp",                        # 59
            "IoBuildAsynchronousFsdRequest",        # 60
            "IoBuildDeviceIoControlRequest",        # 61
            "IoBuildSynchronousFsdRequest",         # 62
            "IoCheckShareAccess",                   # 63
            "IoCompletionObjectType",               # 64
            "IoCreateDevice",                       # 65
            "IoCreateFile",                         # 66
            "IoCreateSymbolicLink",                 # 67
            "IoDeleteDevice",                       # 68
            "IoDeleteSymbolicLink",                 # 69
            "IoDeviceObjectType",                   # 70
            "IoFileObjectType",                     # 71
            "IoFreeIrp",                            # 72
            "IoInitializeIrp",                      # 73
            "IoInvalidDeviceRequest",               # 74
            "IoQueryFileInformation",               # 75
            "IoQueryVolumeInformation",             # 76
            "IoQueueThreadIrp",                     # 77
            "IoRemoveShareAccess",                  # 78
            "IoSetIoCompletion",                    # 79
            "IoSetShareAccess",                     # 80
            "IoStartNextPacket",                    # 81
            "IoStartNextPacketByKey",               # 82
            "IoStartPacket",                        # 83
            "IoSynchronousDeviceIoControlRequest",  # 84
            "IoSynchronousFsdRequest",              # 85
            "IofCallDriver",                        # 86
            "IofCompleteRequest",                   # 87
            "KdDebuggerEnabled",                    # 88
            "KdDebuggerNotPresent",                 # 89
            "IoDismountVolume",                     # 90
            "IoDismountVolumeByName",               # 91
            "KeAlertResumeThread",                  # 92
            "KeAlertThread",                        # 93
            "KeBoostPriorityThread",                # 94
            "KeBugCheck",                           # 95
            "KeBugCheckEx",                         # 96
            "KeCancelTimer",                        # 97
            "KeConnectInterrupt",                   # 98
            "KeDelayExecutionThread",               # 99
            "KeDisconnectInterrupt",                # 100
            "KeEnterCriticalRegion",                # 101
            "MmGlobalData",                         # 102
            "KeGetCurrentIrql",                     # 103
            "KeGetCurrentThread",                   # 104
            "KeInitializeApc",                      # 105
            "KeInitializeDeviceQueue",              # 106
            "KeInitializeDpc",                      # 107
            "KeInitializeEvent",                    # 108
            "KeInitializeInterrupt",                # 109
            "KeInitializeMutant",                   # 110
            "KeInitializeQueue",                    # 111
            "KeInitializeSemaphore",                # 112
            "KeInitializeTimerEx",                  # 113
            "KeInsertByKeyDeviceQueue",             # 114
            "KeInsertDeviceQueue",                  # 115
            "KeInsertHeadQueue",                    # 116
            "KeInsertQueue",                        # 117
            "KeInsertQueueApc",                     # 118
            "KeInsertQueueDpc",                     # 119
            "KeInterruptTime",                      # 120
            "KeIsExecutingDpc",                     # 121
            "KeLeaveCriticalRegion",                # 122
            "KePulseEvent",                         # 123
            "KeQueryBasePriorityThread",            # 124
            "KeQueryInterruptTime",                 # 125
            "KeQueryPerformanceCounter",            # 126
            "KeQueryPerformanceFrequency",          # 127
            "KeQuerySystemTime",                    # 128
            "KeRaiseIrqlToDpcLevel",                # 129
            "KeRaiseIrqlToSynchLevel",              # 130
            "KeReleaseMutant",                      # 131
            "KeReleaseSemaphore",                   # 132
            "KeRemoveByKeyDeviceQueue",             # 133
            "KeRemoveDeviceQueue",                  # 134
            "KeRemoveEntryDeviceQueue",             # 135
            "KeRemoveQueue",                        # 136
            "KeRemoveQueueDpc",                     # 137
            "KeResetEvent",                         # 138
            "KeRestoreFloatingPointState",          # 139
            "KeResumeThread",                       # 140
            "KeRundownQueue",                       # 141
            "KeSaveFloatingPointState",             # 142
            "KeSetBasePriorityThread",              # 143
            "KeSetDisableBoostThread",              # 144
            "KeSetEvent",                           # 145
            "KeSetEventBoostPriority",              # 146
            "KeSetPriorityProcess",                 # 147
            "KeSetPriorityThread",                  # 148
            "KeSetTimer",                           # 149
            "KeSetTimerEx",                         # 150
            "KeStallExecutionProcessor",            # 151
            "KeSuspendThread",                      # 152
            "KeSynchronizeExecution",               # 153
            "KeSystemTime",                         # 154
            "KeTestAlertThread",                    # 155
            "KeTickCount",                          # 156
            "KeTimeIncrement",                      # 157
            "KeWaitForMultipleObjects",             # 158
            "KeWaitForSingleObject",                # 159
            "KfRaiseIrql",                          # 160
            "KfLowerIrql",                          # 161
            "KiBugCheckData",                       # 162
            "KiUnlockDispatcherDatabase",           # 163
            "LaunchDataPage",                       # 164
            "MmAllocateContiguousMemory",           # 165
            "MmAllocateContiguousMemoryEx",         # 166
            "MmAllocateSystemMemory",               # 167
            "MmClaimGpuInstanceMemory",             # 168
            "MmCreateKernelStack",                  # 169
            "MmDeleteKernelStack",                  # 170
            "MmFreeContiguousMemory",               # 171
            "MmFreeSystemMemory",                   # 172
            "MmGetPhysicalAddress",                 # 173
            "MmIsAddressValid",                     # 174
            "MmLockUnlockBufferPages",              # 175
            "MmLockUnlockPhysicalPage",             # 176
            "MmMapIoSpace",                         # 177
            "MmPersistContiguousMemory",            # 178
            "MmQueryAddressProtect",                # 179
            "MmQueryAllocationSize",                # 180
            "MmQueryStatistics",                    # 181
            "MmSetAddressProtect",                  # 182
            "MmUnmapIoSpace",                       # 183
            "NtAllocateVirtualMemory",              # 184
            "NtCancelTimer",                        # 185
            "NtClearEvent",                         # 186
            "NtClose",                              # 187
            "NtCreateDirectoryObject",              # 188
            "NtCreateEvent",                        # 189
            "NtCreateFile",                         # 190
            "NtCreateIoCompletion",                 # 191
            "NtCreateMutant",                       # 192
            "NtCreateSemaphore",                    # 193
            "NtCreateTimer",                        # 194
            "NtDeleteFile",                         # 195
            "NtDeviceIoControlFile",                # 196
            "NtDuplicateObject",                    # 197
            "NtFlushBuffersFile",                   # 198
            "NtFreeVirtualMemory",                  # 199
            "NtFsControlFile",                      # 200
            "NtOpenDirectoryObject",                # 201
            "NtOpenFile",                           # 202
            "NtOpenSymbolicLinkObject",             # 203
            "NtProtectVirtualMemory",               # 204
            "NtPulseEvent",                         # 205
            "NtQueueApcThread",                     # 206
            "NtQueryDirectoryFile",                 # 207
            "NtQueryDirectoryObject",               # 208
            "NtQueryEvent",                         # 209
            "NtQueryFullAttributesFile",            # 210
            "NtQueryInformationFile",               # 211
            "NtQueryIoCompletion",                  # 212
            "NtQueryMutant",                        # 213
            "NtQuerySemaphore",                     # 214
            "NtQuerySymbolicLinkObject",            # 215
            "NtQueryTimer",                         # 216
            "NtQueryVirtualMemory",                 # 217
            "NtQueryVolumeInformationFile",         # 218
            "NtReadFile",                           # 219
            "NtReadFileScatter",                    # 220
            "NtReleaseMutant",                      # 221
            "NtReleaseSemaphore",                   # 222
            "NtRemoveIoCompletion",                 # 223
            "NtResumeThread",                       # 224
            "NtSetEvent",                           # 225
            "NtSetInformationFile",                 # 226
            "NtSetIoCompletion",                    # 227
            "NtSetSystemTime",                      # 228
            "NtSetTimerEx",                         # 229
            "NtSignalAndWaitForSingleObjectEx",     # 230
            "NtSuspendThread",                      # 231
            "NtUserIoApcDispatcher",                # 232
            "NtWaitForSingleObject",                # 233
            "NtWaitForSingleObjectEx",              # 234
            "NtWaitForMultipleObjectsEx",           # 235
            "NtWriteFile",                          # 236
            "NtWriteFileGather",                    # 237
            "NtYieldExecution",                     # 238
            "ObCreateObject",                       # 239
            "ObDirectoryObjectType",                # 240
            "ObInsertObject",                       # 241
            "ObMakeTemporaryObject",                # 242
            "ObOpenObjectByName",                   # 243
            "ObOpenObjectByPointer",                # 244
            "ObpObjectHandleTable",                 # 245
            "ObReferenceObjectByHandle",            # 246
            "ObReferenceObjectByName",              # 247
            "ObReferenceObjectByPointer",           # 248
            "ObSymbolicLinkObjectType",             # 249
            "ObfDereferenceObject",                 # 250
            "ObfReferenceObject",                   # 251
            "PhyGetLinkState",                      # 252
            "PhyInitialize",                        # 253
            "PsCreateSystemThread",                 # 254
            "PsCreateSystemThreadEx",               # 255
            "PsQueryStatistics",                    # 256
            "PsSetCreateThreadNotifyRoutine",       # 257
            "PsTerminateSystemThread",              # 258
            "PsThreadObjectType",                   # 259
            "RtlAnsiStringToUnicodeString",         # 260
            "RtlAppendStringToString",              # 261
            "RtlAppendUnicodeStringToString",       # 262
            "RtlAppendUnicodeToString",             # 263
            "RtlAssert",                            # 264
            "RtlCaptureContext",                    # 265
            "RtlCaptureStackBackTrace",             # 266
            "RtlCharToInteger",                     # 267
            "RtlCompareMemory",                     # 268
            "RtlCompareMemoryUlong",                # 269
            "RtlCompareString",                     # 270
            "RtlCompareUnicodeString",              # 271
            "RtlCopyString",                        # 272
            "RtlCopyUnicodeString",                 # 273
            "RtlCreateUnicodeString",               # 274
            "RtlDowncaseUnicodeChar",               # 275
            "RtlDowncaseUnicodeString",             # 276
            "RtlEnterCriticalSection",              # 277
            "RtlEnterCriticalSectionAndRegion",     # 278
            "RtlEqualString",                       # 279
            "RtlEqualUnicodeString",                # 280
            "RtlExtendedIntegerMultiply",           # 281
            "RtlExtendedLargeIntegerDivide",        # 282
            "RtlExtendedMagicDivide",               # 283
            "RtlFillMemory",                        # 284
            "RtlFillMemoryUlong",                   # 285
            "RtlFreeAnsiString",                    # 286
            "RtlFreeUnicodeString",                 # 287
            "RtlGetCallersAddress",                 # 288
            "RtlInitAnsiString",                    # 289
            "RtlInitUnicodeString",                 # 290
            "RtlInitializeCriticalSection",         # 291
            "RtlIntegerToChar",                     # 292
            "RtlIntegerToUnicodeString",            # 293
            "RtlLeaveCriticalSection",              # 294
            "RtlLeaveCriticalSectionAndRegion",     # 295
            "RtlLowerChar",                         # 296
            "RtlMapGenericMask",                    # 297
            "RtlMoveMemory",                        # 298
            "RtlMultiByteToUnicodeN",               # 299
            "RtlMultiByteToUnicodeSize",            # 300
            "RtlNtStatusToDosError",                # 301
            "RtlRaiseException",                    # 302
            "RtlRaiseStatus",                       # 303
            "RtlTimeFieldsToTime",                  # 304
            "RtlTimeToTimeFields",                  # 305
            "RtlTryEnterCriticalSection",           # 306
            "RtlUlongByteSwap",                     # 307
            "RtlUnicodeStringToAnsiString",         # 308
            "RtlUnicodeStringToInteger",            # 309
            "RtlUnicodeToMultiByteN",               # 310
            "RtlUnicodeToMultiByteSize",            # 311
            "RtlUnwind",                            # 312
            "RtlUpcaseUnicodeChar",                 # 313
            "RtlUpcaseUnicodeString",               # 314
            "RtlUpcaseUnicodeToMultiByteN",         # 315
            "RtlUpperChar",                         # 316
            "RtlUpperString",                       # 317
            "RtlUshortByteSwap",                    # 318
            "RtlWalkFrameChain",                    # 319
            "RtlZeroMemory",                        # 320
            "XboxEEPROMKey",                        # 321
            "XboxHardwareInfo",                     # 322
            "XboxHDKey",                            # 323
            "XboxKrnlVersion",                      # 324
            "XboxSignatureKey",                     # 325
            "XeImageFileName",                      # 326
            "XeLoadSection",                        # 327
            "XeUnloadSection",                      # 328
            "READ_PORT_BUFFER_UCHAR",               # 329
            "READ_PORT_BUFFER_USHORT",              # 330
            "READ_PORT_BUFFER_ULONG",               # 331
            "WRITE_PORT_BUFFER_UCHAR",              # 332
            "WRITE_PORT_BUFFER_USHORT",             # 333
            "WRITE_PORT_BUFFER_ULONG",              # 334
            "XcSHAInit",                            # 335
            "XcSHAUpdate",                          # 336
            "XcSHAFinal",                           # 337
            "XcRC4Key",                             # 338
            "XcRC4Crypt",                           # 339
            "XcHMAC",                               # 340
            "XcPKEncPublic",                        # 341
            "XcPKDecPrivate",                       # 342
            "XcPKGetKeyLen",                        # 343
            "XcVerifyPKCS1Signature",               # 344
            "XcModExp",                             # 345
            "XcDESKeyParity",                       # 346
            "XcKeyTable",                           # 347
            "XcBlockCrypt",                         # 348
            "XcBlockCryptCBC",                      # 349
            "XcCryptService",                       # 350
            "XcUpdateCrypto",                       # 351
            "RtlRip",                               # 352
            "XboxLANKey",                           # 353
            "XboxAlternateSignatureKeys",           # 354
            "XePublicKeyData",                      # 355
            "HalBootSMCVideoMode",                  # 356
            "IdexChannelObject",                    # 357
            "HalIsResetOrShutdownPending",          # 358
            "IoMarkIrpMustComplete",                # 359
            "HalInitiateShutdown",                  # 360
            "RtlSnprintf",                          # 361
            "RtlSprintf",                           # 362
            "RtlVsnprintf",                         # 363
            "RtlVsprintf",                          # 364
            "HalEnableSecureTrayEject",             # 365
            "HalWriteSMCScratchRegister",           # 366
            "",                                     # 367
            "",                                     # 368
            "",                                     # 369
            "",                                     # 370
            "",                                     # 371
            "",                                     # 372
            "",                                     # 373
            "MmDbgAllocateMemory",                  # 374
            "MmDbgFreeMemory",                      # 375
            "MmDbgQueryAvailablePages",             # 376
            "MmDbgReleaseAddress",                  # 377
            "MmDbgWriteCheck",                      # 378
        ]

        extern_addrs = list()
        test = dict()
        while True:
            data = self.get_data_var_at(address)
            if data is None:
                break

            import_addr = ctypes.c_uint32(data.value).value
            extern_addrs.append(import_addr)
            import_name = kernel_exports[import_addr & ~0x80000000]

            # Create data ref symbols in proper section
            self.define_auto_symbol_and_var_or_function(
                Symbol(
                    SymbolType.ImportAddressSymbol,
                    address,
                    import_name,
                    namespace="xboxkrnl.exe",
                    binding=SymbolBinding.NoBinding,
                ),
                Type.int(0x4, False),
            )

            test[import_addr] = import_name

            address += 0x4

        extern_addrs.sort()
        # extern_addrs = [int(x, 16) for x in extern_addrs]

        # Map external segment
        self.add_auto_segment(
            extern_addrs[0] - 1,
            extern_addrs[-1] - extern_addrs[0] +  1,
            0,
            0,
            0
        )

        self.add_auto_section(
            ".extern",
            extern_addrs[0] - 1,
            extern_addrs[-1] - extern_addrs[0] + 1,
            SectionSemantics.ExternalSectionSemantics,
        )
        
        # Create external function symbols
        for import_addr, import_name in test.items():
            self.define_auto_symbol_and_var_or_function(
                Symbol(
                    SymbolType.ExternalSymbol,
                    import_addr,
                    import_name,
                    binding=SymbolBinding.NoBinding
                ),
                Type.int(0x4, False),
            )
            self.log(f'Setting up kernel export "{import_name}" at {hex(import_addr)}')
        

        self.log("Done setting up kernel exports!")

    def define_xbe_symbols(self):
        '''
        Download, extract and run the XbSymbolDatabase analyzer tool.
        Create symbols from its analysis.
        '''

        # Setup paths
        release_url = "https://github.com/Cxbx-Reloaded/XbSymbolDatabase/releases/latest/download/XbSymbolDatabase.zip"
        analyzer_zip_filename = pathlib.Path(release_url).name
        current_file_filepath = str(pathlib.Path(__file__).parent.resolve())
        download_filepath = os.path.join(current_file_filepath, analyzer_zip_filename)
        extract_path = os.path.join(current_file_filepath, pathlib.Path(download_filepath).stem)

        # Get correct filepath for host
        os_plat = platform.system()
        analyzer_tool_name = "XbSymbolDatabaseCLI"
        analyzer_tool_filepath = str()
        if os_plat == "Windows":
            # Analyzer tool supports 32-bit hosts but Binja does not so we won't bother checking here
            analyzer_tool_filepath = (
                os.path.join("win_x64/bin/", analyzer_tool_name + ".exe")
            )
        elif os_plat == "Linux":
            analyzer_tool_filepath = (
                os.path.join("linux_x64/bin/", analyzer_tool_name)
            )
        elif os_plat == "Darwin":
            analyzer_tool_filepath = (
                os.path.join("macos_x64/bin/", analyzer_tool_name)
            )

        # Get version string to check for an update
        try:
            release_version = pathlib.Path(requests.get(os.path.dirname(release_url)).url).name
            db_version_file = os.path.join(current_file_filepath, "xbe_analyzer_ver")

            # Get version string of local database tool, if previously downloaded
            if os.path.exists(extract_path):
                with open(db_version_file, "r") as file_obj:
                    current_version = file_obj.readline()

            # Download and extract if symbol analyzer doesn't already exist
            # or if release versions differ, download the latest update
            if not os.path.exists(extract_path) or release_version != current_version:
                self.log(f"Downloading XbSymbolDatabase analyzer")
                try:
                    request_obj = requests.get(release_url, allow_redirects=True)
                except requests.exceptions.RequestException as e:
                    self.log(
                        "Unable to download XbSymbolDatabase analyzer: " + str(e), error=True
                    )
                    return

                # Write version to file
                with open(db_version_file, "w") as file_obj:
                    file_obj.write(release_version)

                # Write analyzer archive
                with open(download_filepath, "wb") as file_obj:
                    file_obj.write(request_obj.content)

                # Extract analyzer archive
                with ZipFile(download_filepath, "r") as zip_obj:
                    zip_obj.extract(analyzer_tool_filepath, extract_path)

        except requests.exceptions.RequestException as e:
            self.log(
                "Unable to reach XbSymbolDatabase GitHub release: " + str(e), error=True
            )

        analyzer_tool_filepath = os.path.join(extract_path, analyzer_tool_filepath)
        if os.path.exists(analyzer_tool_filepath):
            # Get current binary filepath
            xbe_filepath = self.file.original_filename

            # Make symbol analyzer executable
            st = os.stat(analyzer_tool_filepath)
            os.chmod(analyzer_tool_filepath, st.st_mode | stat.S_IEXEC)

            self.log("Running XbSymbolDatabase analyzer.")
            output = subprocess.run(
                [analyzer_tool_filepath, xbe_filepath], capture_output=True
            )

            # Parse analyzer output
            # Format is: function_name = function_address
            output_split = output.stdout.splitlines()
            for line in output_split:
                symbol_and_address = line.split(b'=')
                mangled_symbol = symbol_and_address[0].strip().decode()
                demangled_namespace, demangled_symbol = mangled_symbol.split("__", 1)

                address = int(symbol_and_address[1].decode(), 16)

                # If a symbol is detected in an invalid segment it is likely a false-positive
                if self.get_segment_at(address) is None:
                    pass

                self.log(f'Found "{demangled_symbol}" at {hex(address)}. Creating label...')

                symbol_type = SymbolType.FunctionSymbol

                # Code sections can contain data and some data symbols may erroneously
                # get marked as code symbols. This is a dumb way to mark data vars.
                if "g_" in demangled_symbol:
                    symbol_type = SymbolType.DataSymbol

                self.define_auto_symbol(
                    Symbol(
                        symbol_type,
                        address,
                        demangled_symbol,
                        namespace=demangled_namespace,
                    )
                )

            self.log("Done adding symbols from XbSymbolDatabase")
            return
        
        self.log("XbSymbolDatabase analyzer not found. Skipping symbol resolution.", error=True)

    def init(self):
        self.arch = Architecture["x86"]
        self.platform = self.arch.standalone_platform

        # After Binja has completed its analysis we do our own
        self.add_analysis_completion_event(self.on_complete)

        xbe_image_header_name = "XBE_IMAGE_HEADER"
        with StructureBuilder.builder(self.raw, xbe_image_header_name) as xbe_image_header:
            xbe_image_header.packed = True
            xbe_image_header.append(Type.array(Type.char(), 0x4), "magic")
            xbe_image_header.append(Type.array(Type.char(), 0x100), "Signature")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "ImageBase"
            )
            xbe_image_header.append(Type.int(0x4, False), "SizeOfHeaders")
            xbe_image_header.append(Type.int(0x4, False), "SizeOfImage")
            xbe_image_header.append(Type.int(0x4, False), "SizeOfImageHeader")
            xbe_image_header.append(Type.int(0x4, False), "TimeDataStamp")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "CertificateHeader"
            )
            xbe_image_header.append(Type.int(0x4, False), "NumberOfSections")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PointerToSectionTable"
            )
            xbe_image_header.append(Type.int(0x4, False), "InitFlags")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "AddressOfEntryPoint"
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PointerToTlsDirectory"
            )
            xbe_image_header.append(Type.int(0x4, False), "SizeOfStack")
            xbe_image_header.append(Type.int(0x4, False), "SizeOfHeapReserve")
            xbe_image_header.append(Type.int(0x4, False), "SizeOfHeapCommit")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PeImageBase"
            )
            xbe_image_header.append(Type.int(0x4, False), "PeSizeOfImage")
            xbe_image_header.append(Type.int(0x4, False), "PeImageChecksum")
            xbe_image_header.append(Type.int(0x4, False), "PeTimeDateStamp")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PeDebugPath"
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PeDebugFilename"
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PeDebugFilenameUnicode"
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "PointerToKernelThunkTable",
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "PointerToDebugImportTable",
            )
            xbe_image_header.append(Type.int(0x4, False), "NumberOfLibraries")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PointerToLibraries"
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PointerToKernelLibrary"
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PointerXapiToLibrary"
            )
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "PointerToLogoBitmap"
            )
            xbe_image_header.append(Type.int(0x4, False), "SizeOfLogoBitmap")

            self.raw.define_data_var(0x0, xbe_image_header, xbe_image_header_name)
            
        image_header_raw = self.raw.get_data_var_at(0x0)
        ImageBase = image_header_raw.value["ImageBase"]
        SizeOfHeaders = image_header_raw.value["SizeOfHeaders"]
        SizeOfImageHeader = image_header_raw.value["SizeOfImageHeader"]

        # Unscramble entry point
        AddressOfEntryPoint = image_header_raw.value["AddressOfEntryPoint"]
        is_debug = False
        ENTRY_DEBUG = 0x94859D4B
        ENTRY_RETAIL = 0xA8FC57AB
        entry_point = AddressOfEntryPoint ^ ENTRY_DEBUG
        if entry_point < 0x4000000:
            is_debug = True
        else:
            entry_point = AddressOfEntryPoint ^ ENTRY_RETAIL
        self.add_entry_point(entry_point)

        PointerToKernelThunkTable = image_header_raw.value["PointerToKernelThunkTable"]
        KTHUNK_DEBUG = 0xEFB1F152
        KTHUNK_RETAIL = 0x5B6D40B6
        self.kernel_thunk_table_addr = PointerToKernelThunkTable ^ KTHUNK_RETAIL
        if is_debug:
            self.kernel_thunk_table_addr = PointerToKernelThunkTable ^ KTHUNK_DEBUG

        self.add_auto_segment(
            ImageBase, SizeOfHeaders, 0x0, SizeOfHeaders, SegmentFlag.SegmentReadable
        )
        self.add_auto_section(
            "headers",
            0x0,
            len(xbe_image_header),
            SectionSemantics.ReadOnlyDataSectionSemantics,
        )

        if SizeOfImageHeader >= 0x180:
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "PointerToFeatureLibraries",
            )
            xbe_image_header.append(Type.int(0x4, False), "NumberOfFeatureLibraries")
        if SizeOfImageHeader >= 0x184:
            xbe_image_header.append(Type.int(0x4, False), "DebugInfo")

        self.define_type(Type.generate_auto_type_id("xbe", xbe_image_header_name), xbe_image_header_name, xbe_image_header)
        self.define_data_var(ImageBase, self.types[xbe_image_header_name], xbe_image_header_name)

        image_header = self.get_data_var_at(ImageBase)
        certificate_address = image_header.value["CertificateHeader"]

        xbe_certificate_header_name = "XBE_CERTIFICATE_HEADER"
        with StructureBuilder.builder(
            self.raw, xbe_certificate_header_name
        ) as xbe_certificate_header:
            xbe_certificate_header.packed = True
            xbe_certificate_header.append(Type.int(0x4, False), "SizeOfHeader")
            xbe_certificate_header.append(Type.int(0x4, False), "TimeDateStamp")
            xbe_certificate_header.append(Type.int(0x4, False), "TitleID")
            xbe_certificate_header.append(
                Type.array(Type.wide_char(0x2), 0x28), "TitleName"
            )
            xbe_certificate_header.append(
                Type.array(Type.char(), 0x40), "AlternativeTitleIDs"
            )
            xbe_certificate_header.append(Type.int(0x4, False), "AllowedMedia")
            xbe_certificate_header.append(Type.int(0x4, False), "GameRegion")
            xbe_certificate_header.append(Type.int(0x4, False), "GameRatings")
            xbe_certificate_header.append(Type.int(0x4, False), "DiskNumber")
            xbe_certificate_header.append(Type.int(0x4, False), "Version")
            xbe_certificate_header.append(Type.array(Type.char(), 0x10), "LANKey")
            xbe_certificate_header.append(Type.array(Type.char(), 0x10), "SignatureKey")
            xbe_certificate_header.append(
                Type.array(Type.char(), 0x100), "AlternativeSignatureKey"
            )

            self.define_data_var(
                certificate_address,
                xbe_certificate_header,
                xbe_certificate_header_name,
            )

        certificate_struct_raw = self.get_data_var_at(certificate_address)
        SizeOfHeader = certificate_struct_raw.value["SizeOfHeader"]
        if SizeOfHeader >= 0x1D4:
            xbe_certificate_header.append(
                Type.int(0x4, False), "OriginalCertificateSize"
            )
        if SizeOfHeader >= 0x1D8:
            xbe_certificate_header.append(Type.int(0x4, False), "OnlineServiceID")
        if SizeOfHeader >= 0x1DC:
            xbe_certificate_header.append(Type.int(0x4, False), "SecurityFlags")
        if SizeOfHeader >= 0x1EC:
            xbe_certificate_header.append(
                Type.array(Type.char(), 0x10), "CodeEncryptionKey"
            )
        
        self.define_type(Type.generate_auto_type_id("xbe", xbe_certificate_header_name), xbe_certificate_header_name, xbe_certificate_header)
        self.define_data_var(certificate_address, self.types[xbe_certificate_header_name], xbe_certificate_header_name)

        with StructureBuilder.builder(
            self.raw, "XBE_SECTION_HEADER"
        ) as xbe_section_header:
            xbe_section_header.packed = True
            xbe_section_header.append(Type.int(0x4, False), "Flags")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "VirtualAddress"
            )
            xbe_section_header.append(Type.int(0x4, False), "VirtualSize")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "RawAddress"
            )
            xbe_section_header.append(Type.int(0x4, False), "RawSize")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.char()), "SectionName"
            )
            xbe_section_header.append(Type.int(0x4, False), "SectionReferenceCount")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "HeadReferenceCount",
            )
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "TailReferenceCount",
            )
            xbe_section_header.append(Type.array(Type.char(), 0x14), "SectionDigest")

        NumberOfSections = image_header.value["NumberOfSections"]
        PointerToSectionTable = image_header.value["PointerToSectionTable"]
        
        self.define_type(Type.generate_auto_type_id("xbe", "XBE_SECTION_HEADER"), "XBE_SECTION_HEADER", xbe_section_header)
        xbe_section_header_list = Type.array(self.types["XBE_SECTION_HEADER"], NumberOfSections)

        self.define_data_var(
            PointerToSectionTable,
            xbe_section_header_list,
            "XBE_SECTION_HEADER",
        )

        FLAG_WRITABLE = 0x00000001
        FLAG_PRELOAD = 0x00000002
        FLAG_EXECUTABLE = 0x00000004
        FLAG_INSERTED_FILE = 0x00000008
        FLAG_HEAD_PAGE_READ_ONLY = 0x00000010
        FLAG_TAIL_PAGE_READ_ONLY = 0x00000020

        readable = SegmentFlag.SegmentReadable
        section_semantics = SectionSemantics.DefaultSectionSemantics

        xbe_sections = self.get_data_var_at(PointerToSectionTable)
        for section in xbe_sections:
            VirtualAddress = section.value["VirtualAddress"]
            VirtualSize = section.value["VirtualSize"]
            RawAddress = section.value["RawAddress"]
            RawSize = section.value["RawSize"]

            Flags = section.value["Flags"]

            writable = 0
            executable = 0
            code = 0
            data = 0
            
            if Flags & FLAG_WRITABLE:
                writable = SegmentFlag.SegmentWritable
            if Flags & FLAG_EXECUTABLE:
                executable = SegmentFlag.SegmentExecutable
                code = SegmentFlag.SegmentContainsCode
                section_semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
            if (Flags & FLAG_WRITABLE) == 0 and (
                Flags & FLAG_EXECUTABLE
            ) == 0:
                data = SegmentFlag.SegmentContainsData
                section_semantics = SectionSemantics.ReadOnlyDataSectionSemantics


            # Not sure how out of hand we should get here. Plenty of other sections
            # specific to particular binaries that could be accounted for here
            SectionName = section.value["SectionName"]
            SectionName = self.get_ascii_string_at(SectionName, min_length=0)
            if str(SectionName) == ".rdata":
                section_semantics = SectionSemantics.ReadOnlyDataSectionSemantics
                data = SegmentFlag.SegmentContainsData
                code = 0
            elif ".data" in str(SectionName):
                section_semantics = SectionSemantics.ReadWriteDataSectionSemantics
                data = SegmentFlag.SegmentContainsData
                code = 0

            flags = readable | writable | executable | code | data

            self.add_auto_segment(
                VirtualAddress,
                VirtualSize,
                RawAddress,
                RawSize,
                flags,
            )

            self.add_auto_section(
                SectionName.value,
                VirtualAddress,
                VirtualSize,
                section_semantics,
            )

        with StructureBuilder.builder(
            self.raw, "XBE_LIBRARY_VERSION"
        ) as xbe_library_version:
            xbe_library_version.packed = True
            xbe_library_version.append(Type.array(Type.char(), 0x8), "LibraryName")
            xbe_library_version.append(Type.int(0x2, False), "MajorVersion")
            xbe_library_version.append(Type.int(0x2, False), "MinorVersion")
            xbe_library_version.append(Type.int(0x2, False), "BuildVersion")
            xbe_library_version.append(Type.int(0x2, False), "LibraryFlags")

        NumberOfLibraries = image_header.value["NumberOfLibraries"]

        self.define_type(Type.generate_auto_type_id("xbe", "XBE_LIBRARY_VERSION"), "XBE_LIBRARY_VERSION", xbe_library_version)
        xbe_library_version_list = Type.array(self.types["XBE_LIBRARY_VERSION"], NumberOfLibraries)

        PointerToLibraries = image_header.value["PointerToLibraries"]
        self.define_data_var(
            PointerToLibraries,
            xbe_library_version_list,
            "XBE_LIBRARY_VERSION",
        )

        with StructureBuilder.builder(
            self.raw, "IMAGE_TLS_DIRECTORY_32"
        ) as image_tls_directory:
            image_tls_directory.packed = True
            image_tls_directory.append(Type.int(0x4, False), "StartAddressOfRawData")
            image_tls_directory.append(Type.int(0x4, False), "EndAddressOfRawData")
            image_tls_directory.append(Type.int(0x4, False), "AddressOfIndex")
            image_tls_directory.append(Type.int(0x4, False), "AddressOfCallbacks")
            image_tls_directory.append(Type.int(0x4, False), "SizeOfZeroFill")
            image_tls_directory.append(Type.int(0x4, False), "Characteristics")

        xbe_tls_sz = len(image_tls_directory)
        PointerToTlsDirectory = image_header.value["PointerToTlsDirectory"]
        self.add_auto_segment(
            PointerToTlsDirectory,
            xbe_tls_sz,
            PointerToTlsDirectory - ImageBase,
            xbe_tls_sz,
            SegmentFlag.SegmentReadable,
        )
        
        self.define_type(Type.generate_auto_type_id("xbe", "IMAGE_TLS_DIRECTORY_32"), "IMAGE_TLS_DIRECTORY_32", image_tls_directory)
        self.define_data_var(
            PointerToTlsDirectory,
            self.types["IMAGE_TLS_DIRECTORY_32"],
            "IMAGE_TLS_DIRECTORY_32",
        )

        return True
