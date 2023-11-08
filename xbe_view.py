from binaryninja import (
    Architecture,
    BinaryView,
    Endianness,
    SegmentFlag,
    StructureBuilder,
    Type,
    SegmentFlag,
    SectionSemantics,
)


class XBELoader(BinaryView):
    name = "XBE"
    long_name = name
    magic = b"XBEH"

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

    def init(self):
        self.arch = Architecture["x86"]
        self.platform = self.arch.standalone_platform

        with StructureBuilder.builder(self.raw, "XBE_IMAGE_HEADER") as xbe_image_header:
            xbe_image_header.packed = True
            xbe_image_header.append(Type.array(Type.char(), 0x4), "magic")
            xbe_image_header.append(Type.array(Type.char(), 0x100), "Signature")
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "ImageBase"
            )
            xbe_image_header.append(Type.int(0x4, False), "SizeOfHeaders")
            xbe_image_header.append(Type.int(0x4, False), "SizeOfImage")
            xbe_image_header.append(Type.int(0x4, False), "SizeOfImageHeaders")
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

            self.raw.define_data_var(0x0, xbe_image_header, "XBE_IMAGE_HEADER")

        image_header_raw = self.raw.get_data_var_at(0x0)
        ImageBase = image_header_raw.value["ImageBase"]
        SizeOfHeaders = image_header_raw.value["SizeOfHeaders"]

        xbe_hdr_len = len(xbe_image_header)
        self.add_auto_segment(
            ImageBase, SizeOfHeaders, 0x0, SizeOfHeaders, SegmentFlag.SegmentReadable
        )
        self.add_auto_section(
            "headers",
            0x0,
            xbe_hdr_len,
            SectionSemantics.ReadOnlyDataSectionSemantics,
        )

        if SizeOfHeaders >= 0x100:
            xbe_image_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "PointerToFeatureLibraries",
            )
            xbe_image_header.append(Type.int(0x4, False), "NumberOfFeatureLibraries")
        if SizeOfHeaders >= 0x184:
            xbe_image_header.append(Type.int(0x4, False), "DebugInfo")

        self.define_data_var(ImageBase, xbe_image_header, "XBE_IMAGE_HEADER")

        image_header = self.get_data_var_at(ImageBase)
        certificate_address = image_header.value["CertificateHeader"]

        with StructureBuilder.builder(
            self.raw, "XBE_CERTIFICATE_HEADER"
        ) as xbe_certificate_header:
            xbe_certificate_header.packed = True
            xbe_certificate_header.append(Type.int(4, False), "SizeOfHeader")
            xbe_certificate_header.append(Type.int(4, False), "TimeDateStamp")
            xbe_certificate_header.append(Type.int(4, False), "TitleID")
            xbe_certificate_header.append(Type.array(Type.wide_char(0x2), 0x28), "TitleName")
            xbe_certificate_header.append(Type.array(Type.char(), 0x40), "AlternativeTitleIDs")
            xbe_certificate_header.append(Type.int(4, False), "AllowedMedia")
            xbe_certificate_header.append(Type.int(4, False), "GameRegion")
            xbe_certificate_header.append(Type.int(4, False), "GameRatings")
            xbe_certificate_header.append(Type.int(4, False), "DiskNumber")
            xbe_certificate_header.append(Type.int(4, False), "Version")
            xbe_certificate_header.append(Type.array(Type.char(), 0x10), "LANKey")
            xbe_certificate_header.append(Type.array(Type.char(), 0x10), "SignatureKey")
            xbe_certificate_header.append(
                Type.array(Type.char(), 0x100), "AlternativeSignatureKey"
            )

            self.raw.define_data_var(
                certificate_address,
                xbe_certificate_header,
                "XBE_CERTIFICATE_HEADER",
            )

        certificate_struct_raw = self.raw.get_data_var_at(certificate_address)
        SizeOfHeader = certificate_struct_raw["SizeOfHeader"]
        if SizeOfHeader.value >= 0x184:
            xbe_certificate_header.append(Type.int(0x4, False), "OriginalCertificateSize")
        if SizeOfHeader.value >= 0x1D8:
            xbe_certificate_header.append(Type.int(0x4, False), "OnlineServiceID")
        if SizeOfHeader.value >= 0x1DC:
            xbe_certificate_header.append(Type.int(0x4, False), "SecurityFlags")
        if SizeOfHeader.value >= 0x1EC:
            xbe_certificate_header.append(Type.array(Type.char(), 0x10), "CodeEncryptionKey")
        self.define_data_var(
            certificate_address,
            xbe_certificate_header,
            "XBE_CERTIFICATE_HEADER",
        )

        with StructureBuilder.builder(
            self.raw, "XBE_SECTION_HEADER"
        ) as xbe_section_header:
            xbe_section_header.packed = True
            xbe_section_header.append(Type.int(4, False), "Flags")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "VirtualAddress"
            )
            xbe_section_header.append(Type.int(4, False), "VirtualSize")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)), "RawAddress"
            )
            xbe_section_header.append(Type.int(4, False), "RawSize")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.char()), "SectionName"
            )
            xbe_section_header.append(Type.int(4, False), "SectionReferenceCount")
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "HeadReferenceCount",
            )
            xbe_section_header.append(
                Type.pointer(self.arch, Type.int(0x4, False)),
                "TailReferenceCount",
            )
            xbe_section_header.append(Type.array(Type.char(), 0x14), "SectionDigest")

        # Define xbe section header
        NumberOfSections = image_header.value["NumberOfSections"]
        PointerToSectionTable = image_header.value["PointerToSectionTable"]
        xbe_section_header_list = Type.array(xbe_section_header, NumberOfSections)
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

        # Map sections
        xbe_sections = self.get_data_var_at(PointerToSectionTable)
        for section in xbe_sections:
            VirtualAddress = section.value["VirtualAddress"]
            VirtualSize = section.value["VirtualSize"]
            RawAddress = section.value["RawAddress"]
            RawSize = section.value["RawSize"]

            readable = SegmentFlag.SegmentReadable
            writable = 0
            executable = 0
            code = 0
            data = 0
            section_flags = section.value["Flags"]
            section_semantics = SectionSemantics.DefaultSectionSemantics

            if section_flags & FLAG_WRITABLE:
                writable = SegmentFlag.SegmentWritable
            if section_flags & FLAG_EXECUTABLE:
                executable = SegmentFlag.SegmentExecutable
                code = SegmentFlag.SegmentContainsCode
                section_semantics = SectionSemantics.ReadOnlyCodeSectionSemantics
            elif (section_flags & FLAG_WRITABLE) == 0 and (
                section_flags & FLAG_EXECUTABLE
            ) == 0:
                data = SegmentFlag.SegmentContainsData
                section_semantics = SectionSemantics.ReadOnlyDataSectionSemantics

            flags = readable | writable | executable | code | data

            self.add_auto_segment(
                VirtualAddress,
                VirtualSize,
                RawAddress,
                RawSize,
                flags,
            )

            SectionName = section.value["SectionName"]
            SectionName = self.get_ascii_string_at(SectionName, min_length=0)
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
            xbe_library_version.append(Type.int(2, False), "MajorVersion")
            xbe_library_version.append(Type.int(2, False), "MinorVersion")
            xbe_library_version.append(Type.int(2, False), "BuildVersion")
            xbe_library_version.append(Type.int(2, False), "LibraryFlags")

        NumberOfLibraries = image_header.value["NumberOfLibraries"]

        xbe_library_version_list = Type.array(xbe_library_version, NumberOfLibraries)

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
            image_tls_directory.append(Type.int(4, False), "StartAddressOfRawData")
            image_tls_directory.append(Type.int(4, False), "EndAddressOfRawData")
            image_tls_directory.append(Type.int(4, False), "AddressOfIndex")
            image_tls_directory.append(Type.int(4, False), "AddressOfCallbacks")
            image_tls_directory.append(Type.int(4, False), "SizeOfZeroFill")
            image_tls_directory.append(Type.int(4, False), "Characteristics")

        xbe_tls_sz = len(image_tls_directory)
        PointerToTlsDirectory = image_header.value["PointerToTlsDirectory"]
        self.add_auto_segment(
            PointerToTlsDirectory,
            xbe_tls_sz,
            PointerToTlsDirectory - ImageBase,
            xbe_tls_sz,
            SegmentFlag.SegmentReadable,
        )
        self.define_data_var(
            PointerToTlsDirectory,
            image_tls_directory,
            "IMAGE_TLS_DIRECTORY_32",
        )

        return True
