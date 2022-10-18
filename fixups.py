#!/usr/bin/env python3

from binaryninja import BinaryView, Architecture
import struct

# Some useful constants
LC_REQ_DYLD = 0x80000000
LC_DYLD_CHAINED_FIXUPS = LC_REQ_DYLD | 0x34
MH_KEXT_BUNDLE = 0x0000000B
MH_EXECUTE = 0x00000002
FAT_MAGIC = 0xBEBAFECA
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007


# Read a 32 bit integer at the specified address
def read32(addr: int, bv: BinaryView):
    return int.from_bytes(bv.read(addr, 4), "little")


# Read a 64 bit integer at the specified address
def read64(addr: int, bv: BinaryView):
    return int.from_bytes(bv.read(addr, 8), "little")


# Read a 32 bit integer at the specified address (big endian)
def read32_be(addr: int, bv: BinaryView):
    return int.from_bytes(bv.read(addr, 4), "big")


# Read a 64 bit integer at the specified address (big endian)
def read64_be(addr: int, bv: BinaryView):
    return int.from_bytes(bv.read(addr, 8), "big")


# Quick check to see if the bv contains an LC_DYLD_CHAINED_FIXUPS
# load command.
def contains_dyld_fixups(bv: BinaryView):
    fixups_addr, _, _ = get_fixups_addr(bv)
    if fixups_addr is None:
        return False
    return True


# Tryna be civilized
CHAINED_FIXUP_HDR = """
struct dyld_chained_fixups_header
{
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};
"""

# Define necessary types
def setup_types(bv: BinaryView):
    typs = bv.parse_types_from_string(CHAINED_FIXUP_HDR)
    for name in typs.types:
        bv.define_user_type(name, typs.types[name])


def is_macho(bv: BinaryView):
    return bv.view_type == "Mach-O"


# Get the start offset of the
def get_arm_slice_start(bv: BinaryView):
    magic = read32(bv.start, bv.file.raw)
    if magic == MH_MAGIC_64:
        # mh_arch = read32(bv.start + 4, bv.file.raw)
        # aarch64 is (not) the only slice type
        return bv.start
    elif magic == FAT_MAGIC:
        n_slices = read32_be(bv.start + 4, bv.file.raw)
        for i in range(n_slices):
            # 20 = sizeof(fat_arch)
            # 8 = sizeof(fat_hdr)
            fat_arch_data = bv.read(bv.start + 8 + (i * 20), 20)
            fat_arch = struct.unpack(">IIIII", fat_arch_data)
            # fat_arch.cputype
            if fat_arch[0] == CPU_TYPE_ARM64 or fat_arch[0] == CPU_TYPE_X86_64:
                # fat_arch.offset
                return bv.start + fat_arch[2]
        return None
    else:
        return None


# Locate the start of the fixup metadata (a DYLD_CHAINED_FIXUPS_HEADER struct)
def get_fixups_addr(bv: BinaryView):
    if not is_macho(bv):
        return (None, None, None)
    read_src = bv.file.raw
    arm_slice_start = get_arm_slice_start(bv.file.raw)
    if arm_slice_start is None:
        return (None, None, None)
    macho_hdr_data = read_src.read(arm_slice_start, 32)
    macho_hdr = struct.unpack("<IIIIIIII", macho_hdr_data)
    fixup_hdr_addr = None

    # sizeof(mach_header_64)
    load_command_offset = 32

    # mach_header_64.ncmds
    for _ in range(macho_hdr[4]):
        lc_hdr_data = read_src.read(arm_slice_start + load_command_offset, 8)
        lc = struct.unpack("<II", lc_hdr_data)
        # load_command.cmd
        if lc[0] == LC_DYLD_CHAINED_FIXUPS:
            lc_fixup = bv.typed_data_accessor(
                arm_slice_start + load_command_offset, bv.types["linkedit_data"]
            )
            # linkedit_data
            lc_fixup_data = read_src.read(arm_slice_start + load_command_offset, 16)
            lc_fixup = struct.unpack("<IIII", lc_fixup_data)

            # linkedit_data.dataoff
            fixup_hdr_addr = arm_slice_start + lc_fixup[2]
            break
        # load_command.cmdsize
        load_command_offset += lc[1]
    return (fixup_hdr_addr, read_src, arm_slice_start)


# Apply fixups from LC_DYLD_CHAINED_FIXUPS to the current bv
def apply_fixups(bv: BinaryView):
    # Set up the necessary types. If they're already defined, just move on
    try:
        setup_types(bv)
    except Exception:
        pass
    # Get the location of the start of the fixups metadata
    fixup_hdr_addr, read_src, arm_slice_start = get_fixups_addr(bv)
    if fixup_hdr_addr is None:
        print("[bn-chained-fixups] [-] Does not contain LC_DYLD_CHAINED_FIXUPS")
        return

    print(f"[bn-chained-fixups] [*] Fixup header at = {hex(fixup_hdr_addr)} ")
    fixup_hdr = read_src.typed_data_accessor(
        fixup_hdr_addr, bv.types["dyld_chained_fixups_header"]
    )

    segs_addr = fixup_hdr_addr + fixup_hdr["starts_offset"].value

    # peek the segs count
    seg_count = read32(segs_addr, read_src)
    print(
        f"[bn-chained-fixups] [*] DYLD_CHAINED_STARTS_IN_IMAGE at = {hex(segs_addr)}, with {hex(seg_count)} segments"
    )

    # start of imports table
    imports_addr = fixup_hdr_addr + fixup_hdr["imports_offset"].value
    print(f"[bn-chained-fixups] [*] Imports table at {hex(imports_addr)} ")

    # start of symbol table
    syms_addr = fixup_hdr_addr + fixup_hdr["symbols_offset"].value
    print(f"[bn-chained-fixups] [*] Symbols table at {hex(syms_addr)}")

    segs = []
    # We wanna read in the the array of offsets from the seg_info_offset
    # field of dyld_chained_starts_in_image
    for i in range(seg_count):
        s = read32((i * 4) + segs_addr + 4, read_src)  # read
        segs.append(s)

    for i in range(seg_count):
        # No fixups in this segment, skip
        if segs[i] == 0:
            continue
        starts_addr = (
            segs_addr + segs[i]
        )  # follow the current segment offset from the start of the segments list

        # read the current dyld_chained_starts_in_segment bytes
        starts_in_segment_data = read_src.read(starts_addr, 24)

        # unpack those bytes into a nice list of fields
        starts_in_segment = struct.unpack("<IHHQIHH", starts_in_segment_data)

        # Give them nice names for my brain cells lol
        page_count = starts_in_segment[5]
        page_size = starts_in_segment[1]
        segment_offset = starts_in_segment[3]
        pointer_type = starts_in_segment[2]

        # read the array of page_starts from dyld_chained_starts_in_segment
        page_starts_data = read_src.read(starts_addr + 22, page_count * 2)
        page_starts = struct.unpack("<" + ("H" * page_count), page_starts_data)

        # handle each page start
        for (j, start) in enumerate(page_starts):
            # DYLD_CHAINED_PTR_START_NONE, denotes a page with no fixups
            if start == 0xFFFF:
                continue

            # The chain entry address is the offset into the raw view
            chain_entry_addr = (
                arm_slice_start + segment_offset + (j * page_size) + start
            )
            print(f"[bn-chained-fixups] [*] Chain start at {hex(chain_entry_addr)}")

            j += 1
            while True:
                content = read64(chain_entry_addr, bv.file.raw)
                offset = content & 0xFFFFFFFF
                nxt = (content >> 51) & 2047
                bind = (content >> 62) & 1

                # handle symbol binding
                if bind == 1:
                    # In the binding case, `offset` is an entry in the imports table
                    # The import entry is a DYLD_CHAINED_IMPORT. The low 23 bits contain
                    # the offset into the symbol table to lookup (DYLD_CHAINED_IMPORT.name_offset)
                    import_entry = read32(imports_addr + offset * 4, bv.file.raw)
                    sym_name_offset = import_entry >> 9
                    sym_name_addr = syms_addr + sym_name_offset

                    # Get the symbol name at the desginated address
                    sym_name = bv.file.raw.get_ascii_string_at(
                        sym_name_addr, require_cstring=True
                    )
                    if sym_name is not None:
                        sym_name = sym_name.value
                    else:
                        print("[bn-chained-fixups] [-] Symbol name not found, malformed or bug?")
                        return

                    print(f"[bn-chained-fixups] [*] Binding {sym_name} at {hex(chain_entry_addr)}")
                    sym_ref: CoreSymbol = bv.get_symbol_by_raw_name(sym_name)
                    if not sym_ref:
                        print(
                            f"[bn-chained-fixups] [-] Could not get reference to symbol named {sym_name}, malformed or bug?"
                        )
                        return

                    # Replace it with the address of the symbol we just found
                    fixed_bytes = struct.pack("<Q", sym_ref.address)
                    bv.write(
                        chain_entry_addr - arm_slice_start,
                        fixed_bytes,
                        except_on_relocation=False,
                    )

                else:
                    # Nothing to bind
                    print(f"[bn-chained-fixups] [*] Rebasing pointer at {hex(chain_entry_addr)}")
                    target = bv.start + offset
                    fixed_bytes = struct.pack("<Q", target)
                    bv.write(
                        chain_entry_addr - arm_slice_start,
                        fixed_bytes,
                        except_on_relocation=False,
                    )

                # next tells us how many u32 until the next chain entry
                skip = nxt * 4
                chain_entry_addr += skip
                # if skip == 0, chain is done
                if skip == 0:
                    break
