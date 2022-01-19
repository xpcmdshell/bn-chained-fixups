#!/usr/bin/env python3

from binaryninja import BinaryView, Architecture
import struct

# Some useful constants
LC_REQ_DYLD = 0x80000000
LC_DYLD_CHAINED_FIXUPS = LC_REQ_DYLD | 0x34
MH_KEXT_BUNDLE = 0x0000000B

# Read a 32 bit integer at the specified address
def read32(addr: int, bv: BinaryView):
    return int.from_bytes(bv.read(addr, 4), "little")


# Read a 64 bit integer at the specified address
def read64(addr: int, bv: BinaryView):
    return int.from_bytes(bv.read(addr, 8), "little")


# Quick check to see if the bv contains an LC_DYLD_CHAINED_FIXUPS
# load command.
def contains_dyld_fixups(bv: BinaryView):
    if bv.arch != Architecture["aarch64"]:
        return False
    fixups_addr = get_fixups_addr(bv)
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
}
"""

# Define necessary types
def setup_types(bv: BinaryView):
    typs = bv.parse_types_from_string(CHAINED_FIXUP_HDR)
    for name in typs.types:
        bv.define_user_type(name, typs.types[name])


# Locate the start of the fixup metadata (a DYLD_CHAINED_FIXUPS_HEADER struct)
def get_fixups_addr(bv: BinaryView):
    macho_hdr = bv.typed_data_accessor(bv.start, bv.types["mach_header_64"])
    # Currently only supports kext bundles, kernel may require other fixes? untested
    if macho_hdr["filetype"].value != MH_KEXT_BUNDLE:
        print("blah")
        return None
    fixup_hdr_addr = None
    load_command_offset = bv.types["mach_header_64"].width
    for _ in range(macho_hdr["ncmds"].value):
        lc = bv.typed_data_accessor(
            bv.start + load_command_offset, bv.types["load_command"]
        )
        if lc["cmd"].value == LC_DYLD_CHAINED_FIXUPS:
            lc_fixup = bv.typed_data_accessor(
                bv.start + load_command_offset, bv.types["linkedit_data"]
            )
            fixup_hdr_addr = bv.start + lc_fixup["dataoff"].value
            break
        load_command_offset += lc["cmdsize"].value

    return fixup_hdr_addr


# Apply fixups from LC_DYLD_CHAINED_FIXUPS to the current bv
def apply_fixups(bv: BinaryView):
    # Set up the necessary types. If they're already defined, just move on
    try:
        setup_types(bv)
    except Exception:
        pass
    # Get the location of the start of the fixups metadata
    fixup_hdr_addr = get_fixups_addr(bv)
    if fixup_hdr_addr is None:
        print("[-] Does not contain LC_DYLD_CHAINED_FIXUPS")
        return

    print(f"[*] Fixup header at = {hex(fixup_hdr_addr)} ")
    fixup_hdr = bv.typed_data_accessor(
        fixup_hdr_addr, bv.types["dyld_chained_fixups_header"]
    )

    segs_addr = fixup_hdr_addr + fixup_hdr["starts_offset"].value

    # peek the segs count
    seg_count = read32(segs_addr, bv)
    print(
        f"[*] DYLD_CHAINED_STARTS_IN_IMAGE at = {hex(segs_addr)}, with {hex(seg_count)} segments"
    )

    # start of imports table
    imports_addr = fixup_hdr_addr + fixup_hdr["imports_offset"].value
    print(f"[*] Imports table at {hex(imports_addr)} ")

    # start of symbol table
    syms_addr = fixup_hdr_addr + fixup_hdr["symbols_offset"].value
    print(f"[*] Symbols table at {hex(syms_addr)}")

    segs = []
    # We wanna read in the the array of offsets from the seg_info_offset
    # field of dyld_chained_starts_in_image
    for i in range(seg_count):
        s = read32((i * 4) + segs_addr + 4, bv)  # read
        segs.append(s)

    for i in range(seg_count):
        # No fixups in this segment, skip
        if segs[i] == 0:
            continue

        starts_addr = (
            segs_addr + segs[i]
        )  # follow the current segment offset from the start of the segments list

        # read the current dyld_chained_starts_in_segment bytes
        starts_in_segment_data = bv.read(starts_addr, 24)

        # unpack those bytes into a nice list of fields
        starts_in_segment = struct.unpack("<IHHQIHH", starts_in_segment_data)

        # Give them nice names for my brain cells lol
        page_count = starts_in_segment[5]
        page_size = starts_in_segment[1]
        segment_offset = starts_in_segment[3]

        # read the array of page_starts from dyld_chained_starts_in_segment
        page_starts_data = bv.read(starts_addr + 22, page_count * 2)
        page_starts = struct.unpack("<" + ("H" * page_count), page_starts_data)

        # handle each page start
        for (j, start) in enumerate(page_starts):
            # DYLD_CHAINED_PTR_START_NONE, denotes a page with no fixups
            if start == 0xFFFF:
                continue

            chain_entry_addr = bv.start + segment_offset + (j * page_size) + start
            print(f"[*] Chain start at {hex(chain_entry_addr)}")

            j += 1
            while True:
                content = read64(chain_entry_addr, bv)
                offset = content & 0xFFFFFFFF
                nxt = (content >> 51) & 2047
                bind = (content >> 62) & 1

                # handle symbol binding
                if bind == 1:
                    # In the binding case, `offset` is an entry in the imports table
                    # The import entry is a DYLD_CHAINED_IMPORT. The low 23 bits contain
                    # the offset into the symbol table to lookup (DYLD_CHAINED_IMPORT.name_offset)
                    import_entry = read32(imports_addr + offset * 4, bv)
                    sym_name_offset = import_entry >> 9
                    sym_name_addr = syms_addr + sym_name_offset

                    # Get the symbol name at the desginated address
                    sym_name = bv.get_ascii_string_at(
                        sym_name_addr, require_cstring=True
                    )
                    if sym_name is not None:
                        sym_name = sym_name.value
                    else:
                        print("[-] Symbol name not found, malformed or bug?")
                        return

                    print(f"[*] Binding {sym_name} at {hex(chain_entry_addr)}")
                    sym_ref: CoreSymbol = bv.get_symbol_by_raw_name(sym_name)
                    if not sym_ref:
                        print(
                            f"[-] Could not get reference to symbol named {sym_name} (malformed or bug?)"
                        )
                        return

                    # Replace it with the address of the symbol we just found
                    fixed_bytes = struct.pack("<Q", sym_ref.address)
                    bv.write(
                        chain_entry_addr,
                        fixed_bytes,
                        except_on_relocation=False,
                    )

                else:
                    # Nothing to bind
                    print(f"[*] Rebasing pointer at {hex(chain_entry_addr)}")
                    target = bv.start + offset
                    fixed_bytes = struct.pack("<Q", target)
                    bv.write(
                        chain_entry_addr,
                        fixed_bytes,
                        except_on_relocation=False,
                    )

                # next tells us how many u32 until the next chain entry
                skip = nxt * 4
                chain_entry_addr += skip
                # if skip == 0, chain is done
                if skip == 0:
                    break
