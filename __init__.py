from binaryninja import *
from .fixups import apply_fixups, contains_dyld_fixups


PluginCommand.register(
    "Apply LC_DYLD_CHAINED_FIXUPS", "", apply_fixups, is_valid=contains_dyld_fixups
)
