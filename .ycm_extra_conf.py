import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

include_dirs = [
    'arch/x86/include',
    'arch/x86/include/generated',
    'arch/x86/include/generated/uapi',
    'arch/x86/include/uapi',
    'include',
    'include/generated/uapi',
    'include/uapi',
]

include_files = [
    'include/linux/kconfig.h',
]

flags = [
    '-D__KERNEL__',
    '-std=gnu89',
    '-xc',
    '-nostdinc',
]

flags_included = False

def Settings( **kwargs ):
    global flags_included
    if not flags_included:
        for idir in include_dirs:
            flags.append('-I' + os.path.join(CURRENT_DIR, idir))
        for ifile in include_files:
            flags.append('-include' + os.path.join(CURRENT_DIR, ifile))
        flags_included = True
    return {
            'flags': flags,
        }
