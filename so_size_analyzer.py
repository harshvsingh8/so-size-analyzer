#! /usr/bin/env python
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection, StringTableSection

class Arch(object):
    ARM_32 = "ARM_32"
    ARM_64 = "ARM_64"
    X86 = "X86"
    X86_64 = "X86_64"
    UNKNOWN = "UNKNOWN"

# Remember if we showed the warning that c++filt isn't available.
demangle_warning_shown = False

def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx:min(ndx + n, l)]

def demangle(names):
    """
    Invokes c++filt command-line tool to demangle the C++ symbols into something readable. If not available,
    it'll do nothing and just return the input names.
    """
    try:
        demangled = []
        batchSize = 50
        for batchedNames in batch(names, batchSize):
            args = ['c++filt', '-n']
            args.extend(batchedNames)
            pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            batchedDemangled = stdout.decode('utf-8').rstrip().split("\n")
            demangled.extend(batchedDemangled)
            
        assert len(demangled) == len(names)
        return demangled[:-1]
    except OSError as e:
        global demangle_warning_shown
        if not demangle_warning_shown:
            print("\n == Couldn't run c++filt tool, " + str(e)  + "\n")
            demangle_warning_shown = True
        return names
    
def sizeof_fmt(num, suffix='B'):
    """
    Formats passed integer number into human readable filesize, e.g. 15000000B into 15MiB.
    """
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


class LibraryInfo(object):
    architecture = Arch.UNKNOWN

    total_size = 0
    total_strings = 0
    total_constants = 0

    # This is list of just top symbols
    top_symbols = []

    def __init__(self, filename, symbol_count):
        print("Processing " + filename)
        self._parse_file(filename, symbol_count)
        print("Architecture: " + str(self.architecture) + "\n")
        
    @staticmethod
    def _machine_description(elf_file):
        """
        Determines architecture of the passed-in library file.
        """
        is_64_bit = elf_file.header.e_ident["EI_CLASS"] == "ELFCLASS64"
        arch = Arch.UNKNOWN

        if is_64_bit:
            if elf_file.header.e_machine == "EM_ARM":
                arch = Arch.ARM_64
            elif elf_file.header.e_machine == "EM_386":
                arch = Arch.X86_64
        else:
            if elf_file.header.e_machine == "EM_ARM":
                arch = Arch.ARM_32
            elif elf_file.header.e_machine == "EM_386":
                arch = Arch.X86
        return arch

    def _process_symbol(self, symbols, symbol):
        """
        Handles a single symbol
        """
        self.total_size += symbol.entry.st_size
        if symbol.entry.st_size > 0:
            symbols.append((symbol.name, symbol.entry.st_size))

    def print_symbol_sizes(self):
        """
        Prints top list of symbols
        :return:
        """
        if len(self.top_symbols) == 0:
            return

        demangled_symbols = zip(demangle([symbol for symbol, _ in self.top_symbols]), [size for _, size in self.top_symbols])
        # max_digits = len(str(self.top_symbols[0][1]))
        fmt_string = " " + "{: <" + str(10) + "}" + "  " + "{}"
        for symbol, size in demangled_symbols:
            print(fmt_string.format(sizeof_fmt(size), symbol.rstrip()))

    def print_statistics(self):
        print("Symbol sizes:")
        print("=============")
        self.print_symbol_sizes()
        print("\n")
        print("=================================")
        print("Total size of symbols: " + sizeof_fmt(self.total_size))
        print("Total size of strings: " + sizeof_fmt(self.total_strings))
        print("Total size of constants: " + sizeof_fmt(self.total_constants))
        print("==================================")
        print("Filesize: " + sizeof_fmt(self.total_size + self.total_strings + self.total_constants))
        print("==================================")

    def _parse_file(self, filename, symbol_count):
        """
        Parses the .so library file and determines sizes of all the symbols.
        """
        symbols = []
        with open(filename, 'rb') as file:
            elf_file = ELFFile(file)
            # Identify architecture and bitness
            self.architecture = LibraryInfo._machine_description(elf_file)
            for sect in elf_file.iter_sections():
                if isinstance(sect, SymbolTableSection):
                    for symbol in sect.iter_symbols():
                        self._process_symbol(symbols, symbol)
                elif isinstance(sect, StringTableSection):
                    # Ignore debug string sections, strtab is only present in debug libraries and size of those we're
                    # not interested in.
                    if sect.name == ".strtab":
                        continue
                    self.total_strings += sect.header.sh_size
                elif sect.name == ".rodata":
                    self.total_constants += sect.header.sh_size

        symbols.sort(key=lambda value: value[1], reverse=True)
        self.top_symbols = symbols[:symbol_count]

def process(filename, maxSymbols):
    try:
        library = LibraryInfo(filename, maxSymbols)
        library.print_statistics()
    except KeyboardInterrupt:
        print("Cancelled!")
        sys.exit(-1)

if __name__ == "__main__":
    filename = sys.argv[1]
    maxSymbols = int(sys.argv[2])
    process(filename, maxSymbols)
