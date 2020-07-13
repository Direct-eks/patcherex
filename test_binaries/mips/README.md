## patcherex
the work for patcherex on mips is available in:
[this link](https://github.com/Direct-eks/patcherex/tree/mips/test_binaries/mips)
(forked from patcherex)

Checkout "mips" branch

The code is not complete and is not working, only some test cases were written
in /tests/test_detourbackend_mips.py, and source code for the tests are available
in /test_binaries/mips/*

## Explainations on usage of binaries
"test" is the original binary used to test patcherex on mips.
It is compiled form test_printf.c.
test_prinf.s is compiled from test_prinf.c for later modification.

There are assembler syntax sugar in mips (e.g la label), so to keep things simple they are avoided.

Since Ghidra seems not working as expected on mips binary, the following things are
done to make sure the added patch works fine:

    1. All test patches are originally written in .s files with patches applied in assembly level, and .s will be compiled to binary and compared with orginal "test" binary to check if there are other unexpected changes done by the compiler.

    2. Since the current data patching in mips (and all other architectures) adds the data to the end of the binary, so all data patching in .s files are only used for verification purposes. The actual test cases that involve data patching written in test_detourbackend_mips.py will be different.

The comments above each test case and comments in .s files should be enough for self explaining.

The binaries test1 test2 ... are compieled from .s files with corresponding names, so, as explained
above, their data patching position in the binaries are different from what patcherex would done.