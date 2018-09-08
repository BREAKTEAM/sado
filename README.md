# SADOMEM

`sadomem` help researcher in the task of exploitation of memory corruption related bugs.

The idea is that the researcher can perform database like `queries` to get information about the contents and layout of the memory of a program. To perform these queries, `sadomem` exposes several global functions listed bellow:

-   `memoryList`: query current memory segments.
-   `memorySearch`: search for a given value.
-   `memoryRead`: read from a memory address.
-   `memoryWrite`: write to a memory address.
-   `memorySearch_pointer`: search any pointers starting from a given address.

## Usage

    $ sadomem -h
    usage: sadomem [-h] [-V] (-p PROC_PID | -n PROC_NAME | -l) [-d DEVICE]
                   [-m MOD_NAMES]

    Memory Grip.

    optional arguments:
      -h, --help     show this help message and exit
      -V, --version  show program's version number and exit
      -p PROC_PID    Process PID.
      -n PROC_NAME   Process name (follows unix wildcard patterns).
      -l             Display running processes.
      -d DEVICE      Select a device by ID. Specify `list` to get a list of
                     available devices.
      -m MOD_NAMES   Specify zero or more modules that need to be loaded in the
                     target process.

### Attaching to a process by pid

    $ sadomem -p 39718
    Using device Device(id="local", name="Local System", type='local').
    Attaching to process pid `39718`.
    Attaching to process `39718`.

    SADOMEM

    Use help(command_name) to see how to use the command.


    In [1]:

## Getting help while on the REPL loop

Each exported function has a help message defined that can be read by using python's `help` function. Each help messages contains usage examples.

    In [10]: help(memoryRead)
    Help on function memoryRead in module sadomem:

    memoryRead(value_format, address, size=32)
        Examples:
        memoryRead("u8", 0xcafecafe)
        memoryRead("u16", 0xcafecafe)
        memoryRead("u32", 0xcafecafe)
        memoryRead("u64", 0xcafecafe)
        memoryRead("hex", 0xcafecafe, 4)
        memoryRead("bytes", 0xcafecafe, 4)
        memoryRead("BBII", 0xcafecafe)

## Listing memory

**Exported function signature:** `memoryList(protection="---")`

### Listing all segments

To list all the segments present in the target process use the `memoryList` function without an argument:

    In [5]: memoryList()
      0: 0x000000010a4f5000 - 0x000000010a4f6000 (      4096 / 0x00001000) next=0x0000000000000000 r-x
      1: 0x000000010a4f6000 - 0x000000010a4f7000 (      4096 / 0x00001000) next=0x0000000000000000 rw-
      2: 0x000000010a4f7000 - 0x000000010a4fa000 (     12288 / 0x00003000) next=0x0000000000000000 r--
      3: 0x000000010a4fa000 - 0x000000010a4fc000 (      8192 / 0x00002000) next=0x0000000000000000 rw-
      ...

`memoryList` allows a `permission` agument that serves as a match filter, allowing the researcher to filter those segments he is interested in. For instance:

### Executable segments

    In [7]: memoryList("x")
     0: 0x000000010a4f5000 - 0x000000010a4f6000 (      4096 / 0x00001000) next=0x0000000000007000 r-x
     1: 0x000000010a4fd000 - 0x000000010a4fe000 (      4096 / 0x00001000) next=0x000000000000a000 r-x
     2: 0x000000010a508000 - 0x000000010a738000 (   2293760 / 0x00230000) next=0x0000000000037000 r-x
     3: 0x000000010a76f000 - 0x000000010a78c000 (    118784 / 0x0001d000) next=0x0000000000091000 r-x
    ...

### RWX segments

    In [8]: memoryList("rwx")
    0: 0x00007fffe8dac000 - 0x00007fffe8dad000 (      4096 / 0x00001000) next=0x000000000001c000 rwx /private/var/db/dyld/dyld_shared_cache_x86_64h
    1: 0x00007fffe8dc9000 - 0x00007fffe8dca000 (      4096 / 0x00001000) next=0x00000000000bc000 rwx /private/var/db/dyld/dyld_shared_cache_x86_64h
    2: 0x00007fffe8e86000 - 0x00007fffe8e87000 (      4096 / 0x00001000) next=0x0000000000000000 rwx /private/var/db/dyld/dyld_shared_cache_x86_64h

## Searching memory

**Exported function signature:** `memorySearch(value_format, value, out_format="hex", out_size=32)`

### Example search expressions

    memorySearch("u8", 0xca)
    memorySearch("u16", 0xcafe)
    memorySearch("u32", 0xcafedead)
    memorySearch("u64", 0xcafecafecafecafe)
    memorySearch("hex", "ca fe ca fe")
    memorySearch("bytes", "\xca\xfe\xca\xfe")

### Example search

    # Search for the string "CAFE" repeated 8 times.
    In [12]: memorySearch("bytes", "CAFE" * 8)
    Found @ 0x000026412eceeeb0
    00000000: 43 41 46 45 43 41 46 45  43 41 46 45 43 41 46 45  CAFECAFECAFECAFE
    00000010: 43 41 46 45 43 41 46 45  43 41 46 45 43 41 46 45  CAFECAFECAFECAFE
    ...
    Got 203 results.

    # Search for a pointer to the found string.
    In [13]: string_address = 0x000026412eceeeb0
    In [14]: memorySearch("u64", string_address)
    Found @ 0x0000000115f1b6d8
    00000000: B0 EE CE 2E 41 26 00 00  50 01 00 00 E5 E5 E5 E5  ....A&..P.......
    00000010: B8 2B 7C 19 01 00 00 00  00 14 A1 2E 41 26 00 00  .+|.........A&..

## Reading memory

**Exported function signature:** `memoryRead(value_format, address, size=32)`

    # Reading possible object that points to our address.
    In [15]: object_address = 0x0000000115f1b6d8

    # Read a couple QWORDs before the object to see whats there.
    In [16]: memoryRead("hex", object_address - 8 * 4)
    Read @ 0x0000000115f1b6b8
    00000000: B8 2B 7C 19 01 00 00 00  40 14 A1 2E 41 26 00 00  .+|.....@...A&..
    00000010: 40 00 00 00 E5 E5 E5 E5  B8 2B 7C 19 01 00 00 00  @........+|.....

    # Looks like the format is pointer|pointer|uint32|uint32|pointer
    In [17]: memoryRead("PPIIP", object_address - 8 * 4)
    Read @ 0x0000000115f1b6b8
    0x00000001197c2bb8 0x000026412ea11440 0x00000040 0xe5e5e5e5 0x00000001197c2bb8

## Searching for pointers

**Exported function signature:** `memorySearchPointer(address, protection)`

The main usage of this function is to search for things to overwrite. Basically one can search for pointers to things that may be useful while exploiting bugs. Two cases come to mind:

-   Pointers to data (to create infoleaks)
-   Pointers to code (to get code execution)

### Example: looking for the position of a function pointer to overwrite.

    In [18]: memorySearch_pointer(object_address, "x")
    Found pointer @ 0x0000000115f36e48 = 0x00000001192bfde8 to segment 0x0000000117cbf000 - 0x0000000119598000 r-x

    In [19]: 0x0000000115f36e48 - object_address
    Out[19]: 112496

    In [20]: function_pointer_address = 0x0000000115f36e48

## Writing memory

**Exported function signature:** `memoryWrite(value_format, address, value)`

    In [21]: memoryWrite("u64", function_pointer_address, 0xdeadbeef)

    # In another console with `lldb` attached:
    (lldb) c
    Process 39718 resuming
    Process 39718 stopped
    * thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0xdeadbeef)

    (lldb) register read rip
         rip = 0x00000000deadbeef
