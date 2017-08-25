# latrace-plus
Fork of (abandoned?) latrace project

Most importantly, the addition of human-friendly bitmask expansion to various parameters.

For example, to take advantage of this feature for the libc wrapper for open():

`int open(char *file, int oflag|open_mode/o);`

Note that the following is also necessary for inclusion (which can be generated programmatically with the included getconsts.sh script):

`bm_enum open_mode { O_ACCMODE=00000003, O_RDONLY=00000000, O_WRONLY=00000001, O_RDWR=00000002, O_CREAT=00000100, O_EXCL=00000200, O_NOCTTY=00000400, O_TRUNC=00001000, O_APPEND=00002000, O_NONBLOCK=00004000, O_DSYNC=00010000, O_DIRECT=00040000, O_LARGEFILE=00100000, O_DIRECTORY=00200000, O_NOFOLLOW=00400000, O_NOATIME=01000000, O_CLOEXEC=02000000, O_PATH=010000000 };`

The lines above instruct the bitmask value for oflag to be expanded based on the bitmask enumeration named "open_mode" and that any remaining unknown bits should be displayed in octal representation ("o").



Also supported at the moment (a bit hack-y):

The "/" switch can be used at the end of a regular function variable declaration to force alternate representation:

`/o`	Octal representation

`/x`	Hexadecimal representation

`/b`	Binary string (hexdump) (defaults to 4 bytes in length)

`/#b`	Binary string dump of # bytes length

`/p`	Print memory address


The "/" switch at the end of a function variable declaration can be used as such, when displayed in conjunction with a bitmasked value:

[none]	Hexadecimal representation (default)

`/o`	Octal representation

`/d`	Force (signed) decimal representation

`/u`	Force unsigned decimal representation

Individual function sub-routine expansion can also be suppressed by appending one of a few special characters to the function name in its declaration.

The characters can be !, ~, or ^

For example: `void ERR_load_crypto_strings!(void);`

results in the suppression of the expansion of all subroutines called internally by the ERR_load_crypto_strings() function.

Use of ~ results in terse single line expansion (child function names are displayed, but no more data beyond that).

^ is bare mode, resulting in a function's return value being displayed on the same output line as its invocation, with no information about nested function calls.

*Please note that no custom user transformer functions are called on functions whose returns have been collapsed.*


*Other new options:*

`latrace -x s`		Display library names in short format (without absolute path prefix)

`latrace -x c`		Display subroutine calls with ANSI color (indentation must also be enabled)

`latrace -x r`		Resolve memory addresses to known symbols when possible




*User transformer libraries:*

Shared libraries with transformers should be dropped into /etc/latrace.d/transformers, where they will be automatically loaded.

Custom user struct transformer functions should be visibly exported and declared as follows: `int latrace_struct_to_str_xxx(xxx *obj, char *buf, size_t blen);`

where xxx is the name of the structure in question.

For example, imagine this module being used in conjunction with the stdio library functions:

`int latrace_struct_to_str_FILE(FILE *obj, char *buf, size_t blen);`

The function takes a buffer and a size of a buffer where a user-defined structure description will be left as a null-terminated string.

The user handler should return 0 on success or -1 on failure.

Very basic support for catching program faults has been added. The underlying assumption is that if a transformer has generated something like a segmentation violation, it is likely due to READING a bad memory address, and not because of any resulting corruption. This is why it will often be safe in our case to resume program execution rather than terminate gracefully.


*New data types:*

Variable argument lists (...) are now understood by the parser (and effectively ignored).

The "*pfn*" primitive type denotes a function pointer. If the address can be resolved to a known symbol, that symbol name will be displayed; otherwise the raw function address will be displayed in hex, as per convention.

*Miscellaneous additions:*

gcc __attributes__ are now ignored by the parser.

C++ style single line comments are supported.
