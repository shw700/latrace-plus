# latrace-plus
Fork of (abandoned?) latrace project

Most importantly, the addition of human-friendly bitmask expansion to various parameters.

For example, to take advantage of this feature for the libc wrapper for open():

int open(char *file, int oflag|open_mode/o);

Note that the following is also necessary for inclusion (which can be generated programmatically with the included getconsts.sh script):

bm_enum open_mode { O_ACCMODE=00000003, O_RDONLY=00000000, O_WRONLY=00000001, O_RDWR=00000002, O_CREAT=00000100, O_EXCL=00000200, O_NOCTTY=00000400, O_TRUNC=00001000, O_APPEND=00002000, O_NONBLOCK=00004000, O_DSYNC=00010000, O_DIRECT=00040000, O_LARGEFILE=00100000, O_DIRECTORY=00200000, O_NOFOLLOW=00400000, O_NOATIME=01000000, O_CLOEXEC=02000000, O_PATH=010000000 };

The lines above instruct the bitmask value for oflag to be expanded based on the bitmask enumeration named "open_mode" and that any remaining unknown bits should be displayed in octal representation ("o").



Also supported at the moment (a bit hack-y):

The "/" switch can be used at the end of a regular function variable declaration to force alternate representation:
/o	Octal representation
/x	Hexadecimal representation
/b	Binary string (hexdump) (defaults to 4 bytes in length)
/#b	Binary string dump of # bytes length


The "/" switch at the end of a function variable declaration can be used as such, when displayed in conjunction with a bitmasked value:
[none]	Hexadecimal representation (default)
/o	Octal representation
/d	Force (signed) decimal representation
/u	Force unsigned decimal representation

Individual function sub-routine expansion can also be suppressed by appending an exclamation mark after the function name in its declaration.
For example: void ERR_load_crypto_strings!(void);
results in the suppression of the expansion of all subroutines called internally by the ERR_load_crypto_strings() function.

