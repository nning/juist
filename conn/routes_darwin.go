package conn

import "syscall"

const notHostsOwn = syscall.RTF_DYNAMIC | syscall.RTF_MODIFIED | syscall.RTF_REJECT | syscall.RTF_BLACKHOLE |
	syscall.RTF_WASCLONED | syscall.RTF_LLINFO
