package instance

import "strconv"

// Device is instance n's TUN device: a utun on macOS, whose name the kernel
// gives by unit number alone.
func Device(n int) string { return "utun" + strconv.Itoa(100+n) }
