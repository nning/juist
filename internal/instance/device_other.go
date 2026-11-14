//go:build !darwin

package instance

// Device is instance n's TUN device, named as the instance.
func Device(n int) string { return Name(n) }
