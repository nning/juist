package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/nning/juist/internal/pairkey"
)

// pairs prints the newest generation of a pair key in use in the pairs file
// at path, zero where every pair is on the group key.
func pairs(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for line := range strings.Lines(string(b)) {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return err
		}
		s, err := pairkey.DecodeStore(raw)
		if err != nil {
			return err
		}
		newest := uint64(0)
		for _, g := range s.Generations() {
			newest = max(newest, g)
		}
		fmt.Println(newest)
		return nil
	}
	return fmt.Errorf("%s holds no store", path)
}
