package policy

import "strings"

// Diff is new line by line against old: "+ " before a line added, "- "
// before one gone, two spaces before one kept.
func Diff(old, new string) []string {
	a, b := lines(old), lines(new)
	// lcs[i][j] is the longest common subsequence of a[i:] and b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			out = append(out, marked(" ", a[i]))
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, marked("-", a[i]))
			i++
		default:
			out = append(out, marked("+", b[j]))
			j++
		}
	}
	return out
}

// marked is line after its mark, without a space at the end of an empty one.
func marked(mark, line string) string {
	return strings.TrimRight(mark+" "+line, " ")
}

func lines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
