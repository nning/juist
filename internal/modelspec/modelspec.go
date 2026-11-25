// Package modelspec reads what a formal model in models/ says of the code:
// the labels it uses and the fields each value is made of, in order, from
// the model's comments opening with an @. Tests hold the code to it.
package modelspec

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// A Spec is a model's labels, by name, and its field lists, by value.
type Spec struct {
	Labels map[string]string
	Fields map[string][]string
}

var annotation = regexp.MustCompile(`\(\*@ (label|fields) ([A-Za-z0-9.]+):? (.*?) \*\)`)

// Read reads the annotations of the model at path.
func Read(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Spec{Labels: map[string]string{}, Fields: map[string][]string{}}
	for _, m := range annotation.FindAllStringSubmatch(string(b), -1) {
		switch m[1] {
		case "label":
			v, err := strconv.Unquote(m[3])
			if err != nil {
				return nil, fmt.Errorf("modelspec: %s: label %s: %w", path, m[2], err)
			}
			s.Labels[m[2]] = v
		case "fields":
			s.Fields[m[2]] = strings.Fields(m[3])
		}
	}
	if len(s.Labels) == 0 && len(s.Fields) == 0 {
		return nil, fmt.Errorf("modelspec: %s names no labels or fields", path)
	}
	return s, nil
}

// Mismatches lists each label the model names that code, the code's labels
// by the model's names, does not hold byte for byte.
func (s *Spec) Mismatches(code map[string]string) []string {
	var out []string
	for name, v := range s.Labels {
		got, ok := code[name]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("the model names %s, which the test does not know", name))
		case got != v:
			out = append(out, fmt.Sprintf("%s is %q in the model, %q in the code", name, v, got))
		}
	}
	return out
}

// Join builds the value the model's field list name makes: each label with a
// zero byte after it, each other field as values holds it.
func (s *Spec) Join(name string, values map[string][]byte) ([]byte, error) {
	list, ok := s.Fields[name]
	if !ok {
		return nil, fmt.Errorf("modelspec: no field list %s", name)
	}
	var b []byte
	for _, f := range list {
		if l, ok := s.Labels[f]; ok {
			b = append(append(b, l...), 0)
			continue
		}
		v, ok := values[f]
		if !ok {
			return nil, errors.New("modelspec: the model names a field " + f + ", which the test does not give")
		}
		b = append(b, v...)
	}
	return b, nil
}
