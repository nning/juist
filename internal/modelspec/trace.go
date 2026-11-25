package modelspec

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// A ModelValue is a TLA+ model value as TLC prints it. A trace's other
// values are an int64, a string, a bool, a set or sequence ([]any), and a
// record or function (map[string]any, keyed by the key's printed form).
type ModelValue string

// Action is the key under which ReadTrace puts the name of the action that
// led to a state, where TLC says it.
const Action = "_action"

// action is the name in the last line of before, TLC's "\\* <Name line …>"
// that heads the state after it.
func action(before string) string {
	before = strings.TrimRight(before, "\n")
	line := before[strings.LastIndex(before, "\n")+1:]
	_, name, ok := strings.Cut(line, "<")
	if !ok {
		return ""
	}
	name, _, _ = strings.Cut(name, " ")
	name, _, _ = strings.Cut(name, "(")
	return name
}

// ReadTrace reads the states of a TLC trace, gzipped: the STATE_n blocks
// TLC's simulation writes, or an error trace's "State n:" ones.
func ReadTrace(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(z)
	if err != nil {
		return nil, err
	}
	var states []map[string]any
	blocks := strings.Split(string(b), "\nSTATE_")
	for i, block := range blocks[1:] {
		_, body, _ := strings.Cut(block, "==")
		state := map[string]any{Action: action(blocks[i])}
		for _, conj := range strings.Split(body, "\n/\\ ")[1:] {
			name, value, ok := strings.Cut(conj, " = ")
			if !ok {
				return nil, fmt.Errorf("modelspec: %s: a state's line %q", path, conj)
			}
			if i := strings.Index(value, "\n\n"); i >= 0 {
				value = value[:i]
			}
			p := &tlaParser{toks: tlaTokens(value)}
			v, err := p.value()
			if err != nil {
				return nil, fmt.Errorf("modelspec: %s: %s: %w", path, name, err)
			}
			state[strings.TrimSpace(name)] = v
		}
		states = append(states, state)
	}
	if len(states) == 0 {
		return nil, fmt.Errorf("modelspec: %s holds no states", path)
	}
	return states, nil
}

func tlaTokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\n' || c == '\t':
			i++
		case strings.HasPrefix(s[i:], "|->"):
			out, i = append(out, "|->"), i+3
		case strings.HasPrefix(s[i:], ":>"), strings.HasPrefix(s[i:], "@@"),
			strings.HasPrefix(s[i:], "<<"), strings.HasPrefix(s[i:], ">>"):
			out, i = append(out, s[i:i+2]), i+2
		case strings.ContainsRune("{}[](),", rune(c)):
			out, i = append(out, string(c)), i+1
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			out, i = append(out, s[i:i+j+2]), i+j+2
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \n\t{}[](),\"", rune(s[j])) &&
				!strings.HasPrefix(s[j:], ":>") && !strings.HasPrefix(s[j:], "@@") &&
				!strings.HasPrefix(s[j:], ">>") && !strings.HasPrefix(s[j:], "|->") {
				j++
			}
			out, i = append(out, s[i:j]), j
		}
	}
	return out
}

type tlaParser struct {
	toks []string
	i    int
}

func (p *tlaParser) next() string {
	if p.i >= len(p.toks) {
		return ""
	}
	p.i++
	return p.toks[p.i-1]
}

func (p *tlaParser) peek() string {
	if p.i >= len(p.toks) {
		return ""
	}
	return p.toks[p.i]
}

func (p *tlaParser) expect(tok string) error {
	if got := p.next(); got != tok {
		return fmt.Errorf("want %q, got %q", tok, got)
	}
	return nil
}

// list parses values up to closing, separated by sep, each by item.
func (p *tlaParser) list(sep, closing string, item func() error) error {
	if p.peek() == closing {
		p.next()
		return nil
	}
	for {
		if err := item(); err != nil {
			return err
		}
		switch tok := p.next(); tok {
		case sep:
		case closing:
			return nil
		default:
			return fmt.Errorf("want %q or %q, got %q", sep, closing, tok)
		}
	}
}

func (p *tlaParser) value() (any, error) {
	tok := p.next()
	switch {
	case tok == "{" || tok == "<<":
		closing := map[string]string{"{": "}", "<<": ">>"}[tok]
		out := []any{}
		err := p.list(",", closing, func() error {
			v, err := p.value()
			out = append(out, v)
			return err
		})
		return out, err
	case tok == "[":
		out := map[string]any{}
		err := p.list(",", "]", func() error {
			field := p.next()
			if err := p.expect("|->"); err != nil {
				return err
			}
			v, err := p.value()
			out[field] = v
			return err
		})
		return out, err
	case tok == "(":
		out := map[string]any{}
		err := p.list("@@", ")", func() error {
			k, err := p.value()
			if err != nil {
				return err
			}
			if err := p.expect(":>"); err != nil {
				return err
			}
			v, err := p.value()
			out[fmt.Sprint(k)] = v
			return err
		})
		return out, err
	case strings.HasPrefix(tok, `"`):
		return strings.Trim(tok, `"`), nil
	case tok == "TRUE" || tok == "FALSE":
		return tok == "TRUE", nil
	case tok == "":
		return nil, errors.New("the value ends early")
	}
	if n, err := strconv.ParseInt(tok, 10, 64); err == nil {
		return n, nil
	}
	return ModelValue(tok), nil
}
