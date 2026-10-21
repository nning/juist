package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// commandsPage writes the handbook's command reference in Markdown, from the
// command table and each command's own help, as [app.manpage] writes juist(1).
func (a *app) commandsPage(w io.Writer) error {
	tmp, err := os.MkdirTemp("", "juist-commands")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	g := globals{home: tmp}
	var b strings.Builder
	group := ""
	for i := range commands {
		c := &commands[i]
		if c.group != group {
			group = c.group
			fmt.Fprintf(&b, "## %s\n\n", group)
		}
		forms := [][]string{nil}
		if c.family != nil {
			forms = forms[:0]
			for k, sub := range c.family().subs {
				if k == 0 {
					forms = append(forms, nil)
				} else {
					forms = append(forms, []string{sub.name})
				}
			}
		}
		for _, args := range forms {
			got, ok := a.captureCommand(g, c, args)
			if !ok {
				return fmt.Errorf("juist __commands: %s %s gave no help to take", c.name, strings.Join(args, " "))
			}
			s := got.spec
			syn := s.name
			if args := s.synopsis(); args != "" && !strings.Contains(args, "SUBCOMMAND") {
				syn += " " + args
			}
			fmt.Fprintf(&b, "### `%s`\n\n", syn)
			about := strings.TrimSpace(s.about)
			if c.family != nil && len(args) == 0 {
				about = strings.TrimSpace(c.family().about())
			}
			for _, p := range strings.Split(about, "\n\n") {
				if strings.HasPrefix(p, "  ") {
					fmt.Fprintf(&b, "```\n%s\n```\n\n", p)
					continue
				}
				fmt.Fprintf(&b, "%s\n\n", markdownText(p))
			}
			for _, o := range optionRows(got.fs) {
				fmt.Fprintf(&b, "- `%s`: %s\n", o[0], markdownText(o[1]))
			}
			if len(optionRows(got.fs)) > 0 {
				b.WriteString("\n")
			}
		}
	}
	_, err = io.WriteString(w, strings.TrimRight(b.String(), "\n")+"\n")
	return err
}

// markdownText joins a paragraph's lines and escapes what Markdown would
// take for markup, the typographer's dashes too.
func markdownText(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	r := strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "<", `\<`, "`", "\\`", "[", `\[`, "--", `\-\-`)
	return r.Replace(strings.Join(lines, " "))
}
