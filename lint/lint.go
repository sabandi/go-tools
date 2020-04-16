// Package lint provides the foundation for tools like staticcheck
package lint // import "honnef.co/go/tools/lint"

import (
	"fmt"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"honnef.co/go/tools/config"
	"honnef.co/go/tools/runner"
	"honnef.co/go/tools/unused"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/packages"
)

type Documentation struct {
	Title      string
	Text       string
	Since      string
	NonDefault bool
	Options    []string
}

func (doc *Documentation) String() string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "%s\n\n", doc.Title)
	if doc.Text != "" {
		fmt.Fprintf(b, "%s\n\n", doc.Text)
	}
	fmt.Fprint(b, "Available since\n    ")
	if doc.Since == "" {
		fmt.Fprint(b, "unreleased")
	} else {
		fmt.Fprintf(b, "%s", doc.Since)
	}
	if doc.NonDefault {
		fmt.Fprint(b, ", non-default")
	}
	fmt.Fprint(b, "\n")
	if len(doc.Options) > 0 {
		fmt.Fprintf(b, "\nOptions\n")
		for _, opt := range doc.Options {
			fmt.Fprintf(b, "    %s", opt)
		}
		fmt.Fprint(b, "\n")
	}
	return b.String()
}

type Ignore interface {
	Match(p Problem) bool
}

type LineIgnore struct {
	File    string
	Line    int
	Checks  []string
	Matched bool
	Pos     token.Position
}

func (li *LineIgnore) Match(p Problem) bool {
	pos := p.Position
	if pos.Filename != li.File || pos.Line != li.Line {
		return false
	}
	for _, c := range li.Checks {
		if m, _ := filepath.Match(c, p.Check); m {
			li.Matched = true
			return true
		}
	}
	return false
}

func (li *LineIgnore) String() string {
	matched := "not matched"
	if li.Matched {
		matched = "matched"
	}
	return fmt.Sprintf("%s:%d %s (%s)", li.File, li.Line, strings.Join(li.Checks, ", "), matched)
}

type FileIgnore struct {
	File   string
	Checks []string
}

func (fi *FileIgnore) Match(p Problem) bool {
	if p.Position.Filename != fi.File {
		return false
	}
	for _, c := range fi.Checks {
		if m, _ := filepath.Match(c, p.Check); m {
			return true
		}
	}
	return false
}

type Severity uint8

const (
	Error Severity = iota
	Warning
	Ignored
)

// Problem represents a problem in some source code.
type Problem struct {
	Position token.Position
	End      token.Position
	Message  string
	Check    string
	Severity Severity
	Related  []Related
}

type Related struct {
	Pos     token.Position
	End     token.Position
	Message string
}

func (p Problem) Equal(o Problem) bool {
	return p.Position == o.Position &&
		p.End == o.End &&
		p.Message == o.Message &&
		p.Check == o.Check &&
		p.Severity == o.Severity
}

func (p *Problem) String() string {
	return fmt.Sprintf("%s (%s)", p.Message, p.Check)
}

// A Linter lints Go source code.
type Linter struct {
	Checkers        []*analysis.Analyzer
	GoVersion       int
	Config          config.Config
	Stats           Stats
	RepeatAnalyzers uint
}

func failed(res runner.Result) []Problem {
	var problems []Problem

	for _, e := range res.Errors {
		switch e := e.(type) {
		case packages.Error:
			msg := e.Msg
			if len(msg) != 0 && msg[0] == '\n' {
				// TODO(dh): See https://github.com/golang/go/issues/32363
				msg = msg[1:]
			}

			var pos token.Position
			if e.Pos == "" {
				// Under certain conditions (malformed package
				// declarations, multiple packages in the same
				// directory), go list emits an error on stderr
				// instead of JSON. Those errors do not have
				// associated position information in
				// go/packages.Error, even though the output on
				// stderr may contain it.
				if p, n, err := parsePos(msg); err == nil {
					if abs, err := filepath.Abs(p.Filename); err == nil {
						p.Filename = abs
					}
					pos = p
					msg = msg[n+2:]
				}
			} else {
				var err error
				pos, _, err = parsePos(e.Pos)
				if err != nil {
					panic(fmt.Sprintf("internal error: %s", e))
				}
			}
			p := Problem{
				Position: pos,
				Message:  msg,
				Severity: Error,
				Check:    "compile",
			}
			problems = append(problems, p)
		case error:
			p := Problem{
				Position: token.Position{},
				Message:  e.Error(),
				Severity: Error,
				Check:    "compile",
			}
			problems = append(problems, p)
		}
	}

	return problems
}

type unusedKey struct {
	pkgPath string
	base    string
	line    int
}

type unusedPair struct {
	key unusedKey
	obj unused.Object
}

func success(allowedChecks map[string]bool, res runner.Result, used map[unusedKey]bool) ([]Problem, unused.Result) {
	diags, err := res.Diagnostics()
	if err != nil {
		// XXX
		panic(err)
	}

	var problems []Problem

	for _, diag := range diags {
		if !allowedChecks[diag.Category] {
			continue
		}
		p := Problem{
			Position: diag.Pos,
			End:      diag.End,
			Message:  diag.Message,
			Check:    diag.Category,
		}
		for _, rel := range diag.Related {
			p.Related = append(p.Related, Related{
				Pos:     rel.Pos,
				End:     rel.End,
				Message: rel.Message,
			})
		}
		problems = append(problems, p)
	}

	u, err := res.Unused()
	if err != nil {
		// XXX
		panic(err)
	}

	return problems, u
}

func filterIgnored(problems []Problem, res runner.Result) []Problem {
	couldveMatched := func(ig *LineIgnore) bool {
		for _, c := range ig.Checks {
			if c == "U1000" {
				// We never want to flag ignores for U1000,
				// because U1000 isn't local to a single
				// package. For example, an identifier may
				// only be used by tests, in which case an
				// ignore would only fire when not analyzing
				// tests. To avoid spurious "useless ignore"
				// warnings, just never flag U1000.
				return false
			}

			// XXX see if check was possible

			// XXX we need the runner to give us the list of analyzers
			// it ran. we can't look at Config.Checks, because that
			// one hasn't been expanded yet.
		}

		return false
	}

	dirs, err := res.Directives()
	if err != nil {
		// XXX
		panic(err)
	}

	ignores, moreProblems := parseDirectives(dirs)

	for _, ig := range ignores {
		for i := range problems {
			p := &problems[i]
			if ig.Match(*p) {
				p.Severity = Ignored
			}
		}

		if ig, ok := ig.(*LineIgnore); ok && !ig.Matched && couldveMatched(ig) {
			p := Problem{
				Position: ig.Pos,
				Message:  "this linter directive didn't match anything; should it be removed?",
				Check:    "",
			}
			moreProblems = append(moreProblems, p)
		}
	}

	return append(problems, moreProblems...)
}

func (l *Linter) Lint(cfg *packages.Config, patterns []string) ([]Problem, error) {
	r, err := runner.New(l.Config)
	if err != nil {
		return nil, err
	}
	// r.goVersion = l.GoVersion

	results, err := r.Run(cfg, l.Checkers, patterns)
	if err != nil {
		return nil, err
	}

	analyzerNames := make([]string, len(l.Checkers))
	for i, a := range l.Checkers {
		analyzerNames[i] = a.Name
	}

	var problems []Problem
	used := map[unusedKey]bool{}
	unusedByResult := make([][]unusedPair, len(results))
	for i, res := range results {
		if len(res.Errors) > 0 && !res.Failed {
			panic("package has errors but isn't marked as failed")
		}
		if res.Failed {
			problems = append(problems, failed(res)...)
		} else {
			allowedAnalyzers := FilterAnalyzerNames(analyzerNames, res.Config.Checks)
			ps, u := success(allowedAnalyzers, res, used)
			problems = append(problems, filterIgnored(ps, res)...)

			for _, obj := range u.Used {
				// FIXME(dh): pick the object whose filename does not include $GOROOT
				key := unusedKey{
					pkgPath: obj.PkgPath,
					base:    filepath.Base(obj.Position.Filename),
					line:    obj.Position.Line,
				}
				used[key] = true
			}

			if allowedAnalyzers["U1000"] {
				unusedByResult[i] = make([]unusedPair, len(u.Unused))
				for j, obj := range u.Unused {
					key := unusedKey{
						pkgPath: obj.PkgPath,
						base:    filepath.Base(obj.Position.Filename),
						line:    obj.Position.Line,
					}
					unusedByResult[i][j] = unusedPair{key, obj}
					if _, ok := used[key]; !ok {
						used[key] = false
					}
				}
			}
		}
	}

	for _, uos := range unusedByResult {
		for _, uo := range uos {
			if used[uo.key] {
				continue
			}
			// XXX we need to filter U1000's problems by our ignores
			// XXX check that we're not in generated code
			problems = append(problems, Problem{
				Position: uo.obj.Position,
				Message:  fmt.Sprintf("%s %s is unused", uo.obj.Kind, uo.obj.Name),
				Check:    "U1000",
			})
		}
	}

	if len(problems) == 0 {
		return nil, nil
	}

	sort.Slice(problems, func(i, j int) bool {
		pi := problems[i].Position
		pj := problems[j].Position

		if pi.Filename != pj.Filename {
			return pi.Filename < pj.Filename
		}
		if pi.Line != pj.Line {
			return pi.Line < pj.Line
		}
		if pi.Column != pj.Column {
			return pi.Column < pj.Column
		}

		return problems[i].Message < problems[j].Message
	})

	var out []Problem
	out = append(out, problems[0])
	for i, p := range problems[1:] {
		// We may encounter duplicate problems because one file
		// can be part of many packages.
		if !problems[i].Equal(p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func FilterAnalyzerNames(analyzers []string, checks []string) map[string]bool {
	allowedChecks := map[string]bool{}

	for _, check := range checks {
		b := true
		if len(check) > 1 && check[0] == '-' {
			b = false
			check = check[1:]
		}
		if check == "*" || check == "all" {
			// Match all
			for _, c := range analyzers {
				allowedChecks[c] = b
			}
		} else if strings.HasSuffix(check, "*") {
			// Glob
			prefix := check[:len(check)-1]
			isCat := strings.IndexFunc(prefix, func(r rune) bool { return unicode.IsNumber(r) }) == -1

			for _, a := range analyzers {
				idx := strings.IndexFunc(a, func(r rune) bool { return unicode.IsNumber(r) })
				if isCat {
					// Glob is S*, which should match S1000 but not SA1000
					cat := a[:idx]
					if prefix == cat {
						allowedChecks[a] = b
					}
				} else {
					// Glob is S1*
					if strings.HasPrefix(a, prefix) {
						allowedChecks[a] = b
					}
				}
			}
		} else {
			// Literal check name
			allowedChecks[check] = b
		}
	}
	return allowedChecks
}

var posRe = regexp.MustCompile(`^(.+?):(\d+)(?::(\d+)?)?`)

func parsePos(pos string) (token.Position, int, error) {
	if pos == "-" || pos == "" {
		return token.Position{}, 0, nil
	}
	parts := posRe.FindStringSubmatch(pos)
	if parts == nil {
		return token.Position{}, 0, fmt.Errorf("malformed position %q", pos)
	}
	file := parts[1]
	line, _ := strconv.Atoi(parts[2])
	col, _ := strconv.Atoi(parts[3])
	return token.Position{
		Filename: file,
		Line:     line,
		Column:   col,
	}, len(parts[0]), nil
}
