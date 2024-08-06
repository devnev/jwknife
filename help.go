package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

var usageTpl = template.Must(template.New("usage").
	Funcs(tplFuncs).
	Parse(`
JWKnife: Manipulate & Convert JWK sets.

 - Read any number of keys in PEM, JWK or JWKS format into a single JWK set.
 - Generate new keys and add them to the set.
 - Output some or all of the JWKs as a JWK set or PEM.

Example:
	{{.Command}} read -pem -path=my.pem gen -rsa=2048 -set=alg=RS256 -set=use=sig write -jwks -path=my-jwk.json

Available subcommands:
{{.ReadSyntax | wrap 92 "     " | indent "\t"}}
{{.GenSyntax | wrap 92 "    " | indent "\t"}}
{{.WriteSyntax | wrap 92 "      " | indent "\t"}}

# Read

{{.ReadSyntax | wrap 100 "     " }}

{{.ReadSummary | wrap 100 "" }}

Flags:
{{.ReadFlags | indent "\t"}}

# Generate

{{.GenSyntax}}

{{.GenSummary | wrap 100 ""}}

Flags:
{{.GenFlags | indent "\t"}}

# Write

{{.WriteSyntax | wrap 100 "      " }}

{{.WriteSummary | wrap 100 ""}}

Flags:
{{.WriteFlags | indent "\t"}}
`))

func usage() string {
	var buf bytes.Buffer
	err := usageTpl.Execute(&buf, map[string]any{
		"Command":      filepath.Base(os.Args[0]),
		"ReadSyntax":   readSyntax,
		"ReadSummary":  readSummary,
		"ReadFlags":    readFlags,
		"GenSyntax":    genSyntax,
		"GenSummary":   genSummary,
		"GenFlags":     genFlags,
		"WriteSyntax":  writeSyntax,
		"WriteSummary": writeSummary,
		"WriteFlags":   writeFlags,
	})
	if err != nil {
		panic(err.Error())
	}
	return strings.TrimSpace(buf.String())
}

var cmdHelpTpl = template.Must(template.New("cmdhelp").
	Funcs(tplFuncs).
	Parse(`
{{.Command}}:
{{.Flags | indent "\t"}}
commands:
{{.ReadSyntax | wrap 92 "     " | indent "\t"}}
{{.GenSyntax | wrap 92 "    " | indent "\t"}}
{{.WriteSyntax | wrap 92 "      " | indent "\t"}}
`))

func cmdHelp(cmd string) string {
	var flags string
	switch cmd {
	case "read":
		flags = readFlags
	case "gen":
		flags = genFlags
	case "write":
		flags = writeFlags
	default:
		return usage()
	}
	var buf bytes.Buffer
	err := cmdHelpTpl.Execute(&buf, map[string]any{
		"Command":     cmd,
		"Flags":       flags,
		"ReadSyntax":  readSyntax,
		"GenSyntax":   genSyntax,
		"WriteSyntax": writeSyntax,
	})
	if err != nil {
		panic(err.Error())
	}
	return strings.TrimSpace(buf.String())
}

var tplFuncs = template.FuncMap{
	"indent": func(indent string, text string) string {
		return indent + strings.ReplaceAll(text, "\n", "\n"+indent)
	},
	"trim": strings.TrimSpace,
	"wrap": func(maxlength int, indent string, text string) string {
		var sb strings.Builder
		for indentline := false; len(text) > 0; indentline = true {
			wraplength := maxlength
			if indentline {
				sb.WriteString(indent)
				wraplength -= len(indent)
			}
			if nl := strings.Index(text, "\n"); nl >= 0 && nl < wraplength {
				sb.WriteString(text[:nl+1])
				text = text[nl+1:]
				continue
			}
			if wraplength >= len(text) {
				break
			}
			wrapAt := strings.LastIndex(text[:wraplength+1], " ")
			if wrapAt < 0 {
				wrapAt = strings.Index(text, " ")
				if wrapAt < 0 {
					break
				}
			}
			sb.WriteString(text[:wrapAt])
			text = text[wrapAt+1:]
			if len(text) > 0 {
				sb.WriteByte('\n')
			}
		}
		sb.WriteString(text)
		return sb.String()
	},
}
