// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) <= 1 {
		//nolint:forbidigo // No args means user is expecting usage on stdout
		fmt.Println(usage())
		return nil
	}
	cmds := [][]string{{"opts"}}
	for _, arg := range args[1:] {
		if arg == "--help" {
			//nolint:forbidigo // Explicit help requested means no other output and help is expected on stdout
			fmt.Println(cmdHelp(cmds[len(cmds)-1][0]))
			return nil
		}
		if strings.HasPrefix(arg, "-") {
			cmds[len(cmds)-1] = append(cmds[len(cmds)-1], arg)
		} else {
			cmds = append(cmds, []string{arg})
		}
	}

	set := jwk.NewSet()
	for _, cmd := range cmds {
		switch cmd[0] {
		case "opts":
			if err := handleOpts(cmd[1:]); err != nil {
				return err
			}
		case "read":
			if err := handleRead(cmd[1:], set); err != nil {
				return err
			}
		case "gen":
			if err := handleGen(cmd[1:], set); err != nil {
				return err
			}
		case "write":
			if err := handleWrite(cmd[1:], set); err != nil {
				return err
			}
		default:
			return errors.New("unknown command")
		}
	}

	return nil
}

func handleOpts(args []string) error {
	if len(args) > 0 {
		return errors.New("invalid option")
	}
	return nil
}
