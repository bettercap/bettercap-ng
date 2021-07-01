package routing

import (
	"regexp"
	"strings"

	"github.com/bettercap/bettercap/core"
	"github.com/evilsocket/islazy/str"
)

var parser = regexp.MustCompile(`^([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+).*$`)

func update() ([]Route, error) {
	table = make([]Route, 0)

	output, err := core.Exec("netstat", []string{"-n", "-r"})
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(output, "\n") {
		if line = str.Trim(line); len(line) > 0 {
			matches := parser.FindStringSubmatch(line)
			if num := len(matches); num == 5 && matches[1] != "Destination" {
				route := Route{
					Destination: matches[1],
					Gateway:     matches[2],
					Flags:       matches[3],
					Device:      matches[4],
					Default:     matches[1] == "default",
				}

				if strings.ContainsRune(route.Destination, '.') || strings.ContainsRune(route.Gateway, '.') {
					route.Type = IPv4
				} else {
					route.Type = IPv6
				}

				table = append(table, route)
			}
		}
	}

	return table, nil
}
