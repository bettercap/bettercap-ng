package routing

import (
	"github.com/bettercap/bettercap/core"
	"github.com/evilsocket/islazy/str"
	"regexp"
	"strings"
)

var parser = regexp.MustCompile(`^(.+)\sdev\s([^\s]+)\s(.+)$`)



func update() ([]Route, error) {
	table = make([]Route, 0)

	for ip, inet := range map[RouteType]string{IPv4: "inet", IPv6: "inet6"} {
		output, err := core.Exec("ip", []string{"-f", inet, "route"})
		if err != nil {
			return nil, err
		}
		if len(regexp.MustCompile(`(default)`).FindStringSubmatch(output))!=2 {
			gwline, err := find_gateway_android7(inet)
			if err != nil {
				return nil, err
			}
			output = gwline + "\n" + output
		}
		for _, line := range strings.Split(output, "\n") {
			if line = str.Trim(line); len(line) > 0 {
				matches := parser.FindStringSubmatch(line)
				if num := len(matches); num == 4 {
					route := Route{
						Type:        ip,
						Destination: matches[1],
						Device:      matches[2],
						Flags:       matches[3],
						Default:     strings.Index(matches[1], "default ") == 0,
					}

					if idx := strings.Index(route.Destination, " via "); idx >= 0 {
						route.Gateway = route.Destination[idx + len(" via "):]
						route.Destination = route.Destination[:idx]
					}
					table = append(table, route)
				}
			}
		}
	}
	return table, nil
}

func find_gateway_android7(inet string) (string, error) {
	output, err := core.Exec("ip", []string{"-f", inet, "route", "get", "8.8.8.8"})
	if err != nil {
		return "", err
	}
	parser3 := regexp.MustCompile(`8.8.8.8`)
	first_line := strings.Split(output, "\n")[0]
	replaced := parser3.ReplaceAllString(first_line, "default")
	return replaced, nil
}
