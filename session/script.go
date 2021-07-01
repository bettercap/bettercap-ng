package session

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bettercap/bettercap/caplets"
	_ "github.com/bettercap/bettercap/js"

	"github.com/evilsocket/islazy/fs"
	"github.com/evilsocket/islazy/plugin"
	"github.com/evilsocket/islazy/str"
)

// require("telegram.js")
var requireParser = regexp.MustCompile(`(?msi)^\s*require\s*\(\s*["']([^"']+)["']\s*\);?\s*$`)

type Script struct {
	*plugin.Plugin
}

// yo! we're doing c-like preprocessing on a javascript file from go :D
func preprocess(basePath string, code string, level int) (string, error) {
	if level >= 255 {
		return "", fmt.Errorf("too many nested includes")
	}

	matches := requireParser.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		expr := match[0]
		fileName := str.Trim(match[1])

		if fileName[0] != '/' {
			searchPaths := []string{
				filepath.Join(basePath, fileName),
				filepath.Join(caplets.InstallBase, fileName),
			}

			if !strings.Contains(fileName, ".js") {
				searchPaths = append(searchPaths, []string{
					filepath.Join(basePath, fileName) + ".js",
					filepath.Join(caplets.InstallBase, fileName) + ".js",
				}...)
			}

			found := false
			for _, fName := range searchPaths {
				if fs.Exists(fName) {
					fileName = fName
					found = true
					break
				}
			}
			if !found {
				return "", fmt.Errorf("file %s not found in any of %#v", fileName, searchPaths)
			}
		}

		raw, err := ioutil.ReadFile(fileName)
		if err != nil {
			return "", fmt.Errorf("%s: %v", fileName, err)
		}

		if includedBody, err := preprocess(filepath.Dir(fileName), string(raw), level+1); err != nil {
			return "", fmt.Errorf("%s: %v", fileName, err)
		} else {
			code = strings.ReplaceAll(code, expr, includedBody)
		}
	}

	return code, nil
}

func LoadScript(fileName string) (*Script, error) {
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	basePath := filepath.Dir(fileName)
	if code, err := preprocess(basePath, string(raw), 0); err != nil {
		return nil, err
	} else if p, err := plugin.Parse(code); err != nil {
		return nil, err
	} else {
		p.Path = fileName
		p.Name = strings.Replace(basePath, ".js", "", -1)
		return &Script{
			Plugin: p,
		}, nil
	}
}
