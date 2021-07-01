package js

import (
	"github.com/robertkrimen/otto"
	"io/ioutil"
)

func readDir(call otto.FunctionCall) otto.Value {
	argv := call.ArgumentList
	argc := len(argv)
	if argc != 1 {
		return ReportError("readDir: expected 1 argument, %d given instead.", argc)
	}

	path := argv[0].String()
	dir, err := ioutil.ReadDir(path)
	if err != nil {
		return ReportError("Could not read directory %s: %s", path, err)
	}

	entry_list := []string{}
	for _, file := range dir {
		entry_list = append(entry_list, file.Name())
	}

	v, err := otto.Otto.ToValue(*call.Otto, entry_list)
	if err != nil {
		return ReportError("Could not convert to array: %s", err)
	}

	return v
}

func readFile(call otto.FunctionCall) otto.Value {
	argv := call.ArgumentList
	argc := len(argv)
	if argc != 1 {
		return ReportError("readFile: expected 1 argument, %d given instead.", argc)
	}

	filename := argv[0].String()
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return ReportError("Could not read file %s: %s", filename, err)
	}

	v, err := otto.ToValue(string(raw))
	if err != nil {
		return ReportError("Could not convert to string: %s", err)
	}
	return v
}

func writeFile(call otto.FunctionCall) otto.Value {
	argv := call.ArgumentList
	argc := len(argv)
	if argc != 2 {
		return ReportError("writeFile: expected 2 arguments, %d given instead.", argc)
	}

	filename := argv[0].String()
	data := argv[1].String()

	err := ioutil.WriteFile(filename, []byte(data), 0644)
	if err != nil {
		return ReportError("Could not write %d bytes to %s: %s", len(data), filename, err)
	}

	return otto.NullValue()
}
