package js

import (
	"github.com/evilsocket/islazy/log"
	"github.com/evilsocket/islazy/plugin"
	"github.com/robertkrimen/otto"
)

var NullValue = otto.Value{}

func ReportError(format string, args ...interface{}) otto.Value {
	log.Error(format, args...)
	return NullValue
}

func init() {
	// TODO: refactor this in packages

	plugin.Defines["readDir"] = readDir
	plugin.Defines["readFile"] = readFile
	plugin.Defines["writeFile"] = writeFile

	plugin.Defines["log"] = flog
	plugin.Defines["log_debug"] = log_debug
	plugin.Defines["log_info"] = log_info
	plugin.Defines["log_warn"] = log_warn
	plugin.Defines["log_error"] = log_error
	plugin.Defines["log_fatal"] = log_fatal

	plugin.Defines["btoa"] = btoa
	plugin.Defines["atob"] = atob
	plugin.Defines["gzipCompress"] = gzipCompress
	plugin.Defines["gzipDecompress"] = gzipDecompress

	plugin.Defines["httpRequest"] = httpRequest
	plugin.Defines["http"] = httpPackage{}

	plugin.Defines["random"] = randomPackage{}
}
