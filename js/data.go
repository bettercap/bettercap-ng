package js

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"

	"github.com/robertkrimen/otto"
)

func btoa(call otto.FunctionCall) otto.Value {
	varValue := base64.StdEncoding.EncodeToString([]byte(call.Argument(0).String()))
	v, err := otto.ToValue(varValue)
	if err != nil {
		return ReportError("Could not convert to string: %s", varValue)
	}

	return v
}

func atob(call otto.FunctionCall) otto.Value {
	varValue, err := base64.StdEncoding.DecodeString(call.Argument(0).String())
	if err != nil {
		return ReportError("Could not decode string: %s", call.Argument(0).String())
	}

	v, err := otto.ToValue(string(varValue))
	if err != nil {
		return ReportError("Could not convert to string: %s", varValue)
	}

	return v
}

func gzipCompress(call otto.FunctionCall) otto.Value {
	argv := call.ArgumentList
	argc := len(argv)
	if argc != 1 {
		return ReportError("gzipCompress: expected 1 argument, %d given instead.", argc)
	}

	uncompressedBytes := []byte(argv[0].String())

	var writerBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&writerBuffer)
	_, err := gzipWriter.Write(uncompressedBytes)
	if err != nil {
		return ReportError("gzipCompress: could not compress data: %s", err.Error())
	}
	gzipWriter.Close()

	compressedBytes := writerBuffer.Bytes()

	v, err := otto.ToValue(string(compressedBytes))
	if err != nil {
		return ReportError("Could not convert to string: %s", err.Error())
	}

	return v
}

func gzipDecompress(call otto.FunctionCall) otto.Value {
	argv := call.ArgumentList
	argc := len(argv)
	if argc != 1 {
		return ReportError("gzipDecompress: expected 1 argument, %d given instead.", argc)
	}

	compressedBytes := []byte(argv[0].String())
	readerBuffer := bytes.NewBuffer(compressedBytes)

	gzipReader, err := gzip.NewReader(readerBuffer)
	if err != nil {
		return ReportError("gzipDecompress: could not create gzip reader: %s", err.Error())
	}

	var decompressedBuffer bytes.Buffer
	_, err = decompressedBuffer.ReadFrom(gzipReader)
	if err != nil {
		return ReportError("gzipDecompress: could not decompress data: %s", err.Error())
	}

	decompressedBytes := decompressedBuffer.Bytes()
	v, err := otto.ToValue(string(decompressedBytes))
	if err != nil {
		return ReportError("Could not convert to string: %s", err.Error())
	}

	return v
}
