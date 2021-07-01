package js

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/robertkrimen/otto"
)

type httpPackage struct {
}

type httpResponse struct {
	Error    error
	Response *http.Response
	Raw      []byte
	Body     string
	JSON     interface{}
}

func (c httpPackage) Encode(s string) string {
	return url.QueryEscape(s)
}

func (c httpPackage) Request(method string, uri string,
	headers map[string]string,
	form map[string]string,
	json string) httpResponse {
	var reader io.Reader

	if form != nil {
		data := url.Values{}
		for k, v := range form {
			data.Set(k, v)
		}
		reader = bytes.NewBufferString(data.Encode())
	} else if json != "" {
		reader = strings.NewReader(json)
	}

	req, err := http.NewRequest(method, uri, reader)
	if err != nil {
		return httpResponse{Error: err}
	}

	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if json != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	for name, value := range headers {
		req.Header.Add(name, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return httpResponse{Error: err}
	}
	defer resp.Body.Close()

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return httpResponse{Error: err}
	}

	res := httpResponse{
		Response: resp,
		Raw:      raw,
		Body:     string(raw),
	}

	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Errorf("%s", resp.Status)
	}

	return res
}

func (c httpPackage) Get(url string, headers map[string]string) httpResponse {
	return c.Request("GET", url, headers, nil, "")
}

func (c httpPackage) PostForm(url string, headers map[string]string, form map[string]string) httpResponse {
	return c.Request("POST", url, headers, form, "")
}

func (c httpPackage) PostJSON(url string, headers map[string]string, json string) httpResponse {
	return c.Request("POST", url, headers, nil, json)
}

func httpRequest(call otto.FunctionCall) otto.Value {
	argv := call.ArgumentList
	argc := len(argv)
	if argc < 2 {
		return ReportError("httpRequest: expected 2 or more, %d given instead.", argc)
	}

	method := argv[0].String()
	url := argv[1].String()

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if argc >= 3 {
		data := argv[2].String()
		req, err = http.NewRequest(method, url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return ReportError("Could create request to url %s: %s", url, err)
		}

		if argc > 3 {
			headers := argv[3].Object()
			for _, key := range headers.Keys() {
				v, err := headers.Get(key)
				if err != nil {
					return ReportError("Could add header %s to request: %s", key, err)
				}
				req.Header.Add(key, v.String())
			}
		}
	} else if err != nil {
		return ReportError("Could create request to url %s: %s", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return ReportError("Could not request url %s: %s", url, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ReportError("Could not read response: %s", err)
	}

	object, err := otto.New().Object("({})")
	if err != nil {
		return ReportError("Could not create response object: %s", err)
	}

	err = object.Set("body", string(body))
	if err != nil {
		return ReportError("Could not populate response object: %s", err)
	}

	v, err := otto.ToValue(object)
	if err != nil {
		return ReportError("Could not convert to object: %s", err)
	}
	return v
}
