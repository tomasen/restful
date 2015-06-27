package restful

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/docker/docker/api"
)

var (
	errConnectionRefused = errors.New("Cannot connect to the restful server")
)

type Client struct {
	// proto holds the client protocol i.e. unix.
	proto string
	// addr holds the client address.
	addr string
	// keyFile holds the key file as a string.
	keyFile string
	// tlsConfig holds the TLS configuration for the client, and will
	// set the scheme to https in NewDockerCli if present.
	tlsConfig *tls.Config
	// scheme holds the scheme of the client i.e. https.
	scheme string
	// transport holds the client transport instance.
	transport *http.Transport
	// default headers
	HttpDefaultHeaders map[string]string
	// user agent string
	UserAgent string
}

func NewClient(keyFile string, proto, addr string, tlsConfig *tls.Config) *Client {
	scheme := "http"
	if tlsConfig != nil {
		scheme = "https"
	}

	// The transport is created here for reuse during the client session.
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	configureTCPTransport(tr, proto, addr)

	return &Client{
		proto:     proto,
		addr:      addr,
		keyFile:   keyFile,
		tlsConfig: tlsConfig,
		scheme:    scheme,
		transport: tr,
	}
}

func configureTCPTransport(tr *http.Transport, proto, addr string) {
	// Why 32? See https://github.com/docker/docker/pull/8035.
	timeout := 32 * time.Second
	if proto == "unix" {
		// No need for compression in local communications.
		tr.DisableCompression = true
		tr.Dial = func(_, _ string) (net.Conn, error) {
			return net.DialTimeout(proto, addr, timeout)
		}
	} else {
		tr.Proxy = http.ProxyFromEnvironment
		tr.Dial = (&net.Dialer{Timeout: timeout}).Dial
	}
}

func (c *Client) Call(method, path string, data interface{}, headers map[string][]string) (io.ReadCloser, http.Header, int, error) {
	params, err := c.encodeData(data)
	if err != nil {
		return nil, nil, -1, err
	}

	if data != nil {
		if headers == nil {
			headers = make(map[string][]string)
		}
		headers["Content-Type"] = []string{"application/json"}
	}

	body, hdr, statusCode, err := c.clientRequest(method, path, params, headers)
	return body, hdr, statusCode, err
}

func (c *Client) encodeData(data interface{}) (*bytes.Buffer, error) {
	params := bytes.NewBuffer(nil)
	if data != nil {
		if err := json.NewEncoder(params).Encode(data); err != nil {
			return nil, err
		}
	}
	return params, nil
}

func (c *Client) HTTPClient() *http.Client {
	return &http.Client{Transport: c.transport}
}

func (c *Client) clientRequest(method, path string, in io.Reader, headers map[string][]string) (io.ReadCloser, http.Header, int, error) {
	expectedPayload := (method == "POST" || method == "PUT")
	if expectedPayload && in == nil {
		in = bytes.NewReader([]byte{})
	}
	req, err := http.NewRequest(method, fmt.Sprintf("/v%s%s", api.Version, path), in)
	if err != nil {
		return nil, nil, -1, err
	}

	// Add Config's HTTP Headers 
	for k, v := range c.HttpDefaultHeaders {
		req.Header.Set(k, v)
	}

	if len(c.UserAgent) != 0 {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	req.URL.Host = c.addr
	req.URL.Scheme = c.scheme

	if headers != nil {
		for k, v := range headers {
			req.Header[k] = v
		}
	}

	if expectedPayload && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "text/plain")
	}

	resp, err := c.HTTPClient().Do(req)
	statusCode := -1
	if resp != nil {
		statusCode = resp.StatusCode
	}
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return nil, nil, statusCode, errConnectionRefused
		}

		if c.tlsConfig == nil {
			return nil, nil, statusCode, fmt.Errorf("%v. Are you trying to connect to a TLS-enabled daemon without TLS?", err)
		}
		return nil, nil, statusCode, fmt.Errorf("An error occurred trying to connect: %v", err)
	}

	if statusCode < 200 || statusCode >= 400 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, statusCode, err
		}
		if len(body) == 0 {
			return nil, nil, statusCode, fmt.Errorf("Error: request returned %s for API route and version %s, check if the server supports the requested API version", http.StatusText(statusCode), req.URL)
		}
		return nil, nil, statusCode, fmt.Errorf("Error response from daemon: %s", bytes.TrimSpace(body))
	}

	return resp.Body, resp.Header, statusCode, nil
}
