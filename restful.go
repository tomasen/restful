package restful

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api"
)

type Config struct {
	Logging     bool
	EnableCors  bool
	CorsHeaders string
	SocketGroup string
	TLSConfig   *tls.Config
}

type Api struct {
	TypeIn  reflect.Type
	TypeOut reflect.Type
	Target  reflect.Value
	Func    reflect.Value
}

// Check to make sure request's Content-Type is application/json
func checkForJson(r *http.Request) error {
	ct := r.Header.Get("Content-Type")

	// No Content-Type header is ok as long as there's no Body
	if ct == "" {
		if r.Body == nil || r.ContentLength == 0 {
			return nil
		}
	}

	// Otherwise it better be json
	if api.MatchesContentType(ct, "application/json") {
		return nil
	}
	return fmt.Errorf("Content-Type specified (%s) must be 'application/json'", ct)
}

func writeCorsHeaders(w http.ResponseWriter, r *http.Request, corsHeaders string) {
	logrus.Debugf("CORS header is enabled and set to: %s", corsHeaders)
	w.Header().Add("Access-Control-Allow-Origin", corsHeaders)
	w.Header().Add("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, X-Registry-Auth")
	w.Header().Add("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, OPTIONS")
}

func httpError(w http.ResponseWriter, err error) {
	if err == nil || w == nil {
		logrus.WithFields(logrus.Fields{"error": err, "writer": w}).Error("unexpected HTTP error handling")
		return
	}
	statusCode := http.StatusInternalServerError
	// FIXME: this is brittle and should not be necessary.
	// If we need to differentiate between different possible error types, we should
	// create appropriate error types with clearly defined meaning.
	errStr := strings.ToLower(err.Error())
	for keyword, status := range map[string]int{
		"not found":             http.StatusNotFound,
		"no such":               http.StatusNotFound,
		"bad parameter":         http.StatusBadRequest,
		"conflict":              http.StatusConflict,
		"impossible":            http.StatusNotAcceptable,
		"wrong login/password":  http.StatusUnauthorized,
		"hasn't been activated": http.StatusForbidden,
	} {
		if strings.Contains(errStr, keyword) {
			statusCode = status
			break
		}
	}

	logrus.WithFields(logrus.Fields{"statusCode": statusCode, "err": err}).Error("HTTP Error")
	http.Error(w, err.Error(), statusCode)
}

// writeJSON writes the value v to the http response stream as json with standard
// json encoding.
func writeJSON(w http.ResponseWriter, code int, v interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(v)
}
