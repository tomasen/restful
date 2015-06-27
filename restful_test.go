package restful

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"runtime/debug"
	"strconv"
	"testing"

	"github.com/Sirupsen/logrus"
)

type F struct {
}

func (f *F) Fct0() {}
func (f *F) Fct1() {}
func (f *F) Fct2() {}
func (f *F) Fct3() {}
func (f *F) Fct4() {}
func (f *F) Fct5() {}
func (f *F) Fct6() {}
func (f *F) Fct7() {}
func (f *F) Fct8() {}
func (f *F) Fct9() {}

func BenchmarkSwitch(b *testing.B) {
	f := new(F)
	for n := 0; n < b.N; n++ {
		fname := "Fct" + strconv.Itoa(n%10)
		switch fname {
		case "Fct0":
			f.Fct0()
		case "Fct1":
			f.Fct1()
		case "Fct2":
			f.Fct2()
		case "Fct3":
			f.Fct3()
		case "Fct4":
			f.Fct4()
		case "Fct5":
			f.Fct5()
		case "Fct6":
			f.Fct6()
		case "Fct7":
			f.Fct7()
		case "Fct8":
			f.Fct8()
		case "Fct9":
			f.Fct9()
		}
	}
}

func BenchmarkReflect(b *testing.B) {
	f := new(F)
	for n := 0; n < b.N; n++ {
		fname := "Fct" + strconv.Itoa(n%10)

		reflect.ValueOf(f).MethodByName(fname).Call([]reflect.Value{})
	}
}

type T struct {
}

func (t *T) ping(w http.ResponseWriter, r *http.Request, vars map[string]string, body io.ReadCloser) (int, interface{}, error) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte{'O', 'K'})
	return 0, nil, err
}

func (t *T) postFoobarCreate(w http.ResponseWriter, r *http.Request, vars map[string]string, body io.ReadCloser) (int, interface{}, error) {
	var v map[string]int

	err := json.NewDecoder(body).Decode(&v)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}

	b, err := json.Marshal(v)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}

	ret := map[string]string{
		"id":   "1",
		"type": vars["type"],
		"form": r.Form.Get("foo"),
		"json": string(b),
	}
	return http.StatusCreated, ret, nil
}

func (t *T) deleteFoobars(w http.ResponseWriter, r *http.Request, vars map[string]string, body io.ReadCloser) (int, interface{}, error) {
	return http.StatusNoContent, nil, nil
}

func (t *T) optionsHandler(w http.ResponseWriter, r *http.Request, vars map[string]string, body io.ReadCloser) (int, interface{}, error) {
	opt := map[string]int{
		"foo": 1,
		"bar": 2,
	}
	return http.StatusOK, opt, nil
}

func TestRestful(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			log.Println("Recovered in", r, ":")
			log.Println(string(debug.Stack()))
		}
	}()

	cfg := &Config{
		Logging:     true,
		EnableCors:  true,
		CorsHeaders: "*",
		SocketGroup: "nobody",
		TLSConfig:   nil,
	}

	s := NewServer(cfg)

	t0 := new(T)

	model := map[string]map[string]ServFunc{
		"GET": {
			"/ping": t0.ping,
		},
		"POST": {
			"/foobar/create/{type:.*}": t0.postFoobarCreate,
		},
		"DELETE": {
			"/foobar/{name:.*}": t0.deleteFoobars,
		},
		"OPTIONS": {
			"": t0.optionsHandler,
		},
	}

	p := []string{"tcp://0.0.0.0:65436"}


	go s.Serve(p, model)

	// TODO: fail if port already been occupied
	s.AcceptConnections()

	c := NewClient("", "tcp", "127.0.0.1:65436", nil)

	r, _, n, err := c.Call("GET", "/ping", nil, nil)
	err = EqualTest(r, n, err, []byte("OK"), http.StatusOK)
	if err != nil {
		t.Fatalf("GET test failed %v", err)
	}

	r, _, n, err = c.Call("POST",
		"/foobar/create/foo",
		map[string]int{"foo": 1, "bar": 2},
		map[string][]string{"foo": []string{"bar"}},
	)
	err = EqualTest(r, n, err, []byte("{\"form\":\"\",\"id\":\"1\",\"json\":\"{\\\"bar\\\":2,\\\"foo\\\":1}\",\"type\":\"foo\"}\n"), http.StatusCreated)
	if err != nil {
		t.Fatalf("POST test failed %v", err)

	}

	r, _, n, err = c.Call("DELETE",
		"/foobar/foo",
		nil,
		nil,
	)
	err = EqualTest(r, n, err, nil, http.StatusNoContent)
	if err != nil {
		t.Fatalf("DELETE test failed %v", err)
	}

	r, _, n, err = c.Call("OPTIONS",
		"",
		nil,
		nil,
	)
	err = EqualTest(r, n, err, []byte("{\"bar\":2,\"foo\":1}\n"), http.StatusOK)
	if err != nil {
		t.Fatalf("OPTIONS test failed %v", err)
	}

	s.Close()
}

func EqualTest(r io.ReadCloser, n0 int, err error, b1 []byte, n1 int) error {
	if err != nil {
		return err
	}

	if b1 != nil {
		b0, err := ioutil.ReadAll(r)
		if err != nil || bytes.Compare(b0, b1) != 0 {
			return fmt.Errorf("response does not match")
		}
	}

	if n0 != n1 {
		return fmt.Errorf("status code does not match %v %v", n0, n1)
	}
	return nil
}
