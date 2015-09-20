### restful 
[![GoDoc](https://godoc.org/github.com/tomasen/restful?status.svg)](http://godoc.org/github.com/tomasen/restful)

Model-driven, RESTful api server framework in golang

#### Concept and Goals

Model-driven software development (MDSD) is an alternative to round-trip engineering. Round-trip engineering is the concept of being able to make any kind of change to a model as well as to the code generated from that model. The changes always propagate bidirectional and both artifacts are always consistent. The transition from code to model (the reverse engineering) is especially interesting in this context.

By that, it means most source code (interfaces for both client and server) can be generated based on an ontological model which to be more specificed - an API protocol scheme definition in a format such as JSON.  

#### Usage

1. preparing api's data model

```Go
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
```

2. writing server-side implementation

```Go

type T struct {}

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
```

and begin to serv

```Go
cfg := &Config{
	Logging:     true,
	EnableCors:  true,
	CorsHeaders: "*",
	SocketGroup: "nobody",
	TLSConfig:   nil,
}

s := NewServer(cfg)

p := []string{"tcp://:80"}

go func() {
	err := s.Prepare(p, model)
	if err != nil {
		t.Fatalf("Server preparation failed %v", err)
	}
}()

s.AcceptConnections()

defer s.Close()
```

3. writing client side

```Go
c := NewClient("", "tcp", "127.0.0.1:65436", nil)

r, _, n, err := c.Call("GET", "/ping", nil, nil)

r, _, n, err = c.Call("POST",
	"/foobar/create/foo",
	map[string]int{"foo": 1, "bar": 2},
	map[string][]string{"foo": []string{"bar"}},
)

r, _, n, err = c.Call("DELETE",
	"/foobar/foo",
	nil,
	nil,
)

r, _, n, err = c.Call("OPTIONS",
	"",
	nil,
	nil,
)
```

#### TODO

* source code generator

