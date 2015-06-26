package restful

import (
	"net/http"
	"reflect"
	"strconv"
	"testing"
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

type Srv struct {
}

func (s *Srv) ping(w http.ResponseWriter) (int, []byte, error) {
	_, err := w.Write([]byte{'O', 'K'})
	return 0, nil, err
}

func TestRestful(t *testing.T) {

	cfg := &Config{
		Logging:     true,
		EnableCors:  true,
		CorsHeaders: "*",
		SocketGroup: "nobody",
		TLSConfig:   nil,
	}

	s := NewServer(cfg)

	srv := new(Srv)

	model := map[string]map[string]Api{
		"GET": {
			"/_ping": Api{
				reflect.TypeOf(nil),
				reflect.TypeOf(new([]byte)),
				reflect.ValueOf(srv),
				reflect.ValueOf(srv.ping),
			},
		},
		"POST": {
		//	"/containers/create/{type:.*}": s.postContainersCreate,
		},
		"DELETE": {
		//	"/containers/{name:.*}": s.deleteContainers,
		},
		"OPTIONS": {
		//	"": s.optionsHandler,
		},
	}

	p := []string{":65436"}

	s.Serve(p, model)

	// TODO: add client test
	s.Close()
}
