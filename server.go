package restful

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/listenbuffer"
	"github.com/docker/docker/pkg/sockets"
	"github.com/gorilla/mux"

	systemdActivation "github.com/coreos/go-systemd/activation"
	systemdDaemon "github.com/coreos/go-systemd/daemon"
)

type Server struct {
	cfg     *Config
	router  *mux.Router
	start   chan struct{}
	servers []serverCloser
}

func NewServer(cfg *Config) *Server {
	srv := &Server{
		cfg:   cfg,
		start: make(chan struct{}, 1),
	}
	return srv
}

type ServFunc func(w http.ResponseWriter, r *http.Request, vars map[string]string, body io.ReadCloser) (int, interface{}, error)

// Prepare loops through all of the protocols sent in to spawns
// off a go routine to setup a serving http.Server for each.
func (s *Server) Prepare(protoAddrs []string, m map[string]map[string]ServFunc) error {
	s.createRouter(m, s.cfg)

	var chErrors = make(chan error, len(protoAddrs))

	for _, protoAddr := range protoAddrs {
		protoAddrParts := strings.SplitN(protoAddr, "://", 2)
		if len(protoAddrParts) != 2 {
			return fmt.Errorf("bad format, expected PROTO://ADDR")
		}
		srvs, err := s.newServer(protoAddrParts[0], protoAddrParts[1])
		if err != nil {
			return err
		}

		s.servers = append(s.servers, srvs...)

		for _, srv := range srvs {
			logrus.Infof("Listening for HTTP on %s (%s)", protoAddrParts[0], protoAddrParts[1])
			go func(v serverCloser) {
				if err := v.Serve(); err != nil && strings.Contains(err.Error(), "use of closed network connection") {
					err = nil
				}
				chErrors <- err
			}(srv)
		}
	}

	for i := 0; i < len(protoAddrs); i++ {
		err := <-chErrors
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) AcceptConnections() {
	go systemdDaemon.SdNotify("READY=1")
	// close the lock so the listeners start accepting connections
	select {
	case <-s.start:
	default:
		close(s.start)
	}
}

func (s *Server) Close() {
	for _, srv := range s.servers {
		if err := srv.Close(); err != nil {
			logrus.Error(err)
		}
	}
}

type serverCloser interface {
	Serve() error
	Close() error
}

type httpServer struct {
	srv *http.Server
	l   net.Listener
}

func (s *httpServer) Serve() error {
	return s.srv.Serve(s.l)
}
func (s *httpServer) Close() error {
	return s.l.Close()
}

func (s *Server) createRouter(m map[string]map[string]ServFunc, cfg *Config) {
	s.router = mux.NewRouter()

	// If "api-cors-header" is not given, but "api-enable-cors" is true, we set cors to "*"
	// otherwise, all head values will be passed to HTTP handler
	corsHeaders := cfg.CorsHeaders
	if corsHeaders == "" && cfg.EnableCors {
		corsHeaders = "*"
	}

	for method, routes := range m {
		for route, fct := range routes {
			logrus.Debugf("Registering %s, %s", method, route)
			// NOTE: scope issue, make sure the variables are local and won't be changed
			localRoute := route
			localFct := fct
			localMethod := method

			// build the handler function
			f := makeHTTPHandler(cfg.Logging, localMethod, localRoute, localFct, corsHeaders)

			// add the new route
			if localRoute == "" {
				s.router.Methods(localMethod).HandlerFunc(f)
			} else {
				s.router.Path("/v{version:[0-9.]+}" + localRoute).Methods(localMethod).HandlerFunc(f)
				s.router.Path(localRoute).Methods(localMethod).HandlerFunc(f)
			}
		}
	}

	return
}

func makeHTTPHandler(logging bool, localMethod string, localRoute string, handlerFunc ServFunc, corsHeaders string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// log the request
		logrus.Debugf("Calling %s %s", localMethod, localRoute)

		if logging {
			logrus.Infof("%s %s", r.Method, r.RequestURI)
		}

		if corsHeaders != "" {
			writeCorsHeaders(w, r, corsHeaders)
		}

		switch localMethod {
		case "POST", "DELETE":
			parseMultipartForm(r)
		}

		// If contentLength is -1, we can assumed chunked encoding
		// or more technically that the length is unknown
		// https://golang.org/src/pkg/net/http/request.go#L139
		// net/http otherwise seems to swallow any headers related to chunked encoding
		// including r.TransferEncoding
		// allow a nil body for backwards compatibility
		var body io.ReadCloser
		if r.Body != nil && (r.ContentLength > 0 || r.ContentLength == -1) {
			if err := checkForJSON(r); err != nil {
				// post body must be json
				logrus.Errorf("checkForJSON returned error: %s", err)
				httpError(w, err)
				return
			}
			body = r.Body
		}

		st, out, err := handlerFunc(w, r, mux.Vars(r), body)
		if err != nil {
			logrus.Errorf("Handler for %s %s returned error: %s", localMethod, localRoute, err)
			httpError(w, err)
		}

		switch {
		case out != nil:
			writeJSON(w, st, out)
		case st != 0:
			w.WriteHeader(st)
		}
	}
}

func (s *Server) initTCPSocket(addr string) (l net.Listener, err error) {
	if s.cfg.TLSConfig == nil || s.cfg.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		logrus.Warn("/!\\ DON'T BIND ON ANY IP ADDRESS WITHOUT setting -tlsverify IF YOU DON'T KNOW WHAT YOU'RE DOING /!\\")
	}
	if l, err = sockets.NewTcpSocket(addr, s.cfg.TLSConfig, s.start); err != nil {
		return nil, err
	}
	return
}

// TODO: mutil-platform support
// newServer sets up the required serverClosers and does protocol specific checking.
func (s *Server) newServer(proto, addr string) ([]serverCloser, error) {
	var (
		err error
		ls  []net.Listener
	)
	switch proto {
	case "fd":
		ls, err = listenFD(addr)
		if err != nil {
			return nil, err
		}
		// We don't want to start serving on these sockets until the
		// daemon is initialized and installed. Otherwise required handlers
		// won't be ready.
		<-s.start
	case "tcp":
		l, err := s.initTCPSocket(addr)
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
	case "unix":
		l, err := newUnixSocket(addr, s.cfg.SocketGroup, s.start)
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
	default:
		return nil, fmt.Errorf("Invalid protocol format: %q", proto)
	}
	var res []serverCloser
	for _, l := range ls {
		res = append(res, &httpServer{
			&http.Server{
				Addr:    addr,
				Handler: s.router,
			},
			l,
		})
	}
	return res, nil
}

func newUnixSocket(path, group string, activate <-chan struct{}) (net.Listener, error) {
	if err := syscall.Unlink(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	mask := syscall.Umask(0777)
	defer syscall.Umask(mask)
	l, err := listenbuffer.NewListenBuffer("unix", path, activate)
	if err != nil {
		return nil, err
	}
	if err := setSocketGroup(path, group); err != nil {
		l.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func setSocketGroup(path, group string) error {
	if group == "" {
		return nil
	}
	if err := changeGroup(path, group); err != nil {
		logrus.Debugf("Warning: could not change group %s to %v: %v", path, group, err)
	}
	return nil
}

func changeGroup(path string, nameOrGid string) error {
	gid, err := lookupGidByName(nameOrGid)
	if err != nil {
		return err
	}
	logrus.Debugf("%s group found. gid: %d", nameOrGid, gid)
	return os.Chown(path, 0, gid)
}

func lookupGidByName(nameOrGid string) (int, error) {
	groupFile := "/etc/group"
	groups, err := parseGroupFileFilter(groupFile, func(g userGroup) bool {
		return g.Name == nameOrGid || strconv.Itoa(g.Gid) == nameOrGid
	})
	if err != nil {
		return -1, err
	}
	if groups != nil && len(groups) > 0 {
		return groups[0].Gid, nil
	}
	gid, err := strconv.Atoi(nameOrGid)
	if err == nil {
		logrus.Warnf("Could not find GID %d", gid)
		return gid, nil
	}
	return -1, fmt.Errorf("Group %s not found", nameOrGid)
}

type userGroup struct {
	Name string
	Pass string
	Gid  int
	List []string
}

func parseGroupFileFilter(path string, filter func(userGroup) bool) ([]userGroup, error) {
	group, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer group.Close()
	return parseGroupFilter(group, filter)
}

func parseGroupFilter(r io.Reader, filter func(userGroup) bool) ([]userGroup, error) {
	if r == nil {
		return nil, fmt.Errorf("nil source for group-formatted data")
	}

	var (
		s   = bufio.NewScanner(r)
		out = []userGroup{}
	)

	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}

		text := s.Text()
		if text == "" {
			continue
		}

		// see: man 5 group
		//  group_name:password:GID:user_list
		// Name:Pass:Gid:List
		//  root:x:0:root
		//  adm:x:4:root,adm,daemon
		p := userGroup{}
		parseLine(
			text,
			&p.Name, &p.Pass, &p.Gid, &p.List,
		)

		if filter == nil || filter(p) {
			out = append(out, p)
		}
	}

	return out, nil
}

func parseLine(line string, v ...interface{}) {
	if line == "" {
		return
	}

	parts := strings.Split(line, ":")
	for i, p := range parts {
		if len(v) <= i {
			// if we have more "parts" than we have places to put them, bail for great "tolerance" of naughty configuration files
			break
		}

		switch e := v[i].(type) {
		case *string:
			// "root", "adm", "/bin/bash"
			*e = p
		case *int:
			// "0", "4", "1000"
			// ignore string to int conversion errors, for great "tolerance" of naughty configuration files
			*e, _ = strconv.Atoi(p)
		case *[]string:
			// "", "root", "root,adm,daemon"
			if p != "" {
				*e = strings.Split(p, ",")
			} else {
				*e = []string{}
			}
		default:
			// panic, because this is a programming/logic error, not a runtime one
			panic("parseLine expects only pointers!  argument " + strconv.Itoa(i) + " is not a pointer!")
		}
	}
}

// listenFD returns the specified socket activated files as a slice of
// net.Listeners or all of the activated files if "*" is given.
func listenFD(addr string) ([]net.Listener, error) {
	// socket activation
	listeners, err := systemdActivation.Listeners(false)
	if err != nil {
		return nil, err
	}

	if listeners == nil || len(listeners) == 0 {
		return nil, fmt.Errorf("No sockets found")
	}

	// default to all fds just like unix:// and tcp://
	if addr == "" {
		addr = "*"
	}

	fdNum, _ := strconv.Atoi(addr)
	fdOffset := fdNum - 3
	if (addr != "*") && (len(listeners) < int(fdOffset)+1) {
		return nil, fmt.Errorf("Too few socket activated files passed in")
	}

	if addr == "*" {
		return listeners, nil
	}

	return []net.Listener{listeners[fdOffset]}, nil
}
