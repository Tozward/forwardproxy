// Integration tests for authenticated CONNECT on a local, disposable Caddy.
package connecttest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

const (
	idle     = 250 * time.Millisecond
	pause    = 850 * time.Millisecond
	hard     = 450 * time.Millisecond
	download = 16 << 20
)

type fixture struct {
	h2, h3   string
	roots    *x509.CertPool
	origin   net.Listener
	accepted atomic.Int32
	next     chan net.Conn
}

func loopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	return ln
}

func cert(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	model := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, model, model, pub, key)
	require.NoError(t, err)
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(certPath, encoded, 0600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600))
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(encoded))
	return certPath, keyPath, roots
}

func start(t *testing.T, binary, readIdle, writeIdle, extra string, auth bool) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{origin: loopback(t), next: make(chan net.Conn, 8)}
	go func() {
		for {
			c, e := f.origin.Accept()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			// Make downstream backpressure reach the test origin promptly.
			_ = c.(*net.TCPConn).SetWriteBuffer(128 * 1024)
			f.accepted.Add(1)
			f.next <- c
		}
	}()
	ordinary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ordinary-download" {
			block := bytes.Repeat([]byte("z"), 64<<10)
			for n := 0; n < download; n += len(block) {
				if _, err := w.Write(block); err != nil {
					return
				}
			}
			return
		}
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "incomplete", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(ordinary.Close)
	tcp := loopback(t)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	f.h2, f.h3 = tcp.Addr().String(), udp.LocalAddr().String()
	certFile, keyFile, roots := cert(t, dir)
	f.roots = roots
	_, port, err := net.SplitHostPort(f.origin.Addr().String())
	require.NoError(t, err)
	authLine := ""
	if auth {
		authLine = "basic_auth integration example-pass\n probe_resistance"
	}
	source := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 storage file_system {
  root %q
 }
 servers {
  timeouts {
   read_body_idle %s
   write_idle %s
   %s
  }
 }
}
https://:%s {
 bind 127.0.0.1
 tls %q %q
 route {
  forward_proxy {
   %s
   hosts localhost
   ports %s
   acl {
    allow 127.0.0.1
    deny all
   }
  }
  reverse_proxy /ordinary* %s
  respond "site" 200
 }
}
`, filepath.Join(dir, "data"), readIdle, writeIdle, extra, strings.Split(f.h2, ":")[1], certFile, keyFile, authLine, port, ordinary.URL)
	cf := filepath.Join(dir, "Caddyfile")
	require.NoError(t, os.WriteFile(cf, []byte(source), 0600))
	env := append(os.Environ(), "XDG_CONFIG_HOME="+dir, "XDG_DATA_HOME="+dir, "QLOGDIR=")
	cmd := exec.Command(binary, "adapt", "--adapter", "caddyfile", "--config", cf)
	cmd.Env = env
	data, err := cmd.Output()
	if x, ok := err.(*exec.ExitError); ok {
		t.Fatalf("adapt: %v: %s", err, x.Stderr)
	}
	require.NoError(t, err)
	var config map[string]any
	require.NoError(t, json.Unmarshal(data, &config))
	servers := config["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, value := range servers {
		h2 := value.(map[string]any)
		h3 := map[string]any{}
		for k, v := range h2 {
			h3[k] = v
		}
		h2["listen"] = []string{f.h2}
		h2["protocols"] = []string{"h1", "h2"}
		h3["listen"] = []string{"udp/" + f.h3}
		h3["protocols"] = []string{"h3"}
		servers["isolatedH3"] = h3
		break
	}
	data, err = json.Marshal(config)
	require.NoError(t, err)
	path := filepath.Join(dir, "caddy.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	log := new(bytes.Buffer)
	cmd = exec.Command(binary, "run", "--config", path)
	cmd.Env = env
	cmd.Stdout = log
	cmd.Stderr = log
	require.NoError(t, tcp.Close())
	require.NoError(t, udp.Close())
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("isolated Caddy: %s", log.String())
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, e := net.DialTimeout("tcp4", f.h2, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return f
}

type client struct {
	http    *http.Client
	address string
	dials   atomic.Int32
}

func (f *fixture) client(t *testing.T, proto int) *client {
	t.Helper()
	c := &client{}
	tlsConfig := &tls.Config{RootCAs: f.roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	if proto == 2 {
		c.address = f.h2
		tr := &http2.Transport{TLSClientConfig: tlsConfig, DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			c.dials.Add(1)
			return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, c.address)
		}}
		c.http = &http.Client{Transport: tr}
		t.Cleanup(tr.CloseIdleConnections)
	} else {
		c.address = f.h3
		tr := &http3.Transport{TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{InitialStreamReceiveWindow: 32 << 10, MaxStreamReceiveWindow: 32 << 10},
			Dial: func(ctx context.Context, addr string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
				c.dials.Add(1)
				return quic.DialAddrEarly(ctx, c.address, cfg, qcfg)
			}}
		c.http = &http.Client{Transport: tr}
		t.Cleanup(func() { tr.Close() })
	}
	return c
}

func (f *fixture) request(t *testing.T, c *client, method, path, auth string, body io.Reader) *http.Request {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	t.Cleanup(cancel)
	r, e := http.NewRequestWithContext(ctx, method, "https://"+c.address+path, body)
	require.NoError(t, e)
	if method == http.MethodConnect {
		r.Host = f.origin.Addr().String()
	} else {
		r.Host = "localhost"
	}
	if auth != "" {
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	return r
}

func (f *fixture) tunnel(t *testing.T, c *client, auth string) (*io.PipeWriter, *http.Response, net.Conn) {
	t.Helper()
	reader, writer := io.Pipe()
	t.Cleanup(func() { writer.Close(); reader.Close() })
	response, e := c.http.Do(f.request(t, c, http.MethodConnect, "", auth, reader))
	require.NoError(t, e)
	t.Cleanup(func() { response.Body.Close() })
	require.Equal(t, 200, response.StatusCode)
	select {
	case origin := <-f.next:
		t.Cleanup(func() { origin.Close() })
		return writer, response, origin
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT never reached its intended fixture")
		return nil, nil, nil
	}
}

func syncWrite(t *testing.T, w io.Writer, data string) {
	t.Helper()
	n, e := io.WriteString(w, data)
	require.NoError(t, e)
	require.Equal(t, len(data), n)
}

func expect(t *testing.T, r io.Reader, data string) {
	t.Helper()
	b := make([]byte, len(data))
	_, e := io.ReadFull(r, b)
	require.NoError(t, e)
	require.Equal(t, data, string(b))
}

func uploadIdle(t *testing.T, f *fixture, c *client) {
	up, resp, origin := f.tunnel(t, c, "integration:example-pass")
	syncWrite(t, up, "a")
	expect(t, origin, "a")
	for end := time.Now().Add(pause); time.Now().Before(end); {
		syncWrite(t, origin, "d")
		expect(t, resp.Body, "d")
		time.Sleep(75 * time.Millisecond)
	}
	syncWrite(t, up, "b")
	expect(t, origin, "b")
	syncWrite(t, origin, "c")
	expect(t, resp.Body, "c")
	require.EqualValues(t, 1, f.accepted.Load())
	require.EqualValues(t, 1, c.dials.Load())
}

func blockWriter(t *testing.T, f *fixture, c *client, auth string, shouldResume, peerStream bool) {
	t.Helper()
	up, resp, origin := f.tunnel(t, c, auth)
	syncWrite(t, up, "a")
	expect(t, origin, "a")
	block := bytes.Repeat([]byte("z"), 64<<10)
	first := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		for written := 0; written < download; written += len(block) {
			if _, e := origin.Write(block); e != nil {
				result <- e
				return
			}
			if written == 0 {
				close(first)
			}
		}
		result <- nil
	}()
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("origin could not send the first block")
	}
	time.Sleep(pause)
	select {
	case e := <-result:
		if shouldResume {
			t.Fatalf("origin was not blocked waiting for client reads: %v", e)
		}
		require.Error(t, e, "the original write deadline should abort the stalled stream")
	default:
	}
	if peerStream {
		peerUp, peerResp, peerOrigin := f.tunnel(t, c, auth)
		syncWrite(t, peerUp, "q")
		expect(t, peerOrigin, "q")
		syncWrite(t, peerOrigin, "r")
		expect(t, peerResp.Body, "r")
	}
	hash := sha256.New()
	n, e := io.CopyN(hash, resp.Body, download)
	if !shouldResume {
		require.Error(t, e, "stream unexpectedly delivered all data after the enforced deadline")
		require.Less(t, n, int64(download))
		return
	}
	require.NoError(t, e, "stalled CONNECT must resume on the same response stream")
	expected := sha256.New()
	for i := 0; i < download/len(block); i++ {
		expected.Write(block)
	}
	require.Equal(t, expected.Sum(nil), hash.Sum(nil))
	require.NoError(t, <-result)
	syncWrite(t, up, "b")
	expect(t, origin, "b")
	syncWrite(t, origin, "c")
	expect(t, resp.Body, "c")
	require.EqualValues(t, 2, f.accepted.Load())
	require.EqualValues(t, 1, c.dials.Load())
}

func TestConnectIdle(t *testing.T) {
	binary := os.Getenv("CADDY_IDLE_TEST_BIN")
	if binary == "" {
		t.Skip("set CADDY_IDLE_TEST_BIN to the Caddy binary")
	}
	for _, proto := range []int{2, 3} {
		t.Run(fmt.Sprintf("H%d", proto), func(t *testing.T) {
			t.Run("baseline_stall", func(t *testing.T) {
				baseline := os.Getenv("CADDY_IDLE_BASELINE_BIN")
				if baseline == "" {
					t.Skip("baseline binary not supplied")
				}
				f := start(t, baseline, idle.String(), idle.String(), "", true)
				blockWriter(t, f, f.client(t, proto), "integration:example-pass", false, false)
			})
			t.Run("idle_upload", func(t *testing.T) {
				f := start(t, binary, idle.String(), idle.String(), "", true)
				uploadIdle(t, f, f.client(t, proto))
			})
			t.Run("stalled_download_and_peer", func(t *testing.T) {
				f := start(t, binary, idle.String(), idle.String(), "", true)
				blockWriter(t, f, f.client(t, proto), "integration:example-pass", true, true)
			})
			t.Run("hard_write", func(t *testing.T) {
				f := start(t, binary, idle.String(), idle.String(), "write "+hard.String(), true)
				blockWriter(t, f, f.client(t, proto), "integration:example-pass", false, false)
			})
			t.Run("hard_read", func(t *testing.T) {
				f := start(t, binary, idle.String(), idle.String(), "read_body "+hard.String(), true)
				c := f.client(t, proto)
				up, _, origin := f.tunnel(t, c, "integration:example-pass")
				syncWrite(t, up, "a")
				expect(t, origin, "a")
				require.NoError(t, origin.SetReadDeadline(time.Now().Add(2*time.Second)))
				_, err := origin.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF, "HTTP hard read deadline should close the upstream upload")
			})
			t.Run("no_auth_configured", func(t *testing.T) {
				f := start(t, binary, idle.String(), idle.String(), "", false)
				blockWriter(t, f, f.client(t, proto), "", false, false)
			})
			t.Run("wrapper_missing", func(t *testing.T) {
				for _, values := range [][2]string{{"-1ns", idle.String()}, {idle.String(), "-1ns"}, {"-1ns", "-1ns"}} {
					f := start(t, binary, values[0], values[1], "", true)
					up, resp, origin := f.tunnel(t, f.client(t, proto), "integration:example-pass")
					syncWrite(t, up, "a")
					expect(t, origin, "a")
					syncWrite(t, origin, "b")
					expect(t, resp.Body, "b")
				}
			})
			t.Run("auth_and_ordinary_http", func(t *testing.T) {
				f := start(t, binary, idle.String(), idle.String(), "", true)
				c := f.client(t, proto)
				for _, auth := range []string{"", "integration:bad"} {
					resp, err := c.http.Do(f.request(t, c, http.MethodConnect, "", auth, nil))
					require.NoError(t, err)
					b, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					require.NoError(t, err)
					require.Equal(t, "site", string(b))
				}
				require.Zero(t, f.accepted.Load())
				resp, err := c.http.Do(f.request(t, c, http.MethodPost, "/ordinary", "integration:example-pass", strings.NewReader("ok")))
				require.NoError(t, err)
				expect(t, resp.Body, "ok")
				resp.Body.Close()
				reader, writer := io.Pipe()
				t.Cleanup(func() { reader.Close(); writer.Close() })
				req := f.request(t, c, http.MethodPost, "/ordinary", "integration:example-pass", reader)
				done := make(chan bool, 1)
				go func() {
					resp, err := c.http.Do(req)
					if err != nil {
						done <- true
						return
					}
					defer resp.Body.Close()
					_, err = io.ReadAll(resp.Body)
					done <- err != nil || resp.StatusCode >= 400
				}()
				syncWrite(t, writer, "a")
				select {
				case expired := <-done:
					require.True(t, expired, "ordinary upload must be terminated by its idle deadline")
				case <-time.After(pause):
					t.Fatal("ordinary upload survived its idle deadline")
				}
				resp, err = c.http.Do(f.request(t, c, http.MethodGet, "/ordinary-download", "", nil))
				require.NoError(t, err)
				defer resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				time.Sleep(pause)
				n, err := io.CopyN(io.Discard, resp.Body, download)
				require.Error(t, err, "ordinary download must be terminated by its write idle deadline")
				require.Less(t, n, int64(download))
			})
		})
	}
}
