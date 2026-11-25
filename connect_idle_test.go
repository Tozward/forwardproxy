package forwardproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
	onWrite  time.Time
}

func (r *deadlineRecorder) SetReadDeadline(time.Time) error { return nil }

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline = deadline
	return nil
}

func (r *deadlineRecorder) Write(p []byte) (int, error) {
	r.onWrite = r.deadline
	return r.ResponseRecorder.Write(p)
}

func TestAuthenticatedConnectWriteIdleOverride(t *testing.T) {
	const minRate = 4096
	const maxChunk = 8192
	for _, major := range []int{2, 3} {
		for _, hard := range []bool{false, true} {
			t.Run(fmt.Sprintf("H%d/hard=%t", major, hard), func(t *testing.T) {
				start := time.Now()
				rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
				ctrl := http.NewResponseController(rec)
				reader := &caddyhttp.IdleTimeoutReader{
					ReadCloser: io.NopCloser(strings.NewReader("")),
					Ctrl:       ctrl,
					Deadline:   caddyhttp.IdleDeadline{Start: start, Timeout: time.Minute},
					Logger:     zap.NewNop(),
				}
				writer := &caddyhttp.IdleTimeoutWriter{
					ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: rec},
					Ctrl:                  ctrl,
					Deadline:              caddyhttp.IdleDeadline{Start: start, Timeout: time.Minute, MinRate: minRate},
					MaxChunk:              maxChunk,
					Logger:                zap.NewNop(),
					ClearBetweenWrites:    major == 2,
				}
				if hard {
					writer.Deadline.HardDeadline = start.Add(75 * time.Second)
				}
				ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
				ctx = caddyhttp.ContextWithIdleTimeouts(ctx, reader, writer)
				const authority = "127.0.0.1:8443"
				req := (&http.Request{
					Method: http.MethodConnect, URL: &url.URL{Host: authority}, Host: authority,
					ProtoMajor: major, Body: reader, Header: make(http.Header),
				}).WithContext(ctx)
				auth := base64.StdEncoding.EncodeToString([]byte("integration:example-pass"))
				req.Header.Set("Proxy-Authorization", "Basic "+auth)

				target, origin := net.Pipe()
				defer target.Close()
				defer origin.Close()
				go func() {
					defer origin.Close()
					_, _ = io.WriteString(origin, "x")
				}()
				allow, err := newACLRule("127.0.0.1", true)
				if err != nil {
					t.Fatal(err)
				}
				handler := Handler{
					AuthCredentials: [][]byte{[]byte(auth)},
					HideIP:          true,
					aclRules:        []aclRule{allow},
					dialContext: func(context.Context, string, string) (net.Conn, error) {
						return target, nil
					},
				}
				if err := handler.ServeHTTP(writer, req, nil); err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusOK || rec.Body.String() != "x" {
					t.Fatalf("CONNECT response = %d %q", rec.Code, rec.Body.String())
				}
				if reader.Deadline.Timeout != 24*time.Hour || writer.Deadline.Timeout != 300*time.Second {
					t.Fatalf("read/write timeout = %v/%v", reader.Deadline.Timeout, writer.Deadline.Timeout)
				}
				if writer.Deadline.MinRate != minRate || writer.MaxChunk != maxChunk {
					t.Fatalf("minimum rate or max chunk changed: %d, %d", writer.Deadline.MinRate, writer.MaxChunk)
				}
				if hard {
					if !rec.onWrite.Equal(writer.Deadline.HardDeadline) {
						t.Fatalf("effective write deadline = %v; want hard deadline %v", rec.onWrite, writer.Deadline.HardDeadline)
					}
				} else if rec.onWrite.Before(start.Add(300*time.Second)) || rec.onWrite.After(time.Now().Add(301*time.Second)) {
					t.Fatalf("effective write deadline = %v; want a finite 300s window", rec.onWrite)
				}
			})
		}
	}
}
