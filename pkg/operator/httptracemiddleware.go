/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package operator

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http/httptrace"
	"strings"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// tracedOperations is the set of EC2 operations we want httptrace diagnostics on.
var tracedOperations = map[string]struct{}{
	"TerminateInstances": {},
	"DescribeInstances":  {},
}

// HTTPTraceMiddleware adds net/http/httptrace instrumentation to specific EC2 API calls
// so we can observe DNS, TLS, connection reuse, and timing at the HTTP/1.1 level.
// It also logs request headers and SigV4 signature details after signing is complete.
func HTTPTraceMiddleware(stack *smithymiddleware.Stack) error {
	if err := stack.Finalize.Add(&httpTraceMiddleware{}, smithymiddleware.Before); err != nil {
		return err
	}
	// Insert after signing so we can see the Authorization header and X-Amz-Date
	return stack.Finalize.Insert(&sigV4LogMiddleware{}, "Signing", smithymiddleware.After)
}

type httpTraceMiddleware struct{}

func (*httpTraceMiddleware) ID() string { return "HTTPTraceMiddleware" }

func (*httpTraceMiddleware) HandleFinalize(ctx context.Context, in smithymiddleware.FinalizeInput, next smithymiddleware.FinalizeHandler) (smithymiddleware.FinalizeOutput, smithymiddleware.Metadata, error) {
	op := awsmiddleware.GetOperationName(ctx)
	if _, ok := tracedOperations[op]; !ok {
		return next.HandleFinalize(ctx, in)
	}
	logger := log.FromContext(ctx).WithValues("operation", op)
	var (
		dnsStart     time.Time
		connStart    time.Time
		tlsStart     time.Time
		gotFirstByte time.Time
	)
	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dur := time.Since(dnsStart)
			if info.Err != nil {
				logger.V(1).Info("httptrace: DNS lookup failed", "duration", dur, "error", info.Err)
			} else {
				addrs := make([]string, len(info.Addrs))
				for i, a := range info.Addrs {
					addrs[i] = a.String()
				}
				logger.V(1).Info("httptrace: DNS resolved", "duration", dur, "addrs", addrs)
			}
		},
		ConnectStart: func(network, addr string) {
			connStart = time.Now()
			logger.V(1).Info("httptrace: connecting", "network", network, "addr", addr)
		},
		ConnectDone: func(network, addr string, err error) {
			dur := time.Since(connStart)
			if err != nil {
				logger.V(1).Info("httptrace: connect failed", "network", network, "addr", addr, "duration", dur, "error", err)
			} else {
				logger.V(1).Info("httptrace: connected", "network", network, "addr", addr, "duration", dur)
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			dur := time.Since(tlsStart)
			if err != nil {
				logger.V(1).Info("httptrace: TLS handshake failed", "duration", dur, "error", err)
			} else {
				logger.V(1).Info("httptrace: TLS handshake done", "duration", dur, "version", fmt.Sprintf("0x%04x", state.Version), "cipherSuite", tls.CipherSuiteName(state.CipherSuite))
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			logger.V(1).Info("httptrace: got conn", "reused", info.Reused, "wasIdle", info.WasIdle, "idleTime", info.IdleTime, "localAddr", info.Conn.LocalAddr(), "remoteAddr", info.Conn.RemoteAddr())
		},
		GotFirstResponseByte: func() {
			gotFirstByte = time.Now()
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)
	start := time.Now()
	if req, ok := in.Request.(*smithyhttp.Request); ok {
		logger.V(1).Info("httptrace: request start", "method", req.Method, "url", req.URL.String())
	}
	out, md, err := next.HandleFinalize(ctx, in)
	total := time.Since(start)
	ttfb := time.Duration(0)
	if !gotFirstByte.IsZero() {
		ttfb = gotFirstByte.Sub(start)
	}
	reqID, _ := awsmiddleware.GetRequestIDMetadata(md)
	logKV := []any{"requestID", reqID, "totalDuration", total, "ttfb", ttfb}
	if err != nil {
		logger.V(1).Info("httptrace: request failed", append(logKV, "error", err)...)
	} else {
		logger.V(1).Info("httptrace: request complete", logKV...)
	}
	return out, md, err
}

// sigV4LogMiddleware logs request headers and SigV4 signature details after signing.
type sigV4LogMiddleware struct{}

func (*sigV4LogMiddleware) ID() string { return "SigV4LogMiddleware" }

func (*sigV4LogMiddleware) HandleFinalize(ctx context.Context, in smithymiddleware.FinalizeInput, next smithymiddleware.FinalizeHandler) (smithymiddleware.FinalizeOutput, smithymiddleware.Metadata, error) {
	op := awsmiddleware.GetOperationName(ctx)
	if _, ok := tracedOperations[op]; !ok {
		return next.HandleFinalize(ctx, in)
	}
	logger := log.FromContext(ctx).WithValues("operation", op)
	if req, ok := in.Request.(*smithyhttp.Request); ok {
		amzDate := req.Header.Get("X-Amz-Date")
		authHeader := req.Header.Get("Authorization")
		amzSecurityToken := req.Header.Get("X-Amz-Security-Token")
		logKV := []any{
			"X-Amz-Date", amzDate,
			"Host", req.Header.Get("Host"),
			"Content-Type", req.Header.Get("Content-Type"),
			"hasSecurityToken", amzSecurityToken != "",
		}
		// Parse the SigV4 Authorization header to extract credential scope and signed headers
		// Format: AWS4-HMAC-SHA256 Credential=.../20260302/us-west-2/ec2/aws4_request, SignedHeaders=..., Signature=...
		if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
			for _, part := range strings.Split(authHeader, ", ") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "AWS4-HMAC-SHA256 Credential=") {
					logKV = append(logKV, "sigv4Credential", strings.TrimPrefix(part, "AWS4-HMAC-SHA256 "))
				} else if strings.HasPrefix(part, "Credential=") {
					logKV = append(logKV, "sigv4Credential", part)
				} else if strings.HasPrefix(part, "SignedHeaders=") {
					logKV = append(logKV, "sigv4SignedHeaders", part)
				} else if strings.HasPrefix(part, "Signature=") {
					// Log only first 12 chars of signature for identification without leaking full sig
					sig := strings.TrimPrefix(part, "Signature=")
					if len(sig) > 12 {
						sig = sig[:12] + "..."
					}
					logKV = append(logKV, "sigv4SignaturePrefix", sig)
				}
			}
		}
		// Log the signing timestamp vs current wall clock to detect drift
		if amzDate != "" {
			if signTime, parseErr := time.Parse("20060102T150405Z", amzDate); parseErr == nil {
				logKV = append(logKV, "sigv4SignAge", time.Since(signTime))
			}
		}
		logger.V(1).Info("httptrace: post-signing headers", logKV...)
	}
	return next.HandleFinalize(ctx, in)
}
