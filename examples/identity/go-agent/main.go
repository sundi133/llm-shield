// Command go-agent is a minimal Go workload that authenticates to Shield using a
// SPIFFE X.509 SVID over mTLS, mirroring examples/langchain/spiffe_guarded_e2e.py.
//
// It fetches its SVID from the SPIRE Agent Workload API socket (auto-rotated by
// go-spiffe's X509Source — do NOT cache the cert yourself), presents it via mTLS
// to the Envoy front door, and mints a Shield agent token.
//
//	SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock \
//	SHIELD_ENVOY=https://envoy:8443 \
//	  go run .
//
// Trust: Envoy performs the real mTLS verification and injects the identity to
// Shield; this client only needs to present a valid SVID.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	envoy := getenv("SHIELD_ENVOY", "https://envoy:8443")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// X509Source streams the SVID + trust bundle from the Workload API socket and
	// rotates transparently. SPIFFE_ENDPOINT_SOCKET selects the socket.
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("fetch SVID from Workload API: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("no SVID: %v", err)
	}
	log.Printf("workload identity: %s", svid.ID)

	// mTLS to Envoy: present our SVID, trust the SPIFFE bundle. AuthorizeAny()
	// because Envoy (not this client) enforces which server identity to accept.
	tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	body, _ := json.Marshal(map[string]any{
		"user_sub":          svid.ID.String(),
		"agent_id":          "go-agent",
		"agent_instance_id": "proc-1",
		"tenant_id":         "bank-co",
		"build_hash":        "dev",
		"model_version":     "n/a",
		"session_id":        "s-1",
	})
	token, err := mintAgentToken(client, envoy, body)
	if err != nil {
		log.Fatalf("mint agent token: %v", err)
	}
	fmt.Printf("agent token minted via SPIFFE identity (len=%d)\n", len(token))
	// From here: send X-Agent-Token on /cap/mint per tool call, then guarded calls.
}

func mintAgentToken(client *http.Client, envoy string, body []byte) (string, error) {
	req, err := http.NewRequest(http.MethodPost, envoy+"/v1/shield/auth/agent-token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(data))
	}
	var out struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.AgentToken, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
