package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"agent_ssh/internal/audit"
	"agent_ssh/internal/localssh"
	"agent_ssh/internal/platform"
	"agent_ssh/internal/reverseagent"
	"agent_ssh/internal/state"
	"agent_ssh/internal/telemetry"
	"agent_ssh/internal/tools"
	"agent_ssh/internal/tunnel"
	"golang.org/x/crypto/ssh"
)

type runtimeFile struct {
	Address string `json:"address"`
	Token   string `json:"token"`
}

type Status struct {
	ConfigurationID string             `json:"configuration_id,omitempty"`
	Phase           string             `json:"phase"`
	PID             int                `json:"pid,omitempty"`
	DeviceID        string             `json:"device_id,omitempty"`
	Destination     string             `json:"destination,omitempty"`
	RemoteAddress   string             `json:"remote_address,omitempty"`
	RemotePort      int                `json:"remote_port,omitempty"`
	LocalAddress    string             `json:"local_address,omitempty"`
	HostKey         string             `json:"host_key,omitempty"`
	AgentEndpoint   string             `json:"agent_endpoint,omitempty"`
	AgentSocket     string             `json:"agent_socket,omitempty"`
	RelayCommand    string             `json:"relay_command,omitempty"`
	Shell           string             `json:"shell,omitempty"`
	WorkDir         string             `json:"work_dir,omitempty"`
	Attempt         int                `json:"attempt,omitempty"`
	LastError       string             `json:"last_error,omitempty"`
	ErrorCode       string             `json:"error_code,omitempty"`
	Metrics         telemetry.Snapshot `json:"metrics"`
	Identity        map[string]string  `json:"identity,omitempty"`
	UpdatedAt       time.Time          `json:"updated_at,omitzero"`
	StartedAt       time.Time          `json:"started_at,omitzero"`
	OnlineSince     time.Time          `json:"online_since,omitzero"`
	// Reconnects counts returns to online after the first connection.
	Reconnects int `json:"reconnects"`
}

type Options struct {
	StateDir       string
	WorkDir        string
	Shell          string
	Tunnel         tunnel.Config
	AllowClipboard bool
	NoAudit        bool
	EventsFile     string
	EventWebhook   string
}

// Only hashes public connection settings and paths, never private key bytes.
func configurationID(opts Options) string {
	opts.Tunnel.LocalAddress = ""
	if opts.Tunnel.Effective != "" {
		opts.Tunnel.SSHArgs = nil
	}
	b, _ := json.Marshal(opts)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func acquire(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := platform.Lock(filepath.Join(dir, "instance.lock"))
	if err != nil {
		return nil, fmt.Errorf("profile is in use (choose another --state-dir for another connection): %w", err)
	}
	return f, nil
}

func run(opts Options) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runContext(ctx, opts, os.Stderr)
}

func runContext(parent context.Context, opts Options, diagnostics io.Writer) error {
	lock, err := acquire(opts.StateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := state.Init(opts.StateDir); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(diagnostics, nil))
	var auditLog *audit.Log
	if !opts.NoAudit {
		if auditLog, err = audit.Open(opts.StateDir); err != nil {
			return err
		}
		defer auditLog.Close()
	}
	var mu sync.Mutex
	var status Status
	toolService := tools.New(tools.Config{Shell: opts.Shell, WorkDir: opts.WorkDir, StateDir: opts.StateDir, AllowClipboard: opts.AllowClipboard, Audit: auditLog, Connection: func() any { mu.Lock(); defer mu.Unlock(); return status }})
	defer toolService.Close()
	metrics := &telemetry.Metrics{}
	eventPath := opts.EventsFile
	if eventPath == "" {
		eventPath = filepath.Join(opts.StateDir, "events.jsonl")
	}
	events, err := telemetry.NewEvents(ctx, eventPath, opts.EventWebhook, logger)
	if err != nil {
		return err
	}
	defer events.Close()
	defer events.Emit(telemetry.Event{Phase: "stopped"})
	signer, err := state.HostSigner(opts.StateDir)
	if err != nil {
		return err
	}
	agentServer, err := reverseagent.Start()
	if err != nil {
		return err
	}
	defer agentServer.Close()
	opts.Tunnel.ForwardAgent = agentServer.Endpoint
	listener, localDone, err := localssh.StartWithTools(ctx, opts.StateDir, opts.Shell, opts.WorkDir, logger, toolService.Handle, metrics, auditLog, agentServer.PublicKey)
	if err != nil {
		return err
	}
	defer listener.Close()
	opts.Tunnel.LocalAddress = listener.Addr().String()
	pub := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	opts.Tunnel.HostKey = pub
	mu.Lock()
	status = Status{
		ConfigurationID: configurationID(opts),
		Phase:           "starting", PID: os.Getpid(), DeviceID: ssh.FingerprintSHA256(signer.PublicKey()),
		Destination: opts.Tunnel.Destination, RemoteAddress: fmt.Sprintf("127.0.0.1:%d", opts.Tunnel.RemotePort),
		LocalAddress: listener.Addr().String(), HostKey: pub, Shell: opts.Shell, WorkDir: opts.WorkDir,
		AgentEndpoint: agentServer.Endpoint,
		UpdatedAt:     time.Now().UTC(), StartedAt: time.Now().UTC(),
	}
	status.Identity = localIdentity()
	mu.Unlock()
	control, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer control.Close()
	token, err := state.Token()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	registerToolControl(mux, toolService.Handle)
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		snapshot := status
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot)
	})
	mux.HandleFunc("POST /stop", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted); cancel() })
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})}
	controlDone := make(chan error, 1)
	go func() { controlDone <- server.Serve(control) }()
	defer server.Close()
	runtimePath := filepath.Join(opts.StateDir, "runtime.json")
	if err := state.WriteJSON(runtimePath, runtimeFile{Address: control.Addr().String(), Token: token}); err != nil {
		return err
	}
	defer os.Remove(runtimePath)
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); monitorHealth(monitorCtx, opts.Tunnel, metrics, &mu, &status) }()
	defer func() { stopMonitor(); <-monitorDone }()
	tunnelDone := make(chan error, 1)
	wasOnline := false
	go func() {
		tunnelDone <- tunnel.Run(ctx, opts.Tunnel, logger, diagnostics, func(u tunnel.Update) {
			mu.Lock()
			defer mu.Unlock()
			if u.Phase == "online" && status.Phase != "online" {
				if wasOnline {
					status.Reconnects++
				}
				wasOnline = true
				status.OnlineSince = time.Now().UTC()
			} else if u.Phase != "online" {
				status.OnlineSince = time.Time{}
			}
			status.Phase, status.Attempt, status.LastError, status.UpdatedAt = u.Phase, u.Attempt, u.Error, time.Now().UTC()
			status.ErrorCode = telemetry.Classify(u.Error)
			events.Emit(telemetry.Event{Phase: u.Phase, Error: u.Error, ErrorCode: status.ErrorCode, Port: u.RemotePort})
			status.AgentSocket = u.AgentSocket
			status.RemotePort = u.RemotePort
			if u.RemotePort > 0 {
				status.RemoteAddress = fmt.Sprintf("127.0.0.1:%d", u.RemotePort)
			}
			status.RelayCommand = ""
			if u.Phase == "online" {
				status.RelayCommand = tunnel.RelayCommand(u.RemotePort, pub, u.AgentSocket)
			}
		})
	}()
	select {
	case <-ctx.Done():
		cancel()
		<-tunnelDone
		<-localDone
		return nil
	case err := <-localDone:
		cancel()
		<-tunnelDone
		return fmt.Errorf("local SSH server stopped: %v", err)
	case err := <-controlDone:
		cancel()
		<-tunnelDone
		<-localDone
		return fmt.Errorf("control server stopped: %v", err)
	case err := <-tunnelDone:
		cancel()
		<-localDone
		return err
	}
}

func controlRequest(dir, method, endpoint string) ([]byte, error) {
	var runtime runtimeFile
	if err := state.ReadJSON(filepath.Join(dir, "runtime.json"), &runtime); err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(runtime.Address)
	if err != nil || host != "127.0.0.1" {
		return nil, errors.New("invalid local control address")
	}
	req, err := http.NewRequest(method, "http://"+runtime.Address+endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+runtime.Token)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("local control: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65536))
}

func getStatus(dir string) (Status, error) {
	b, err := controlRequest(dir, http.MethodGet, "/status")
	if err != nil {
		return Status{Phase: "stopped"}, err
	}
	var s Status
	err = json.Unmarshal(b, &s)
	return s, err
}
