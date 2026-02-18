package bootstrap

import (
	"net"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/webishdev/fail2ban-dashboard/metrics"
	"github.com/webishdev/fail2ban-dashboard/server"
)

// findAvailablePort returns an available port for testing
func findAvailablePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find available port: %v", err)
	}
	defer func(listener net.Listener) {
		closeErr := listener.Close()
		if closeErr != nil {
			panic(closeErr)
		}
	}(listener)
	return listener.Addr().String()
}

func TestStartDashboardServer_Success(t *testing.T) {
	address := findAvailablePort(t)

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	config := &server.Configuration{
		Address: address,
	}

	// Start server in goroutine
	serverStarted := make(chan bool)
	go func() {
		// Signal that we're about to start
		serverStarted <- true
		StartDashboardServer(app, config)
	}()

	// Wait for server to start
	<-serverStarted
	time.Sleep(100 * time.Millisecond)

	// Verify server is listening
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Errorf("Server not listening on %s: %v", address, err)
	} else {
		closeErr := conn.Close()
		if closeErr != nil {
			return
		}
	}

	// Cleanup
	if err := app.Shutdown(); err != nil {
		t.Errorf("Failed to shutdown server: %v", err)
	}
}

func TestStartMetricsServer_Success(t *testing.T) {
	address := findAvailablePort(t)

	metricsApp := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	config := &metrics.Configuration{
		Address: address,
	}

	// Start server in goroutine
	serverStarted := make(chan bool)
	go func() {
		// Signal that we're about to start
		serverStarted <- true
		StartMetricsServer(metricsApp, config)
	}()

	// Wait for server to start
	<-serverStarted
	time.Sleep(100 * time.Millisecond)

	// Verify server is listening
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Errorf("Server not listening on %s: %v", address, err)
	} else {
		closeErr := conn.Close()
		if closeErr != nil {
			return
		}
	}

	// Cleanup
	if err := metricsApp.Shutdown(); err != nil {
		t.Errorf("Failed to shutdown server: %v", err)
	}
}

func TestStartDashboardServer_PortAlreadyInUse(t *testing.T) {
	// Mock osExit to capture the exit code
	var exitCode int
	originalExit := osExit
	osExit = func(code int) {
		exitCode = code
	}
	defer func() {
		osExit = originalExit
	}()

	// Occupy a port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	address := listener.Addr().String()
	defer func(listener net.Listener) {
		closeErr := listener.Close()
		if closeErr != nil {
			panic(closeErr)
		}
	}(listener)

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	config := &server.Configuration{
		Address: address,
	}

	// Try to start server on occupied port
	StartDashboardServer(app, config)

	// Verify osExit was called with code 1
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestStartMetricsServer_PortAlreadyInUse(t *testing.T) {
	// Mock osExit to capture the exit code
	var exitCode int
	originalExit := osExit
	osExit = func(code int) {
		exitCode = code
	}
	defer func() {
		osExit = originalExit
	}()

	// Occupy a port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	address := listener.Addr().String()
	defer func(listener net.Listener) {
		closeErr := listener.Close()
		if closeErr != nil {
			panic(closeErr)
		}
	}(listener)

	metricsApp := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	config := &metrics.Configuration{
		Address: address,
	}

	// Try to start server on occupied port
	StartMetricsServer(metricsApp, config)

	// Verify osExit was called with code 1
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestStartDashboardServer_InvalidAddress(t *testing.T) {
	// Mock osExit to capture the exit code
	var exitCode int
	originalExit := osExit
	osExit = func(code int) {
		exitCode = code
	}
	defer func() {
		osExit = originalExit
	}()

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	config := &server.Configuration{
		Address: "invalid:address:format:with:too:many:colons",
	}

	// Try to start server with invalid address
	StartDashboardServer(app, config)

	// Verify osExit was called with code 1
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}

func TestStartMetricsServer_InvalidAddress(t *testing.T) {
	// Mock osExit to capture the exit code
	var exitCode int
	originalExit := osExit
	osExit = func(code int) {
		exitCode = code
	}
	defer func() {
		osExit = originalExit
	}()

	metricsApp := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	config := &metrics.Configuration{
		Address: "invalid:address:format:with:too:many:colons",
	}

	// Try to start server with invalid address
	StartMetricsServer(metricsApp, config)

	// Verify osExit was called with code 1
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}
