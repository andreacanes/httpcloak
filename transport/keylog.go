// keylog.go provides TLS key logging for traffic analysis with Wireshark.
//
// This implements the SSLKEYLOGFILE format that allows Wireshark to decrypt
// TLS traffic when the key log file is configured in Wireshark's settings.
//
// Usage:
//
//	// Automatic: reads from SSLKEYLOGFILE environment variable
//	// Just set SSLKEYLOGFILE=/path/to/keys.log before running
//
//	// Manual: set a specific file
//	transport.SetKeyLogFile("/path/to/keys.log")
//
//	// Custom writer
//	transport.SetKeyLogWriter(myWriter)
package transport

import (
	"io"
	"os"
	"sync"
)

var (
	globalKeyLogWriter io.Writer
	globalKeyLogMu     sync.RWMutex
	keyLogInitialized  bool
)

// init checks the SSLKEYLOGFILE environment variable on startup
func init() {
	initKeyLogFromEnv()
}

// initKeyLogFromEnv initializes the global writer from SSLKEYLOGFILE env var
func initKeyLogFromEnv() {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	if keyLogInitialized {
		return
	}
	keyLogInitialized = true

	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		// Silently ignore errors - this is a debug feature
		return
	}
	globalKeyLogWriter = f
}

// GetKeyLogWriter returns the global key log writer, or nil if not configured.
// This is used internally by transport code to set tls.Config.KeyLogWriter.
func GetKeyLogWriter() io.Writer {
	globalKeyLogMu.RLock()
	defer globalKeyLogMu.RUnlock()
	return globalKeyLogWriter
}

// SetKeyLogFile sets the global key log file path.
// This overrides the SSLKEYLOGFILE environment variable.
// Pass empty string to disable key logging.
func SetKeyLogFile(path string) error {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	// Close existing writer if it's a file we opened
	if closer, ok := globalKeyLogWriter.(io.Closer); ok {
		closer.Close()
	}
	globalKeyLogWriter = nil

	if path == "" {
		return nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	globalKeyLogWriter = f
	return nil
}

// SetKeyLogWriter sets a custom key log writer.
// This allows writing to any io.Writer (e.g., a buffer for testing).
// Pass nil to disable key logging.
func SetKeyLogWriter(w io.Writer) {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	// Close existing writer if it's a file we opened
	if closer, ok := globalKeyLogWriter.(io.Closer); ok {
		closer.Close()
	}
	globalKeyLogWriter = w
}

// NewKeyLogFileWriter creates a new key log writer for a specific file.
// This is useful for session-level key logging that doesn't affect the global writer.
// The caller is responsible for closing the returned writer.
func NewKeyLogFileWriter(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
}

// CloseKeyLog closes the global key log writer if it was opened by this package.
// This should be called on application shutdown for clean resource release.
func CloseKeyLog() error {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	if closer, ok := globalKeyLogWriter.(io.Closer); ok {
		err := closer.Close()
		globalKeyLogWriter = nil
		return err
	}
	globalKeyLogWriter = nil
	return nil
}
