package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestCommandFlagParsingAndViperBinding(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		expectedAddr  string
		expectedCache string
		expectErr     bool
	}{
		{
			name:          "Root command accepts --address and global flags",
			args:          []string{"--address", "192.168.1.100:8080", "--cache-dir", "/tmp/cache"},
			expectedAddr:  "192.168.1.100:8080",
			expectedCache: "/tmp/cache",
			expectErr:     false,
		},
		{
			name:          "Serve command accepts --address and global flags",
			args:          []string{"serve", "--address", "10.0.0.1:4000", "--cache-dir", "/var/cache"},
			expectedAddr:  "10.0.0.1:4000",
			expectedCache: "/var/cache",
			expectErr:     false,
		},
		{
			name:      "Version command rejects --address flag",
			args:      []string{"version", "--address", "0.0.0.0:3000"},
			expectErr: true,
		},
		{
			name:      "Version command accepts default execution without flags",
			args:      []string{"version"},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset Viper state between sub-tests to avoid flag bleed
			viper.Reset()

			// Instantiate a fresh command tree for isolation
			rootCmd := setupRootCommand()

			// Stub the execution function on root and serve to prevent triggering the actual web server
			rootCmd.Run = func(cmd *cobra.Command, args []string) {}
			if serveCmd, _, err := rootCmd.Find([]string{"serve"}); err == nil {
				serveCmd.Run = func(cmd *cobra.Command, args []string) {}
			}

			buf := new(bytes.Buffer)
			rootCmd.SetOut(buf)
			rootCmd.SetErr(buf)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error for args %v, got nil", tt.args)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected execution error for args %v: %v", tt.args, err)
			}

			// Validate Viper settings if we expected a successful run with flags
			if tt.expectedAddr != "" {
				actualAddr := viper.GetString("address")
				if actualAddr != tt.expectedAddr {
					t.Errorf("expected address %q in Viper, got %q", tt.expectedAddr, actualAddr)
				}
			}

			if tt.expectedCache != "" {
				actualCache := viper.GetString("cache-dir")
				if actualCache != tt.expectedCache {
					t.Errorf("expected cache-dir %q in Viper, got %q", tt.expectedCache, actualCache)
				}
			}
		})
	}
}

func TestCommandStructureAndFlagPresence(t *testing.T) {
	viper.Reset()
	rootCmd := setupRootCommand()

	// Verify subcommands exist
	serveCmd, _, err := rootCmd.Find([]string{"serve"})
	if err != nil || serveCmd == rootCmd {
		t.Fatalf("serve subcommand missing from rootCmd")
	}

	versionCmd, _, err := rootCmd.Find([]string{"version"})
	if err != nil || versionCmd == rootCmd {
		t.Fatalf("version subcommand missing from rootCmd")
	}

	// Helper assertions
	assertFlagExists(t, rootCmd, "address", "rootCmd")
	assertFlagExists(t, rootCmd, "cache-dir", "rootCmd")

	assertFlagExists(t, serveCmd, "address", "serveCmd")
	assertFlagExists(t, serveCmd, "cache-dir", "serveCmd")

	assertFlagDoesNotExist(t, versionCmd, "address", "versionCmd")
	assertFlagDoesNotExist(t, versionCmd, "cache-dir", "versionCmd")
}

func assertFlagExists(t *testing.T, cmd *cobra.Command, flagName, cmdName string) {
	t.Helper()
	if flag := cmd.Flags().Lookup(flagName); flag == nil {
		t.Errorf("expected flag %q to exist on %s, but it was missing", flagName, cmdName)
	}
}

func assertFlagDoesNotExist(t *testing.T, cmd *cobra.Command, flagName, cmdName string) {
	t.Helper()
	if flag := cmd.Flags().Lookup(flagName); flag != nil {
		t.Errorf("expected flag %q NOT to exist on %s, but it was present", flagName, cmdName)
	}
}
