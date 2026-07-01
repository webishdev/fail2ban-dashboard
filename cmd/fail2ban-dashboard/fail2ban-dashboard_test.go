package main

import (
	"testing"

	"github.com/spf13/cobra"
)

var initialized = false

func setupOnce() {
	if initialized {
		return
	}
	setupRootCommand()
	initialized = true
}

func TestSetupRootCommand(t *testing.T) {
	// Initialize the commands once
	setupOnce()

	// Verify subcommands
	if !hasSubCommand(rootCmd, versionCmd) {
		t.Errorf("version command missing from root")
	}
	if !hasSubCommand(rootCmd, serveCmd) {
		t.Errorf("serve command missing from root")
	}

	// Verify flags on rootCmd
	assertFlagExists(t, rootCmd, "cache-dir", "rootCmd")
	assertFlagExists(t, rootCmd, "socket", "rootCmd")
	assertFlagExists(t, rootCmd, "address", "rootCmd")

	// Verify flags on serveCmd
	assertFlagExists(t, serveCmd, "cache-dir", "serveCmd")
	assertFlagExists(t, serveCmd, "socket", "serveCmd")
	assertFlagExists(t, serveCmd, "address", "serveCmd")

	// Verify flags NOT on versionCmd
	assertFlagDoesNotExist(t, versionCmd, "cache-dir", "versionCmd")
	assertFlagDoesNotExist(t, versionCmd, "address", "versionCmd")
}

func hasSubCommand(parent *cobra.Command, sub *cobra.Command) bool {
	for _, cmd := range parent.Commands() {
		if cmd == sub {
			return true
		}
	}
	return false
}

func assertFlagExists(t *testing.T, cmd *cobra.Command, flagName, cmdName string) {
	t.Helper()
	if flag := cmd.Flags().Lookup(flagName); flag == nil {
		t.Errorf("flag %s missing on %s", flagName, cmdName)
	}
}

func assertFlagDoesNotExist(t *testing.T, cmd *cobra.Command, flagName, cmdName string) {
	t.Helper()
	if flag := cmd.Flags().Lookup(flagName); flag != nil {
		t.Errorf("flag %s unexpectedly present on %s", flagName, cmdName)
	}
}
