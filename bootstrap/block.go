package bootstrap

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2/log"
)

func BlockUntilSignalReceived() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh // blocks here
	log.Debugf("Exited because of signal: %v", sig)
}
