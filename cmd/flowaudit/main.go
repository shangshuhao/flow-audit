// Command flowaudit collects Linux connection events and serves audit queries.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"flowaudit/internal/app/runtime"
	"flowaudit/internal/config"
	"flowaudit/internal/logging"
	"flowaudit/internal/source"
	conntracksource "flowaudit/internal/source/conntrack"
	"flowaudit/internal/store/sqlite"
	"flowaudit/internal/version"
)

// main dispatches the CLI and terminates with a non-zero status on failure.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run selects the requested application command.
func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "run":
		return runCollection(args[1:])
	case "serve":
		return runServer(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "version":
		fmt.Printf(
			"flowaudit %s commit=%s build_date=%s\n",
			version.Version,
			version.Commit,
			version.BuildDate,
		)
		return nil
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// runCollection starts conntrack collection together with the read-only server.
func runCollection(args []string) error {
	cfg, logger, err := loadConfigAndLogger(args)
	if err != nil {
		return err
	}

	sourceImpl, err := conntracksource.New(conntracksource.Options{
		NodeID:             cfg.Node.ID,
		IncludePreexisting: cfg.Source.IncludePreexisting,
		IncludeUnreplied:   cfg.Source.IncludeUnreplied,
		NetlinkReadBuffer:  cfg.Source.NetlinkReceiveBuffer,
		EventQueueSize:     cfg.Source.QueueSize,
	})
	if err != nil {
		return fmt.Errorf("create conntrack source: %w", err)
	}

	ctx, stop := signalContext()
	defer stop()

	return runtime.RunAll(ctx, cfg, sourceImpl, logger)
}

// runServer serves existing data without starting a telemetry source.
func runServer(args []string) error {
	cfg, logger, err := loadConfigAndLogger(args)
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	return runtime.RunServe(ctx, cfg, logger)
}

// runDoctor checks storage, source access, and HTTP listener availability.
func runDoctor(args []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to YAML configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report := map[string]string{}
	failed := false

	storage, err := sqlite.Open(ctx, cfg.Store.Path)
	if err != nil {
		report["store"] = "failed: " + err.Error()
		failed = true
	} else {
		if pingErr := storage.Ping(ctx); pingErr != nil {
			report["store"] = "failed: " + pingErr.Error()
			failed = true
		} else {
			report["store"] = "ok"
		}
		_ = storage.Close()
	}

	sourceImpl, err := conntracksource.New(conntracksource.Options{
		NodeID:             cfg.Node.ID,
		IncludePreexisting: cfg.Source.IncludePreexisting,
		IncludeUnreplied:   cfg.Source.IncludeUnreplied,
		NetlinkReadBuffer:  cfg.Source.NetlinkReceiveBuffer,
		EventQueueSize:     cfg.Source.QueueSize,
	})
	if err != nil {
		report["source"] = "failed: " + err.Error()
		failed = true
	} else if checker, ok := source.Source(sourceImpl).(source.Checker); ok {
		if err := checker.Check(ctx); err != nil {
			report["source"] = "failed: " + err.Error()
			failed = true
		} else {
			report["source"] = "ok"
		}
	} else {
		report["source"] = "created"
	}

	listener, err := net.Listen("tcp", cfg.HTTP.Listen)
	if err != nil {
		report["http"] = "failed: " + err.Error()
		failed = true
	} else {
		report["http"] = "ok"
		_ = listener.Close()
	}
	report["node_id"] = cfg.Node.ID
	report["database"] = cfg.Store.Path

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode doctor report: %w", err)
	}
	if failed {
		return errors.New("doctor found configuration or runtime problems")
	}

	return nil
}

// loadConfigAndLogger parses shared startup flags and constructs a logger.
func loadConfigAndLogger(args []string) (config.Config, *slog.Logger, error) {
	flags := flag.NewFlagSet("flowaudit", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to YAML configuration")
	if err := flags.Parse(args); err != nil {
		return config.Config{}, nil, err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return config.Config{}, nil, err
	}
	logger, err := logging.New(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return config.Config{}, nil, err
	}

	return cfg, logger, nil
}

// signalContext returns a context canceled by common termination signals.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// printUsage writes the command-line help text.
func printUsage() {
	fmt.Print(`flowaudit - Linux connection audit

Usage:
  flowaudit run    [-config path]   collect conntrack events and serve UI
  flowaudit serve  [-config path]   serve existing data without collection
  flowaudit doctor [-config path]   check configuration and runtime access
  flowaudit version                 print build information
`)
}
