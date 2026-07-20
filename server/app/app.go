package app

import (
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/porto/gserver"
	"github.com/effective-security/porto/pkg/appinit"
	appinitCfg "github.com/effective-security/porto/pkg/appinit/config"
	"github.com/effective-security/porto/pkg/discovery"
	"github.com/effective-security/porto/pkg/tasks"
	"github.com/effective-security/promptviser/api/version"
	"github.com/effective-security/promptviser/internal/adviserdb"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/promptviser/pkg/metricskey"
	"github.com/effective-security/promptviser/server/appcontainer"
	"github.com/effective-security/promptviser/server/service"
	trustyTasks "github.com/effective-security/promptviser/server/tasks"
	"github.com/effective-security/x/netutil"
	"github.com/effective-security/x/values"
	"github.com/effective-security/xlog"
	"go.uber.org/dig"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/promptviser/server", "app")

// appFlags specifies application flags
type appFlags struct {
	appinit.LogConfig
	appinit.Flags

	PromAddr            string   `help:"Address for Prometheus metrics end point"`
	HostName            []string `help:"hostname to use for the service certificate"`
	ListenURL           []string `help:"URL for the service listening end-point"`
	HttpsCertFile       string   `help:"HTTPS server certificate file"`
	HttpsKeyFile        string   `help:"HTTPS server key file"`
	HttpsTrustedCAFile  string   `help:"HTTPS server trusted CA file"`
	ClientCertFile      string   `help:"Client certificate file"`
	ClientKeyFile       string   `help:"Client key file"`
	ClientTrustedCAFile string   `help:"Client trusted CA file"`
	OnlyServer          string   `help:"Only start the specified server"`
}

// App provides application container
type App struct {
	sigs      chan os.Signal
	container *dig.Container
	closers   []io.Closer
	closed    bool
	lock      sync.RWMutex
	hostname  string

	args             []string
	flags            appFlags
	cfg              *config.Configuration
	scheduler        tasks.Scheduler
	containerFactory appcontainer.ContainerFactoryFn
	servers          map[string]gserver.GServer
}

// NewApp returns new App
func NewApp(args []string) *App {
	app := &App{
		container: nil,
		args:      args,
		closers:   make([]io.Closer, 0, 8),
		servers:   make(map[string]gserver.GServer),
	}

	f := appcontainer.NewContainerFactory(app).
		WithConfigurationProvider(func() (*config.Configuration, error) {
			return app.Configuration()
		})

	// use default Container Factory
	return app.WithContainerFactory(f.CreateContainerWithDependencies)
}

// WithConfiguration allows to specify a custom configuration,
// used mainly for testing purposes
func (a *App) WithConfiguration(cfg *config.Configuration) *App {
	a.cfg = cfg
	return a
}

// WithContainerFactory allows to specify an app container factory,
// used mainly for testing purposes
func (a *App) WithContainerFactory(f appcontainer.ContainerFactoryFn) *App {
	a.containerFactory = f
	return a
}

// WithSignal adds cusom signal channel
func (a *App) WithSignal(sigs chan os.Signal) *App {
	a.sigs = sigs
	return a
}

// OnClose adds a closer to be called when application exists
func (a *App) OnClose(closer io.Closer) {
	if closer == nil {
		return
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	a.closers = append(a.closers, closer)
}

// Close implements Closer interface to clean up resources
func (a *App) Close() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.closed {
		return errors.New("already closed")
	}

	a.closed = true
	// close in reverse order
	for i := len(a.closers) - 1; i >= 0; i-- {
		closer := a.closers[i]
		if closer != nil {
			err := closer.Close()
			if err != nil {
				logger.KV(xlog.ERROR, "err", err)
			}
		}
	}
	logger.KV(xlog.WARNING, "status", "closed")

	return nil
}

// Container returns the current app container populater with dependencies
func (a *App) Container() (*dig.Container, error) {
	var err error
	if a.container == nil {
		a.container, err = a.containerFactory()
		if err != nil {
			return nil, err
		}
	}
	return a.container, nil
}

// Configuration returns the current app configuration
func (a *App) Configuration() (*config.Configuration, error) {
	var err error
	if a.cfg == nil {
		err = a.loadConfig()
		if err != nil {
			return nil, err
		}
	}
	return a.cfg, nil
}

// Run the application
func (a *App) Run(startedCh chan<- bool) error {
	if a.sigs == nil {
		a.WithSignal(make(chan os.Signal, 2))
	}

	ipaddr, err := netutil.WaitForNetwork(30 * time.Second)
	if err != nil {
		return errors.WithMessage(err, "unable to resolve local IP")
	}

	a.hostname, err = os.Hostname()
	if err != nil {
		return errors.WithMessage(err, "unable to resolve hostname")
	}

	_, err = a.Configuration()
	if err != nil {
		return err
	}

	ver := version.Current().String()
	logger.KV(xlog.INFO, "hostname", a.hostname, "ip", ipaddr, "version", ver)

	if a.flags.CPUProfile != "" {
		closer, err := appinit.CPUProfiler(a.flags.CPUProfile)
		if err != nil {
			return err
		}
		a.OnClose(closer)
	}

	if a.flags.DryRun {
		logger.KV(xlog.NOTICE, "status", "metrics_disabled")
	} else if !a.cfg.Metrics.GetDisabled() {
		ver := version.Current()
		closer, err := appinit.Metrics(
			&a.cfg.Metrics,
			a.cfg.ServiceName,
			a.cfg.ClusterName,
			ver.String(),
			int(ver.Commit),
			metricskey.Metrics,
		)
		if err != nil {
			return err
		}
		a.OnClose(closer)
	} else {
		logger.KV(xlog.NOTICE, "status", "metrics_disabled")
	}

	dig, err := a.Container()
	if err != nil {
		return err
	}

	// err = a.genCert()
	// if err != nil {
	// 	return err
	// }

	if a.flags.DryRun {
		err = dig.Invoke(func(_ adviserdb.Provider) error {
			// this will force schema migration check
			return nil
		})

		logger.KV(xlog.INFO, "status", "exit_on_dry_run")
		return err
	}

	for name, svcCfg := range a.cfg.HTTPServers {
		if !svcCfg.Disabled {
			httpServer, err := gserver.Start(name, svcCfg, a.container, service.Factories)
			if err != nil {
				a.stopServers()
				return err
			}
			a.servers[httpServer.Name()] = httpServer
		} else {
			logger.KV(xlog.INFO, "reason", "skip_disabled", "server", name)
		}
	}

	err = a.scheduleTasks()
	if err != nil {
		a.stopServers()
		return err
	}
	_ = a.scheduler.Start()

	// Notify services
	err = a.container.Invoke(func(disco discovery.Discovery) error {
		var svc gserver.Service
		return disco.ForEach(&svc, func(key string) error {
			if onstarted, ok := svc.(gserver.StartSubcriber); ok {
				logger.KV(xlog.INFO, "src", "Run", "onstarted", "running", "key", key, "service", svc.Name())
				return onstarted.OnStarted()
			}
			logger.KV(xlog.INFO, "src", "Run", "onstarted", "skipped", "key", key, "service", svc.Name())
			return nil
		})
	})
	if err != nil {
		a.stopServers()
		return err
	}

	if startedCh != nil {
		// notify
		startedCh <- true
	}

	// register for signals, and wait to be shutdown
	signal.Notify(a.sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR2, syscall.SIGABRT)

	// Block until a signal is received.
	sig := <-a.sigs
	logger.KV(xlog.WARNING, "status", "shuting_down", "sig", sig)

	a.stopServers()

	// let to stop
	time.Sleep(time.Second * 3)

	// SIGUSR2 is triggered by the upstart pre-stop script, we don't want
	// to actually exit the process in that case until upstart sends SIGTERM
	if sig == syscall.SIGUSR2 {
		select {
		case <-time.After(time.Second * 15):
			logger.KV(xlog.INFO, "status", "SIGUSR2", "waiting", "SIGTERM")
		case sig = <-a.sigs:
			logger.KV(xlog.INFO, "status", "exiting", "reason", "received_signal", "sig", sig)
		}
	}

	return nil
}

// Server returns a running TrustyServer by name
func (a *App) Server(name string) gserver.GServer {
	return a.servers[name]
}

func (a *App) stopServers() {
	if a.scheduler != nil {
		_ = a.scheduler.Stop()
	}
	for _, running := range a.servers {
		running.Close()
	}
}

func (a *App) loadConfig() error {
	parser, err := kong.New(&a.flags,
		kong.Name("promptviser"),
		kong.Description("Prompt Adviser service"),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"version": version.Current().String(),
		},
	)
	if err != nil {
		return errors.WithMessagef(err, "failed to parse arguments: %v", a.args)
	}
	_, err = parser.Parse(a.args)
	if err != nil {
		return errors.WithMessagef(err, "failed to parse arguments: %v", a.args)
	}

	closer, err := appinit.Logs(&a.flags.LogConfig, "trusty")
	if err != nil {
		return err
	}
	a.OnClose(closer)

	a.cfg = new(config.Configuration)
	err = config.LoadWithOverride(
		values.StringsCoalesce(a.flags.Cfg, config.ConfigFileName),
		a.flags.CfgOverride,
		a.cfg,
		nil,
	)
	if err != nil {
		return err
	}

	xlog.SetRepoLevels(a.cfg.LogLevels)

	if a.flags.PromAddr != "" {
		if a.cfg.Metrics.Prometheus == nil {
			a.cfg.Metrics.Prometheus = &appinitCfg.Prometheus{
				Addr: a.flags.PromAddr,
			}
		} else {
			a.cfg.Metrics.Prometheus.Addr = a.flags.PromAddr
		}
	}

	overrideStrings := []struct {
		to   *string
		from *string
	}{
		{&a.cfg.Environment, &a.flags.Env},
		{&a.cfg.ServiceName, &a.flags.ServiceName},
		{&a.cfg.Region, &a.flags.Region},
		{&a.cfg.ClusterName, &a.flags.Cluster},
		{&a.cfg.Client.ClientTLS.CertFile, &a.flags.ClientCert},
		{&a.cfg.Client.ClientTLS.KeyFile, &a.flags.ClientKey},
		{&a.cfg.Client.ClientTLS.TrustedCAFile, &a.flags.ClientTrustedCA},
	}
	for _, o := range overrideStrings {
		if *o.from != "" {
			*o.to = *o.from
		}
	}

	for name, httpCfg := range a.cfg.HTTPServers {
		if httpCfg.ServerTLS != nil {
			if a.flags.HttpsCertFile != "" {
				httpCfg.ServerTLS.CertFile = a.flags.HttpsCertFile
			}
			if a.flags.HttpsKeyFile != "" {
				httpCfg.ServerTLS.KeyFile = a.flags.HttpsKeyFile
			}
			if a.flags.HttpsTrustedCAFile != "" {
				httpCfg.ServerTLS.TrustedCAFile = a.flags.HttpsTrustedCAFile
			}
		}

		if a.flags.OnlyServer != "" {
			httpCfg.Disabled = name != a.flags.OnlyServer
		} else {
			switch name {
			case config.WFEServerName:
				if len(a.flags.ListenURL) > 0 {
					httpCfg.ListenURLs = a.flags.ListenURL
					httpCfg.Disabled = len(httpCfg.ListenURLs) == 1 && httpCfg.ListenURLs[0] == "none"
				}

			default:
				return errors.Errorf("unknows server name in configuration: %s", name)
			}
		}
	}

	return nil
}

func (a *App) scheduleTasks() error {
	err := a.container.Invoke(func(scheduler tasks.Scheduler) error {
		a.scheduler = scheduler
		return nil
	})
	if err != nil {
		return errors.WithMessagef(err, "failed to create scheduler")
	}
	for _, task := range a.cfg.Tasks {
		tf := trustyTasks.Factories[task.Name]
		if tf == nil {
			return errors.Errorf("task not registered: %s", task.Name)
		}

		err := a.container.Invoke(tf(a.scheduler, task.Name, task.Schedule, task.Args...))
		if err != nil {
			return errors.WithMessagef(err, "failed to create a task: %s", task.Name)
		}
		logger.KV(xlog.INFO, "task", task.Name, "schedule", task.Schedule)
	}
	return nil
}
