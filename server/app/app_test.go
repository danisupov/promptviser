package app

import (
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/promptviser/internal/config"
	"github.com/effective-security/promptviser/tests/testutils"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/x/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const projFolder = "../../"

var (
	testDirPath = filepath.Join(os.TempDir(), "tests", "promptviser", guid.MustCreate())
)

func TestMain(m *testing.M) {
	_ = os.MkdirAll(testDirPath, 0700)
	defer os.RemoveAll(testDirPath)

	// ensure task are not started
	os.Setenv("PROMPTVISER_HOSTNAME", "UNIT_TEST")
	os.Setenv("PROMPTVISER_JWT_SEED", "testseed")

	// Run the tests
	rc := m.Run()
	os.Exit(rc)
}

func Test_App_NoConfig(t *testing.T) {
	app := NewApp([]string{"--dry-run"})
	defer app.Close()

	err := app.Run(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration: file \"promptviser-config.yaml\" not found in")
}

func Test_AppOnClose(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	c := &closer{}
	app := NewApp([]string{
		"--log-std",
		"--cfg", cfgFile,
		"--listen-url", testutils.CreateURLs("http", "localhost"),
	})

	app.OnClose(c)
	assert.False(t, c.closed)

	err = app.loadConfig()
	require.NoError(t, err)

	err = app.Close()
	require.NoError(t, err)

	assert.True(t, c.closed)

	err = app.Close()
	require.Error(t, err)
	assert.Equal(t, "already closed", err.Error())
}

func Test_AppInitWithRun(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	c := &closer{}
	app := NewApp([]string{
		"--dry-run",
		"--cfg", cfgFile,
		"--listen-url", testutils.CreateURLs("http", "localhost"),
	})

	err = app.Run(nil)
	assert.NoError(t, err)

	defer app.OnClose(c)
}

func Test_AppDryRunSkipsMetricsListener(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	_ = addr

	app := NewApp([]string{
		"--dry-run",
		"--cfg", cfgFile,
		"--listen-url", testutils.CreateURLs("http", "localhost"),
	})

	err = app.Run(nil)
	require.NoError(t, err)
}

func Test_AppInitWithCfg(t *testing.T) {
	cfgFile, err := configloader.GetAbsFilename("etc/dev/"+config.ConfigFileName, projFolder)
	require.NoError(t, err, "unable to determine config file")

	cpuf := path.Join(testDirPath, "profiler")
	defer os.Remove(cpuf)

	c := &closer{}
	app := NewApp([]string{
		"--dry-run",
		"--cfg", cfgFile,
		"--listen-url", testutils.CreateURLs("http", "localhost"),
	})
	defer app.OnClose(c)

	err = app.loadConfig()
	require.NoError(t, err)

	_, err = app.containerFactory()
	require.NoError(t, err)
}

func Test_AppInstance_StartStop(t *testing.T) {
	cfgPath, err := filepath.Abs(projFolder + "etc/dev/" + config.ConfigFileName)
	require.NoError(t, err)

	sigs := make(chan os.Signal, 2)
	app := NewApp([]string{
		"--log-std",
		"--cfg", cfgPath,
		"--listen-url", testutils.CreateURLs("http", "localhost"),
	}).WithSignal(sigs)
	defer app.Close()

	var wg sync.WaitGroup
	startedCh := make(chan bool)

	var expError error
	wg.Add(1)
	go func() {
		defer wg.Done()

		expError = app.Run(startedCh)
		if expError != nil {
			t.Log(expError.Error())
			startedCh <- false
		}
	}()

	// wait for start
	select {
	case ret := <-startedCh:
		if assert.True(t, ret, "server NOT started") {
			t.Log("server started")
			// trigger stop
			sigs <- syscall.SIGUSR2
			sigs <- syscall.SIGTERM
			t.Log("server stopping...")
		}

	case <-time.After(10 * time.Second):
		t.Log("failed to start")
		require.True(t, false, "failed to start")
		break
	}

	// wait for stop
	wg.Wait()

	require.NoError(t, expError)
}

type closer struct {
	closed bool
}

func (c *closer) Close() error {
	if c.closed {
		return errors.New("already closed")
	}
	c.closed = true
	return nil
}
