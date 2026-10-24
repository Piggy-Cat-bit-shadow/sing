package pause

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/service"
)

// The manager is a lifecycle primitive: a wait must be parked while either source is paused, must be
// woken by the matching wake, must be cancellable independently of the manager, and must never be
// left waiting on a channel that can no longer close. These tests are deterministic: they assert
// the parked state before releasing it rather than sleeping for "long enough".

func newTestManager(t *testing.T) (context.Context, Manager, context.CancelFunc) {
	t.Helper()
	root, cancel := context.WithCancel(context.Background())
	managerContext := WithDefaultManager(root)
	manager := service.FromContext[Manager](managerContext)
	if manager == nil {
		t.Fatal("WithDefaultManager did not install a manager")
	}
	return managerContext, manager, cancel
}

func waitInBackground(manager Manager, ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		manager.WaitActiveContext(ctx)
		close(done)
	}()
	return done
}

func requireBlocked(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
		t.Fatalf("%s returned while the manager was paused", what)
	case <-time.After(100 * time.Millisecond):
	}
}

func requireReturns(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return after it was released", what)
	}
}

func TestWaitActiveContextBlocksWhilePausedAndWakesOnWake(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	defer cancel()

	manager.NetworkPause()
	if !manager.IsPaused() || !manager.IsNetworkPaused() {
		t.Fatal("network pause did not mark the manager paused")
	}
	done := waitInBackground(manager, context.Background())
	requireBlocked(t, done, "WaitActiveContext")

	manager.NetworkWake()
	requireReturns(t, done, "WaitActiveContext after NetworkWake")
	if manager.IsPaused() {
		t.Fatal("the manager stayed paused after the only pause was released")
	}
}

func TestWaitActiveContextReturnsOnContextCancelWhilePaused(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	defer cancel()

	manager.DevicePause()
	manager.NetworkPause()
	waitCtx, waitCancel := context.WithCancel(context.Background())
	done := waitInBackground(manager, waitCtx)
	requireBlocked(t, done, "WaitActiveContext")

	waitCancel()
	requireReturns(t, done, "WaitActiveContext after cancel")
	if !manager.IsPaused() {
		t.Fatal("cancelling a waiter changed the manager's paused state")
	}

	// A new waiter must still park: the cancellation applied to the waiter, not to the manager.
	second := waitInBackground(manager, context.Background())
	requireBlocked(t, second, "second WaitActiveContext")
	manager.DeviceWake()
	manager.NetworkWake()
	requireReturns(t, second, "second WaitActiveContext after wake")
}

func TestWaitActiveContextReturnsOnManagerContextCancel(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	manager.NetworkPause()
	done := waitInBackground(manager, context.Background())
	requireBlocked(t, done, "WaitActiveContext")

	cancel()
	requireReturns(t, done, "WaitActiveContext after the manager context was cancelled")
}

func TestDeviceAndNetworkPausesAreIndependent(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	defer cancel()

	manager.DevicePause()
	deviceWait := waitInBackground(manager, context.Background())
	requireBlocked(t, deviceWait, "device-only WaitActiveContext")

	// The network was never paused, so this is not a wake for the device pause.
	manager.NetworkWake()
	requireBlocked(t, deviceWait, "device-only WaitActiveContext after NetworkWake")

	manager.DeviceWake()
	requireReturns(t, deviceWait, "device-only WaitActiveContext after DeviceWake")

	manager.NetworkPause()
	networkWait := waitInBackground(manager, context.Background())
	requireBlocked(t, networkWait, "network-only WaitActiveContext")
	manager.DeviceWake()
	requireBlocked(t, networkWait, "network-only WaitActiveContext after DeviceWake")
	manager.NetworkWake()
	requireReturns(t, networkWait, "network-only WaitActiveContext after NetworkWake")
}

func TestRepeatedEventsAreIdempotent(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	defer cancel()

	var events atomic.Int32
	element := manager.RegisterCallback(func(event int) { events.Add(1) })
	defer manager.UnregisterCallback(element)

	manager.DevicePause()
	manager.DevicePause()
	manager.NetworkPause()
	manager.NetworkPause()
	if got := events.Load(); got != 2 {
		t.Fatalf("pause events = %d, want one device and one network event", got)
	}
	if !manager.IsDevicePaused() || !manager.IsNetworkPaused() || !manager.IsPaused() {
		t.Fatal("paused flags do not reflect both pauses")
	}

	manager.DeviceWake()
	manager.DeviceWake()
	manager.NetworkWake()
	manager.NetworkWake()
	if got := events.Load(); got != 4 {
		t.Fatalf("events = %d, want one wake per source", got)
	}
	if manager.IsPaused() || manager.IsDevicePaused() || manager.IsNetworkPaused() {
		t.Fatal("wake flags do not reflect that both pauses were released")
	}
}

func TestWaitActiveContextReturnsImmediatelyWhenActive(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	defer cancel()
	if manager.IsPaused() {
		t.Fatal("a fresh manager is paused")
	}
	done := waitInBackground(manager, context.Background())
	requireReturns(t, done, "WaitActiveContext on an active manager")
}

func TestWaitActiveContextWithCancelledContextWhilePaused(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	defer cancel()
	manager.NetworkPause()
	ctx, waitCancel := context.WithCancel(context.Background())
	waitCancel()
	done := waitInBackground(manager, ctx)
	requireReturns(t, done, "WaitActiveContext with a cancelled context")
}

func TestConcurrentEventsAndWaitsDoNotDeadlock(t *testing.T) {
	t.Parallel()
	_, manager, cancel := newTestManager(t)
	defer cancel()

	var workers sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				manager.DevicePause()
				manager.DeviceWake()
			}
		})
	}
	for range 4 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				manager.NetworkPause()
				manager.NetworkWake()
			}
		})
	}
	for range 8 {
		workers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Millisecond)
				manager.WaitActiveContext(waitCtx)
				waitCancel()
			}
		})
	}

	// Let the loop run through several pause/wake windows, then stop it and require every worker to
	// observe the stop. A lost wake or a wait on a closed channel would keep a worker parked.
	time.Sleep(100 * time.Millisecond)
	close(stop)
	finished := make(chan struct{})
	go func() {
		workers.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("pause/wake workers did not finish: a waiter or a lock is stuck")
	}
}

func TestWithDefaultManagerDoesNotReplaceAnInstalledManager(t *testing.T) {
	t.Parallel()
	root := t.Context()
	firstContext := WithDefaultManager(root)
	first := service.FromContext[Manager](firstContext)
	secondContext := WithDefaultManager(firstContext)
	second := service.FromContext[Manager](secondContext)
	if first != second {
		t.Fatal("a second WithDefaultManager replaced the installed manager")
	}
}
