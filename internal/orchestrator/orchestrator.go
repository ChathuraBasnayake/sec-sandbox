package orchestrator

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"detonator/internal/config"
)

// Orchestrator manages Docker container lifecycle for detonation runs.
type Orchestrator struct {
	docker *client.Client
	cfg    *config.Config
}

// New creates a new Orchestrator connected to the local Docker daemon.
func New(cfg *config.Config) (*Orchestrator, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client init failed: %w", err)
	}
	return &Orchestrator{docker: cli, cfg: cfg}, nil
}

// Close releases the Docker client connection.
func (o *Orchestrator) Close() error {
	return o.docker.Close()
}

// Ping verifies the Docker daemon is reachable.
func (o *Orchestrator) Ping(ctx context.Context) error {
	_, err := o.docker.Ping(ctx, client.PingOptions{})
	return err
}

// PullImage pulls the base container image for the configured registry.
func (o *Orchestrator) PullImage(ctx context.Context) error {
	resp, err := o.docker.ImagePull(ctx, o.cfg.Image(), client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("image pull failed for %s: %w", o.cfg.Image(), err)
	}
	defer resp.Close()
	// Drain the pull progress stream (required to complete the pull)
	io.Copy(io.Discard, resp)
	return nil
}

// CreateChamber creates an isolated container configured for detonation.
// Returns the container ID.
func (o *Orchestrator) CreateChamber(ctx context.Context) (string, error) {
	installCmd := o.cfg.InstallCommand()
	memBytes := o.cfg.MemoryLimitMB * 1024 * 1024
	containerName := fmt.Sprintf("detonator-%s-%d", sanitizeName(o.cfg.PackageName), time.Now().Unix())

	result, err := o.docker.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: o.cfg.Image(),
			Cmd:   []string{"sh", "-c", installCmd + " 2>&1; echo '--- INSTALL COMPLETE ---'; sleep 86400"},
			Tty:   false,
			Labels: map[string]string{
				"detonator.package":  o.cfg.PackageName,
				"detonator.registry": string(o.cfg.Registry),
				"detonator.managed":  "true",
			},
		},
		HostConfig: &container.HostConfig{
			NetworkMode: "none", // NO network access
			Resources: container.Resources{
				Memory:    memBytes,
				PidsLimit: &o.cfg.PidsLimit,
			},
			AutoRemove: false, // Keep alive so we can grab logs before killing
		},
		NetworkingConfig: &network.NetworkingConfig{},
		Name:             containerName,
	})
	if err != nil {
		return "", fmt.Errorf("container create failed: %w", err)
	}

	return result.ID, nil
}

// StartContainer starts the detonation container.
func (o *Orchestrator) StartContainer(ctx context.Context, containerID string) error {
	_, err := o.docker.ContainerStart(ctx, containerID, client.ContainerStartOptions{})
	return err
}

// GetLogs retrieves stdout/stderr from the container.
func (o *Orchestrator) GetLogs(ctx context.Context, containerID string) (string, error) {
	result, err := o.docker.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("log retrieval failed: %w", err)
	}
	defer result.Close()

	buf := new(strings.Builder)
	io.Copy(buf, result)
	return buf.String(), nil
}

// GetContainerPID returns the host-visible PID of the container's init process.
// This is used by the eBPF sensor to filter syscalls to only this container.
func (o *Orchestrator) GetContainerPID(ctx context.Context, containerID string) (int, error) {
	result, err := o.docker.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return 0, fmt.Errorf("container inspect failed: %w", err)
	}
	if result.Container.State == nil || result.Container.State.Pid == 0 {
		return 0, fmt.Errorf("container %s has no running PID", containerID[:12])
	}
	return result.Container.State.Pid, nil
}

// Kill forcefully terminates and removes the container.
func (o *Orchestrator) Kill(ctx context.Context, containerID string) error {
	// Best-effort kill — ignore errors if already dead
	_, _ = o.docker.ContainerKill(ctx, containerID, client.ContainerKillOptions{
		Signal: "SIGKILL",
	})

	_, err := o.docker.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{
		Force: true,
	})
	return err
}

// sanitizeName cleans a package name for use in container naming.
func sanitizeName(name string) string {
	r := strings.NewReplacer("/", "-", "@", "", ".", "-")
	return r.Replace(name)
}
