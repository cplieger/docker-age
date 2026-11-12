# Monitoring and alerts

docker-age reports each decrypt pass through the exit code of the command that ran it, and that code is the verdict. It serves no metrics page and ships no alert rules. The deploy step that runs the pass is the one party that must act on a failure. It reads the exit code before your stacks start.

## What you get

| You run | You get | You set up |
| --- | --- | --- |
| Prometheus, Mimir or VictoriaMetrics, with Alertmanager | No metrics and no alert rules from this app | An alert on your deploy step's failure, such as a failed CI job or deploy action |
| Loki and Alertmanager, no metric store | The waiting container's start and stop lines, and no alert rules | The same alert on your deploy step's failure |
| Docker or Unraid only | The exit code of each pass, and Docker health while the container waits | A deploy step that stops when the pass exits with a code other than 0 |

## Knowing the app is alive

A `decrypt` command exits 0 when every file it selected decrypted, and also when it found no matching file, which it logs as a warning. It exits 1 when a file fails, a folder cannot be read or the identity file cannot be loaded. It also exits 1 when the pass is stopped or names nothing to decrypt. It exits 2 when an argument or a setting is invalid, such as an unknown flag or an unset `IDENTITY_PATH`. A `docker exec` against a stopped container fails too, so the deploy stops.

A pass writes its lines, its summary line included, to the output of the command that ran it, which is your deploy tool's log or your terminal. They never appear in `docker logs age`, which holds only the waiting container's own start and stop lines. So alert on your deploy step's failure, not on the container's log.

A pass has no time limit of its own, so bound the deploy step on the host, for example `timeout 120 docker exec age /age-decrypt decrypt --ext .env`. `timeout` ends the command with exit code 124 when the pass runs over, which fails the step as well. `timeout` stops only the `docker exec` command. Docker leaves the pass running inside the container until it ends, so restart the container (`docker restart age`) to stop a pass that hangs.

The image opens no port, so nothing outside the container can probe it. Its Docker health means only that the waiting container is up and ready for `docker exec`. The image runs `/age-decrypt health` every 30 seconds, which reads the health file the waiting process writes at `/dev/shm/docker-age.healthy` when it starts and removes when it stops. If that file cannot be written, as under `ipc: none`, the check passes and the log says so once. Docker marks the container unhealthy after 3 failures and allows 15 seconds after a start. A failed pass leaves it healthy, and Docker's health status notifies nobody on its own.
