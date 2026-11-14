# Troubleshooting Notes

## 1. Process PID Not Found

### Command

```bash
ps -fp 8683
```

### Observation

The command returned only the column headers and no process entry.

### Explanation

The OpenSSL process associated with PID `8683` was no longer running when the process lookup was performed.

A process may terminate after its connection closes. Therefore, process details should be collected while the connection is active.

### Lesson

Capture socket and process information together:

```bash
sudo ss -tnp state established
```

## 2. Auditd Captured Local UNIX Socket Connections

### Observation

The Auditd search returned events involving:

- `wazuh-remoted`
- `goa-identity-service`
- Wazuh Indexer Java

The socket addresses included local paths such as:

```text
queue/db/wdb
```

and:

```text
/var/run/.heim_org.h5l.kcm-socket
```

### Explanation

The Auditd rule monitored the `connect()` syscall. This syscall can be used for both network sockets and local UNIX domain sockets.

The rule was therefore broader than external outbound network monitoring.

### Lesson

Always inspect the socket family and address.

- `saddr_fam=local` indicates a local UNIX socket.
- An IP-based socket address represents network communication.

A matching Auditd key alone does not establish external network activity.

## 3. Wazuh Displayed a Sudo Event Instead of an Outbound Alert

### Observation

The Dashboard displayed:

```text
Successful sudo to ROOT executed.
```

The command recorded in the event was:

```text
ausearch -k lab137_outbound -i
```

### Explanation

The event recorded the execution of the audit search command through sudo.

It did not indicate that Wazuh had detected the controlled OpenSSL connection.

### Lesson

Distinguish between:

- An event showing that an investigation command was executed.
- An Auditd event recording a system call.
- A Wazuh alert identifying activity through a configured detection rule.

These are different types of evidence.

## 4. Final Socket Snapshot Did Not Show the Earlier OpenSSL Connection

### Observation

The final `ss -tunap` output showed local Wazuh communication and connections to the VM's HTTPS listener.

It did not show the earlier connection to:

```text
172.66.147.243:443
```

### Explanation

The earlier OpenSSL connection was a controlled test and was no longer present in the later snapshot.

Socket inspection provides a view of connection state at the time the command runs. It does not provide historical connection records.

### Lesson

Run socket inspection while the test connection is still active.

