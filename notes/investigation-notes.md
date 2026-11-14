# Lab 137 – Investigation Notes

## Investigation Scenario

Investigate Linux network connections to understand how outbound activity can be identified, attributed to processes, and reviewed through Auditd and Wazuh.

A controlled HTTPS connection was generated to observe the connection details and examine the resulting system activity.

## 1. Established Connection Analysis

Command:

```bash
sudo ss -tnp state established
```

The initial output contained several local Wazuh connections and a controlled external HTTPS connection.

Observed connection:

```text
Local Address:  192.168.203.129:46718
Remote Address: 172.66.147.243:443
Process:        openssl
PID:            8683
State:          ESTAB
```

### Interpretation

- `ESTAB` indicates that the TCP connection was established.
- `192.168.203.129` was the local VM address.
- `46718` was the local ephemeral port.
- `172.66.147.243` was the observed remote IP.
- `443` was the remote HTTPS port.
- `openssl` was the process associated with the socket.

This was a controlled connection to `example.com`, not evidence of malicious activity.

## 2. Process Attribution

Command:

```bash
ps -fp 8683
```

The command returned the header but no process entry.

### Interpretation

The process was no longer present when the command was executed. A process may terminate after its connection closes, so a later process lookup may not return its details.

The earlier `ss` output remains evidence that PID `8683` owned the observed socket at the time of that snapshot.

## 3. HTTPS Connectivity Test

Command:

```bash
curl -I --connect-timeout 10 --max-time 15 https://example.com
```

Observed response:

```text
HTTP/2 200
```

### Interpretation

The HTTPS request completed successfully and the server returned an HTTP 200 response.

This confirms successful application-layer communication for the test request. It does not independently establish anything about other connections on the system.

## 4. Auditd Connection Monitoring

A temporary Auditd rule was used:

```bash
sudo auditctl -a always,exit -F arch=b64 -S connect -k lab137_outbound
```

The rule monitored 64-bit `connect()` system calls.

The audit output included the following event:

```text
comm=wazuh-remoted
exe=/bin/wazuh-remoted
key=lab137_outbound
success=yes
```

The socket address was:

```text
saddr_fam=local
path=queue/db/wdb
```

Other observed events included:

- `goa-identity-service` connecting to a local credential-cache socket.
- Wazuh Indexer Java connecting to a local process socket.
- Wazuh-related processes communicating through local UNIX sockets.

### Interpretation

The Auditd rule captured local UNIX socket connections as well as connections that may use network sockets.

The key `lab137_outbound` identifies the audit rule that generated the event. It does not prove that the event was an external outbound connection.

The `success=yes` field confirms that the recorded syscall succeeded. It does not prove that data was transferred to an external destination.

## 5. Wazuh Dashboard Review

The Dashboard displayed the following event:

```text
rule.description:
Successful sudo to ROOT executed.

full_log:
COMMAND=/sbin/ausearch -k lab137_outbound -i

rule.groups:
syslog, sudo
```

### Interpretation

This event recorded the execution of the `ausearch` command through sudo.

It confirms that the audit search command was executed with root privileges. It is not a Wazuh alert identifying suspicious outbound network activity.

## 6. Final Socket Inspection

Command:

```bash
sudo ss -tunap
```

The final snapshot showed:

- NetworkManager DHCP communication.
- Chrony and Avahi UDP sockets.
- Wazuh services listening on ports `1514` and `1515`.
- A Node process listening on port `443`.
- Established connections from `192.168.203.1` to the VM's local HTTPS listener at `192.168.203.129:443`.
- Local Wazuh communication over `127.0.0.1:9200`.

### Important distinction

The following entry:

```text
192.168.203.129:443  192.168.203.1:2143
users:(("node",pid=1040,fd=25))
```

shows the VM's local port `443` as the listening endpoint and `192.168.203.1` as the peer.

This is not evidence of an outbound connection from the VM to an external HTTPS server.

The final snapshot did not show the earlier OpenSSL connection to `172.66.147.243:443`.

## Investigation Conclusion

The investigation successfully demonstrated:

1. Identifying established TCP connections using `ss`.
2. Associating a socket with its owning process and PID.
3. Confirming controlled HTTPS connectivity.
4. Monitoring `connect()` system calls through Auditd.
5. Recognizing local UNIX socket activity in audit records.
6. Distinguishing a sudo-related Wazuh event from an outbound-network detection.
7. Removing the temporary Auditd rule after testing.

No confirmed malicious outbound connection was identified during this controlled investigation.
