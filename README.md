# Lab 137 – Linux Suspicious Outbound Connection Investigation

## Overview

This lab investigates Linux network connections to understand how processes communicate with remote systems and how to identify potentially suspicious outbound activity.

The investigation uses `ss` to inspect network sockets, process information to identify connection owners, Auditd to monitor `connect()` system calls, and Wazuh to review collected security events.

A controlled HTTPS connection to `example.com` was used to observe an established TCP connection and understand how network activity can be investigated.

## Lab Environment

- **Operating System:** Rocky Linux 9.8
- **Wazuh:** 4.13.1
- **Auditd:** 3.1.5
- **Network Interface:** ens160
- **Local IP:** 192.168.203.129
- **Tools:** ss, ps, curl, OpenSSL, Auditd, Wazuh Dashboard

## Investigation Objectives

- Understand outbound network connections on Linux.
- Identify established TCP connections and their remote endpoints.
- Associate network sockets with processes and PIDs.
- Monitor `connect()` system calls using Auditd.
- Review Auditd events and Wazuh-collected logs.
- Distinguish local service communication from external network connections.
- Understand why a connection or audit event alone does not establish malicious activity.

## Investigation Activities

### 1. Inspecting Established Connections

The following command was used to display established TCP connections and associated processes:

```bash
sudo ss -tnp state established
```

The output included local Wazuh component communication and a controlled HTTPS connection.

### 2. Identifying the Connection Process

The controlled OpenSSL connection to `example.com` produced the following socket entry:

```text
192.168.203.129:46718  172.66.147.243:443
users:(("openssl",pid=8683,fd=3))
```

This identified the local process, PID, local port, remote IP, and destination port.

### 3. Testing HTTPS Connectivity

A controlled HTTPS request was performed:

```bash
curl -I --connect-timeout 10 --max-time 15 https://example.com
```

The server returned:

```text
HTTP/2 200
```

This confirmed that the HTTPS request completed successfully.

### 4. Monitoring Connection System Calls

Auditd was used to monitor `connect()` system calls with a temporary key:

```bash
sudo auditctl -a always,exit -F arch=b64 -S connect -k lab137_outbound
```

The resulting audit records included process details, executable paths, user information, socket addresses, and syscall status.

The collected records also included local UNIX socket connections from Wazuh components and other system services. This demonstrated that the rule was not limited to external network connections.

### 5. Reviewing Wazuh Events

The Wazuh Dashboard showed a sudo-related event for the execution of:

```text
/sbin/ausearch -k lab137_outbound -i
```

The displayed event was a successful sudo operation. It was not an alert confirming suspicious outbound network activity.

### 6. Removing the Temporary Audit Rule

The temporary rule was removed:

```bash
sudo auditctl -d always,exit -F arch=b64 -S connect -k lab137_outbound
```

The rule list was checked afterward:

```bash
sudo auditctl -l | grep lab137
```

No matching rule was returned.

## Key Findings

- The controlled OpenSSL connection was associated with PID `8683` and remote port `443`.
- The later `ps -fp 8683` command returned no process entry, indicating that the process was no longer present when checked.
- The controlled HTTPS request to `example.com` returned HTTP/2 200.
- Auditd recorded successful `connect()` system calls involving local UNIX sockets.
- Wazuh components generated some of the observed local socket activity.
- The Wazuh Dashboard evidence showed a sudo event, not a confirmed outbound-connection detection.
- The final socket snapshot showed local Wazuh communication and connections to the VM's local HTTPS listener on port 443. It did not show the earlier external OpenSSL connection.

## Conclusion

This lab demonstrated how Linux network connections can be examined using socket information, process attribution, and Auditd syscall monitoring.

It also highlighted an important investigation principle: not every `connect()` event represents an external connection, and not every established connection is suspicious.

The evidence must be correlated with the process, user, destination, socket family, timing, and expected system behavior before reaching a conclusion.

## Evidence

Screenshots and command outputs document:

- Established TCP connections.
- OpenSSL process attribution.
- Successful HTTPS connectivity.
- Auditd `connect()` events.
- Wazuh Dashboard sudo event.
- Temporary Auditd rule removal.
- Final socket and listening-port inspection.
