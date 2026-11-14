# linux-suspicious-outbound-connection-investigation
## Overview
### Concept

An outbound connection occurs when a process running on a Linux system initiates communication with another endpoint.

For example, a browser connecting to a website, a package manager downloading updates, or an application communicating with an API can all generate outbound connections.

In security monitoring, the objective is to identify connections that may be unexpected or suspicious and determine which process initiated them.

### What Makes an Outbound Connection Suspicious?

A connection deserves further investigation when it involves indicators such as:

- An unfamiliar or unexpected destination IP address.
- An unusual destination port or protocol.
- A process that should not normally communicate over the network.
- An executable running from an unusual location.
- Repeated connections at regular intervals.
- Unexpected network activity under a privileged or unusual user account.

These indicators are not proof of malicious activity. They must be evaluated against the system's expected behavior and other available evidence.

### How to Identify an Active Connection

Linux provides the `ss` command to inspect network sockets.

```bash
sudo ss -tnp state established
```

Important fields:

- **State:** Indicates whether the TCP connection is established.
- **Local Address:** The local IP address and port.
- **Peer Address:** The remote IP address and port.
- **Process:** The process name and PID associated with the socket.

An established TCP connection means the TCP connection has reached the established state. It does not automatically mean that data is currently being transferred.

### Process Attribution

After identifying a connection, the associated PID can be investigated using:

```bash
ps -fp <PID>
```

This helps identify the process owner, parent process, start information, and command.

Process details should be collected while the connection is active because a process may terminate before a later lookup.

### Auditd Monitoring

Auditd can monitor Linux system calls, including `connect()`.

Example temporary rule:

```bash
sudo auditctl -a always,exit -F arch=b64 -S connect -k lab137_outbound
```

This records matching connection system calls.

The audit event can provide information such as:

- Process name and executable.
- Process ID and parent process ID.
- User identity.
- Syscall success or failure.
- Socket address information.

The `connect()` syscall is not limited to external network connections. It can also be used for local UNIX domain sockets.

Therefore, the socket family and address must be inspected before classifying an event as outbound network activity.

### Wazuh Monitoring

Wazuh can collect and display security events from Linux systems, including configured Auditd-related logs.

However, collecting a log and generating a security alert are different things.

A Wazuh alert depends on the available event data, decoding, and configured detection rules. A sudo event showing the execution of `ausearch` is not an outbound-connection detection.

### Investigation Approach

A reliable investigation follows this sequence:

1. Identify active connections.
2. Record the local and remote endpoints.
3. Identify the process and PID.
4. Review the process owner and executable.
5. Examine relevant Auditd events.
6. Check whether the socket is local or network-based.
7. Correlate the evidence with Wazuh events.
8. Decide whether the activity is expected, suspicious, or confirmed malicious.

### Key Takeaway

A network connection, a successful `connect()` syscall, or an unfamiliar destination does not independently prove malicious activity.

The process, user, destination, socket type, timing, and surrounding system activity must be correlated before reaching an investigation conclusion.

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

## Lab Objectives

The objective of this lab is to investigate Linux network connections and understand how to identify the process responsible for initiating communication with another endpoint.

By completing this lab, the learner should be able to:

1. **Inspect active network connections:** Use `ss` to identify established TCP connections and review their local and remote IP addresses, ports, and connection states.

2. **Identify the owning process:** Associate an active socket with its process name and PID, then use process information to understand which application initiated the connection.

3. **Understand connection states:** Recognize the meaning of `ESTAB`, `LISTEN`, and other socket states, and distinguish an active connection from a service waiting for incoming connections.

4. **Perform controlled HTTPS testing:** Generate a benign connection to a known external endpoint and observe the resulting network activity.

5. **Monitor connection system calls:** Configure a temporary Auditd rule for the `connect()` syscall and examine the process, user, executable, syscall result, and socket address information.

6. **Recognize local socket activity:** Distinguish UNIX domain socket communication between local processes from IP-based network connections, including external outbound connections.

7. **Review Wazuh events:** Examine collected events in the Wazuh Dashboard and distinguish command-execution records from actual network-related security detections.

8. **Correlate evidence before classifying activity:** Evaluate the process, destination, user, connection state, and supporting logs instead of treating an unfamiliar connection or successful syscall as proof of malicious behavior.

9. **Perform safe cleanup:** Remove the temporary Auditd rule and verify that it is no longer present in the active rule list.

### Expected Learning Outcome

By the end of the lab, the learner should be able to explain how to identify an active Linux connection, attribute it to a process, investigate connection-related Auditd records, and assess whether the observed activity is expected or requires further investigation.

## Lab Scenario

A Linux server is running several services, including Wazuh Manager, Wazuh Indexer, and other system processes. During routine security monitoring, network connections are observed between local services and external endpoints.

The security analyst needs to understand which processes are initiating these connections, identify their destinations, and determine whether the activity is expected or potentially suspicious.

To investigate this, a controlled HTTPS connection to `example.com` is generated from the Rocky Linux server. The analyst uses `ss` to inspect established connections and identify the associated process, PID, local port, and remote endpoint.

Auditd is then used to monitor `connect()` system calls to examine the processes and socket information involved in connection activity. The resulting audit records are reviewed alongside events displayed in the Wazuh Dashboard.

During the investigation, several events are found to involve local UNIX sockets used by Wazuh and other system services. A sudo-related Wazuh event also records the execution of the `ausearch` command.

The analyst must distinguish local inter-process communication from external network connections and determine what the available evidence actually confirms.

### Investigation Goals

- Identify established network connections and their endpoints.
- Attribute observed connections to processes and PIDs.
- Examine connection-related system calls using Auditd.
- Review relevant events in the Wazuh Dashboard.
- Distinguish local service communication from external connections.
- Determine whether the available evidence supports suspicious activity or only expected system behavior.

**Expected Outcome:** Produce an evidence-based investigation documenting the observed connections, associated processes, Auditd events, and Wazuh findings without treating every connection or syscall as malicious.

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

