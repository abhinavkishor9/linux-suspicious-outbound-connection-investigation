# Lab 137 – Investigation Timeline

| Stage | Activity | Evidence / Observation | Interpretation |
|---|---|---|---|
| 1 | Initial socket inspection | `ss -tnp state established` displayed local Wazuh connections and other established TCP sockets. | Identified active TCP communication and associated processes. |
| 2 | Controlled OpenSSL connection | `openssl` PID `8683` connected from `192.168.203.129:46718` to `172.66.147.243:443`. | Confirmed a controlled external HTTPS connection. |
| 3 | Process lookup | `ps -fp 8683` returned no process entry. | The process was no longer running when checked. |
| 4 | HTTPS connectivity test | `curl -I https://example.com` returned `HTTP/2 200`. | Confirmed successful HTTPS request completion. |
| 5 | Auditd monitoring | Temporary `connect()` rule used the key `lab137_outbound`. | Recorded connection-related syscalls, including local UNIX socket activity. |
| 6 | Auditd event review | Events included `wazuh-remoted`, `goa-identity-service`, and Wazuh Indexer Java. | Demonstrated that the rule also captured local socket connections. |
| 7 | Wazuh Dashboard review | Successful sudo event recorded execution of `ausearch -k lab137_outbound -i`. | Confirmed the audit search command execution, not an outbound-network alert. |
| 8 | Final socket inspection | `ss -tunap` displayed local Wazuh connections and connections to the VM's HTTPS listener. | The earlier external OpenSSL connection was not present in this later snapshot. |
| 9 | Auditd cleanup | Temporary rule deleted and `auditctl -l \| grep lab137` returned no match. | Confirmed removal of the temporary lab rule. |

## Final Assessment

The lab demonstrated process-level network connection inspection, controlled HTTPS testing, Auditd syscall monitoring, and Wazuh event review.

The evidence confirmed a controlled external HTTPS connection and several local socket operations. No confirmed malicious outbound connection or corresponding Wazuh detection alert was established.
