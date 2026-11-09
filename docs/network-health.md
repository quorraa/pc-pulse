# Network health checks

PC Pulse can flag the DNS and IPv6 failures that make new pages and chats take seconds to open while established activity continues normally. Enable **Settings → Network health checks**, enter **on**, and press **s** to save. The setting is off by default, including when loading an older settings file.

Checks run inside the `PcPulseCollector` Windows service. The terminal and tray can be closed; they only display the service's results. Findings use the existing history, acknowledgement, archive, and notification controls. Notification eligibility still follows the existing learning and confidence policy.

## What a finding means

| Finding | Evidence and next step |
| --- | --- |
| Slow or failing DNS | Repeated Windows name lookups are slow or fail. Small comparison queries help distinguish a resolver-path failure from general connectivity loss. Review the recorded timings and the configured DNS/VPN path. |
| IPv6 connectivity failure | IPv4 comparison tests succeed while configured IPv6 tests fail repeatedly. Compare another device on the same network before blaming the PC. If multiple devices fail, a router restart can be a controlled test after saving active work; persistent failures warrant an ISP investigation. |
| Connectivity failure | The comparison cannot establish a working internet path. Check the link, VPN state, and whether another device can connect. A failed public probe can also be caused by an intentional network policy. |
| Recent TCP port allocation failure | Windows reported event 4231 or 4227. This establishes an allocation failure, not which process held the resource. A later table snapshot cannot reconstruct every allocation at the event's exact instant. |
| Network monitor unavailable | The worker could not start or a probe did not finish within the watchdog limit. This reports a monitoring limit; it does not diagnose an internet outage. |

An absent IPv6 route is not itself a failure: an IPv4-only network may be working as intended. A single PC cannot prove whether a router or ISP is dropping forwarded traffic. A VPN can intentionally change routing and DNS policy. A public endpoint being blocked does not justify changing those policies automatically.

PC Pulse recommends checks; it never restarts a router, reconnects an adapter, changes DNS, disables IPv6, stops an app, or weakens security software in response to these findings.

## Work and resource limits

- A 60-second startup grace keeps probes out of the busiest startup period.
- Healthy checks run every five minutes. They resolve at most two fixed public names using Windows' resolver.
- Suspected problems receive a confirmation check after one minute. Two of the latest three checks must show the same fault within ten minutes on the same network before a warning. This catches intermittent delays while ignoring a single hiccup. Persistent consecutive failure backs off to a 15-minute cadence; two successful recovery checks clear an active finding.
- Comparison probes run only when a problem warrants them. A comparison uses at most three small UDP DNS queries and two TCP connection attempts. It does not download a web page or upload a file.
- The service uses one internal worker, with no overlapping probe runs or worker process per request. Probe results are bounded. The main performance sampling loop does not wait for network responses.
- Each Windows lookup has a two-second requested timeout. Each UDP/TCP comparison has a 1.5-second timeout. Requested network waits total at most 11.5 seconds per full comparison and are clipped to a shared 14-second deadline, spent waiting on the worker rather than consuming a core.
- Windows DNS uses one event-based native request at a time. When its time limit expires, the service cancels the request and waits for actual completion before freeing its buffers. This adds no per-query thread or callback. A faulty operating-system provider can delay cancellation beyond the requested budget; native metadata calls also have no universal cancellation guarantee.
- A worker that stalls for 30 seconds is marked unavailable and is not replaced with an accumulating series of threads. Its buffers remain alive until the pending native call finishes, and the service does not block its main sampler or shutdown waiting for that worker. A stall therefore limits this monitor rather than slowing the main sampler.
- Existing Windows Event Log collection supplies the DNS/port signals. No continuous network ETW trace, packet capture, PowerShell loop, or separate background recorder is added.
- A TCP table summary is collected only after a relevant allocation event. It reports bounded counts without assuming the Windows dynamic-port range or accusing the requesting application of a leak.
- Network finding timestamps and occurrence counts advance on new evidence. Re-reading a cached result every sampling tick does not manufacture more observations or repeated database writes.

## Data recorded

The normal checks resolve `discord.com` and `github.com` through Windows. Comparison DNS requests use Cloudflare's public resolver addresses and one IPv6 resolver already configured on the selected adapter; TCP checks connect to port 443 at the public resolver addresses. They send no HTTP request or application payload. The service records durations, success/failure, aggregate network state, and an opaque topology identifier. It does not inspect browsing history, Discord messages, uploaded images, application traffic, or private DNS questions. The existing Windows diagnostic-log collector remains a separate feature with its existing redaction and retention rules.

Disabling **Network health checks** stops scheduling new probe runs. A probe already underway may finish. Existing findings remain in normal retained history; this switch is not a history-deletion command.

## Validation boundaries

DNS and TCP success show name resolution and connection reachability. They do not measure a whole webpage's rendering time, TLS/application behaviour, or Discord image processing. Healthy routine checks test DNS; IPv6 connection comparisons are follow-up diagnostics, so an IPv6 failure that leaves Windows DNS fast may remain undetected. A quiet TCP table does not disprove a brief allocation failure or a kernel reservation problem. The service should record these limits alongside its recommendations instead of claiming a precise cause from incomplete evidence.
