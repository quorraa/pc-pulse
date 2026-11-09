//! Native, single-worker network diagnostics. No subprocess, WMI, ETW, or setting writes.
//!
//! Required windows 0.62 features: Win32_Networking_WinSock,
//! Win32_NetworkManagement_IpHelper, Win32_NetworkManagement_Ndis,
//! Win32_System_IO, Win32_System_Threading, Win32_Security and Win32_Foundation.
//!
//! Routine: <=2 absolute public-name Windows DNS requests, 2s each, plus IP Helper.
//! Escalation: <=3 one-packet UDP DNS requests and <=2 TCP connects, 1.5s each.
//! Requested network waits total <=11.5s, clipped to a shared 14s deadline.
//! GetAdaptersAddresses/GetBestRoute2 are synchronous OS APIs without a timeout;
//! their calls and allocation/retry counts are bounded, but a faulty OS/provider can
//! still hang. The owning worker must mark stale, never spawn a replacement or join
//! a hung worker on Drop. This module never spawns threads or uses async callbacks.
//!
//! GetAddrInfoExW explicitly supports timeout for its Unicode/W entry point:
//! https://learn.microsoft.com/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw
//! TIMEVAL uses seconds/microseconds. It requires asynchronous OVERLAPPED mode on
//! the tested Windows build; synchronous TIMEVAL calls immediately return 10022.
//! A manual-reset event provides completion without callbacks. At the 2s deadline
//! the single worker cancels and drains completion before freeing stable buffers.
//! If an OS/provider fails to complete cancellation, that worker remains blocked:
//! the owner's 30s stale fuse must stop scheduling, not replace/terminate the worker.
//! Route/source selection: GetBestInterfaceEx then constrained GetBestRoute2;
//! explicit comparisons bind the chosen source and set the outgoing interface.
//! https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-getbestroute2
//! https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
//!
//! Addresses, adapter names, DNS packets, and resolver results stay in memory only.
//! Topology hashes are keyed per service process and are not stable across restart.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ProbeTiming {
    pub success: bool,
    pub elapsed_ms: u64,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct ProbeReport {
    pub observed_at_ms: i64,
    pub topology_id: u64,
    pub interface_index: u32,
    pub has_ipv6_route: bool,
    /// Heuristic: an active PPP/tunnel or recognizable VPN adapter. Not proof of VPN routing.
    pub vpn_present: bool,
    pub configured_ipv6_dns_count: u32,
    pub normal_dns: Vec<ProbeTiming>,
    pub ipv4_dns: Option<ProbeTiming>,
    pub configured_ipv6_dns: Option<ProbeTiming>,
    pub public_ipv6_dns: Option<ProbeTiming>,
    pub ipv4_tcp: Option<ProbeTiming>,
    pub ipv6_tcp: Option<ProbeTiming>,
    pub detail_error: Option<String>,
    /// Different actual IPv4/IPv6 public-destination egress; comparisons are not like-for-like.
    pub route_mismatch: bool,
    pub ipv4_interface_index: Option<u32>,
    pub ipv6_interface_index: Option<u32>,
    pub comparison_triggered: bool,
    /// False for skipped probes (absent route, interface mismatch, or elapsed budget).
    pub comparison_complete: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
pub struct TcpPortUsage {
    pub observed_at_ms: i64,
    pub tcp_rows: u32,
    /// Distinct (address family, local port), including listening ports. Not pool occupancy.
    pub distinct_local_ports: u32,
    pub time_wait_rows: u32,
}

pub fn probe(force_comparison: bool) -> ProbeReport {
    #[cfg(windows)]
    {
        win::probe(force_comparison)
    }
    #[cfg(not(windows))]
    {
        let _ = force_comparison;
        ProbeReport {
            detail_error: Some("Native Windows probe unavailable".into()),
            ..Default::default()
        }
    }
}

/// Only call after a newly observed Tcpip 4231/4227 event. No polling or owner attribution.
/// These tables exclude UDP and internal reservations; this is not proof of exhaustion.
pub fn tcp_port_usage() -> Option<TcpPortUsage> {
    #[cfg(windows)]
    {
        win::tcp_port_usage()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(any(windows, test))]
const PUBLIC_NAMES: [&str; 2] = ["discord.com", "github.com"];
#[cfg(any(windows, test))]
const DNS_TYPE_AAAA: u16 = 28;

/// One RD=1 AAAA/IN question. No EDNS, retries, cache flush, private names, or random subdomains.
#[cfg(any(windows, test))]
fn dns_question(id: u16) -> Vec<u8> {
    let mut b = vec![0; 12];
    b[..2].copy_from_slice(&id.to_be_bytes());
    b[2] = 1;
    b[5] = 1;
    for label in PUBLIC_NAMES[0].split('.') {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0);
    b.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b
}

#[cfg(any(windows, test))]
fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// Bounds compressed names and pointer chains; returns normalized labels and encoded end.
#[cfg(any(windows, test))]
fn dns_name(b: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut pos = start;
    let mut end = None;
    let mut name = Vec::new();
    for _ in 0..128 {
        let len = *b.get(pos)?;
        if len & 0xc0 == 0xc0 {
            let target = (((len & 0x3f) as usize) << 8) | *b.get(pos + 1)? as usize;
            // DNS compression points backward; reject cycles and unsupported forward references.
            if target >= pos {
                return None;
            }
            end.get_or_insert(pos + 2);
            pos = target;
        } else if len == 0 {
            return Some((name, end.unwrap_or(pos + 1)));
        } else {
            if len > 63 || name.len() + len as usize + 1 > 255 {
                return None;
            }
            let label = b.get(pos + 1..pos + 1 + len as usize)?;
            name.push(len);
            name.extend(label.iter().map(u8::to_ascii_lowercase));
            pos += 1 + len as usize;
        }
    }
    None
}

/// Successful DNS transport means a well-formed NOERROR or authoritative negative result,
/// not necessarily an AAAA address. NODATA/negative AAAA is healthy; TC/SERVFAIL/REFUSED is not.
#[cfg(any(windows, test))]
fn valid_dns_response(b: &[u8], id: u16) -> bool {
    fn check(b: &[u8], id: u16) -> Option<bool> {
        if b.len() < 12 || be16(b, 0)? != id {
            return None;
        }
        let flags = be16(b, 2)?;
        if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 {
            return None;
        }
        let rcode = flags & 15;
        if rcode != 0 && rcode != 3 {
            return None;
        }
        if be16(b, 4)? != 1 {
            return None;
        }
        let question = dns_question(id);
        let (expected, _) = dns_name(&question, 12)?;
        let (actual, mut pos) = dns_name(b, 12)?;
        if actual != expected || be16(b, pos)? != DNS_TYPE_AAAA || be16(b, pos + 2)? != 1 {
            return None;
        }
        pos += 4;
        let answers = be16(b, 6)? as usize;
        let authority = be16(b, 8)? as usize;
        let additional = be16(b, 10)? as usize;
        let total = answers.checked_add(authority)?.checked_add(additional)?;
        if total > 128 {
            return None;
        }
        let mut negative_soa = false;
        for n in 0..total {
            let (_, at) = dns_name(b, pos)?;
            let rr_type = be16(b, at)?;
            let rr_class = be16(b, at + 2)?;
            let size = be16(b, at + 8)? as usize;
            let data_start = at.checked_add(10)?;
            pos = data_start.checked_add(size)?;
            if pos > b.len() {
                return None;
            }
            if rr_type == 41 && *b.get(at + 4)? != 0 {
                return None;
            } // Extended EDNS error code.
            if rr_type == 28 && size != 16 {
                return None;
            }
            if n >= answers && n < answers + authority && rr_type == 6 && rr_class == 1 {
                let (_, first_end) = dns_name(b, data_start)?;
                if first_end > pos {
                    return None;
                }
                let (_, second_end) = dns_name(b, first_end)?;
                if second_end.checked_add(20)? != pos {
                    return None;
                }
                negative_soa = true;
            }
        }
        if pos != b.len() {
            return None;
        }
        // Reject a referral/empty unqualified response as evidence of recursive resolution.
        Some(if rcode == 3 {
            negative_soa || flags & 0x0400 != 0
        } else {
            answers > 0 || negative_soa || flags & 0x0400 != 0
        })
    }
    check(b, id).unwrap_or(false)
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::{
        cell::UnsafeCell,
        collections::{HashSet, hash_map::RandomState},
        hash::{BuildHasher, Hash, Hasher},
        io,
        mem::{offset_of, size_of, size_of_val},
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
        os::windows::io::AsRawSocket,
        ptr,
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use windows::{
        Win32::{
            Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
            NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
            Networking::WinSock::*,
            System::{
                IO::OVERLAPPED,
                Threading::{CreateEventW, WaitForSingleObject},
            },
        },
        core::{PCWSTR, PSTR},
    };

    const NORMAL_TIMEOUT: Duration = Duration::from_millis(2000);
    const WIRE_TIMEOUT: Duration = Duration::from_millis(1500);
    const TOTAL_BUDGET: Duration = Duration::from_secs(14);
    const PUBLIC4: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53));
    const PUBLIC6: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        53,
        0,
        0,
    ));
    static HASH_KEY: OnceLock<RandomState> = OnceLock::new();
    static QUERY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64
    }
    fn elapsed(start: Instant, success: bool, timed_out: bool) -> ProbeTiming {
        ProbeTiming {
            success,
            elapsed_ms: start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            timed_out,
        }
    }
    fn remaining(deadline: Instant, cap: Duration) -> Option<Duration> {
        let left = deadline.saturating_duration_since(Instant::now()).min(cap);
        (left >= Duration::from_millis(1)).then_some(left)
    }
    fn timeval(duration: Duration) -> TIMEVAL {
        TIMEVAL {
            tv_sec: duration.as_secs().min(i32::MAX as u64) as i32,
            tv_usec: duration.subsec_micros() as i32,
        }
    }
    fn note(report: &mut ProbeReport, text: &str) {
        let error = report.detail_error.get_or_insert_with(String::new);
        if error.len() + text.len() + 2 <= 256 {
            if !error.is_empty() {
                error.push_str("; ");
            }
            error.push_str(text);
        }
    }
    struct Winsock;
    impl Winsock {
        fn new() -> Option<Self> {
            let mut data = WSADATA::default();
            (unsafe { WSAStartup(0x0202, &mut data) } == 0).then_some(Self)
        }
    }
    impl Drop for Winsock {
        fn drop(&mut self) {
            unsafe {
                WSACleanup();
            }
        }
    }
    struct NativeSocket(SOCKET);
    impl Drop for NativeSocket {
        fn drop(&mut self) {
            unsafe {
                closesocket(self.0);
            }
        }
    }
    struct DnsEvent(HANDLE);
    impl Drop for DnsEvent {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    // Only constructed in a Box, never moved out while pending. UnsafeCell marks
    // fields written by the OS; no Rust reference to their contents crosses a wait.
    // The cancellation handle belongs to Winsock and must NOT be CloseHandle'd.
    struct DnsRequest {
        name: Vec<u16>,
        hints: ADDRINFOEXW,
        timeout: TIMEVAL,
        result: UnsafeCell<*mut ADDRINFOEXW>,
        overlapped: UnsafeCell<OVERLAPPED>,
        cancel_handle: UnsafeCell<HANDLE>,
        event: DnsEvent,
        pending: bool,
    }
    fn dns_pending(code: i32) -> bool {
        code == WSA_IO_PENDING.0 || code == WSAEINPROGRESS.0
    }
    impl DnsRequest {
        fn new(name: &'static str, budget: Duration) -> Result<Box<Self>, i32> {
            let event = DnsEvent(
                unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
                    .map_err(|error| error.code().0)?,
            );
            Ok(Box::new(Self {
                name: format!("{name}.").encode_utf16().chain(Some(0)).collect(),
                hints: ADDRINFOEXW {
                    ai_family: AF_UNSPEC.0 as i32,
                    ai_socktype: SOCK_STREAM.0,
                    ai_protocol: IPPROTO_TCP.0,
                    ..Default::default()
                },
                timeout: timeval(budget),
                result: UnsafeCell::new(ptr::null_mut()),
                overlapped: UnsafeCell::new(OVERLAPPED {
                    hEvent: event.0,
                    ..Default::default()
                }),
                cancel_handle: UnsafeCell::new(HANDLE::default()),
                event,
                pending: false,
            }))
        }
        fn completion(&mut self) -> i32 {
            let code = unsafe { GetAddrInfoExOverlappedResult(self.overlapped.get()) };
            self.pending = dns_pending(code);
            code
        }
        fn cancel_and_drain(&mut self) -> i32 {
            unsafe {
                GetAddrInfoExCancel(self.cancel_handle.get());
            }
            // Never release pending OVERLAPPED/name/hints/result storage. Even a
            // cancellation failure can mean completion won the race; inspect it.
            // Broken providers can block here beyond the requested time budget.
            loop {
                let wait = unsafe { WaitForSingleObject(self.event.0, 1000) };
                let code = self.completion();
                if !self.pending {
                    return code;
                }
                if wait != WAIT_TIMEOUT {
                    // An anomalous signaled/failed event must not create a busy loop.
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
    impl Drop for DnsRequest {
        fn drop(&mut self) {
            if self.pending {
                self.cancel_and_drain();
            }
            let result = unsafe { *self.result.get() };
            if !result.is_null() {
                unsafe {
                    FreeAddrInfoExW(Some(result));
                }
            }
            // event closes only after this Drop body; all other buffers remain live.
        }
    }
    struct NormalDns {
        timing: ProbeTiming,
        api_error: Option<i32>,
    }
    fn dns_api_error(code: i32, has_result: bool, deadline_cancelled: bool) -> Option<i32> {
        if code == 0 {
            return (!has_result).then_some(13); // ERROR_INVALID_DATA: unexpected empty result.
        }
        if [
            WSAHOST_NOT_FOUND.0,
            WSATRY_AGAIN.0,
            WSANO_RECOVERY.0,
            WSANO_DATA.0,
            WSAETIMEDOUT.0,
            WSAENETUNREACH.0,
            WSAEHOSTUNREACH.0,
            1460,
        ]
        .contains(&code)
            || (deadline_cancelled && [WSA_E_CANCELLED.0, WSA_OPERATION_ABORTED.0].contains(&code))
        {
            None
        } else {
            Some(code)
        }
    }
    fn normal_dns(name: &'static str, budget: Duration) -> NormalDns {
        let began = Instant::now();
        let mut request = match DnsRequest::new(name, budget) {
            Ok(request) => request,
            Err(code) => {
                return NormalDns {
                    timing: elapsed(began, false, false),
                    api_error: Some(code),
                };
            }
        };
        let start_code = unsafe {
            GetAddrInfoExW(
                PCWSTR(request.name.as_ptr()),
                PCWSTR::null(),
                NS_DNS,
                None,
                Some(&request.hints),
                request.result.get(),
                Some(&request.timeout),
                Some(request.overlapped.get()),
                None,
                Some(request.cancel_handle.get()),
            )
        };
        // Only WSA_IO_PENDING starts an asynchronous request. WSAEINPROGRESS is
        // a pending status from OverlappedResult, but an immediate start failure.
        request.pending = start_code == WSA_IO_PENDING.0;
        let mut code = start_code;
        let mut deadline_cancelled = false;
        let mut wait_error = None;
        if request.pending {
            let left = budget.saturating_sub(began.elapsed());
            let wait_ms = left.as_micros().div_ceil(1000).min(u32::MAX as u128 - 1) as u32;
            let wait = unsafe { WaitForSingleObject(request.event.0, wait_ms) };
            if wait == WAIT_OBJECT_0 {
                code = request.completion();
                if request.pending {
                    // Signaled before completion is an API anomaly, not DNS evidence.
                    wait_error = Some(WSAEINPROGRESS.0);
                    code = request.cancel_and_drain();
                }
            } else {
                deadline_cancelled = wait == WAIT_TIMEOUT;
                if !deadline_cancelled {
                    wait_error = Some(unsafe { GetLastError() }.0 as i32);
                }
                code = request.cancel_and_drain();
            }
        }
        let has_result = !unsafe { *request.result.get() }.is_null();
        let api_error = wait_error.or_else(|| dns_api_error(code, has_result, deadline_cancelled));
        #[cfg(test)]
        eprintln!(
            "{}",
            serde_json::json!({"nativeDnsApi":"GetAddrInfoExW","mode":"event-overlapped","startCode":start_code,"returnCode":code,"apiError":api_error,"deadlineCancelled":deadline_cancelled,"elapsedMs":began.elapsed().as_millis()})
        );
        NormalDns {
            timing: elapsed(
                began,
                code == 0 && has_result && api_error.is_none(),
                deadline_cancelled || code == WSAETIMEDOUT.0 || code == 1460,
            ),
            api_error,
        }
    }

    fn native_address(address: SocketAddr) -> SOCKADDR_INET {
        match address {
            SocketAddr::V4(v) => SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: v.port().to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(v.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                },
            },
            SocketAddr::V6(v) => SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: v.port().to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: v.ip().octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 {
                        sin6_scope_id: v.scope_id(),
                    },
                },
            },
        }
    }
    fn native_len(address: SocketAddr) -> i32 {
        (if address.is_ipv4() {
            size_of::<SOCKADDR_IN>()
        } else {
            size_of::<SOCKADDR_IN6>()
        }) as i32
    }
    unsafe fn read_address(address: *const SOCKADDR, length: usize) -> Option<SocketAddr> {
        if address.is_null() || length < size_of::<ADDRESS_FAMILY>() {
            return None;
        }
        let family = unsafe { ptr::read_unaligned(address.cast::<ADDRESS_FAMILY>()) };
        if family == AF_INET && length >= size_of::<SOCKADDR_IN>() {
            let a = unsafe { ptr::read_unaligned(address.cast::<SOCKADDR_IN>()) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(unsafe { a.sin_addr.S_un.S_addr }.to_ne_bytes()),
                u16::from_be(a.sin_port),
            )))
        } else if family == AF_INET6 && length >= size_of::<SOCKADDR_IN6>() {
            let a = unsafe { ptr::read_unaligned(address.cast::<SOCKADDR_IN6>()) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(unsafe { a.sin6_addr.u.Byte }),
                u16::from_be(a.sin6_port),
                0,
                unsafe { a.Anonymous.sin6_scope_id },
            )))
        } else {
            None
        }
    }
    #[derive(Clone)]
    struct Route {
        index: u32,
        source: SocketAddr,
        next_hop: Option<SocketAddr>,
        metric: u32,
    }
    fn route_to(destination: SocketAddr, constrained: Option<u32>) -> Option<Route> {
        let destination_native = native_address(destination);
        let mut index = constrained.unwrap_or(0);
        if index == 0
            && unsafe {
                GetBestInterfaceEx(
                    (&destination_native as *const SOCKADDR_INET).cast(),
                    &mut index,
                )
            } != 0
        {
            return None;
        }
        if index == 0 {
            return None;
        }
        let mut row = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        if unsafe {
            GetBestRoute2(
                None,
                index,
                None,
                &destination_native,
                0,
                &mut row,
                &mut source,
            )
        }
        .0 != 0
            || row.Loopback
        {
            return None;
        }
        let mut source = unsafe {
            read_address(
                (&source as *const SOCKADDR_INET).cast(),
                size_of::<SOCKADDR_INET>(),
            )
        }?;
        if source.ip().is_unspecified()
            || source.ip().is_loopback()
            || source.ip().is_multicast()
            || source.is_ipv4() != destination.is_ipv4()
        {
            return None;
        }
        if let (SocketAddr::V6(src), SocketAddr::V6(dst)) = (source, destination) {
            // An interface with link-local IPv6 only has no usable public IPv6 path.
            if src.ip().is_unicast_link_local() && !dst.ip().is_unicast_link_local() {
                return None;
            }
        }
        source.set_port(0);
        Some(Route {
            index: row.InterfaceIndex,
            source,
            metric: row.Metric,
            next_hop: unsafe {
                read_address(
                    (&row.NextHop as *const SOCKADDR_INET).cast(),
                    size_of::<SOCKADDR_INET>(),
                )
            },
        })
    }

    #[derive(Default)]
    struct Adapter {
        index4: u32,
        index6: u32,
        dns: Vec<SocketAddr>,
        vpn: bool,
    }
    fn in_buffer<T>(p: *const T, buffer: &[u64]) -> bool {
        let start = buffer.as_ptr() as usize;
        let end = start + size_of_val(buffer);
        let p = p as usize;
        p >= start && p.checked_add(size_of::<T>()).is_some_and(|v| v <= end)
    }
    fn buffer_wide(p: *const u16, buffer: &[u64]) -> String {
        let mut text = Vec::new();
        if p.is_null() {
            return String::new();
        }
        for n in 0..128 {
            let p = p.wrapping_add(n);
            if !in_buffer(p, buffer) {
                break;
            }
            let value = unsafe { ptr::read_unaligned(p) };
            if value == 0 {
                break;
            }
            text.push(value);
        }
        String::from_utf16_lossy(&text).to_ascii_lowercase()
    }
    fn adapters() -> Option<Vec<Adapter>> {
        let mut bytes = 15_000u32;
        for _ in 0..2 {
            if bytes > 256 * 1024 {
                return None;
            }
            let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
            bytes = (buffer.len() * 8) as u32;
            let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let code = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                    None,
                    Some(first),
                    &mut bytes,
                )
            };
            if code == 111 {
                continue;
            } // ERROR_BUFFER_OVERFLOW; exactly one bounded retry.
            if code != 0 {
                return None;
            }
            let mut out = Vec::new();
            let mut p = first;
            for _ in 0..128 {
                if p.is_null() {
                    return Some(out);
                }
                if !in_buffer(p, &buffer) {
                    return None;
                }
                let a = unsafe { &*p };
                if unsafe { a.Anonymous1.Anonymous.Length }
                    < size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32
                {
                    return None;
                }
                if a.OperStatus == IfOperStatusUp {
                    let name = buffer_wide(a.FriendlyName.0, &buffer);
                    let description = buffer_wide(a.Description.0, &buffer);
                    let vpn = matches!(a.IfType, IF_TYPE_PPP | IF_TYPE_TUNNEL)
                        || [
                            "vpn",
                            "tailscale",
                            "wireguard",
                            "wintun",
                            "openvpn",
                            "tap-windows",
                        ]
                        .iter()
                        .any(|s| name.contains(s) || description.contains(s));
                    let mut adapter = Adapter {
                        index4: unsafe { a.Anonymous1.Anonymous.IfIndex },
                        index6: a.Ipv6IfIndex,
                        dns: Vec::new(),
                        vpn,
                    };
                    let mut dns = a.FirstDnsServerAddress;
                    for _ in 0..16 {
                        if dns.is_null() {
                            break;
                        }
                        if !in_buffer(dns, &buffer) {
                            return None;
                        }
                        let node = unsafe { &*dns };
                        let len = usize::try_from(node.Address.iSockaddrLength).ok()?;
                        let address = node.Address.lpSockaddr;
                        if len <= size_of::<SOCKADDR_INET>()
                            && in_buffer(address.cast::<u8>(), &buffer)
                            && (address as usize).checked_add(len).is_some_and(|end| {
                                end <= buffer.as_ptr() as usize + buffer.len() * 8
                            })
                            && let Some(mut value) = unsafe { read_address(address, len) }
                        {
                            value.set_port(53);
                            if let SocketAddr::V6(v) = &mut value
                                && v.ip().is_unicast_link_local()
                                && v.scope_id() == 0
                            {
                                v.set_scope_id(a.Ipv6IfIndex);
                            }
                            adapter.dns.push(value);
                        }
                        dns = node.Next;
                    }
                    out.push(adapter);
                }
                p = a.Next;
            }
            return None; // Unusually large/cyclic list: skip instead of unbounded work.
        }
        None
    }

    fn set_interface(socket: SOCKET, route: &Route) -> bool {
        let (level, option, bytes) = if route.source.is_ipv4() {
            (IPPROTO_IP.0, IP_UNICAST_IF, route.index.to_be_bytes())
        } else {
            (IPPROTO_IPV6.0, IPV6_UNICAST_IF, route.index.to_ne_bytes())
        };
        unsafe { setsockopt(socket, level, option, Some(&bytes)) == 0 }
    }
    fn timeout_error(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        )
    }
    fn query_id() -> u16 {
        let mut h = HASH_KEY.get_or_init(RandomState::new).build_hasher();
        QUERY_SEQUENCE.fetch_add(1, Ordering::Relaxed).hash(&mut h);
        now_ms().hash(&mut h);
        h.finish() as u16
    }
    fn hash_source_prefix(source: SocketAddr, hash: &mut impl Hasher) {
        match source {
            SocketAddr::V4(v) => {
                4u8.hash(hash);
                v.ip().octets().hash(hash);
            }
            SocketAddr::V6(v) => {
                6u8.hash(hash);
                // Rotating privacy interface identifiers must not rearm a topology change.
                v.ip().octets()[..8].hash(hash);
                v.scope_id().hash(hash);
            }
        }
    }
    fn udp_dns(destination: SocketAddr, route: &Route, budget: Duration) -> ProbeTiming {
        let start = Instant::now();
        let deadline = start + budget;
        let socket = match UdpSocket::bind(route.source) {
            Ok(s) => s,
            Err(_) => return elapsed(start, false, false),
        };
        if !set_interface(SOCKET(socket.as_raw_socket() as usize), route) {
            return elapsed(start, false, false);
        }
        if socket.set_write_timeout(Some(budget)).is_err() || socket.connect(destination).is_err() {
            return elapsed(start, false, false);
        }
        let id = query_id();
        let question = dns_question(id);
        match socket.send(&question) {
            Ok(n) if n == question.len() => {}
            Ok(_) => return elapsed(start, false, false),
            Err(e) => return elapsed(start, false, timeout_error(&e)),
        }
        let mut response = [0u8; 4096];
        // Connected UDP checks peer. At most four invalid datagrams; never retry/send again.
        for _ in 0..4 {
            let Some(wait) = remaining(deadline, budget) else {
                return elapsed(start, false, true);
            };
            if socket.set_read_timeout(Some(wait)).is_err() {
                return elapsed(start, false, false);
            }
            match socket.recv(&mut response) {
                Ok(n) => {
                    if be16(&response[..n], 0) != Some(id) {
                        continue;
                    }
                    return elapsed(start, valid_dns_response(&response[..n], id), false);
                }
                Err(e) => return elapsed(start, false, timeout_error(&e)),
            }
        }
        elapsed(start, false, false)
    }
    fn tcp_connect(mut destination: SocketAddr, route: &Route, budget: Duration) -> ProbeTiming {
        let start = Instant::now();
        let deadline = start + budget;
        destination.set_port(443);
        let Ok(handle) = (unsafe {
            socket(
                if destination.is_ipv4() {
                    AF_INET.0
                } else {
                    AF_INET6.0
                } as i32,
                SOCK_STREAM,
                IPPROTO_TCP.0,
            )
        }) else {
            return elapsed(start, false, false);
        };
        let socket = NativeSocket(handle);
        if !set_interface(socket.0, route) {
            return elapsed(start, false, false);
        }
        let source = native_address(route.source);
        let target = native_address(destination);
        let mut nonblocking = 1u32;
        if unsafe {
            bind(
                socket.0,
                (&source as *const SOCKADDR_INET).cast(),
                native_len(route.source),
            )
        } != 0
            || unsafe { ioctlsocket(socket.0, FIONBIO, &mut nonblocking) } != 0
        {
            return elapsed(start, false, false);
        }
        if unsafe {
            connect(
                socket.0,
                (&target as *const SOCKADDR_INET).cast(),
                native_len(destination),
            )
        } == 0
        {
            return elapsed(start, true, false);
        }
        let error = unsafe { WSAGetLastError().0 };
        if error != WSAEWOULDBLOCK.0 && error != 10036 {
            return elapsed(start, false, error == WSAETIMEDOUT.0);
        }
        let Some(wait) = remaining(deadline, budget) else {
            return elapsed(start, false, true);
        };
        let mut writes = FD_SET {
            fd_count: 1,
            ..Default::default()
        };
        writes.fd_array[0] = socket.0;
        let mut errors = writes;
        let timeout = timeval(wait);
        let selected = unsafe {
            select(
                0,
                None,
                Some(&mut writes),
                Some(&mut errors),
                Some(&timeout),
            )
        };
        if selected <= 0 {
            return elapsed(start, false, selected == 0);
        }
        let mut code = 0i32;
        let mut length = size_of::<i32>() as i32;
        let read = unsafe {
            getsockopt(
                socket.0,
                SOL_SOCKET,
                SO_ERROR,
                PSTR((&mut code as *mut i32).cast()),
                &mut length,
            )
        };
        elapsed(
            start,
            read == 0 && length == size_of::<i32>() as i32 && code == 0,
            code == WSAETIMEDOUT.0,
        )
    }

    pub(super) fn probe(force: bool) -> ProbeReport {
        let deadline = Instant::now() + TOTAL_BUDGET;
        let mut report = ProbeReport {
            observed_at_ms: now_ms(),
            ..Default::default()
        };
        let Some(_winsock) = Winsock::new() else {
            note(&mut report, "Winsock initialization unavailable");
            return report;
        };
        let route4 = route_to(PUBLIC4, None);
        let route6 = route_to(PUBLIC6, None);
        report.ipv4_interface_index = route4.as_ref().map(|r| r.index);
        report.ipv6_interface_index = route6.as_ref().map(|r| r.index);
        report.interface_index = report
            .ipv4_interface_index
            .or(report.ipv6_interface_index)
            .unwrap_or(0);
        report.has_ipv6_route = route6.is_some();
        report.route_mismatch = report
            .ipv4_interface_index
            .zip(report.ipv6_interface_index)
            .is_some_and(|(a, b)| a != b);
        let snapshot = adapters();
        if snapshot.is_none() {
            note(&mut report, "Adapter snapshot unavailable");
        }
        let selected = snapshot.as_ref().and_then(|all| {
            all.iter()
                .find(|a| a.index4 == report.interface_index || a.index6 == report.interface_index)
        });
        report.vpn_present = snapshot
            .as_ref()
            .is_some_and(|all| all.iter().any(|a| a.vpn));
        report.configured_ipv6_dns_count =
            selected.map_or(0, |a| a.dns.iter().filter(|d| d.is_ipv6()).count() as u32);
        let configured6 = selected
            .and_then(|a| a.dns.iter().find(|d| d.is_ipv6()))
            .copied();
        let mut hash = HASH_KEY.get_or_init(RandomState::new).build_hasher();
        for route in [&route4, &route6] {
            if let Some(r) = route {
                r.index.hash(&mut hash);
                hash_source_prefix(r.source, &mut hash);
                r.next_hop.hash(&mut hash);
                r.metric.hash(&mut hash);
            } else {
                0u32.hash(&mut hash);
            }
        }
        if let Some(a) = selected {
            a.dns.hash(&mut hash);
        }
        report.vpn_present.hash(&mut hash);
        report.topology_id = hash.finish();
        if report.route_mismatch {
            note(
                &mut report,
                "IPv4 and IPv6 use different interfaces; configured IPv6 comparison skipped",
            );
        }
        if route4.is_none() && route6.is_none() {
            report.comparison_triggered = force;
            note(&mut report, "No public route; network probes skipped");
            return report;
        }
        for name in PUBLIC_NAMES {
            let Some(budget) = remaining(deadline, NORMAL_TIMEOUT) else {
                note(&mut report, "Probe time budget reached");
                break;
            };
            let dns = normal_dns(name, budget);
            report.normal_dns.push(dns.timing);
            if let Some(code) = dns.api_error {
                note(
                    &mut report,
                    &format!("Native DNS API unavailable (code {code}); probe inconclusive"),
                );
                return report; // Invocation/setup failure must not trigger wire comparisons or a network warning.
            }
        }
        report.comparison_triggered = force
            || report
                .normal_dns
                .iter()
                .any(|r| !r.success || r.timed_out || r.elapsed_ms >= 1500);
        if !report.comparison_triggered {
            return report;
        }
        if let (Some(r), Some(b)) = (&route4, remaining(deadline, WIRE_TIMEOUT)) {
            report.ipv4_dns = Some(udp_dns(PUBLIC4, r, b));
        }
        if report.has_ipv6_route
            && !report.route_mismatch
            && let Some(server) = configured6
            && let Some(r) = route_to(server, report.ipv6_interface_index)
            && let Some(b) = remaining(deadline, WIRE_TIMEOUT)
        {
            report.configured_ipv6_dns = Some(udp_dns(server, &r, b));
        }
        if let (Some(r), Some(b)) = (&route6, remaining(deadline, WIRE_TIMEOUT)) {
            report.public_ipv6_dns = Some(udp_dns(PUBLIC6, r, b));
        }
        if let (Some(r), Some(b)) = (&route4, remaining(deadline, WIRE_TIMEOUT)) {
            report.ipv4_tcp = Some(tcp_connect(PUBLIC4, r, b));
        }
        if let (Some(r), Some(b)) = (&route6, remaining(deadline, WIRE_TIMEOUT)) {
            report.ipv6_tcp = Some(tcp_connect(PUBLIC6, r, b));
        }
        report.comparison_complete = report.ipv4_dns.is_some()
            && report.ipv4_tcp.is_some()
            && report.public_ipv6_dns.is_some()
            && report.ipv6_tcp.is_some()
            && report.configured_ipv6_dns.is_some();
        if Instant::now() >= deadline {
            note(
                &mut report,
                "Probe time budget reached; remaining comparisons skipped",
            );
        }
        report
    }

    fn tcp_table(ipv6: bool) -> Option<(Vec<u64>, usize)> {
        let mut bytes = 64 * 1024u32;
        for _ in 0..2 {
            if bytes > 1024 * 1024 {
                return None;
            }
            let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
            bytes = (buffer.len() * 8) as u32;
            let code = unsafe {
                if ipv6 {
                    GetTcp6Table(buffer.as_mut_ptr().cast(), &mut bytes, false)
                } else {
                    GetTcpTable(Some(buffer.as_mut_ptr().cast()), &mut bytes, false)
                }
            };
            if code == 122 {
                continue;
            } // ERROR_INSUFFICIENT_BUFFER
            if code != 0 || bytes as usize > buffer.len() * 8 {
                return None;
            }
            return Some((buffer, bytes as usize));
        }
        None
    }
    pub(super) fn tcp_port_usage() -> Option<TcpPortUsage> {
        let mut result = TcpPortUsage {
            observed_at_ms: now_ms(),
            ..Default::default()
        };
        let mut ports = HashSet::new();
        for ipv6 in [false, true] {
            let (buffer, length) = tcp_table(ipv6)?;
            if length < 4 {
                return None;
            }
            let count = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
            let (offset, row_size) = if ipv6 {
                (offset_of!(MIB_TCP6TABLE, table), size_of::<MIB_TCP6ROW>())
            } else {
                (offset_of!(MIB_TCPTABLE, table), size_of::<MIB_TCPROW_LH>())
            };
            if offset.checked_add(count.checked_mul(row_size)?)? > length {
                return None;
            }
            for n in 0..count {
                let at = unsafe { buffer.as_ptr().cast::<u8>().add(offset + n * row_size) };
                let (port, state) = unsafe {
                    if ipv6 {
                        let r = ptr::read_unaligned(at.cast::<MIB_TCP6ROW>());
                        (r.dwLocalPort, r.State.0)
                    } else {
                        let r = ptr::read_unaligned(at.cast::<MIB_TCPROW_LH>());
                        (r.dwLocalPort, r.Anonymous.dwState as i32)
                    }
                };
                ports.insert((if ipv6 { 6u8 } else { 4u8 }, u16::from_be(port as u16)));
                result.tcp_rows += 1;
                if state == 11 {
                    result.time_wait_rows += 1;
                }
            }
        }
        result.distinct_local_ports = ports.len() as u32;
        Some(result)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn timeval_budget_and_sockaddr_round_trip() {
            let t = timeval(Duration::from_millis(1500));
            assert_eq!((t.tv_sec, t.tv_usec), (1, 500_000));
            assert!(remaining(Instant::now(), WIRE_TIMEOUT).is_none());
            for a in [
                PUBLIC4,
                PUBLIC6,
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 9)),
            ] {
                let n = native_address(a);
                assert_eq!(
                    unsafe {
                        read_address(
                            (&n as *const SOCKADDR_INET).cast(),
                            size_of::<SOCKADDR_INET>(),
                        )
                    },
                    Some(a)
                );
            }
        }
        #[test]
        fn bounded_generic_diagnostics_and_family_distinct_ports() {
            let mut r = ProbeReport::default();
            for _ in 0..100 {
                note(&mut r, "Generic diagnostic");
            }
            assert!(r.detail_error.unwrap().len() <= 256);
            let ports: HashSet<_> = [(4u8, 443u16), (4, 443), (6, 443)].into_iter().collect();
            assert_eq!(ports.len(), 2);
        }
        #[test]
        fn resolver_api_errors_are_inconclusive_and_completion_states_are_distinct() {
            for code in [
                WSAEINVAL.0,
                WSA_IO_PENDING.0,
                WSAEINPROGRESS.0,
                WSA_NOT_ENOUGH_MEMORY.0,
            ] {
                assert_eq!(dns_api_error(code, false, false), Some(code));
                assert_eq!(dns_api_error(code, false, true), Some(code));
            }
            for code in [
                WSAHOST_NOT_FOUND.0,
                WSANO_DATA.0,
                WSATRY_AGAIN.0,
                WSAETIMEDOUT.0,
            ] {
                assert_eq!(dns_api_error(code, false, false), None);
            }
            assert_eq!(dns_api_error(0, true, false), None);
            assert_eq!(dns_api_error(0, false, false), Some(13));
            assert_eq!(
                dns_api_error(WSA_E_CANCELLED.0, false, false),
                Some(WSA_E_CANCELLED.0)
            );
            assert_eq!(dns_api_error(WSA_E_CANCELLED.0, false, true), None);
            assert_eq!(dns_api_error(WSA_OPERATION_ABORTED.0, false, true), None);
            assert!(dns_pending(WSA_IO_PENDING.0));
            assert!(dns_pending(WSAEINPROGRESS.0));
            assert!(!dns_pending(0));
            assert!(!dns_pending(WSA_E_CANCELLED.0));
        }
        #[test]
        fn privacy_address_rotation_keeps_topology_prefix_key() {
            fn key(address: &str) -> u64 {
                let mut hash = std::collections::hash_map::DefaultHasher::new();
                hash_source_prefix(
                    SocketAddr::V6(SocketAddrV6::new(address.parse().unwrap(), 0, 0, 0)),
                    &mut hash,
                );
                hash.finish()
            }
            assert_eq!(
                key("2001:db8:1234:5678::1"),
                key("2001:db8:1234:5678:abcd:1234:5678:90ab")
            );
            assert_ne!(key("2001:db8:1234:5678::1"), key("2001:db8:1234:5679::1"));
        }
        #[test]
        #[ignore = "At most three native probes (warm/routine/forced), 45s budget; sends only fixed public diagnostics; run manually only"]
        fn live_probe_is_bounded_and_returns_no_addresses() {
            use windows::Win32::{
                Foundation::FILETIME,
                System::{
                    ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX},
                    Threading::{GetCurrentProcess, GetProcessHandleCount, GetProcessTimes},
                },
            };
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Resources {
                cpu_seconds: f64,
                handles: u32,
                working_set_bytes: usize,
                peak_working_set_bytes: usize,
                private_bytes: usize,
            }
            fn resources() -> Resources {
                fn ticks(t: FILETIME) -> u64 {
                    ((t.dwHighDateTime as u64) << 32) | t.dwLowDateTime as u64
                }
                let process = unsafe { GetCurrentProcess() }; // Borrowed pseudo-handle; do not close.
                let mut created = FILETIME::default();
                let mut exited = FILETIME::default();
                let mut kernel = FILETIME::default();
                let mut user = FILETIME::default();
                let mut handles = 0;
                let mut memory = PROCESS_MEMORY_COUNTERS_EX {
                    cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
                    ..Default::default()
                };
                unsafe {
                    GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user)
                        .expect("Current-process CPU counters unavailable");
                    GetProcessHandleCount(process, &mut handles)
                        .expect("Current-process handle count unavailable");
                    GetProcessMemoryInfo(
                        process,
                        (&mut memory as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
                        size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
                    )
                    .expect("Current-process memory counters unavailable");
                }
                Resources {
                    cpu_seconds: (ticks(kernel) + ticks(user)) as f64 / 10_000_000.0,
                    handles,
                    working_set_bytes: memory.WorkingSetSize,
                    peak_working_set_bytes: memory.PeakWorkingSetSize,
                    private_bytes: memory.PrivateUsage,
                }
            }
            let wall = Instant::now();
            let limit = Duration::from_secs(45);
            // No retry or test worker is created. As in production, a broken synchronous
            // OS API needs the external test runner timeout, not a replacement thread.
            for (stage, force) in [("warmRoutine", false), ("routine", false), ("forced", true)] {
                assert!(
                    wall.elapsed() + TOTAL_BUDGET <= limit,
                    "Remaining 45-second budget cannot accommodate another probe"
                );
                let before = resources();
                let started = Instant::now();
                let report = probe(force);
                let probe_elapsed_ms = started.elapsed().as_millis();
                let after = resources();
                let output = serde_json::json!({
                    "test": "nativeNetworkProbeResources",
                    "stage": stage,
                    "scope": "Isolated test process; deltas include native resolver/runtime activity, not full-service footprint",
                    "elapsedMs": probe_elapsed_ms,
                    "totalElapsedMs": wall.elapsed().as_millis(),
                    "report": report,
                    "before": before,
                    "after": after,
                    "delta": {
                        "cpuSeconds": after.cpu_seconds - before.cpu_seconds,
                        "handles": after.handles as i64 - before.handles as i64,
                        "workingSetBytes": after.working_set_bytes as i64 - before.working_set_bytes as i64,
                        "peakWorkingSetBytes": after.peak_working_set_bytes as i64 - before.peak_working_set_bytes as i64,
                        "privateBytes": after.private_bytes as i64 - before.private_bytes as i64
                    },
                    "peakMeaning": "Process-lifetime peak at each snapshot; this is not an independently sampled per-probe peak"
                });
                let json = serde_json::to_string(&output).unwrap();
                println!("{json}");
                // Connectivity may legitimately be unavailable; output is evidence, not
                // an assertion that public endpoints or every resolver must succeed.
                assert!(report.normal_dns.len() <= 2);
                assert!(report.detail_error.as_ref().is_none_or(|s| s.len() <= 256));
                assert!(!json.contains("2606:") && !json.contains("1.1.1.1"));
                assert!(wall.elapsed() < limit, "Native live-test budget exceeded");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(id: u16, flags: u16) -> Vec<u8> {
        let mut b = dns_question(id);
        b[2..4].copy_from_slice(&flags.to_be_bytes());
        b
    }
    fn add_soa(b: &mut Vec<u8>) {
        b[8..10].copy_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0xc0, 12, 0, 6, 0, 1, 0, 0, 0, 0, 0, 24, 0xc0, 12, 0xc0, 12]);
        b.extend_from_slice(&[0; 20]);
    }
    #[test]
    fn fixed_public_question_and_negative_aaaa_success() {
        let q = dns_question(0x1234);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[q.len() - 4..], &[0, 28, 0, 1]);
        let mut nodata = response(1, 0x8180);
        add_soa(&mut nodata);
        assert!(valid_dns_response(&nodata, 1));
        let mut nx = response(1, 0x8183);
        add_soa(&mut nx);
        assert!(valid_dns_response(&nx, 1));
    }
    #[test]
    fn reject_wrong_transaction_question_tc_servfail_and_malformed_records() {
        let mut good = response(3, 0x8580);
        assert!(valid_dns_response(&good, 3));
        assert!(!valid_dns_response(&good, 4));
        for flags in [0x8780, 0x8582, 0x8585, 0x0580, 0x8d80] {
            let b = response(3, flags);
            assert!(!valid_dns_response(&b, 3));
        }
        good[13] = b'x';
        assert!(!valid_dns_response(&good, 3));
        let mut truncated = response(3, 0x8180);
        add_soa(&mut truncated);
        truncated.pop();
        assert!(!valid_dns_response(&truncated, 3));
        let mut bad = response(3, 0x8580);
        bad[12] = 0xc0;
        bad[13] = 12;
        assert!(!valid_dns_response(&bad, 3));
        assert!(!valid_dns_response(&response(3, 0x8180), 3)); // no answer, SOA or AA: not resolution evidence
    }
    #[test]
    fn question_case_is_insensitive_and_parser_is_bounded() {
        let mut b = response(7, 0x8580);
        b[13] = b'D';
        assert!(valid_dns_response(&b, 7));
        for n in 0..12 {
            assert!(!valid_dns_response(&b[..n], 7));
        }
        let mut b = response(7, 0x8580);
        b[6..8].copy_from_slice(&65535u16.to_be_bytes());
        assert!(!valid_dns_response(&b, 7));
    }
}
