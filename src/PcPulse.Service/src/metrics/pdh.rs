use anyhow::{Result, bail};
use windows::{
    Win32::System::Performance::{
        PDH_FMT_COUNTERVALUE, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_HCOUNTER,
        PDH_HQUERY, PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData,
        PdhGetFormattedCounterArrayW, PdhGetFormattedCounterValue, PdhOpenQueryW,
    },
    core::PCWSTR,
};

pub(super) const ERROR_SUCCESS: u32 = 0;
/// PDH's "call again with this buffer size" status for array counters.
const PDH_MORE_DATA: u32 = 0x8000_07D2;

/// Own the query before adding counters: a missing counter must close the
/// query and every counter already attached to it, including during startup.
pub(super) struct PdhQuery(pub(super) PDH_HQUERY);

#[cfg(test)]
thread_local! {
    // Observe the real close call on this test's thread without touching a
    // freed raw handle that another concurrent query could already reuse.
    static QUERY_CLOSE_OBSERVER: std::cell::Cell<Option<(usize, u32)>> = const {
        std::cell::Cell::new(None)
    };
}

impl PdhQuery {
    pub(super) fn open() -> Result<Self> {
        let mut query = PDH_HQUERY::default();
        let status = unsafe { PdhOpenQueryW(PCWSTR::null(), 0, &mut query) };
        if status != ERROR_SUCCESS {
            bail!("PdhOpenQueryW failed with status 0x{status:08x}");
        }
        Ok(Self(query))
    }
}

impl Drop for PdhQuery {
    fn drop(&mut self) {
        let status = unsafe { PdhCloseQuery(self.0) };
        #[cfg(test)]
        QUERY_CLOSE_OBSERVER.with(|observer| {
            if let Some((calls, _)) = observer.get() {
                observer.set(Some((calls + 1, status)));
            }
        });
        let _ = status;
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PdhSample {
    pub cpu_percent: f64,
    pub disk_latency_ms: f64,
    pub dpc_rate: f64,
    pub interrupt_rate: f64,
    /// `\Network Interface(*)\Bytes Total/sec` summed across physical
    /// instances, or 0.0 when the counter set is unavailable.
    pub network_bytes_per_sec: f64,
    /// Effective processor frequency (base MHz × % performance), or `None`
    /// when the "Processor Information" counter set is unavailable.
    pub cpu_frequency_mhz: Option<f64>,
}

pub struct PdhCollector {
    query: PdhQuery,
    cpu: PDH_HCOUNTER,
    disk_latency: PDH_HCOUNTER,
    dpc_rate: PDH_HCOUNTER,
    interrupt_rate: PDH_HCOUNTER,
    /// Wildcard counter over every network interface instance; formatted as
    /// an array each sample and summed. Optional so a machine without the
    /// "Network Interface" counter set still starts and simply reports zero.
    network_total: Option<PDH_HCOUNTER>,
    /// Optional pair: base frequency plus % performance. Missing on systems
    /// without the "Processor Information" counter set; the collector then
    /// simply reports no frequency instead of failing to start.
    processor_frequency: Option<PDH_HCOUNTER>,
    processor_performance: Option<PDH_HCOUNTER>,
}

// PDH query handles are valid across the dedicated sampling thread.
unsafe impl Send for PdhCollector {}

impl PdhCollector {
    pub fn new() -> Result<Self> {
        unsafe {
            let owned_query = PdhQuery::open()?;
            let query = owned_query.0;
            let result = Self {
                query: owned_query,
                cpu: add_counter(query, r"\Processor(_Total)\% Processor Time")?,
                disk_latency: add_counter(query, r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer")?,
                dpc_rate: add_counter(query, r"\Processor(_Total)\DPC Rate")?,
                interrupt_rate: add_counter(query, r"\Processor(_Total)\Interrupts/sec")?,
                network_total: add_counter(query, r"\Network Interface(*)\Bytes Total/sec").ok(),
                processor_frequency: add_counter(
                    query,
                    r"\Processor Information(_Total)\Processor Frequency",
                )
                .ok(),
                processor_performance: add_counter(
                    query,
                    r"\Processor Information(_Total)\% Processor Performance",
                )
                .ok(),
            };
            // Rate counters require two samples. Prime them without blocking.
            let _ = PdhCollectQueryData(query);
            Ok(result)
        }
    }

    pub fn sample(&mut self) -> PdhSample {
        unsafe {
            if PdhCollectQueryData(self.query.0) != ERROR_SUCCESS {
                return PdhSample::default();
            }
            PdhSample {
                cpu_percent: formatted(self.cpu).clamp(0.0, 100.0),
                disk_latency_ms: (formatted(self.disk_latency) * 1_000.0).max(0.0),
                dpc_rate: formatted(self.dpc_rate).max(0.0),
                interrupt_rate: formatted(self.interrupt_rate).max(0.0),
                network_bytes_per_sec: self
                    .network_total
                    .map_or(0.0, |counter| formatted_wildcard_sum(counter)),
                cpu_frequency_mhz: self.effective_frequency_mhz(),
            }
        }
    }
}

impl PdhCollector {
    /// Current effective MHz: base frequency scaled by % performance (which
    /// exceeds 100 under turbo). Falls back to the raw base frequency when
    /// the performance counter is missing, and to `None` when neither
    /// counter yields a positive value.
    fn effective_frequency_mhz(&self) -> Option<f64> {
        let base = unsafe { formatted(self.processor_frequency?) };
        if base <= 0.0 {
            return None;
        }
        let performance = self
            .processor_performance
            .map(|counter| unsafe { formatted(counter) })
            .filter(|value| *value > 0.0);
        Some(match performance {
            Some(percent) => base * percent / 100.0,
            None => base,
        })
    }
}

pub(super) unsafe fn add_counter(query: PDH_HQUERY, path: &str) -> Result<PDH_HCOUNTER> {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut counter = PDH_HCOUNTER::default();
    let status = unsafe { PdhAddEnglishCounterW(query, PCWSTR(wide.as_ptr()), 0, &mut counter) };
    if status != ERROR_SUCCESS {
        bail!("PdhAddEnglishCounterW({path}) failed with status 0x{status:08x}");
    }
    Ok(counter)
}

/// Formats a wildcard counter as an instance array and sums the healthy
/// values. A `_Total` pseudo-instance (not normally present for "Network
/// Interface") is skipped so nothing is counted twice; any status other than
/// success degrades to zero rather than failing the sample.
pub(super) unsafe fn formatted_wildcard_sum(counter: PDH_HCOUNTER) -> f64 {
    unsafe {
        let mut buffer_bytes = 0u32;
        let mut item_count = 0u32;
        let status = PdhGetFormattedCounterArrayW(
            counter,
            PDH_FMT_DOUBLE,
            &mut buffer_bytes,
            &mut item_count,
            None,
        );
        if status != PDH_MORE_DATA || buffer_bytes == 0 {
            return 0.0;
        }
        // u64 alignment satisfies PDH_FMT_COUNTERVALUE_ITEM_W's layout.
        let mut buffer = vec![0u64; (buffer_bytes as usize).div_ceil(size_of::<u64>())];
        let items_ptr = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
        let status = PdhGetFormattedCounterArrayW(
            counter,
            PDH_FMT_DOUBLE,
            &mut buffer_bytes,
            &mut item_count,
            Some(items_ptr),
        );
        if status != ERROR_SUCCESS {
            return 0.0;
        }
        std::slice::from_raw_parts(items_ptr, item_count as usize)
            .iter()
            .filter(|item| item.FmtValue.CStatus == ERROR_SUCCESS)
            .filter(|item| {
                item.szName.is_null() || !item.szName.to_string().is_ok_and(|name| name == "_Total")
            })
            .map(|item| {
                let value = item.FmtValue.Anonymous.doubleValue;
                if value.is_finite() {
                    value.max(0.0)
                } else {
                    0.0
                }
            })
            .sum()
    }
}

pub(super) unsafe fn formatted(counter: PDH_HCOUNTER) -> f64 {
    let mut value = PDH_FMT_COUNTERVALUE::default();
    let status = unsafe { PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut value) };
    if status != ERROR_SUCCESS || value.CStatus != ERROR_SUCCESS {
        return 0.0;
    }
    let result = unsafe { value.Anonymous.doubleValue };
    if result.is_finite() { result } else { 0.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_counter_setup_closes_its_query() {
        QUERY_CLOSE_OBSERVER.with(|observer| observer.set(Some((0, ERROR_SUCCESS))));
        let result = (|| -> Result<()> {
            let query = PdhQuery::open().expect("local PDH query must open for cleanup test");
            unsafe {
                add_counter(query.0, r"\PcPulseDefinitelyMissingCounter\Missing")?;
            }
            Ok(())
        })();
        assert!(
            result.is_err(),
            "the deliberately invalid counter must fail"
        );
        let closed = QUERY_CLOSE_OBSERVER.with(|observer| observer.take());
        assert_eq!(
            closed,
            Some((1, ERROR_SUCCESS)),
            "one successful close on setup failure"
        );
    }
}
