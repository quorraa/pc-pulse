use anyhow::{Result, bail};
use windows::{
    Win32::System::Performance::{
        PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PdhAddEnglishCounterW,
        PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue, PdhOpenQueryW,
    },
    core::PCWSTR,
};

const ERROR_SUCCESS: u32 = 0;

#[derive(Debug, Clone, Copy, Default)]
pub struct PdhSample {
    pub cpu_percent: f64,
    pub disk_latency_ms: f64,
    pub dpc_rate: f64,
    pub interrupt_rate: f64,
    /// Effective processor frequency (base MHz × % performance), or `None`
    /// when the "Processor Information" counter set is unavailable.
    pub cpu_frequency_mhz: Option<f64>,
}

pub struct PdhCollector {
    query: PDH_HQUERY,
    cpu: PDH_HCOUNTER,
    disk_latency: PDH_HCOUNTER,
    dpc_rate: PDH_HCOUNTER,
    interrupt_rate: PDH_HCOUNTER,
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
            let mut query = PDH_HQUERY::default();
            let status = PdhOpenQueryW(PCWSTR::null(), 0, &mut query);
            if status != ERROR_SUCCESS {
                bail!("PdhOpenQueryW failed with status 0x{status:08x}");
            }
            let result = Self {
                query,
                cpu: add_counter(query, r"\Processor(_Total)\% Processor Time")?,
                disk_latency: add_counter(query, r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer")?,
                dpc_rate: add_counter(query, r"\Processor(_Total)\DPC Rate")?,
                interrupt_rate: add_counter(query, r"\Processor(_Total)\Interrupts/sec")?,
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
            if PdhCollectQueryData(self.query) != ERROR_SUCCESS {
                return PdhSample::default();
            }
            PdhSample {
                cpu_percent: formatted(self.cpu).clamp(0.0, 100.0),
                disk_latency_ms: (formatted(self.disk_latency) * 1_000.0).max(0.0),
                dpc_rate: formatted(self.dpc_rate).max(0.0),
                interrupt_rate: formatted(self.interrupt_rate).max(0.0),
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

impl Drop for PdhCollector {
    fn drop(&mut self) {
        unsafe {
            let _ = PdhCloseQuery(self.query);
        }
    }
}

unsafe fn add_counter(query: PDH_HQUERY, path: &str) -> Result<PDH_HCOUNTER> {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut counter = PDH_HCOUNTER::default();
    let status = unsafe { PdhAddEnglishCounterW(query, PCWSTR(wide.as_ptr()), 0, &mut counter) };
    if status != ERROR_SUCCESS {
        bail!("PdhAddEnglishCounterW({path}) failed with status 0x{status:08x}");
    }
    Ok(counter)
}

unsafe fn formatted(counter: PDH_HCOUNTER) -> f64 {
    let mut value = PDH_FMT_COUNTERVALUE::default();
    let status = unsafe { PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut value) };
    if status != ERROR_SUCCESS || value.CStatus != ERROR_SUCCESS {
        return 0.0;
    }
    let result = unsafe { value.Anonymous.doubleValue };
    if result.is_finite() { result } else { 0.0 }
}
