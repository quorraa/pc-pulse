//! Hardware gauges: ACPI thermal zones (WMI `root\WMI`
//! `MSAcpi_ThermalZoneTemperature`) and NVIDIA GPU telemetry (NVML, loaded
//! dynamically from the driver's `nvml.dll`). The effective CPU frequency
//! rides in from the sibling PDH collector, which already owns the query.
//!
//! Budget contract: the probes are constructed once and their COM/driver
//! handles are reused for the life of the collector (a fixed handle set —
//! no per-cycle create/teardown, so no growth). One probe pass runs at most
//! every [`SAMPLE_INTERVAL`]; between passes callers get the cached
//! [`HardwareMetrics`]. Every degraded path — namespace absent, access
//! denied, zero zones, missing DLL or symbol — becomes an explicit
//! unavailable state with a human-readable detail, never a crash or a fake
//! zero reading.

use crate::models::{GpuMetrics, HardwareMetrics, ThermalZone};
use anyhow::{Result, anyhow};
use std::{
    ffi::c_void,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::HMODULE,
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoInitializeSecurity, CoSetProxyBlanket, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
            },
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            Variant::{VARIANT, VT_BSTR, VT_I4, VT_R8, VT_UI4, VariantClear},
            Wmi::{
                IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices,
                WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE,
                WbemLocator,
            },
        },
    },
    core::{BSTR, PCSTR, PCWSTR, w},
};

/// Temperatures and clocks drift slowly; probing every snapshot would spend
/// collector budget for no extra signal. One pass at most every five
/// seconds, cached between snapshots.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/// NTLM authentication service id for [`CoSetProxyBlanket`]
/// (`RPC_C_AUTHN_WINNT`); defined locally so the crate needs no extra
/// `Win32_System_Rpc` feature for one constant.
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;

/// The probe families the sampler consults. Production uses WMI + NVML
/// through [`SystemProbe`]; tests substitute stubs so the degraded paths
/// and cadence are provable without real hardware.
pub(crate) trait HardwareProbe {
    /// ACPI thermal zone readings, already converted to Celsius.
    fn thermal_zones(&mut self) -> Result<Vec<ThermalZone>, String>;
    /// Best-effort GPU telemetry; `Err` when the vendor library or every
    /// device is unavailable.
    fn gpus(&mut self) -> Result<Vec<GpuMetrics>, String>;
}

pub struct HardwareSampler<P = SystemProbe> {
    probe: P,
    cached: HardwareMetrics,
    last_probe: Option<Instant>,
}

impl HardwareSampler<SystemProbe> {
    pub fn new() -> Self {
        Self::with_probe(SystemProbe::new())
    }
}

impl Default for HardwareSampler<SystemProbe> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: HardwareProbe> HardwareSampler<P> {
    pub(crate) fn with_probe(probe: P) -> Self {
        Self {
            probe,
            cached: HardwareMetrics::default(),
            last_probe: None,
        }
    }

    /// The current hardware picture. Runs the probes at most once per
    /// [`SAMPLE_INTERVAL`]; between passes the cached reading is returned
    /// (with the free PDH CPU frequency kept fresh).
    pub fn sample(&mut self, timestamp_ms: i64, cpu_frequency_mhz: Option<f64>) -> HardwareMetrics {
        let now = Instant::now();
        let due = self
            .last_probe
            .is_none_or(|last| now.duration_since(last) >= SAMPLE_INTERVAL);
        if !due {
            if cpu_frequency_mhz.is_some() {
                self.cached.cpu_frequency_mhz = cpu_frequency_mhz;
                self.cached.available = true;
            }
            return self.cached.clone();
        }
        self.last_probe = Some(now);
        let mut notes: Vec<String> = Vec::new();
        let thermal_zones = match self.probe.thermal_zones() {
            Ok(zones) if zones.is_empty() => {
                notes.push("no ACPI thermal zones reported".into());
                Vec::new()
            }
            Ok(zones) => zones,
            Err(error) => {
                notes.push(format!("thermal zones unavailable: {error}"));
                Vec::new()
            }
        };
        let gpus = match self.probe.gpus() {
            Ok(gpus) => gpus,
            Err(error) => {
                notes.push(format!("GPU telemetry unavailable: {error}"));
                Vec::new()
            }
        };
        if cpu_frequency_mhz.is_none() {
            notes.push("CPU frequency counter unavailable".into());
        }
        let available =
            !thermal_zones.is_empty() || !gpus.is_empty() || cpu_frequency_mhz.is_some();
        self.cached = HardwareMetrics {
            sampled_at_ms: timestamp_ms,
            cpu_frequency_mhz,
            thermal_zones,
            gpus,
            available,
            detail: notes.join("; "),
        };
        self.cached.clone()
    }
}

/// `MSAcpi_ThermalZoneTemperature.CurrentTemperature` reports tenths of a
/// kelvin.
pub(crate) fn decikelvin_to_celsius(decikelvin: f64) -> f64 {
    decikelvin / 10.0 - 273.15
}

// ---- production probe ---------------------------------------------------

/// The real probe pair. Construction runs once (COM connect + NVML init);
/// failures are sticky details so a machine without ACPI access or an
/// NVIDIA driver degrades once, quietly, instead of retrying into the
/// collector's CPU budget every cycle.
pub struct SystemProbe {
    thermal: Result<WmiThermal, String>,
    nvml: Result<Nvml, String>,
}

impl SystemProbe {
    fn new() -> Self {
        Self {
            thermal: WmiThermal::connect().map_err(|error| format!("{error:#}")),
            nvml: Nvml::load().map_err(|error| format!("{error:#}")),
        }
    }
}

impl HardwareProbe for SystemProbe {
    fn thermal_zones(&mut self) -> Result<Vec<ThermalZone>, String> {
        match &self.thermal {
            Ok(wmi) => match wmi.zones() {
                Ok(zones) => Ok(zones),
                Err(error) => {
                    let detail = format!("{error:#}");
                    // A permanent failure (firmware without thermal zones,
                    // absent class/namespace, denied access) will never
                    // succeed in this process: make it sticky so the query
                    // stops re-running every cycle, and drop the whole WMI
                    // stack — its COM apartment's handle footprint is dead
                    // weight against the collector's handle budget.
                    if is_permanent_thermal_failure(&detail) {
                        self.thermal = Err(detail.clone());
                    }
                    Err(detail)
                }
            },
            Err(detail) => Err(detail.clone()),
        }
    }

    fn gpus(&mut self) -> Result<Vec<GpuMetrics>, String> {
        match &self.nvml {
            Ok(nvml) => Ok(nvml.gpus()),
            Err(detail) => Err(detail.clone()),
        }
    }
}

/// A persistent connection to `root\WMI`. The locator/services objects are
/// refcounted COM interfaces created once and reused for every query, so
/// the handle footprint is a small constant.
struct WmiThermal {
    services: IWbemServices,
}

// The services pointer lives in the multithreaded apartment initialized in
// `connect` and is only used from the dedicated sampling thread.
unsafe impl Send for WmiThermal {}

impl WmiThermal {
    fn connect() -> Result<Self> {
        unsafe {
            // S_OK or S_FALSE (already initialized) both leave COM usable.
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .map_err(|error| anyhow!("CoInitializeEx failed: {error}"))?;
            // Best effort: another component may have set process security
            // already (RPC_E_TOO_LATE), which is fine for local WMI reads.
            let _ = CoInitializeSecurity(
                None,
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
                None,
            );
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
                .map_err(|error| anyhow!("WbemLocator unavailable: {error}"))?;
            let services = locator
                .ConnectServer(
                    &BSTR::from(r"root\WMI"),
                    &BSTR::new(),
                    &BSTR::new(),
                    &BSTR::new(),
                    0,
                    &BSTR::new(),
                    None,
                )
                .map_err(|error| anyhow!(r"root\WMI namespace unavailable: {error}"))?;
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )
            .map_err(|error| anyhow!("CoSetProxyBlanket failed: {error}"))?;
            Ok(Self { services })
        }
    }

    fn zones(&self) -> Result<Vec<ThermalZone>> {
        unsafe {
            let enumerator: IEnumWbemClassObject = self
                .services
                .ExecQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from(
                        "SELECT InstanceName, CurrentTemperature \
                         FROM MSAcpi_ThermalZoneTemperature",
                    ),
                    WBEM_GENERIC_FLAG_TYPE(
                        WBEM_FLAG_FORWARD_ONLY.0 | WBEM_FLAG_RETURN_IMMEDIATELY.0,
                    ),
                    None,
                )
                .map_err(|error| {
                    anyhow!(
                        "thermal-zone query failed: {}",
                        wbem_error_text(error.code())
                    )
                })?;
            let mut zones = Vec::new();
            loop {
                let mut row: [Option<IWbemClassObject>; 1] = [None];
                let mut returned = 0_u32;
                // WBEM_INFINITE: the local WMI service answers immediately.
                let status = enumerator.Next(-1, &mut row, &mut returned);
                if status.is_err() {
                    return Err(anyhow!(
                        "thermal-zone enumeration failed: {}",
                        wbem_error_text(status)
                    ));
                }
                let Some(object) = row[0].take().filter(|_| returned > 0) else {
                    break;
                };
                let Some(decikelvin) = get_f64(&object, w!("CurrentTemperature")) else {
                    continue;
                };
                let name = get_string(&object, w!("InstanceName"))
                    .map(|instance| zone_display_name(&instance))
                    .unwrap_or_else(|| format!("TZ{:02}", zones.len()));
                zones.push(ThermalZone {
                    name,
                    temperature_c: decikelvin_to_celsius(decikelvin),
                });
            }
            Ok(zones)
        }
    }
}

/// Failure modes that cannot heal within this process lifetime: firmware
/// without ACPI thermal zones, an absent WMI class or namespace, or denied
/// access. Matches the phrases `wbem_error_text` maps in this module.
fn is_permanent_thermal_failure(detail: &str) -> bool {
    detail.contains("not supported by this system's ACPI firmware")
        || detail.contains("is absent")
        || detail.contains("access denied")
}

/// The WMI failure modes a user can actually act on, in plain words; other
/// codes fall back to the raw HRESULT.
fn wbem_error_text(status: windows::core::HRESULT) -> String {
    match status.0 as u32 {
        // WBEM_E_ACCESS_DENIED
        0x8004_1003 => "access denied (the installed LocalSystem service may have access)".into(),
        // WBEM_E_INVALID_NAMESPACE / WBEM_E_INVALID_CLASS
        0x8004_100E => "WMI namespace root\\WMI is absent".into(),
        0x8004_1010 => "MSAcpi_ThermalZoneTemperature class is absent".into(),
        // WBEM_E_NOT_SUPPORTED: the firmware exposes no ACPI thermal zone.
        0x8004_100C => "not supported by this system's ACPI firmware".into(),
        code => format!("WMI error 0x{code:08x}"),
    }
}

/// `"ACPI\ThermalZone\TZ00_0"` → `"TZ00"`: the last path segment without
/// the WMI instance suffix.
fn zone_display_name(instance: &str) -> String {
    let tail = instance.rsplit('\\').next().unwrap_or(instance);
    tail.trim_end_matches("_0").to_string()
}

unsafe fn get_f64(object: &IWbemClassObject, name: PCWSTR) -> Option<f64> {
    unsafe {
        let mut variant = VARIANT::default();
        object.Get(name, 0, &mut variant, None, None).ok()?;
        let inner = &variant.Anonymous.Anonymous;
        let value = match inner.vt {
            VT_I4 => Some(f64::from(inner.Anonymous.lVal)),
            VT_UI4 => Some(f64::from(inner.Anonymous.ulVal)),
            VT_R8 => Some(inner.Anonymous.dblVal),
            _ => None,
        };
        let _ = VariantClear(&mut variant);
        value
    }
}

unsafe fn get_string(object: &IWbemClassObject, name: PCWSTR) -> Option<String> {
    unsafe {
        let mut variant = VARIANT::default();
        object.Get(name, 0, &mut variant, None, None).ok()?;
        let inner = &variant.Anonymous.Anonymous;
        let value = (inner.vt == VT_BSTR).then(|| inner.Anonymous.bstrVal.to_string());
        let _ = VariantClear(&mut variant);
        value
    }
}

// ---- NVML (NVIDIA driver) -----------------------------------------------

const NVML_SUCCESS: i32 = 0;
const NVML_TEMPERATURE_GPU: u32 = 0;
const NVML_CLOCK_GRAPHICS: u32 = 0;
const NVML_CLOCK_MEM: u32 = 2;
/// Enumerate a bounded handful of adapters; a workstation with more than
/// four NVIDIA GPUs is out of scope for a gauges page.
const NVML_MAX_DEVICES: u32 = 4;
const NVML_NAME_BUFFER: usize = 96;

type NvmlDevice = *mut c_void;
type NvmlGetTemperature = unsafe extern "C" fn(NvmlDevice, u32, *mut u32) -> i32;
type NvmlGetClockInfo = unsafe extern "C" fn(NvmlDevice, u32, *mut u32) -> i32;
type NvmlGetUtilization = unsafe extern "C" fn(NvmlDevice, *mut NvmlUtilization) -> i32;

#[repr(C)]
#[derive(Default)]
struct NvmlUtilization {
    gpu: u32,
    memory: u32,
}

/// `nvml.dll`, initialized once and kept for the collector's lifetime.
/// `nvmlShutdown` is deliberately never called per sample — init/shutdown
/// churn is the expensive path; the OS reclaims everything at exit.
struct Nvml {
    _library: HMODULE,
    get_temperature: NvmlGetTemperature,
    get_clock_info: NvmlGetClockInfo,
    get_utilization: Option<NvmlGetUtilization>,
    devices: Vec<(String, NvmlDevice)>,
}

// NVML is documented thread-safe; the handles are only used from the
// dedicated sampling thread anyway.
unsafe impl Send for Nvml {}

impl Nvml {
    fn load() -> Result<Self> {
        unsafe {
            let library = LoadLibraryW(w!("nvml.dll"))
                .map_err(|_| anyhow!("nvml.dll not present (no NVIDIA driver)"))?;
            type NvmlInit = unsafe extern "C" fn() -> i32;
            type NvmlGetCount = unsafe extern "C" fn(*mut u32) -> i32;
            type NvmlGetHandle = unsafe extern "C" fn(u32, *mut NvmlDevice) -> i32;
            type NvmlGetName = unsafe extern "C" fn(NvmlDevice, *mut u8, u32) -> i32;
            let init: NvmlInit = symbol(library, "nvmlInit_v2")?;
            let get_count: NvmlGetCount = symbol(library, "nvmlDeviceGetCount_v2")?;
            let get_handle: NvmlGetHandle = symbol(library, "nvmlDeviceGetHandleByIndex_v2")?;
            let get_name: NvmlGetName = symbol(library, "nvmlDeviceGetName")?;
            let get_temperature: NvmlGetTemperature = symbol(library, "nvmlDeviceGetTemperature")?;
            let get_clock_info: NvmlGetClockInfo = symbol(library, "nvmlDeviceGetClockInfo")?;
            let get_utilization: Option<NvmlGetUtilization> =
                symbol(library, "nvmlDeviceGetUtilizationRates").ok();
            let status = init();
            if status != NVML_SUCCESS {
                return Err(anyhow!("nvmlInit_v2 failed with code {status}"));
            }
            let mut count = 0_u32;
            if get_count(&mut count) != NVML_SUCCESS {
                return Err(anyhow!("nvmlDeviceGetCount_v2 failed"));
            }
            let mut devices = Vec::new();
            for index in 0..count.min(NVML_MAX_DEVICES) {
                let mut device: NvmlDevice = std::ptr::null_mut();
                if get_handle(index, &mut device) != NVML_SUCCESS || device.is_null() {
                    continue;
                }
                let mut buffer = [0_u8; NVML_NAME_BUFFER];
                let name = if get_name(device, buffer.as_mut_ptr(), NVML_NAME_BUFFER as u32)
                    == NVML_SUCCESS
                {
                    let length = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);
                    String::from_utf8_lossy(&buffer[..length]).into_owned()
                } else {
                    format!("NVIDIA GPU {index}")
                };
                devices.push((name, device));
            }
            if devices.is_empty() {
                return Err(anyhow!("NVML initialized but reported no devices"));
            }
            Ok(Self {
                _library: library,
                get_temperature,
                get_clock_info,
                get_utilization,
                devices,
            })
        }
    }

    fn gpus(&self) -> Vec<GpuMetrics> {
        self.devices
            .iter()
            .map(|(name, device)| unsafe {
                let mut value = 0_u32;
                let temperature_c =
                    ((self.get_temperature)(*device, NVML_TEMPERATURE_GPU, &mut value)
                        == NVML_SUCCESS)
                        .then_some(f64::from(value));
                let mut core = 0_u32;
                let core_clock_mhz =
                    ((self.get_clock_info)(*device, NVML_CLOCK_GRAPHICS, &mut core)
                        == NVML_SUCCESS)
                        .then_some(f64::from(core));
                let mut memory = 0_u32;
                let memory_clock_mhz =
                    ((self.get_clock_info)(*device, NVML_CLOCK_MEM, &mut memory) == NVML_SUCCESS)
                        .then_some(f64::from(memory));
                let utilization_percent = self.get_utilization.and_then(|get| {
                    let mut utilization = NvmlUtilization::default();
                    ((get)(*device, &mut utilization) == NVML_SUCCESS)
                        .then_some(f64::from(utilization.gpu))
                });
                GpuMetrics {
                    name: name.clone(),
                    temperature_c,
                    core_clock_mhz,
                    memory_clock_mhz,
                    utilization_percent,
                }
            })
            .collect()
    }
}

/// Resolve one exported symbol into a typed function pointer.
///
/// # Safety contract
/// `T` must be a function-pointer type matching the export's real
/// signature; callers pin that with the explicit `Nvml*` type aliases.
unsafe fn symbol<T: Copy>(library: HMODULE, name: &str) -> Result<T> {
    assert_eq!(
        std::mem::size_of::<T>(),
        std::mem::size_of::<*const c_void>(),
        "symbol targets must be function pointers"
    );
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    let address = unsafe { GetProcAddress(library, PCSTR(bytes.as_ptr())) }
        .ok_or_else(|| anyhow!("{name} not exported by nvml.dll"))?;
    // FARPROC -> T: both are non-null pointer-sized function pointers.
    Ok(unsafe { std::mem::transmute_copy::<unsafe extern "system" fn() -> isize, T>(&address) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decikelvin_conversion_matches_known_points() {
        assert!((decikelvin_to_celsius(2_731.5) - 0.0).abs() < 1e-9);
        assert!((decikelvin_to_celsius(3_032.0) - 30.05).abs() < 1e-9);
        assert!((decikelvin_to_celsius(3_681.5) - 95.0).abs() < 1e-9);
    }

    #[test]
    fn zone_names_reduce_to_their_acpi_tail() {
        assert_eq!(zone_display_name(r"ACPI\ThermalZone\TZ00_0"), "TZ00");
        assert_eq!(zone_display_name("CPUZ"), "CPUZ");
    }

    struct StubProbe {
        thermal: Result<Vec<ThermalZone>, String>,
        gpus: Result<Vec<GpuMetrics>, String>,
        calls: usize,
    }

    impl HardwareProbe for StubProbe {
        fn thermal_zones(&mut self) -> Result<Vec<ThermalZone>, String> {
            self.calls += 1;
            self.thermal.clone()
        }

        fn gpus(&mut self) -> Result<Vec<GpuMetrics>, String> {
            self.gpus.clone()
        }
    }

    fn gpu() -> GpuMetrics {
        GpuMetrics {
            name: "NVIDIA GeForce RTX 4080".into(),
            temperature_c: Some(62.0),
            core_clock_mhz: Some(2_550.0),
            memory_clock_mhz: Some(10_500.0),
            utilization_percent: Some(34.0),
        }
    }

    #[test]
    fn healthy_probe_reports_available_hardware() {
        let mut sampler = HardwareSampler::with_probe(StubProbe {
            thermal: Ok(vec![ThermalZone {
                name: "TZ00".into(),
                temperature_c: 48.9,
            }]),
            gpus: Ok(vec![gpu()]),
            calls: 0,
        });
        let metrics = sampler.sample(1_000, Some(4_200.0));
        assert!(metrics.available);
        assert!(metrics.detail.is_empty());
        assert_eq!(metrics.sampled_at_ms, 1_000);
        assert_eq!(metrics.thermal_zones.len(), 1);
        assert_eq!(metrics.gpus[0].name, "NVIDIA GeForce RTX 4080");
        assert_eq!(metrics.cpu_frequency_mhz, Some(4_200.0));
    }

    #[test]
    fn fully_degraded_probe_reports_unavailable_with_details() {
        let mut sampler = HardwareSampler::with_probe(StubProbe {
            thermal: Err("access denied".into()),
            gpus: Err("nvml.dll not present (no NVIDIA driver)".into()),
            calls: 0,
        });
        let metrics = sampler.sample(2_000, None);
        assert!(!metrics.available);
        assert!(metrics.thermal_zones.is_empty());
        assert!(metrics.gpus.is_empty());
        assert!(
            metrics
                .detail
                .contains("thermal zones unavailable: access denied")
        );
        assert!(metrics.detail.contains("GPU telemetry unavailable"));
        assert!(metrics.detail.contains("CPU frequency counter unavailable"));
    }

    #[test]
    fn zero_thermal_instances_degrade_honestly_without_fake_readings() {
        let mut sampler = HardwareSampler::with_probe(StubProbe {
            thermal: Ok(Vec::new()),
            gpus: Ok(vec![gpu()]),
            calls: 0,
        });
        let metrics = sampler.sample(3_000, Some(3_600.0));
        // GPU and CPU clock still make the page worth showing…
        assert!(metrics.available);
        assert!(metrics.thermal_zones.is_empty());
        // …but the missing zones are called out, not silently zeroed.
        assert!(metrics.detail.contains("no ACPI thermal zones reported"));
    }

    #[test]
    #[ignore = "dev harness: probes the real WMI/NVML/PDH sources on this machine and prints the resulting HardwareMetrics"]
    fn dev_probe_real_hardware() {
        let mut pdh = super::super::pdh::PdhCollector::new().expect("PDH query");
        // Rate counters need two collections a beat apart.
        std::thread::sleep(Duration::from_millis(600));
        let cpu_frequency_mhz = pdh.sample().cpu_frequency_mhz;
        let mut sampler = HardwareSampler::new();
        let metrics = sampler.sample(chrono::Utc::now().timestamp_millis(), cpu_frequency_mhz);
        println!(
            "{}",
            serde_json::to_string_pretty(&metrics).expect("serialize hardware metrics")
        );
    }

    #[test]
    fn probes_run_at_most_once_per_interval_and_cache_between() {
        let mut sampler = HardwareSampler::with_probe(StubProbe {
            thermal: Ok(vec![ThermalZone {
                name: "TZ00".into(),
                temperature_c: 51.0,
            }]),
            gpus: Ok(Vec::new()),
            calls: 0,
        });
        let first = sampler.sample(1_000, Some(4_000.0));
        let second = sampler.sample(3_000, Some(4_100.0));
        assert_eq!(sampler.probe.calls, 1, "second sample must hit the cache");
        assert_eq!(second.sampled_at_ms, first.sampled_at_ms);
        assert_eq!(second.thermal_zones, first.thermal_zones);
        // The CPU frequency is free with every PDH pass and stays fresh.
        assert_eq!(second.cpu_frequency_mhz, Some(4_100.0));
        // Backdating the probe clock forces the next pass.
        sampler.last_probe = Some(Instant::now() - Duration::from_secs(6));
        let third = sampler.sample(9_000, Some(4_200.0));
        assert_eq!(sampler.probe.calls, 2);
        assert_eq!(third.sampled_at_ms, 9_000);
    }
}
