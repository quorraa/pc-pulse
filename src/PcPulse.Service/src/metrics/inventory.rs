//! Vendor-neutral hardware inventory: CPU, system/model, BIOS, memory,
//! storage, and GPU identity, queried once via WMI (`root\CIMV2`, plus
//! `root\microsoft\windows\storage` for `MSFT_PhysicalDisk` when the
//! namespace is available).
//!
//! Mirrors the `WmiThermal` COM pattern in `hardware.rs`: a persistent
//! `IWbemServices` connection per namespace created once, `ExecQuery` per
//! group, and honest per-group degradation. Missing hardware TELEMETRY
//! never implies missing hardware — inventory states what exists, gauges
//! state what is measurable. A failed group query yields
//! `unavailable{detail}`, never a fabricated reading, and never stops the
//! other groups from being probed.
//!
//! [`InventorySampler`] runs the probe once at construction (with one
//! bounded retry for a cold WMI service) and caches the result for the
//! process lifetime; `collect()` re-probes at most once a day via a plain
//! timestamp check, so hardware changes without a service restart still
//! surface eventually without spending WMI round-trips on every sample.

use crate::models::{
    BiosInventory, CpuInventory, GpuInventory, HardwareInventory, InventoryGroup, MemoryInventory,
    StorageDevice, SystemInventory,
};
use anyhow::{Result, anyhow};
use std::time::{Duration, Instant};
use windows::{
    Win32::System::{
        Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoInitializeSecurity, CoSetProxyBlanket, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        },
        Variant::{VARIANT, VT_BSTR, VT_I4, VT_UI4, VariantClear},
        Wmi::{
            IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices,
            WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE,
            WbemLocator,
        },
    },
    core::{BSTR, PCWSTR, w},
};

/// NTLM authentication service id for [`CoSetProxyBlanket`]
/// (`RPC_C_AUTHN_WINNT`); defined locally as in `hardware.rs` so the crate
/// needs no extra `Win32_System_Rpc` feature for one constant.
const RPC_C_AUTHN_WINNT: u32 = 10;
const RPC_C_AUTHZ_NONE: u32 = 0;

/// Inventory drifts on hardware-change timescales, not sampling ones; a
/// re-probe once a day is generous.
const REPROBE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// A cap on rows read per query — generous for any real machine, and a
/// backstop against an unbounded enumeration on a hostile WMI provider.
const MAX_ROWS: usize = 64;

/// The probe the sampler consults. Production uses WMI through
/// [`WmiInventoryProbe`]; tests substitute stubs so the per-group
/// degradation and the present/unavailable split are provable without real
/// hardware.
pub(crate) trait InventoryProbe {
    fn collect(&self) -> HardwareInventory;
}

/// Caches the result of an [`InventoryProbe`] for the process lifetime,
/// re-probing at most once a day.
pub struct InventorySampler<P = WmiInventoryProbe> {
    probe: P,
    cached: HardwareInventory,
    last_probe: Instant,
}

impl InventorySampler<WmiInventoryProbe> {
    pub fn new() -> Self {
        Self::with_probe(WmiInventoryProbe::new())
    }
}

impl Default for InventorySampler<WmiInventoryProbe> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: InventoryProbe> InventorySampler<P> {
    pub(crate) fn with_probe(probe: P) -> Self {
        let mut cached = probe.collect();
        // One bounded retry: a cold WMI service (first query moments after
        // boot, COM apartment still warming up) can fail transiently even
        // on a machine that genuinely has every group available. A single
        // immediate retry catches that without looping or blocking the
        // startup path indefinitely.
        if Self::fully_unavailable(&cached) {
            cached = probe.collect();
        }
        Self {
            probe,
            cached,
            last_probe: Instant::now(),
        }
    }

    fn fully_unavailable(inventory: &HardwareInventory) -> bool {
        inventory.cpu.value.is_none()
            && inventory.system.value.is_none()
            && inventory.bios.value.is_none()
            && inventory.memory.value.is_none()
            && inventory.storage.value.is_none()
            && inventory.gpus.value.is_none()
    }

    /// The cached inventory. Re-probes at most once a day; every other
    /// call is a clone of the cache, so this never delays the sampling
    /// loop.
    pub fn collect(&mut self) -> HardwareInventory {
        if self.last_probe.elapsed() >= REPROBE_INTERVAL {
            self.cached = self.probe.collect();
            self.last_probe = Instant::now();
        }
        self.cached.clone()
    }
}

// ---- production probe ---------------------------------------------------

/// A persistent connection pair: `root\CIMV2` for CPU/system/BIOS/memory/
/// GPU, and `root\microsoft\windows\storage` for `MSFT_PhysicalDisk`
/// (falls back to `Win32_DiskDrive` under CIMV2 when that namespace is
/// absent or its query fails). Each connection is created once and its
/// failure is a sticky detail, matching `SystemProbe` in `hardware.rs`.
pub struct WmiInventoryProbe {
    cimv2: Result<IWbemServices, String>,
    storage: Result<IWbemServices, String>,
}

// The services pointers live in the multithreaded apartment initialized in
// `connect_namespace` and are only used from the dedicated sampling thread.
unsafe impl Send for WmiInventoryProbe {}

impl WmiInventoryProbe {
    pub fn new() -> Self {
        Self {
            cimv2: connect_namespace(r"root\CIMV2").map_err(|error| format!("{error:#}")),
            storage: connect_namespace(r"root\microsoft\windows\storage")
                .map_err(|error| format!("{error:#}")),
        }
    }

    fn group<T>(
        &self,
        label: &str,
        probe: impl FnOnce(&IWbemServices) -> Result<T>,
    ) -> InventoryGroup<T> {
        match &self.cimv2 {
            Ok(services) => match probe(services) {
                Ok(value) => InventoryGroup::present(value),
                Err(error) => {
                    InventoryGroup::unavailable(format!("{label} query failed: {error:#}"))
                }
            },
            Err(detail) => {
                InventoryGroup::unavailable(format!("root\\CIMV2 unavailable: {detail}"))
            }
        }
    }

    fn storage_group(&self) -> InventoryGroup<Vec<StorageDevice>> {
        match &self.storage {
            Ok(services) => match physical_disk_inventory(services) {
                Ok(devices) => InventoryGroup::present(devices),
                Err(error) => {
                    self.fallback_disk_drive(&format!("MSFT_PhysicalDisk query failed: {error:#}"))
                }
            },
            Err(detail) => self.fallback_disk_drive(&format!(
                "root\\microsoft\\windows\\storage unavailable: {detail}"
            )),
        }
    }

    fn fallback_disk_drive(&self, reason: &str) -> InventoryGroup<Vec<StorageDevice>> {
        match &self.cimv2 {
            Ok(services) => match disk_drive_inventory(services) {
                Ok(devices) => InventoryGroup::present(devices),
                Err(error) => InventoryGroup::unavailable(format!(
                    "{reason}; Win32_DiskDrive fallback failed: {error:#}"
                )),
            },
            Err(detail) => {
                InventoryGroup::unavailable(format!("{reason}; root\\CIMV2 unavailable: {detail}"))
            }
        }
    }
}

impl Default for WmiInventoryProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl InventoryProbe for WmiInventoryProbe {
    fn collect(&self) -> HardwareInventory {
        HardwareInventory {
            cpu: self.group("CPU", cpu_inventory),
            system: self.group("system", system_inventory),
            bios: self.group("BIOS", bios_inventory),
            memory: self.group("memory", memory_inventory),
            storage: self.storage_group(),
            gpus: self.group("GPU", gpu_inventory_list),
            collected_at_ms: chrono::Utc::now().timestamp_millis(),
        }
    }
}

fn connect_namespace(namespace: &str) -> Result<IWbemServices> {
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
                &BSTR::from(namespace),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
            .map_err(|error| anyhow!("WMI namespace {namespace} unavailable: {error}"))?;
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
        Ok(services)
    }
}

/// Runs one WQL query to completion, bounded to [`MAX_ROWS`] instances.
unsafe fn query_rows(services: &IWbemServices, wql: &str) -> Result<Vec<IWbemClassObject>> {
    unsafe {
        let enumerator: IEnumWbemClassObject = services
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(wql),
                WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_FORWARD_ONLY.0 | WBEM_FLAG_RETURN_IMMEDIATELY.0),
                None,
            )
            .map_err(|error| anyhow!("query failed: {}", wbem_error_text(error.code())))?;
        let mut rows = Vec::new();
        while rows.len() < MAX_ROWS {
            let mut row: [Option<IWbemClassObject>; 1] = [None];
            let mut returned = 0_u32;
            let status = enumerator.Next(-1, &mut row, &mut returned);
            if status.is_err() {
                return Err(anyhow!("enumeration failed: {}", wbem_error_text(status)));
            }
            let Some(object) = row[0].take().filter(|_| returned > 0) else {
                break;
            };
            rows.push(object);
        }
        Ok(rows)
    }
}

fn wbem_error_text(status: windows::core::HRESULT) -> String {
    match status.0 as u32 {
        // WBEM_E_ACCESS_DENIED
        0x8004_1003 => "access denied".into(),
        // WBEM_E_INVALID_NAMESPACE
        0x8004_100E => "WMI namespace is absent".into(),
        // WBEM_E_INVALID_CLASS
        0x8004_1010 => "WMI class is absent".into(),
        code => format!("WMI error 0x{code:08x}"),
    }
}

fn cpu_inventory(services: &IWbemServices) -> Result<CpuInventory> {
    let rows = unsafe {
        query_rows(
            services,
            "SELECT Manufacturer, Name, NumberOfCores, NumberOfLogicalProcessors, \
             CurrentClockSpeed, MaxClockSpeed FROM Win32_Processor",
        )?
    };
    let object = rows
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no Win32_Processor instances"))?;
    unsafe {
        Ok(CpuInventory {
            manufacturer: get_string(&object, w!("Manufacturer")).unwrap_or_default(),
            brand: get_string(&object, w!("Name")).unwrap_or_default(),
            physical_cores: get_u32(&object, w!("NumberOfCores")).unwrap_or(0),
            logical_processors: get_u32(&object, w!("NumberOfLogicalProcessors")).unwrap_or(0),
            base_clock_mhz: get_u32(&object, w!("CurrentClockSpeed")),
            max_clock_mhz: get_u32(&object, w!("MaxClockSpeed")),
        })
    }
}

fn system_inventory(services: &IWbemServices) -> Result<SystemInventory> {
    let rows = unsafe {
        query_rows(
            services,
            "SELECT Manufacturer, Model FROM Win32_ComputerSystem",
        )?
    };
    let object = rows
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no Win32_ComputerSystem instances"))?;
    unsafe {
        Ok(SystemInventory {
            manufacturer: get_string(&object, w!("Manufacturer")).unwrap_or_default(),
            model: get_string(&object, w!("Model")).unwrap_or_default(),
        })
    }
}

fn bios_inventory(services: &IWbemServices) -> Result<BiosInventory> {
    let rows = unsafe {
        query_rows(
            services,
            "SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS",
        )?
    };
    let object = rows
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no Win32_BIOS instances"))?;
    unsafe {
        Ok(BiosInventory {
            version: get_string(&object, w!("SMBIOSBIOSVersion")).unwrap_or_default(),
            release_date: get_string(&object, w!("ReleaseDate")),
        })
    }
}

fn memory_inventory(services: &IWbemServices) -> Result<MemoryInventory> {
    let rows = unsafe { query_rows(services, "SELECT Capacity, Speed FROM Win32_PhysicalMemory")? };
    if rows.is_empty() {
        return Err(anyhow!("no Win32_PhysicalMemory instances"));
    }
    let installed_bytes = rows
        .iter()
        .filter_map(|object| unsafe { get_u64(object, w!("Capacity")) })
        .sum();
    let speed_mts = rows
        .iter()
        .find_map(|object| unsafe { get_u32(object, w!("Speed")) });
    Ok(MemoryInventory {
        installed_bytes,
        module_count: rows.len() as u32,
        speed_mts,
    })
}

/// `root\microsoft\windows\storage`'s `MSFT_PhysicalDisk`: the preferred,
/// media-aware source.
fn physical_disk_inventory(services: &IWbemServices) -> Result<Vec<StorageDevice>> {
    let rows = unsafe {
        query_rows(
            services,
            "SELECT FriendlyName, Size, BusType, MediaType FROM MSFT_PhysicalDisk",
        )?
    };
    Ok(rows
        .iter()
        .map(|object| unsafe {
            StorageDevice {
                model: get_string(object, w!("FriendlyName")).unwrap_or_else(|| "unknown".into()),
                size_bytes: get_u64(object, w!("Size")).unwrap_or(0),
                bus_type: get_u32(object, w!("BusType"))
                    .map(bus_type_name)
                    .unwrap_or_else(|| "unknown".into()),
                media_type: get_u32(object, w!("MediaType"))
                    .map(media_type_name)
                    .unwrap_or("unknown")
                    .into(),
            }
        })
        .collect())
}

/// The CIMV2 fallback when the storage namespace is absent or its query
/// fails. `Win32_DiskDrive` cannot distinguish SSD from HDD, so
/// `media_type` is always `"unknown"` here rather than guessed.
fn disk_drive_inventory(services: &IWbemServices) -> Result<Vec<StorageDevice>> {
    let rows = unsafe {
        query_rows(
            services,
            "SELECT Model, Size, InterfaceType FROM Win32_DiskDrive",
        )?
    };
    Ok(rows
        .iter()
        .map(|object| unsafe {
            StorageDevice {
                model: get_string(object, w!("Model")).unwrap_or_else(|| "unknown".into()),
                size_bytes: get_u64(object, w!("Size")).unwrap_or(0),
                bus_type: get_string(object, w!("InterfaceType"))
                    .unwrap_or_else(|| "unknown".into()),
                media_type: "unknown".into(),
            }
        })
        .collect())
}

fn gpu_inventory_list(services: &IWbemServices) -> Result<Vec<GpuInventory>> {
    let rows = unsafe {
        query_rows(
            services,
            "SELECT Name, AdapterCompatibility, DriverVersion, AdapterRAM \
             FROM Win32_VideoController",
        )?
    };
    Ok(rows
        .iter()
        .map(|object| unsafe {
            GpuInventory {
                name: get_string(object, w!("Name")).unwrap_or_else(|| "unknown".into()),
                vendor: get_string(object, w!("AdapterCompatibility"))
                    .unwrap_or_else(|| "unknown".into()),
                driver_version: get_string(object, w!("DriverVersion")),
                // AdapterRAM is a 32-bit WMI field that wraps for VRAM sizes
                // at/above 4 GiB on many drivers; a reported zero is not a
                // trustworthy reading either way, so treat it as unknown
                // rather than a fabricated "0 bytes of VRAM".
                vram_bytes: get_u32(object, w!("AdapterRAM"))
                    .map(u64::from)
                    .filter(|&bytes| bytes > 0),
            }
        })
        .collect())
}

/// `STORAGE_BUS_TYPE` values used by `MSFT_PhysicalDisk.BusType`.
fn bus_type_name(code: u32) -> String {
    match code {
        1 => "SCSI".into(),
        2 => "ATAPI".into(),
        3 => "ATA".into(),
        4 => "IEEE1394".into(),
        5 => "SSA".into(),
        6 => "FibreChannel".into(),
        7 => "USB".into(),
        8 => "RAID".into(),
        9 => "iSCSI".into(),
        10 => "SAS".into(),
        11 => "SATA".into(),
        12 => "SD".into(),
        13 => "MMC".into(),
        15 => "FileBackedVirtual".into(),
        16 => "StorageSpaces".into(),
        17 => "NVMe".into(),
        other => format!("bus type {other}"),
    }
}

/// `MSFT_PhysicalDisk.MediaType`: 3 = HDD, 4 = SSD, everything else
/// (including "unspecified") reports honestly as unknown rather than
/// guessing.
fn media_type_name(code: u32) -> &'static str {
    match code {
        3 => "hdd",
        4 => "ssd",
        _ => "unknown",
    }
}

/// A handful of WMI string fields (`Win32_Processor.Name` notably) are
/// fixed-width and padded with trailing spaces; trimming here keeps every
/// caller from having to know that.
unsafe fn get_string(object: &IWbemClassObject, name: PCWSTR) -> Option<String> {
    unsafe {
        let mut variant = VARIANT::default();
        object.Get(name, 0, &mut variant, None, None).ok()?;
        let inner = &variant.Anonymous.Anonymous;
        let value = (inner.vt == VT_BSTR).then(|| inner.Anonymous.bstrVal.to_string());
        let _ = VariantClear(&mut variant);
        value
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

unsafe fn get_u32(object: &IWbemClassObject, name: PCWSTR) -> Option<u32> {
    unsafe {
        let mut variant = VARIANT::default();
        object.Get(name, 0, &mut variant, None, None).ok()?;
        let inner = &variant.Anonymous.Anonymous;
        let value = match inner.vt {
            VT_I4 => u32::try_from(inner.Anonymous.lVal).ok(),
            VT_UI4 => Some(inner.Anonymous.ulVal),
            // Some providers marshal small integers as strings too.
            VT_BSTR => inner.Anonymous.bstrVal.to_string().parse().ok(),
            _ => None,
        };
        let _ = VariantClear(&mut variant);
        value
    }
}

/// WMI marshals `CIM_UINT64` fields (`Capacity`, `Size`, …) as decimal
/// strings — `VARIANT` has no native unsigned 64-bit member — so the
/// `VT_BSTR` path is the common case here, not a fallback.
unsafe fn get_u64(object: &IWbemClassObject, name: PCWSTR) -> Option<u64> {
    unsafe {
        let mut variant = VARIANT::default();
        object.Get(name, 0, &mut variant, None, None).ok()?;
        let inner = &variant.Anonymous.Anonymous;
        let value = match inner.vt {
            VT_BSTR => inner.Anonymous.bstrVal.to_string().parse().ok(),
            VT_I4 => u64::try_from(inner.Anonymous.lVal).ok(),
            VT_UI4 => Some(u64::from(inner.Anonymous.ulVal)),
            _ => None,
        };
        let _ = VariantClear(&mut variant);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HardwareMetrics, Snapshot};

    struct LenovoStub;
    impl InventoryProbe for LenovoStub {
        fn collect(&self) -> HardwareInventory {
            HardwareInventory {
                cpu: InventoryGroup::present(CpuInventory {
                    manufacturer: "AuthenticAMD".into(),
                    brand: "AMD Ryzen 5 PRO 5650GE with Radeon Graphics".into(),
                    physical_cores: 6,
                    logical_processors: 12,
                    base_clock_mhz: Some(3400),
                    max_clock_mhz: Some(4400),
                }),
                gpus: InventoryGroup::present(vec![GpuInventory {
                    name: "AMD Radeon(TM) Graphics".into(),
                    vendor: "Advanced Micro Devices, Inc.".into(),
                    driver_version: Some("31.0.21912.14".into()),
                    vram_bytes: None,
                }]),
                memory: InventoryGroup::present(MemoryInventory {
                    installed_bytes: 16 * 1024 * 1024 * 1024,
                    module_count: 2,
                    speed_mts: Some(3200),
                }),
                storage: InventoryGroup::unavailable(
                    "WMI storage namespace query failed: access denied",
                ),
                ..HardwareInventory::empty(0)
            }
        }
    }

    #[test]
    fn inventory_reports_hardware_independent_of_telemetry() {
        // The Lenovo field case: Radeon iGPU EXISTS (inventory) while NVML
        // telemetry is unavailable (gauges). The two must never be
        // conflated.
        let inventory = LenovoStub.collect();
        let gpus = inventory.gpus.value.as_ref().unwrap();
        assert_eq!(gpus.len(), 1);
        assert!(gpus[0].name.contains("Radeon"));
        // Unavailable group keeps its reason and fabricates nothing.
        assert!(inventory.storage.value.is_none());
        assert!(inventory.storage.detail.contains("access denied"));
    }

    #[test]
    fn inventory_rides_the_snapshot_into_the_agent_context() {
        // Attach a stub inventory to HardwareMetrics, build a Snapshot the
        // way runtime does, and confirm the serialized snapshot (which
        // AgentContext.current is a clone of) carries it end to end.
        let inventory = LenovoStub.collect();
        let snapshot = Snapshot {
            hardware: HardwareMetrics {
                inventory: Some(inventory),
                ..HardwareMetrics::default()
            },
            ..Snapshot::default()
        };
        let json = serde_json::to_value(&snapshot).expect("serialize snapshot");
        assert_eq!(
            json["hardware"]["inventory"]["cpu"]["value"]["brand"],
            "AMD Ryzen 5 PRO 5650GE with Radeon Graphics"
        );
        assert_eq!(
            json["hardware"]["inventory"]["storage"]["value"],
            serde_json::Value::Null
        );
        assert!(
            json["hardware"]["inventory"]["storage"]["detail"]
                .as_str()
                .unwrap()
                .contains("access denied")
        );
    }

    #[test]
    fn pre_inventory_snapshot_json_still_deserializes() {
        // A snapshot from a service older than hardware inventory has no
        // `inventory` key at all under `hardware`; `#[serde(default)]` on
        // HardwareMetrics must keep it decodable as `inventory: None`.
        let json = serde_json::json!({
            "protocolVersion": 1,
            "serviceVersion": "1.0.0",
            "system": serde_json::to_value(crate::models::SystemMetric::default()).unwrap(),
            "processes": [],
            "activeAlerts": [],
            "hardware": {
                "sampledAtMs": 0,
                "cpuFrequencyMhz": null,
                "thermalZones": [],
                "gpus": [],
                "available": false,
                "detail": "no hardware telemetry in this snapshot"
            }
        });
        let snapshot: Snapshot = serde_json::from_value(json).expect("deserialize legacy snapshot");
        assert!(snapshot.hardware.inventory.is_none());
    }

    struct EmptyStub {
        calls: std::cell::Cell<usize>,
    }
    impl InventoryProbe for EmptyStub {
        fn collect(&self) -> HardwareInventory {
            self.calls.set(self.calls.get() + 1);
            HardwareInventory::empty(0)
        }
    }

    struct HealthyStub {
        calls: std::cell::Cell<usize>,
    }
    impl InventoryProbe for HealthyStub {
        fn collect(&self) -> HardwareInventory {
            self.calls.set(self.calls.get() + 1);
            HardwareInventory {
                cpu: InventoryGroup::present(CpuInventory {
                    manufacturer: "GenuineIntel".into(),
                    brand: "Intel Core i7".into(),
                    physical_cores: 8,
                    logical_processors: 16,
                    base_clock_mhz: Some(2600),
                    max_clock_mhz: Some(4800),
                }),
                ..HardwareInventory::empty(1_000)
            }
        }
    }

    #[test]
    fn a_fully_failed_first_probe_gets_one_retry() {
        let sampler = InventorySampler::with_probe(EmptyStub {
            calls: std::cell::Cell::new(0),
        });
        // A fully-unavailable first pass triggers exactly one retry, not a
        // loop; the cached result honestly reports every group
        // unavailable either way.
        assert_eq!(sampler.probe.calls.get(), 2);
        assert!(sampler.cached.cpu.value.is_none());
        assert_eq!(sampler.cached.cpu.detail, "not probed");
    }

    #[test]
    fn healthy_probe_is_cached_between_collect_calls() {
        let mut sampler = InventorySampler::with_probe(HealthyStub {
            calls: std::cell::Cell::new(0),
        });
        assert_eq!(sampler.probe.calls.get(), 1, "constructor probes once");
        let first = sampler.collect();
        let second = sampler.collect();
        assert_eq!(sampler.probe.calls.get(), 1, "collect() must hit the cache");
        assert_eq!(first, second);
        assert_eq!(first.cpu.value.as_ref().unwrap().brand, "Intel Core i7");
        // Backdating the probe clock forces the next pass.
        sampler.last_probe = Instant::now() - Duration::from_secs(25 * 60 * 60);
        let third = sampler.collect();
        assert_eq!(sampler.probe.calls.get(), 2);
        assert_eq!(third, first);
    }

    #[test]
    #[ignore = "dev harness: probes the real WMI CIMV2/storage sources on this machine and prints the resulting HardwareInventory"]
    fn dev_probe_real_hardware() {
        let probe = WmiInventoryProbe::new();
        let inventory = probe.collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&inventory).expect("serialize hardware inventory")
        );
    }
}
