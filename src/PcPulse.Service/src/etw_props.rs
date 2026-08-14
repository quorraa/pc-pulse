//! TDH property decode core for Microsoft-Windows-Kernel-Process events.
//!
//! `decode_event` is a pure, fixture-testable function that turns an
//! already-extracted property bag into a [`ParsedProcessEvent`]. The unsafe
//! shell (`parse_process_event`) walks `TRACE_EVENT_INFO` via
//! `TdhGetEventInformation` and reads each top-level property via
//! `TdhGetProperty`, then hands the resulting bag to `decode_event`.

use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_PROPERTY_INFO, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR, TDH_INTYPE_FILETIME,
    TDH_INTYPE_UINT32, TDH_INTYPE_UINT64, TDH_INTYPE_UNICODESTRING, TRACE_EVENT_INFO,
    TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
};

const PROCESS_START_EVENT_ID: u16 = 1;
const PROCESS_STOP_EVENT_ID: u16 = 2;

/// FILETIME ticks (100ns intervals) between 1601-01-01 and 1970-01-01.
const FILETIME_EPOCH_DIFF_TICKS: i64 = 116_444_736_000_000_000;
const TICKS_PER_MS: i64 = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessStartProps {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub create_time_ms: i64,
    pub image_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessStopProps {
    pub pid: u32,
    pub exit_code: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParsedProcessEvent {
    Start(ProcessStartProps),
    Stop(ProcessStopProps),
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    MissingProperty(&'static str),
    BadType(&'static str),
    Tdh(u32),
    UnknownEventId(u16),
}

/// A single decoded top-level property value. Unknown in-types for
/// properties we don't need are skipped by the unsafe shell rather than
/// surfaced as an error.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PropValue {
    U32(u32),
    U64(u64),
    FileTime(i64),
    Unicode(String),
}

fn get<'a>(
    props: &'a [(String, PropValue)],
    name: &'static str,
) -> Result<&'a PropValue, ParseError> {
    props
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or(ParseError::MissingProperty(name))
}

/// Reads a property as `u32`, accepting a lossless `U64` widening for
/// manifest versions that emit certain fields as `UInt64`.
fn get_u32(props: &[(String, PropValue)], name: &'static str) -> Result<u32, ParseError> {
    match get(props, name)? {
        PropValue::U32(value) => Ok(*value),
        PropValue::U64(value) => u32::try_from(*value).map_err(|_| ParseError::BadType(name)),
        _ => Err(ParseError::BadType(name)),
    }
}

fn get_filetime_ms(props: &[(String, PropValue)], name: &'static str) -> Result<i64, ParseError> {
    match get(props, name)? {
        PropValue::FileTime(ms) => Ok(*ms),
        _ => Err(ParseError::BadType(name)),
    }
}

fn get_unicode<'a>(
    props: &'a [(String, PropValue)],
    name: &'static str,
) -> Result<&'a str, ParseError> {
    match get(props, name)? {
        PropValue::Unicode(value) => Ok(value.as_str()),
        _ => Err(ParseError::BadType(name)),
    }
}

/// Pure, testable core: decode from an already-extracted property bag.
pub(crate) fn decode_event(
    event_id: u16,
    props: &[(String, PropValue)],
) -> Result<ParsedProcessEvent, ParseError> {
    match event_id {
        PROCESS_START_EVENT_ID => {
            let pid = get_u32(props, "ProcessID")?;
            let parent_pid = get_u32(props, "ParentProcessID")?;
            let session_id = get_u32(props, "SessionID")?;
            let create_time_ms = get_filetime_ms(props, "CreateTime")?;
            let image_name = get_unicode(props, "ImageName")?.to_string();
            Ok(ParsedProcessEvent::Start(ProcessStartProps {
                pid,
                parent_pid,
                session_id,
                create_time_ms,
                image_name,
            }))
        }
        PROCESS_STOP_EVENT_ID => {
            let pid = get_u32(props, "ProcessID")?;
            let exit_code = get_u32(props, "ExitCode")?;
            Ok(ParsedProcessEvent::Stop(ProcessStopProps {
                pid,
                exit_code,
            }))
        }
        other => Err(ParseError::UnknownEventId(other)),
    }
}

/// Converts a raw FILETIME value (100ns ticks since 1601-01-01) to
/// milliseconds since the Unix epoch.
pub(crate) fn filetime_to_epoch_ms(filetime: u64) -> i64 {
    (filetime as i64 - FILETIME_EPOCH_DIFF_TICKS) / TICKS_PER_MS
}

/// Reads a native-endian `u32` from the start of `bytes`, or `None` if too short.
fn read_u32_le(bytes: &[u8]) -> Option<u32> {
    let array: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(array))
}

/// Reads a native-endian `u64` from the start of `bytes`, or `None` if too short.
fn read_u64_le(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_ne_bytes(array))
}

/// Pure, testable core of the property-array bounds check: given the byte
/// offset of the property array within the TDH info buffer, the TDH-reported
/// element count, the element size, and the buffer's actual populated
/// length, returns the number of whole elements that fit entirely inside
/// the buffer.
///
/// `count` is TDH-supplied and must never be trusted directly — a naive
/// `offset + count * elem <= buf_len` check would need to guard the
/// multiply/add against overflow itself. This instead divides the
/// remaining space by `elem` (division can never overflow) to get the
/// maximum element count that fits, then takes the smaller of that and
/// `count`. An out-of-range `offset` clamps to 0 fits rather than
/// underflowing.
///
/// Clamping (rather than returning `Err`) is deliberate here, matching the
/// rest of this shell: a single unreadable/oversized property already
/// degrades gracefully (the `continue` cases above), and `decode_event`
/// still surfaces a `MissingProperty` error if clamping drops a property
/// the event actually needs. There is no case where reading fewer
/// properties than TDH claims makes decoding less safe, only potentially
/// incomplete.
fn props_that_fit(offset: usize, count: u32, elem: usize, buf_len: usize) -> usize {
    if offset > buf_len {
        return 0;
    }
    let available = buf_len - offset;
    if elem == 0 {
        return count as usize;
    }
    let max_that_fit = available / elem;
    (count as usize).min(max_that_fit)
}

thread_local! {
    /// Reused across calls on the dedicated `pcpulse-etw` thread to avoid
    /// reallocating the TDH info buffer for every event.
    static TDH_INFO_BUFFER: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Unsafe shell: `EVENT_RECORD` -> property bag via `TdhGetEventInformation`,
/// then `decode_event`. Called only from the ETW callback (Task 2).
///
/// # Safety
/// `record` must point to a valid, live `EVENT_RECORD` for the duration of
/// this call, as provided by the ETW `EventRecordCallback`.
pub unsafe fn parse_process_event(
    record: *const EVENT_RECORD,
) -> Result<ParsedProcessEvent, ParseError> {
    if record.is_null() {
        return Err(ParseError::MissingProperty("EVENT_RECORD"));
    }
    let event_id = unsafe { (*record).EventHeader.EventDescriptor.Id };

    let info_ptr = TDH_INFO_BUFFER.with(|cell| -> Result<*const TRACE_EVENT_INFO, ParseError> {
        let mut buffer = cell.borrow_mut();
        if buffer.is_empty() {
            buffer.resize(4096, 0);
        }
        loop {
            let mut buffer_size = buffer.len() as u32;
            let status = unsafe {
                TdhGetEventInformation(
                    record,
                    None,
                    Some(buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>()),
                    &mut buffer_size,
                )
            };
            if status == 0 {
                return Ok(buffer.as_ptr().cast::<TRACE_EVENT_INFO>());
            }
            if status == ERROR_INSUFFICIENT_BUFFER.0 {
                buffer.resize(buffer_size as usize, 0);
                continue;
            }
            return Err(ParseError::Tdh(status));
        }
    })?;

    // Bound every offset-based read against the buffer TdhGetEventInformation
    // actually populated, never against the pointer alone: NameOffset (and
    // other *Offset fields) are TDH-supplied and must not be trusted to stay
    // within the allocation if TDH ever misbehaves or a future refactor
    // changes buffer sizing.
    let info_buffer_len = TDH_INFO_BUFFER.with(|cell| cell.borrow().len());
    let info = unsafe { &*info_ptr };
    let base = info_ptr.cast::<u8>();
    let info_buffer: &[u8] = unsafe { std::slice::from_raw_parts(base, info_buffer_len) };
    // Same invariant as above, applied to the property array itself:
    // TopLevelPropertyCount is TDH-supplied and must not be trusted to fit
    // inside the populated buffer. Clamp to the number of whole
    // EVENT_PROPERTY_INFO entries that actually fit at the array's offset
    // before ever forming the slice, so a hostile/corrupt count can never
    // walk `from_raw_parts` past the allocation.
    let array_offset = info.EventPropertyInfoArray.as_ptr() as usize - base as usize;
    let property_count = props_that_fit(
        array_offset,
        info.TopLevelPropertyCount,
        std::mem::size_of::<EVENT_PROPERTY_INFO>(),
        info_buffer_len,
    );
    let property_array =
        unsafe { std::slice::from_raw_parts(info.EventPropertyInfoArray.as_ptr(), property_count) };

    let mut props: Vec<(String, PropValue)> = Vec::with_capacity(property_count);
    for property in property_array {
        let name = read_wide_string_at(info_buffer, property.NameOffset);
        let in_type = unsafe { property.Anonymous1.nonStructType.InType };

        let mut name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let descriptor = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: name_wide.as_mut_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };

        let mut property_size: u32 = 0;
        let size_status = unsafe {
            TdhGetPropertySize(
                record,
                None,
                std::slice::from_ref(&descriptor),
                &mut property_size,
            )
        };
        if size_status != 0 {
            // A property that fails to size/fetch is simply absent from the
            // bag, not a fatal error for the whole event: exotic manifest
            // properties we don't need can fail without killing otherwise-
            // decodable events. If a *required* property is missing,
            // decode_event surfaces that as MissingProperty.
            continue;
        }

        let mut value_buffer = vec![0u8; property_size as usize];
        let get_status = unsafe {
            TdhGetProperty(
                record,
                None,
                std::slice::from_ref(&descriptor),
                &mut value_buffer,
            )
        };
        if get_status != 0 {
            continue;
        }

        let value = match in_type {
            t if t == TDH_INTYPE_UINT32.0 as u16 => match read_u32_le(&value_buffer) {
                Some(raw) => PropValue::U32(raw),
                None => continue,
            },
            t if t == TDH_INTYPE_UINT64.0 as u16 => match read_u64_le(&value_buffer) {
                Some(raw) => PropValue::U64(raw),
                None => continue,
            },
            t if t == TDH_INTYPE_FILETIME.0 as u16 => match read_u64_le(&value_buffer) {
                Some(raw) => PropValue::FileTime(filetime_to_epoch_ms(raw)),
                None => continue,
            },
            t if t == TDH_INTYPE_UNICODESTRING.0 as u16 => {
                let wide: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        value_buffer.as_ptr().cast::<u16>(),
                        value_buffer.len() / 2,
                    )
                };
                let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
                PropValue::Unicode(String::from_utf16_lossy(&wide[..end]))
            }
            // Unknown in-types for properties we don't need are skipped, not errors.
            _ => continue,
        };

        props.push((name, value));
    }

    decode_event(event_id, &props)
}

/// Scans `buffer` for a NUL-terminated UTF-16LE string starting at byte
/// `offset`, without ever reading past `buffer`'s end. Returns `None` if
/// `offset` is out of range or no NUL code unit is found before the end of
/// `buffer` (a bounded miss, never an out-of-bounds read). Pure and safe:
/// this is the testable core of `read_wide_string_at`.
fn scan_wide_string_bounded(buffer: &[u8], offset: usize) -> Option<String> {
    if offset == 0 {
        return Some(String::new());
    }
    let rest = buffer.get(offset..)?;
    let mut units: Vec<u16> = Vec::new();
    for chunk in rest.chunks_exact(2) {
        // SAFETY-free: plain byte indexing, no pointer arithmetic.
        let unit = u16::from_ne_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(unit);
    }
    None
}

/// Reads a NUL-terminated UTF-16 string at the given byte offset within
/// `buffer`, as used for the various `*Offset` fields in `TRACE_EVENT_INFO`.
/// Bounded to `buffer`'s actual length: an offset or missing terminator that
/// would run past the end of `buffer` yields an empty string instead of
/// reading past the allocation. `buffer` must be the full TDH info buffer
/// that `offset` is relative to (not just the tail from `offset` onward).
fn read_wide_string_at(buffer: &[u8], offset: u32) -> String {
    scan_wide_string_bounded(buffer, offset as usize).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn start_bag() -> Vec<(String, PropValue)> {
        vec![
            ("ProcessID".into(), PropValue::U32(4242)),
            ("ParentProcessID".into(), PropValue::U32(1000)),
            ("SessionID".into(), PropValue::U32(1)),
            ("CreateTime".into(), PropValue::FileTime(1_786_600_000_000)),
            (
                "ImageName".into(),
                PropValue::Unicode(r"\Device\HarddiskVolume4\Windows\System32\cmd.exe".into()),
            ),
        ]
    }
    #[test]
    fn decodes_process_start() {
        let ParsedProcessEvent::Start(s) = decode_event(1, &start_bag()).unwrap() else {
            panic!("expected Start")
        };
        assert_eq!(s.pid, 4242);
        assert_eq!(s.parent_pid, 1000);
        assert_eq!(s.session_id, 1);
        assert_eq!(s.create_time_ms, 1_786_600_000_000);
        assert!(s.image_name.ends_with("cmd.exe"));
    }
    #[test]
    fn decodes_process_stop() {
        let bag = vec![
            ("ProcessID".into(), PropValue::U32(4242)),
            ("ExitCode".into(), PropValue::U32(0)),
        ];
        let ParsedProcessEvent::Stop(s) = decode_event(2, &bag).unwrap() else {
            panic!("expected Stop")
        };
        assert_eq!(s.pid, 4242);
        assert_eq!(s.exit_code, 0);
    }
    #[test]
    fn missing_property_is_error_not_panic() {
        let mut bag = start_bag();
        bag.retain(|(k, _)| k != "ParentProcessID");
        assert_eq!(
            decode_event(1, &bag).unwrap_err(),
            ParseError::MissingProperty("ParentProcessID")
        );
    }
    #[test]
    fn wrong_type_is_error() {
        let mut bag = start_bag();
        bag.iter_mut().find(|(k, _)| k == "ProcessID").unwrap().1 = PropValue::Unicode("42".into());
        assert_eq!(
            decode_event(1, &bag).unwrap_err(),
            ParseError::BadType("ProcessID")
        );
    }
    #[test]
    fn unknown_event_id_is_error() {
        assert_eq!(
            decode_event(15, &start_bag()).unwrap_err(),
            ParseError::UnknownEventId(15)
        );
    }
    #[test]
    fn scan_wide_string_bounded_offset_zero_is_empty() {
        assert_eq!(
            scan_wide_string_bounded(&[1, 2, 3, 4], 0),
            Some(String::new())
        );
    }
    #[test]
    fn scan_wide_string_bounded_reads_nul_terminated_string() {
        // "Hi" as UTF-16LE followed by a NUL terminator.
        let mut buffer = vec![0u8; 4];
        buffer.extend_from_slice(&[b'H', 0, b'i', 0, 0, 0]);
        assert_eq!(scan_wide_string_bounded(&buffer, 4), Some("Hi".to_string()));
    }
    #[test]
    fn scan_wide_string_bounded_missing_nul_returns_none_not_panic() {
        // Data runs to the very end of the buffer with no NUL terminator:
        // must return None rather than reading past the allocation.
        let mut buffer = vec![0u8; 4];
        buffer.extend_from_slice(&[b'H', 0, b'i', 0]); // no trailing NUL
        assert_eq!(scan_wide_string_bounded(&buffer, 4), None);
    }
    #[test]
    fn scan_wide_string_bounded_offset_out_of_range_returns_none() {
        let buffer = vec![0u8; 4];
        assert_eq!(scan_wide_string_bounded(&buffer, 100), None);
    }
    #[test]
    fn scan_wide_string_bounded_offset_at_exact_end_returns_none() {
        let buffer = vec![0u8; 4];
        assert_eq!(scan_wide_string_bounded(&buffer, 4), None);
    }
    #[test]
    fn read_wide_string_at_falls_back_to_empty_on_bounded_miss() {
        let mut buffer = vec![0u8; 4];
        buffer.extend_from_slice(&[b'H', 0, b'i', 0]); // no trailing NUL
        assert_eq!(read_wide_string_at(&buffer, 4), "");
    }
    #[test]
    fn sessionid_u64_widening_accepted() {
        // Some manifest versions emit UInt64 for SessionID; accept lossless widening.
        let mut bag = start_bag();
        bag.iter_mut().find(|(k, _)| k == "SessionID").unwrap().1 = PropValue::U64(1);
        assert!(decode_event(1, &bag).is_ok());
    }
    #[test]
    fn props_that_fit_exact_fit_returns_full_count() {
        // offset 8, 4 elements of size 8 bytes = 32 bytes, buffer exactly 40.
        assert_eq!(props_that_fit(8, 4, 8, 40), 4);
    }
    #[test]
    fn props_that_fit_overflowing_count_is_clamped() {
        // A hostile/corrupt count that would read far past the buffer must
        // be clamped to what actually fits, not panic or wrap.
        assert_eq!(props_that_fit(8, u32::MAX, 8, 40), 4);
    }
    #[test]
    fn props_that_fit_offset_past_buffer_is_zero() {
        assert_eq!(props_that_fit(100, 4, 8, 40), 0);
    }
    #[test]
    fn props_that_fit_offset_at_exact_end_is_zero() {
        assert_eq!(props_that_fit(40, 4, 8, 40), 0);
    }
    #[test]
    fn props_that_fit_partial_remainder_rounds_down() {
        // 40 - 8 = 32 bytes remaining, elem size 12 -> only 2 whole elements
        // fit (24 bytes), the trailing 8 bytes are not a whole element.
        assert_eq!(props_that_fit(8, 10, 12, 40), 2);
    }
    #[test]
    fn props_that_fit_zero_count_is_zero() {
        assert_eq!(props_that_fit(0, 0, 8, 40), 0);
    }
}
