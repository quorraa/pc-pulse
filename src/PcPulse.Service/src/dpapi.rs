//! At-rest encryption for already-redacted command-line text, via Windows
//! DPAPI. The service runs as LocalSystem, so we use machine scope
//! (`CRYPTPROTECT_LOCAL_MACHINE`) rather than the (non-existent, for
//! LocalSystem) per-user scope.

use windows::Win32::Foundation::LocalFree;
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
};
use windows::core::PCWSTR;

/// Encrypts `data` with DPAPI (machine scope). Returns the encrypted blob,
/// or the raw `GetLastError` code on failure.
pub fn protect(data: &[u8]) -> Result<Vec<u8>, u32> {
    dpapi_call(data, |input, output| unsafe {
        CryptProtectData(
            input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            output,
        )
    })
}

/// Decrypts a blob previously produced by [`protect`]. Returns the raw
/// `GetLastError` code on failure.
pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, u32> {
    dpapi_call(blob, |input, output| unsafe {
        CryptUnprotectData(
            input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            output,
        )
    })
}

/// Shared plumbing for `CryptProtectData`/`CryptUnprotectData`: builds the
/// input `CRYPT_INTEGER_BLOB`, invokes `call`, copies the output blob into an
/// owned `Vec<u8>`, and frees the DPAPI-allocated output buffer with
/// `LocalFree` regardless of outcome.
fn dpapi_call(
    data: &[u8],
    call: impl FnOnce(*const CRYPT_INTEGER_BLOB, *mut CRYPT_INTEGER_BLOB) -> windows::core::Result<()>,
) -> Result<Vec<u8>, u32> {
    // CRYPT_INTEGER_BLOB.pbData is *mut u8 even for the input blob; DPAPI
    // does not mutate it, but the type requires a mutable pointer.
    let mut input_buf = data.to_vec();
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_buf.len() as u32,
        pbData: input_buf.as_mut_ptr(),
    };

    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = call(&input, &mut output);

    match result {
        Ok(()) => {
            let out = if output.pbData.is_null() || output.cbData == 0 {
                Vec::new()
            } else {
                // Safety: DPAPI populated `output` with a buffer of
                // `cbData` bytes on success.
                unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }
                    .to_vec()
            };
            free_output(&output);
            Ok(out)
        }
        Err(e) => {
            free_output(&output);
            Err(win32_error(&e))
        }
    }
}

fn free_output(blob: &CRYPT_INTEGER_BLOB) {
    if !blob.pbData.is_null() {
        unsafe {
            let hlocal = windows::Win32::Foundation::HLOCAL(blob.pbData.cast());
            let _ = LocalFree(Some(hlocal));
        }
    }
}

/// Extracts the raw Win32 error code (as returned by `GetLastError`) from a
/// `windows` crate error. The `windows` crate encodes GetLastError-derived
/// errors as an HRESULT via `HRESULT_FROM_WIN32`, which packs the Win32 code
/// into the low 16 bits; unpack it here to hand callers the raw u32 code the
/// brief calls for rather than an opaque HRESULT.
fn win32_error(e: &windows::core::Error) -> u32 {
    (e.code().0 as u32) & 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip() {
        let blob = protect(b"redacted line").unwrap();
        assert_ne!(blob.as_slice(), b"redacted line");
        assert_eq!(unprotect(&blob).unwrap(), b"redacted line");
    }

    #[test]
    fn dpapi_round_trip_empty_input() {
        let blob = protect(b"").unwrap();
        assert_eq!(unprotect(&blob).unwrap(), b"");
    }

    #[test]
    fn unprotect_garbage_fails_with_error_code() {
        let err = unprotect(b"not a real dpapi blob").unwrap_err();
        assert_ne!(err, 0);
    }
}
