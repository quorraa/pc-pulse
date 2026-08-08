use crate::{
    PIPE_NAME,
    models::{PipeRequest, PipeResponse},
    runtime::AppState,
};
use anyhow::{Context, Result, bail};
use std::{
    mem::size_of,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HLOCAL, LocalFree,
        },
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
            ReadFile, WriteFile,
        },
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
    },
    core::{HRESULT, PCWSTR},
};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const SDDL_REVISION_1: u32 = 1;

pub fn serve(state: Arc<AppState>, stop: Arc<AtomicBool>) -> Result<()> {
    let pipe_name = wide(PIPE_NAME);
    while !stop.load(Ordering::Acquire) {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let sddl = wide("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                5_000,
                Some(&attributes),
            )
        };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        if handle.is_invalid() {
            bail!(
                "CreateNamedPipeW failed: {}",
                windows::core::Error::from_thread()
            );
        }
        let connected = match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => true,
            Err(error) => error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0),
        };
        if connected && !stop.load(Ordering::Acquire) {
            let _ = serve_client(handle, &state);
        }
        unsafe {
            let _ = DisconnectNamedPipe(handle);
            let _ = CloseHandle(handle);
        }
    }
    Ok(())
}

fn serve_client(handle: windows::Win32::Foundation::HANDLE, state: &AppState) -> Result<()> {
    let mut buffer = vec![0u8; MAX_MESSAGE_BYTES];
    loop {
        let mut bytes_read = 0;
        unsafe { ReadFile(handle, Some(&mut buffer), Some(&mut bytes_read), None) }
            .context("named-pipe read failed")?;
        if bytes_read == 0 {
            return Ok(());
        }
        let response = match serde_json::from_slice::<PipeRequest>(&buffer[..bytes_read as usize]) {
            Ok(request) => state.handle(request),
            Err(error) => PipeResponse::Error {
                code: "invalidRequest".into(),
                message: format!("invalid JSON request: {error}"),
            },
        };
        let payload = serialize_response(&response)?;
        let mut written = 0;
        unsafe { WriteFile(handle, Some(&payload), Some(&mut written), None) }
            .context("named-pipe write failed")?;
        if written as usize != payload.len() {
            bail!("named-pipe write was incomplete");
        }
    }
}

fn serialize_response(response: &PipeResponse) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(response)?;
    if payload.len() <= MAX_MESSAGE_BYTES {
        return Ok(payload);
    }
    Ok(serde_json::to_vec(&PipeResponse::Error {
        code: "responseTooLarge".into(),
        message: "response exceeded the one-MiB protocol limit; request a smaller window or limit"
            .into(),
    })?)
}

pub fn wake() {
    let name = wide(PIPE_NAME);
    if let Ok(handle) = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    } {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_response_becomes_structured_error_instead_of_dead_pipe() {
        let response = PipeResponse::Ok {
            data: serde_json::json!({ "archive": "x".repeat(MAX_MESSAGE_BYTES) }),
        };
        let payload = serialize_response(&response).unwrap();
        assert!(payload.len() < MAX_MESSAGE_BYTES);
        let parsed: PipeResponse = serde_json::from_slice(&payload).unwrap();
        match parsed {
            PipeResponse::Error { code, message } => {
                assert_eq!(code, "responseTooLarge");
                assert!(message.contains("smaller window or limit"));
            }
            PipeResponse::Ok { .. } => panic!("oversized response was not converted to an error"),
        }
    }
}
