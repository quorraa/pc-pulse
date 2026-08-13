#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod alerting;
pub mod analysis;
pub mod baselines;
pub mod config;
pub mod etw;
pub mod eventlog;
pub mod metrics;
pub mod models;
pub mod pipe;
pub mod runtime;
pub mod service;
pub mod stats;
pub mod storage;

pub const SERVICE_NAME: &str = "PcPulseCollector";
pub const PIPE_NAME: &str = r"\\.\pipe\PcPulse.v1";
pub const PROTOCOL_VERSION: u32 = 1;
