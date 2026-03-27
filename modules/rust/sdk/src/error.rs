//! Error types for the OpenSIPS Rust SDK.

use core::fmt;

/// SDK result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur in the SDK.
#[derive(Debug)]
pub enum Error {
    /// A pseudo-variable operation failed.
    Pv(PvError),
    /// A module function call failed.
    Call(CallError),
    /// A null pointer was encountered.
    NullPointer(&'static str),
    /// UTF-8 conversion failed.
    Utf8,
}

#[derive(Debug)]
pub enum PvError {
    /// Failed to parse the PV spec string.
    ParseFailed,
    /// The PV is not writable.
    NotWritable,
    /// pv_set_value returned an error.
    SetFailed(i32),
    /// pv_get_spec_value returned an error.
    GetFailed(i32),
    /// pv_printf returned an error.
    PrintfFailed(i32),
}

#[derive(Debug)]
pub enum CallError {
    /// The named function was not found.
    NotFound(String),
    /// fix_cmd failed.
    FixupFailed(i32),
    /// The function call returned an error.
    ExecFailed(i32),
    /// Memory allocation failed.
    AllocFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pv(e) => write!(f, "PV error: {e:?}"),
            Error::Call(e) => write!(f, "Call error: {e:?}"),
            Error::NullPointer(ctx) => write!(f, "null pointer in {ctx}"),
            Error::Utf8 => write!(f, "UTF-8 conversion failed"),
        }
    }
}

impl From<PvError> for Error {
    fn from(e: PvError) -> Self {
        Error::Pv(e)
    }
}

impl From<CallError> for Error {
    fn from(e: CallError) -> Self {
        Error::Call(e)
    }
}
