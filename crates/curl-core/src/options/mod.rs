//! A transfer's options, in typed groups: what `curl_easy_setopt` sets.
//!
//! Only the options the multi reads exist yet; the rest arrive with the
//! code that reads them.

#[cfg(any(test, feature = "test-util"))]
pub mod script;

use curl_alloc::{OutOfMemory, TryVec};

use crate::handler::{Handler, HeaderHandler, WriteHandler};
use crate::time::TimeLimit;

/// Every option of a transfer. The default sets nothing and allocates
/// nothing.
#[derive(Debug, Default)]
pub struct Options {
    url: Option<Vec<u8>>,
    pub limits: Limits,
    pub callbacks: Callbacks,
    /// What the test protocol `script:` plays.
    #[cfg(any(test, feature = "test-util"))]
    pub script: Option<script::Script>,
}

impl Options {
    /// The URL to transfer (`CURLOPT_URL`), as given: it is parsed when
    /// the transfer starts.
    pub fn url(&self) -> Option<&[u8]> {
        self.url.as_deref()
    }

    pub fn set_url(&mut self, url: Option<&[u8]>) -> Result<(), OutOfMemory> {
        self.url = url.map(copy).transpose()?;
        Ok(())
    }

    /// A copy (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<Options, OutOfMemory> {
        Ok(Options {
            url: self.url.as_deref().map(copy).transpose()?,
            limits: self.limits,
            callbacks: self.callbacks.clone(),
            #[cfg(any(test, feature = "test-util"))]
            script: self.script.clone(),
        })
    }
}

fn copy(s: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(s)?;
    Ok(v)
}

/// How long a transfer may take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// The whole transfer (`CURLOPT_TIMEOUT_MS`).
    pub total: Option<TimeLimit>,
    /// Each connection (`CURLOPT_CONNECTTIMEOUT_MS`); five minutes if none.
    pub connect: Option<TimeLimit>,
}

/// Where a transfer's output goes. A copy of the options shares each
/// handler, as C's copies share a callback and its userdata.
#[derive(Clone, Debug, Default)]
pub struct Callbacks {
    /// The body; without one, it is dropped.
    pub write: Option<Handler<dyn WriteHandler>>,
    /// Header lines; without one, they go nowhere.
    pub header: Option<Handler<dyn HeaderHandler>>,
}
