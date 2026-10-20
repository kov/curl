//! Delivering a transfer's output to the application's handlers
//! (`Curl_client_write`).

#![cfg_attr(
    not(any(test, feature = "test-util")),
    expect(dead_code, reason = "no protocol is built in before step 8")
)]

use crate::error::ErrorKind;
use crate::handler::{HeaderOrigin, Write};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};

/// Give `body` to the transfer's write handler. The handler is read from
/// the options at each call, so one installed by the call before takes
/// this piece.
pub(crate) fn body<H: Host>(cx: &mut StepCx<'_, H>, body: &[u8]) -> Result<(), ErrorKind> {
    let Some(handler) = cx.easy().options().callbacks.write.clone() else {
        return Ok(());
    };
    verdict(handler.write(&mut TransferCx::new(cx), body))
}

/// Give one header line to the transfer's header handler.
pub(crate) fn header<H: Host>(
    cx: &mut StepCx<'_, H>,
    line: &[u8],
    origin: HeaderOrigin,
) -> Result<(), ErrorKind> {
    let Some(handler) = cx.easy().options().callbacks.header.clone() else {
        return Ok(());
    };
    verdict(handler.header(&mut TransferCx::new(cx), line, origin))
}

fn verdict(w: Write) -> Result<(), ErrorKind> {
    match w {
        Write::Accepted => Ok(()),
        // No protocol can pause yet ("Write callback asked for PAUSE when
        // not supported").
        Write::Pause | Write::Fail => Err(ErrorKind::WriteError),
    }
}
