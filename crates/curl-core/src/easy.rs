//! The easy handle: one transfer's configuration, added to a multi to run.

use curl_alloc::OutOfMemory;

use crate::options::Options;

/// A transfer's configuration. `Multi::add` takes it by value to run it
/// and `Multi::remove` gives it back. The default allocates nothing.
#[derive(Debug, Default)]
pub struct Easy {
    options: Options,
}

impl Easy {
    pub fn new() -> Easy {
        Easy::default()
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn options_mut(&mut self) -> &mut Options {
        &mut self.options
    }

    /// A handle with the same options (`curl_easy_duphandle`).
    pub fn try_clone(&self) -> Result<Easy, OutOfMemory> {
        Ok(Easy {
            options: self.options.try_clone()?,
        })
    }

    /// Every option back to its default (`curl_easy_reset`).
    pub fn reset(&mut self) {
        self.options = Options::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TimeLimit;

    #[test]
    fn clones_options_and_resets_them() {
        let mut easy = Easy::new();
        easy.options_mut().set_url(Some(b"file:///x")).unwrap();
        easy.options_mut().limits.total = TimeLimit::from_millis(5);
        let copy = easy.try_clone().unwrap();
        assert_eq!(copy.options().url(), Some(&b"file:///x"[..]));
        assert_eq!(copy.options().limits.total, TimeLimit::from_millis(5));
        easy.reset();
        assert_eq!(easy.options().url(), None);
        assert_eq!(easy.options().limits.total, None);
        assert_eq!(copy.options().url(), Some(&b"file:///x"[..]));
    }
}
