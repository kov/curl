//! `std::cell::Cell`'s API over a lock, for what tests record from inside
//! handlers, which must be `Sync` as a handler is.

use std::sync::Mutex;

#[derive(Debug, Default)]
pub(crate) struct Cell<T>(Mutex<T>);

impl<T> Cell<T> {
    pub(crate) const fn new(value: T) -> Cell<T> {
        Cell(Mutex::new(value))
    }

    pub(crate) fn set(&self, value: T) {
        *self.0.lock().unwrap() = value;
    }

    pub(crate) fn replace(&self, value: T) -> T {
        std::mem::replace(&mut self.0.lock().unwrap(), value)
    }
}

impl<T: Copy> Cell<T> {
    pub(crate) fn get(&self) -> T {
        *self.0.lock().unwrap()
    }
}

impl<T: Default> Cell<T> {
    pub(crate) fn take(&self) -> T {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}
