use std::{
    cmp::{Eq, PartialEq},
    fmt::Debug,
    sync::{Arc, RwLock},
};

#[derive(Clone, Debug)]
pub struct Shared<T>(Arc<RwLock<T>>)
where
    T: Clone + Debug + PartialEq + Eq;

impl<T> PartialEq for Shared<T>
where
    T: Clone + Debug + PartialEq + Eq,
{
    fn eq(&self, other: &Self) -> bool { *self.read() == *other.read() }
}

impl<T> Eq for Shared<T> where T: Clone + Debug + PartialEq + Eq {}

impl<T> Shared<T>
where
    T: Clone + Debug + PartialEq + Eq,
{
    pub fn new(value: T) -> Self { Shared(Arc::new(RwLock::new(value))) }

    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.0.read().unwrap()
    }

    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.0.write().unwrap()
    }
}
