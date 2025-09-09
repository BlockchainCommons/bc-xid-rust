use crate::{Error, Result};

pub trait HasNickname {
    fn nickname(&self) -> &str;

    fn set_nickname(&mut self, name: impl Into<String>);

    fn add_nickname(&mut self, name: &str) -> Result<()> {
        if !self.nickname().is_empty() {
            return Err(Error::Duplicate { item: "nickname".to_string() });
        }
        if name.is_empty() {
            return Err(Error::EmptyValue { field: "nickname".to_string() });
        }
        self.set_nickname(name);

        Ok(())
    }
}
