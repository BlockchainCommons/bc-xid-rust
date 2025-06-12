use anyhow::{Result, bail};

pub trait HasNickname {
    fn nickname(&self) -> &str;

    fn set_nickname(&mut self, name: impl Into<String>);

    fn add_nickname(&mut self, name: &str) -> Result<()> {
        if !self.nickname().is_empty() {
            bail!("Duplicate nickname");
        }
        if name.is_empty() {
            bail!("Nickname is empty");
        }
        self.set_nickname(name);

        Ok(())
    }
}
