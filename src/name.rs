use anyhow::{Result, bail};

pub trait HasName {
    fn name(&self) -> &str;

    fn set_name(&mut self, name: impl Into<String>);

    fn add_name(&mut self, name: &str) -> Result<()> {
        if !self.name().is_empty() {
            bail!("Duplicate name");
        }
        if name.is_empty() {
            bail!("Name is empty");
        }
        self.set_name(name);

        Ok(())
    }
}
