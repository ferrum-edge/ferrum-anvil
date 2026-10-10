//! Cooperative process fence for key changes. Lock failure is never ignored.
use std::{
    fs::{File, OpenOptions},
    path::Path,
};
pub(crate) fn shared(dir: &Path) -> std::io::Result<File> {
    let file = open(dir)?;
    file.lock_shared()?;
    Ok(file)
}
pub(crate) fn exclusive(dir: &Path) -> std::io::Result<File> {
    let file = open(dir)?;
    file.lock()?;
    Ok(file)
}
fn open(dir: &Path) -> std::io::Result<File> {
    std::fs::create_dir_all(dir)?;
    OpenOptions::new().create(true).truncate(false).read(true).write(true).open(dir.join("profile-data.lock"))
}
