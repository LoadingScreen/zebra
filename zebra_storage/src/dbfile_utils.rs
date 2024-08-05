use std::path::{Path, PathBuf};

use directories::ProjectDirs;

pub(crate) const SERVICE_NAME: &str = "ZebraSign";

fn app_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("me", "w-r", SERVICE_NAME) {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::new()
    }
}

#[cfg(not(feature = "debug"))]
pub fn default_db_path() -> PathBuf {
    app_dir().join("zebra_db.age")
}

#[cfg(feature = "debug")]
pub fn default_db_path() -> PathBuf {
    app_dir().join("zebra_debug_db.age")
}

#[cfg(all(not(target_os = "android"), not(feature = "debug")))]
pub(crate) fn get_username() -> String {
    let mut result = whoami::username();
    if result.is_empty() {
        result = "zebra_user".to_string();
    }
    result
}

pub(crate) fn lockfile_path<P: AsRef<Path>>(p: &P) -> PathBuf {
    p.as_ref().with_extension("lock")
}
