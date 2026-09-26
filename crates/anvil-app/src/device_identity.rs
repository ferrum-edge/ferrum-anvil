//! Workspaces sealed from this device's workload identity.
//!
//! A JWT-SVID drawn from the SPIFFE Workload API or read from a token file
//! is this device's own identity, not a secret a bundle carries, so a request
//! a bundle brings in would present it to whatever destination the bundle
//! names. A bundle import therefore records, on this device only, that every
//! workspace it wrote into is sealed, whatever the conflict policy (a
//! Duplicate copy and a new workspace included). While a workspace is sealed
//! [`App::build_context`] refuses auth that would present this device's
//! JWT-SVID for its requests. The seal holds until the user lifts it on this
//! device ([`App::allow_device_identity`]: the desktop's workspace settings,
//! or `anvil workspace allow-device-identity`). Seals are device-specific:
//! they are not exported, not carried by a full backup, and only a bundle
//! import creates one. Deleting a workspace deletes its seal.

use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::workload::JwtSvidSource;
use anvil_domain::workspace::Workspace;
use anvil_storage::StoreTx;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Object kind of a seal, stored under the id of the workspace it seals.
/// Device-specific: not in `anvil_storage::kind::ALL`, never exported,
/// backed up or imported.
pub const DEVICE_IDENTITY_SEAL: &str = "device_identity_seal";

/// A workspace whose requests may not use this device's JWT-SVID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentitySeal {
    pub workspace_id: Id,
    pub sealed_at: DateTime<Utc>,
}

impl App {
    /// Whether requests in `ws` are refused this device's JWT-SVID.
    pub fn device_identity_sealed(&self, ws: &Id) -> Result<bool> {
        Ok(self.store.get::<DeviceIdentitySeal>(DEVICE_IDENTITY_SEAL, ws)?.is_some())
    }

    /// The user's explicit choice on this device to let requests in `ws` use
    /// this device's JWT-SVID (Workload API or token file) again. Returns
    /// whether the workspace was sealed.
    pub fn allow_device_identity(&self, ws: &Id) -> Result<bool> {
        self.workspace(ws)?;
        Ok(self.store.delete(DEVICE_IDENTITY_SEAL, ws)?)
    }

    /// Refuse auth that would present this device's JWT-SVID for a request
    /// in `ws` while `ws` is sealed.
    pub(crate) fn check_device_identity(&self, ws: &Workspace, auth: &AuthConfig) -> Result<()> {
        if uses_device_identity(auth) && self.device_identity_sealed(&ws.meta.id)? {
            return Err(AppError::Invalid(format!(
                "a bundle import wrote into workspace '{}', so its requests do not use this device's workload identity (a JWT-SVID from the Workload API or a token file); to allow it on this device, choose Allow on this device in the workspace settings' Auth tab, or run `anvil workspace allow-device-identity {}`",
                ws.name, ws.meta.id
            )));
        }
        Ok(())
    }
}

/// Seal every workspace in `workspaces`, inside the import's transaction.
pub(crate) fn seal_in<'a>(s: &StoreTx<'_>, workspaces: impl IntoIterator<Item = &'a Id>) -> anvil_storage::store::Result<()> {
    let sealed_at = Utc::now();
    for ws in workspaces {
        s.put(DEVICE_IDENTITY_SEAL, ws, Some(ws), None, 0.0, &DeviceIdentitySeal { workspace_id: *ws, sealed_at })?;
    }
    Ok(())
}

/// The import report's note for the workspaces a bundle import sealed.
pub(crate) fn sealed_note(workspaces: &[Workspace]) -> Option<String> {
    if workspaces.is_empty() {
        return None;
    }
    let names: Vec<String> = workspaces.iter().map(|w| format!("'{}'", w.name)).collect();
    Some(format!(
        "Requests in {} do not use this device's workload identity (a JWT-SVID from the Workload API or a token file) until you allow it with Allow on this device in the workspace settings' Auth tab or with `anvil workspace allow-device-identity`.",
        names.join(", ")
    ))
}

/// Whether auth would present this device's own workload identity: a
/// JWT-SVID from the Workload API or a token file.
pub(crate) fn uses_device_identity(auth: &AuthConfig) -> bool {
    match auth {
        AuthConfig::JwtSvid { config } => !matches!(config.source, JwtSvidSource::Value { .. }),
        AuthConfig::Multi { profiles } => profiles.iter().any(uses_device_identity),
        _ => false,
    }
}
