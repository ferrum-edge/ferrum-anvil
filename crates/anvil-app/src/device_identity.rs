//! Workspaces sealed from this device's workload identity.
//!
//! A JWT-SVID drawn from the SPIFFE Workload API or read from a token file,
//! and an X.509-SVID from the Workload API, are this device's own identity,
//! not a secret a bundle or backup carries, so a request either brings in
//! would present it to whatever destination it names. A bundle import and a
//! full-backup restore therefore record, on this device only, that every
//! workspace they wrote into is sealed, whatever the conflict policy (a
//! Duplicate copy and a new workspace included). While a workspace is sealed
//! [`App::build_context`] refuses its requests auth that would present this
//! device's JWT-SVID, and a TLS profile (the request's own or its proxy's)
//! whose client identity is this device's X.509-SVID. The seal holds until
//! the user lifts it on this device ([`App::allow_device_identity`]: the
//! desktop's workspace settings, or `anvil workspace allow-device-identity`),
//! so restoring your own backup on a new device means lifting the seals of
//! the workspaces you trust. Seals are device-specific
//! ([`kind::DEVICE_IDENTITY_SEAL`]): they are not exported, not carried by a
//! full backup, and only a bundle import or a restore creates one. Deleting a
//! workspace deletes its seal.

use crate::{App, AppError, Result};
use anvil_domain::Id;
use anvil_domain::auth::AuthConfig;
use anvil_domain::tls::{ClientIdentity, TlsProfile};
use anvil_domain::workload::JwtSvidSource;
use anvil_domain::workspace::Workspace;
use anvil_engine::context::ExecutionContext;
use anvil_storage::{StoreTx, kind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A workspace whose requests may not use this device's workload identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentitySeal {
    pub workspace_id: Id,
    pub sealed_at: DateTime<Utc>,
}

impl App {
    /// Whether requests in `ws` are refused this device's workload identity.
    pub fn device_identity_sealed(&self, ws: &Id) -> Result<bool> {
        Ok(self.store.get::<DeviceIdentitySeal>(kind::DEVICE_IDENTITY_SEAL, ws)?.is_some())
    }

    /// The user's explicit choice on this device to let requests in `ws` use
    /// this device's workload identity (JWT-SVID or X.509-SVID) again.
    /// Returns whether the workspace was sealed.
    pub fn allow_device_identity(&self, ws: &Id) -> Result<bool> {
        self.workspace(ws)?;
        Ok(self.store.delete(kind::DEVICE_IDENTITY_SEAL, ws)?)
    }

    /// Refuse, while `ws` is sealed, a request context that would present
    /// this device's workload identity: auth that draws its JWT-SVID, or a
    /// TLS profile that presents its X.509-SVID.
    pub(crate) fn check_device_identity(&self, ws: &Workspace, ctx: &ExecutionContext) -> Result<()> {
        let presents = uses_device_identity(&ctx.effective_auth().1) || presents_device_svid(ctx);
        if presents && self.device_identity_sealed(&ws.meta.id)? {
            return Err(AppError::Invalid(format!(
                "a bundle import or backup restore wrote into workspace '{}', so its requests do not use this device's workload identity (JWT-SVID or X.509-SVID); to allow it on this device, choose Allow on this device in the workspace settings' Auth tab, or run `anvil workspace allow-device-identity {}`",
                ws.name, ws.meta.id
            )));
        }
        Ok(())
    }
}

/// Seal every workspace in `workspaces`, inside the import's or restore's
/// transaction.
pub(crate) fn seal_in<'a>(s: &StoreTx<'_>, workspaces: impl IntoIterator<Item = &'a Id>) -> anvil_storage::store::Result<()> {
    let sealed_at = Utc::now();
    for ws in workspaces {
        s.put(kind::DEVICE_IDENTITY_SEAL, ws, Some(ws), None, 0.0, &DeviceIdentitySeal { workspace_id: *ws, sealed_at })?;
    }
    Ok(())
}

/// The import or restore report's note for the workspaces it seals.
pub(crate) fn sealed_note(workspaces: &[Workspace]) -> Option<String> {
    if workspaces.is_empty() {
        return None;
    }
    let names: Vec<String> = workspaces.iter().map(|w| format!("'{}'", w.name)).collect();
    Some(format!(
        "Requests in {} do not use this device's workload identity (JWT-SVID or X.509-SVID) until you allow it with Allow on this device in the workspace settings' Auth tab or with `anvil workspace allow-device-identity`.",
        names.join(", ")
    ))
}

/// Whether auth would present this device's own JWT-SVID: one from the
/// Workload API or a token file.
pub(crate) fn uses_device_identity(auth: &AuthConfig) -> bool {
    match auth {
        AuthConfig::JwtSvid { config } => !matches!(config.source, JwtSvidSource::Value { .. }),
        AuthConfig::Multi { profiles } => profiles.iter().any(uses_device_identity),
        _ => false,
    }
}

/// Whether a TLS profile the request selects, its own or its proxy's, has
/// this device's X.509-SVID as its client identity. Decided from the
/// selection alone, whatever the scheme, host bindings or `no_proxy`, so a
/// sealed workspace fails closed.
fn presents_device_svid(ctx: &ExecutionContext) -> bool {
    let settings = anvil_engine::settings::resolve(&ctx.settings_layers);
    let proxy = settings.proxy_profile_id.and_then(|id| ctx.proxy_profiles.iter().find(|p| p.id == id));
    let selected = [settings.tls_profile_id, proxy.and_then(|p| p.tls_profile_id)];
    let svid = |p: &TlsProfile| matches!(p.client_identity, Some(ClientIdentity::WorkloadApi { .. }));
    ctx.tls_profiles.iter().any(|p| selected.contains(&Some(p.id)) && svid(p))
}
