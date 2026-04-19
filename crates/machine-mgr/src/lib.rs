//! machine-mgr — semantic API behind the SOVD diagnostic server.
//!
//! `diagserver` (the SOVD adapter) holds an `Arc<dyn Machine>`. Each `Machine`
//! exposes a registry of `Component` objects — one per independently-updatable
//! thing (host OS, vm1, vm2, hsm, ...). Components declare their `Capabilities`
//! so an external orchestrator (in-vehicle OTA or workshop tool) can plan
//! against them.
//!
//! Every `Component` method has a `NotSupported` default; a concrete component
//! only overrides the operations it actually supports.
//!
//! Production vs. simulation deployments differ only in how the `Machine` is
//! composed in `vm-sovd`'s `main()`. The trait surface and `diagserver` are
//! identical across deployments.

pub mod component;
pub mod error;
pub mod machine;
pub mod types;

#[cfg(test)]
mod tests;

pub use component::Component;
pub use error::{MachineError, MachineResult};
pub use machine::{Machine, MachineRegistry};
pub use types::*;

// Re-exports of SOVD wire types that are also our domain types.
// The diagserver layer treats SOVD as the canonical interface, so where
// a wire type already names the right thing we use it directly.
pub use sovd_core::{
    ActivationState, ClearFaultsResult, DataValue, EntityInfo, Fault, FaultFilter, FaultsResult,
    FlashProgress, FlashState, FlashStatus, PackageInfo, ParameterInfo, VerifyResult,
};
