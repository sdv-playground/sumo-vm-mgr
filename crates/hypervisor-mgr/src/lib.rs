pub mod backend;
pub mod component_adapter;
pub mod diag_backend;
pub mod did;
pub mod ifs;
pub mod manifest;
pub mod manifest_provider;
pub mod ota;
pub mod streaming;
pub mod suit_provider;

pub mod sovd {
    pub mod security;
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod sovd_tests;

#[cfg(test)]
mod component_adapter_tests;

#[cfg(test)]
mod diag_backend_tests;

#[cfg(test)]
mod wrapper_http_tests;
