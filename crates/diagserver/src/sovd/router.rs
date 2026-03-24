use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

use nv_store::block::BlockDevice;

use crate::sovd::handlers;
use crate::sovd::state::AppState;

pub fn create_router<D: BlockDevice + Send + Sync + 'static>(state: AppState<D>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(handlers::health))
        .route(
            "/vehicle/v1/components",
            get(handlers::list_components),
        )
        .route(
            "/vehicle/v1/components/{component_id}",
            get(handlers::get_component),
        )
        .route(
            "/vehicle/v1/components/{component_id}/data",
            get(handlers::list_parameters::<D>),
        )
        .route(
            "/vehicle/v1/components/{component_id}/data/{param_id}",
            get(handlers::read_parameter::<D>)
                .put(handlers::write_parameter::<D>),
        )
        .route(
            "/vehicle/v1/components/{component_id}/faults",
            get(handlers::list_faults::<D>)
                .delete(handlers::clear_faults::<D>),
        )
        // Flash: file upload and verification
        .route(
            "/vehicle/v1/components/{component_id}/files",
            post(handlers::upload_file::<D>),
        )
        .route(
            "/vehicle/v1/components/{component_id}/files/{upload_id}",
            get(handlers::get_upload_status::<D>),
        )
        .route(
            "/vehicle/v1/components/{component_id}/files/{upload_id}/verify",
            post(handlers::verify_file::<D>),
        )
        // Flash: transfer and progress
        .route(
            "/vehicle/v1/components/{component_id}/flash/transfer",
            post(handlers::start_transfer::<D>),
        )
        .route(
            "/vehicle/v1/components/{component_id}/flash/transfer/{transfer_id}",
            get(handlers::transfer_progress::<D>)
                .put(handlers::finalize_transfer::<D>),
        )
        // Flash: activation, commit, rollback (existing)
        .route(
            "/vehicle/v1/components/{component_id}/flash/activation",
            get(handlers::get_activation_state::<D>),
        )
        .route(
            "/vehicle/v1/components/{component_id}/flash/commit",
            post(handlers::commit_flash::<D>),
        )
        .route(
            "/vehicle/v1/components/{component_id}/flash/rollback",
            post(handlers::rollback_flash::<D>),
        )
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024)) // 256 MB
        .layer(cors)
        .with_state(state)
}
