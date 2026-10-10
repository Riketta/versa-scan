//! Driving ports (inbound edge): contracts the world uses to drive the
//! core. Implemented by core services, called by inbound adapters.

pub mod scan_pipeline;

pub use scan_pipeline::Delivery;
pub use scan_pipeline::DeliveryHandle;
pub use scan_pipeline::ScanPipelinePort;
