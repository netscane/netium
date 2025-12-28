//! Common types and abstractions
//!
//! This module defines the core types used throughout the application:
//! - Stream: unified async I/O abstraction
//! - Metadata: connection context for routing
//! - Address: network address representation
//! - Error: unified error types

mod stream;
mod metadata;
mod address;

pub use stream::{Stream, BoxedStream, IntoStream};
pub use metadata::{Metadata, Network};
pub use address::Address;

// Re-export error types from crate root
pub use crate::error::{Error, Result};
