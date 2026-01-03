//! Common types and abstractions
//!
//! This module defines the core types used throughout the application:
//! - Stream: unified async I/O abstraction
//! - Metadata: connection context for routing
//! - Address: network address representation
//! - Pipe: bidirectional data channel with lifecycle management
//! - Error: unified error types

mod stream;
mod metadata;
mod address;
pub mod pipe;

pub use stream::{Stream, BoxedStream, IntoStream};
pub use metadata::{Metadata, Network};
pub use address::Address;
pub use pipe::{Pipe, relay};

// Re-export error types from crate root
pub use crate::error::{Error, Result};
