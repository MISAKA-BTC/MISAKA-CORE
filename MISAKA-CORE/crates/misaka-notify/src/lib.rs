//! # misaka-notify
//!
//! Event notification system for MISAKA Network. Provides:
//! - Typed pub/sub notification routing
//! - Address-based transaction tracking
//! - Broadcast channels for block/mempool events
//! - Subscriber management with scope-based filtering
//! - Connection-aware notification delivery

pub mod address;
pub mod broadcaster;
pub mod collector;
pub mod connection;
pub mod converter;
pub mod error;
pub mod events;
pub mod listener;
pub mod notification;
pub mod notifier;
pub mod root;
pub mod scope;
pub mod subscriber;
pub mod subscription;
pub mod processor;
pub mod flow_control;
pub mod delivery_manager;
pub mod subscription_store;
