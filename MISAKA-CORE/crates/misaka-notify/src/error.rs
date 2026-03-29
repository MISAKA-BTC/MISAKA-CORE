//! Notification system errors.

#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("listener not found: {0}")]
    ListenerNotFound(u64),
    #[error("channel closed")]
    ChannelClosed,
    #[error("subscription error: {0}")]
    SubscriptionError(String),
    #[error("broadcast error: {0}")]
    BroadcastError(String),
    #[error("address tracking error: {0}")]
    AddressTrackingError(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type NotifyResult<T> = Result<T, NotifyError>;
