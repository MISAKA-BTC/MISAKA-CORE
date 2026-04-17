// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! `AuthorityClient` trait — async request/response to a single authority.

use crate::committee::AuthorityIndex;
use crate::error::AuthorityError;

/// Trait for sending a request to one authority and receiving a response.
///
/// The aggregator calls `request` for each authority concurrently
/// via `tokio::task::JoinSet`.
#[async_trait::async_trait]
pub trait AuthorityClient<Req, Resp>: Send + Sync + 'static
where
    Req: Send + Sync + 'static,
    Resp: Send + 'static,
{
    /// Send `req` to the authority at `authority_index`.
    async fn request(
        &self,
        authority_index: AuthorityIndex,
        req: Req,
    ) -> Result<Resp, AuthorityError>;
}
