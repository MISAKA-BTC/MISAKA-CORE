# MISAKA License Guide

## License: Apache License 2.0

MISAKA is licensed under the [Apache License, Version 2.0](../LICENSE).

## SPDX Header for Rust Source Files

Add this header to the top of every new `.rs` file:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
```

## Why Apache-2.0?

### Enterprise & Exchange Friendly
- **Patent grant**: Contributors explicitly grant patent rights, protecting users from patent litigation
- **No copyleft**: Companies can use MISAKA in proprietary products without releasing their source code
- **Clear contribution terms**: Section 5 defines contribution licensing automatically
- **Compatible with most corporate policies**: Apache-2.0 is pre-approved at most enterprises

### How It Differs from MIT and GPL

| Aspect | Apache-2.0 | MIT | GPL-3.0 |
|--------|-----------|-----|---------|
| Patent grant | Yes (explicit) | No | Yes (implicit) |
| Copyleft | No | No | Yes (strong) |
| Trademark protection | Yes | No | No |
| State changes required | Yes (modified files) | No | Yes (source disclosure) |
| Compatible with proprietary use | Yes | Yes | No |
| NOTICE file required | Yes | No | No |

### User Obligations

When using or distributing MISAKA:

1. **Include the LICENSE file** in distributions
2. **Include the NOTICE file** in distributions
3. **Mark modified files** with prominent notices stating the changes
4. **Retain all copyright/patent/trademark notices** from the source
5. **Do NOT use MISAKA trademarks** without permission (except to describe origin)

### What You CAN Do

- Use MISAKA commercially without royalties
- Modify and create derivative works
- Distribute modified versions under different license terms (for your modifications)
- Use in proprietary/closed-source products
- Patent your own contributions (but cannot revoke the patent grant to others)
