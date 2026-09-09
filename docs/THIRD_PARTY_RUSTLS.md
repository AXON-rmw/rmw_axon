# Bundled rustls-axon

Axon includes the `rustls-axon` fork as a Git subtree under
`third_party/rustls-axon`. The imported snapshot is commit
`545f1f6d2ca6d32e0daa3c0683998ab6e4c63b37`, based on rustls 0.23.40, and adds
the narrow TLS 1.3 external-PSK API required by QKD mode.

Cargo applies the local fork through the `[patch.crates-io]` entry in
`axon_core/Cargo.toml`. A normal clone of Axon therefore contains the complete
fork; no second clone or SSH deploy key is needed.

## Updating the fork

Develop rustls changes in the upstream `rustls-axon` repository first. Then,
from the Axon repository, import the reviewed commit:

```bash
git remote add rustls-axon ssh://git@github.com/ssancd03/rustls-axon.git
git fetch rustls-axon
git subtree pull --prefix=third_party/rustls-axon rustls-axon main --squash
```

Review the resulting upstream commit before merging it. After updating, run
the Rust and ROS test suites, and commit the subtree update together with the
lockfile.
