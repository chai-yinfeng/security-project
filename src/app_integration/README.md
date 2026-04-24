# C Host Entry Placeholder

This directory is currently a placeholder for the C host entry logic.

Planned responsibilities:

- receive control when the protected executable starts
- call the Rust core through the agreed interface
- gate entry into the protected path on an allow decision

The host side should not implement embedded-policy parsing, verification, or authorization logic on its own.
