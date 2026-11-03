# Security

## Reporting a vulnerability

Report it privately: open the repository's **Security** tab and choose
**Report a vulnerability**. Please do not open a public issue for it.

Include what you can of:

- the version (`sda --version`) and platform;
- what an attacker controls: the scanned repository, its `.sda/` files, a model
  artifact, an MCP client, or a page in the workbench;
- the smallest input that shows it, and what happens.

## Supported versions

Fixes go into the latest release. Release candidates are not supported once a
release replaces them.

## What `sda` trusts

`sda` reads code it did not write. The README's section on code you did not
write says what a scan, a build, the MCP server and the workbench will and will
not do with it. Anything that runs a project's own build or test code is opt-in
and says so.
