# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Report it privately with
GitHub's form: **Security → Report a vulnerability**
(<https://github.com/wvmscs/geohash-relays-net/security/advisories/new>).

Say what you found, how to reproduce it, and what an attacker gains. A fix and an advisory
follow, crediting you if you wish.

## What counts

Anything that breaks what this project promises its users, for example:

- a key, a seed or a private message that leaves the machine, reaches a log or a file it
  should not, or can be read by another local user;
- a connection that bypasses Tor where Tor is required, or leaks the user's IP address;
- a web page or a request that can command the local server from another origin;
- a crafted relay message, event or file that crashes the program or runs code.

Weaknesses of the BitChat protocol or apps themselves belong to their projects
(<https://github.com/permissionlesstech>), but tell us too if they affect this one.

## Supported versions

The latest release tag and the `main` branch.
