# Simple CGI (RFC 3875) handler for Rocket

[![https://img.shields.io/crates/v/rocket-cgi.svg]](https://crates.io/crates/rocket-cgi)

Simple standards compliant CGI handler for Rocket. This is still a WIP, and will
remain so until the security todo items have been handled.

## Usage

Simply mount a directory with a CGI handler.

```rust
rocket().mount("/cgi", CGIDir::new("./cgi"))
```

## Configuration

- `cgi` data limit for post requests (1 MiB default)

## Notes

This CGI handler will automatically attempt to kill the script as soon as
possible. If the process closes stdout, the header lines have been printed for a
HEAD request, or a redirect was sent will all cause the process to be killed.

This also don't implement several optional parts of the spec. For example,
extension methods (even just PUT & DELETE) are not supported.

## TODO

- Security
  - [ ] Check file permissions - Deny writable files?
  - [x] Check file permissions - Deny setuid bit
  - [x] Block path traversal
  - [x] Ignore dot files / hidden files
- Functionality
  - [x] Additional default filetypes
  - [x] Redirection
  - [ ] Extension headers
- Testing
  - [ ] Test Windows-only features (Hidden Files & System/Temporary Files)
