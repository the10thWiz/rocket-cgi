# Simple CGI (RFC 3875) handler for Rocket

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

- [x] Security
  - [ ] Check file permissions - Deny writable files?
  - [x] Check file permissions - Deny setuid bit
  - [x] Block path traversal
  - [x] Ignore dot files / hidden files
- [x] Configuration
  - [x] CGI data limitation
  - [x] Limit file types (i.e. a CGIDir can only execute python, etc)
  - [x] Custom file types
- [ ] Functionality
  - [x] Additional default filetypes
  - [ ] Allocate less
  - [x] Redirection
  - [ ] Extension headers
