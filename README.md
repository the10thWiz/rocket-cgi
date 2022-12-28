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

This CGI handler will automatically attempt to kill the script when stdout has
been closed. More most usecases this is fine, since the script will close stdout
by exiting.

This also don't implement several optional parts of the spec. For example,
extension methods (even just PUT & DELETE) are not supported.

## TODO

- [ ] Security
  - [ ] Check file permissions - Deny writable files?
  - [ ] Check file permissions - Deny setuid bit
  - [x] Block path traversal
  - [ ] Ignore dot files / hidden files
- [ ] Configuration
  - [x] CGI data limitation
  - [ ] Limit file types (i.e. a CGIDir can only execute python, etc)
  - [ ] Custom file types
- [ ] Functionality
  - [ ] Additional default filetypes
  - [ ] Allocate less
  - [ ] Redirection
  - [ ] Extension headers
