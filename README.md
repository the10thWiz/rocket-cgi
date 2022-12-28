# Simple CGI (RFC 3875) handler for Rocket

Simple standards compliant CGI handler for Rocket

## Usage

Simply mount a directory with a CGI handler.

```rust
rocket().mount("/cgi", CGIDir::new("./cgi"))
```

## Notes

This CGI handler will automatically attempt to kill the script when stdout has
been closed. More most usecases this is fine, since the script will close stdout
by exiting.

## TODO

- [ ] Security
  - [ ] Check file permissions - Deny writable files?
  - [ ] Check file permissions - Deny setuid bit
  - [ ] Block path traversal
  - [ ] Ignore dot files / hidden files
- [ ] Configuration
  - [ ] CGI data limitation
  - [ ] Limit file types (i.e. a CGIDir can only execute python, etc)
  - [ ] Custom file types
- [ ] Functionality
  - [ ] Additional default filetypes
