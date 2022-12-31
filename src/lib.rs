#![deny(missing_docs)]
//! Implement CGI directory handler for Rocket

mod os;

use std::{
    borrow::Cow,
    collections::HashMap,
    future::{ready, Future},
    io::{self, Error, ErrorKind, Read},
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    task::Poll,
};

use bitfield::bitfield;
use os::{allowed, has_dot_file, has_setuid, is_writable};
use rocket::{
    data::ToByteUnit,
    http::{uncased, ContentType, Method},
    log::*,
    request::Request,
    response::{Redirect, Responder},
    route::Outcome,
};
use rocket::{http::Status, Data};
use rocket::{response::Response, route::Handler, Route};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

const PATH_DEF: &str = "/<path..>?<..>";

bitfield! {
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct CGISettings(u64);
    impl Debug;
    unencoded_equals, set_unencoded_equals: 0;
    dot_files, set_dot_files: 1;
    hidden_files, set_hidden_files: 2;
    setuid, set_setuid: 3;
    direct_executable, set_direct_executable: 4;
    writable_files, set_writable_files: 5;
    allow_post, set_allow_post: 6;
    allow_get, set_allow_get: 7;
    ensure_newline, set_ensure_newline: 8;
}

/// Custom handler to execute CGIScripts
///
/// This handler will execute any script within the directory provided.
/// See examples/cgi.rs for a full usage example
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGIDir {
    path: PathBuf,
    settings: CGISettings,
    file_types: HashMap<Cow<'static, str>, Cow<'static, Path>>,
}

impl CGIDir {
    /// Generate a CGI script from the associated path
    ///
    /// ```rust
    /// # use rocket::build;
    /// # use rocket_cgi::CGIDir;
    /// build().mount("/", CGIDir::new("examples"))
    /// # ;
    /// ```
    pub fn new(path: impl AsRef<Path>) -> Self {
        let mut settings = CGISettings(0);
        settings.set_unencoded_equals(false);
        settings.set_dot_files(false);
        settings.set_hidden_files(false);
        settings.set_setuid(false);
        settings.set_direct_executable(true);
        settings.set_writable_files(true);
        settings.set_allow_get(true);
        settings.set_allow_post(true);
        settings.set_ensure_newline(false);
        Self {
            path: std::fs::canonicalize(path).expect("Path does not exist"),
            settings,
            file_types: [("pl", "perl"), ("py", "python"), ("sh", "sh")]
                .iter()
                .map(|&(a, b)| (a.into(), Path::new(b).into()))
                .collect(),
        }
    }

    /// Clear file type associations, and disables directly running executables
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").clear_file_types());
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::InternalServerError);
    /// // Since the file could not be executed, a 500 error is returned
    /// ```
    pub fn clear_file_types(mut self) -> Self {
        self.file_types.clear();
        self.settings.set_direct_executable(false);
        self
    }

    /// Add a file type association for executing a file. Overrides an existing file type
    /// association if one exists.
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// # use std::path::Path;
    /// let rocket = build().mount("/",
    ///     CGIDir::new("test")
    ///         .clear_file_types()// Clear file types
    ///         .set_file_type("sh", Path::new("sh"))// manually insert `sh`
    ///     );
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// ```
    pub fn set_file_type(
        mut self,
        extension: impl Into<Cow<'static, str>>,
        executable: impl Into<Cow<'static, Path>>,
    ) -> Self {
        self.file_types.insert(extension.into(), executable.into());
        self
    }

    /// Only allow executing perl scripts. Disables all filetypes except `.pl`
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").only_perl());
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.pl").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// let res = client.get("/simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::InternalServerError);
    /// ```
    pub fn only_perl(mut self) -> Self {
        self.file_types.retain(|s, _| s == "pl");
        self.settings.set_direct_executable(false);
        self
    }

    /// Only allow executing python scripts. Disables all filetypes except `.py`
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").only_python().detect_python3());
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.py").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// let res = client.get("/simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::InternalServerError);
    /// ```
    pub fn only_python(mut self) -> Self {
        self.file_types.retain(|s, _| s == "py");
        self.settings.set_direct_executable(false);
        self
    }

    /// Automatically detect python executables. This should allow either `python` or `python3` to
    /// be present on the system
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").detect_python3());
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.py").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// ```
    ///
    /// # Panics
    ///
    /// If python cannot be found on the current Path. If a version of python not on the path is
    /// desired, it is recommended to explicitly set the path e.g.
    /// `.set_file_type("py", Path::new("/opt/py/bin/python"))`
    pub fn detect_python3(self) -> Self {
        use std::process::Command;
        match Command::new("python3").arg("-V").spawn() {
            Ok(_) => return self.set_file_type("py", Path::new("python3")),
            _ => (),
        }
        match Command::new("python").arg("-V").spawn() {
            Ok(c) => {
                let mut s = String::new();
                let _ = c.stdout.unwrap().read_to_string(&mut s);
                if s.starts_with("Python 3") {
                    return self.set_file_type("py", Path::new("python"));
                }
            }
            _ => (),
        }
        panic!("Python 3 not found")
    }

    /// Automatically detect python executables. This should allow either `python` or `python2` to
    /// be present on the system
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").detect_python2());
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.py").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// ```
    ///
    /// # Panics
    ///
    /// If python cannot be found on the current Path. If a version of python not on the path is
    /// desired, it is recommended to explicitly set the path e.g.
    /// `.set_file_type("py", Path::new("/opt/py/bin/python"))`
    pub fn detect_python2(self) -> Self {
        use std::process::Command;
        match Command::new("python2").arg("-V").spawn() {
            Ok(_) => return self.set_file_type("py", Path::new("python3")),
            _ => (),
        }
        match Command::new("python").arg("-V").spawn() {
            Ok(c) => {
                let mut s = String::new();
                let _ = c.stdout.unwrap().read_to_string(&mut s);
                if s.starts_with("Python 2") {
                    return self.set_file_type("py", Path::new("python"));
                }
            }
            _ => (),
        }
        panic!("Python 2 not found")
    }

    /// Only allow executing python scripts. Disables all filetypes except `.sh`
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").only_sh());
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// let res = client.get("/simple.py").dispatch();
    /// assert_eq!(res.status(), Status::InternalServerError);
    /// ```
    pub fn only_sh(mut self) -> Self {
        self.file_types.retain(|s, _| s == "sh");
        self.settings.set_direct_executable(false);
        self
    }

    /// Sets the shell interpreter. Implicitly enables `.sh` files if they are currently disabled
    ///
    /// Default is `sh`
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// # use std::path::Path;
    /// let rocket = build().mount("/", CGIDir::new("test").shell_interpreter(Path::new("bash")));
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/shell.sh").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// assert_eq!(res.into_string().unwrap(), "bash\n");
    /// ```
    pub fn shell_interpreter(mut self, executable: impl Into<Cow<'static, Path>>) -> Self {
        self.file_types.insert("sh".into(), executable.into());
        self
    }

    /// Adds default Windows Shell Script types:
    /// - cmd.exe: .cmd, .bat
    /// - powershell.exe: .ps1
    /// - cscript.exe: .wsf, .vbs, .js
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// # use std::path::Path;
    /// # #[cfg(windows)]
    /// # fn main() {
    /// let rocket = build().mount("/", CGIDir::new("test").add_windows_scripts());
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/simple.cmd").dispatch();
    /// assert_eq!(res.status(), Status::Ok);
    /// # }
    /// # // Empty main to allow testing on non-windows platforms
    /// # #[cfg(not(windows))] fn main() {}
    /// ```
    pub fn add_windows_scripts(mut self) -> Self {
        [
            ("cmd", "cmd.exe"),
            ("bat", "cmd.exe"),
            ("ps1", "powershell.exe"),
            ("wsf", "csript.exe"),
            ("vbs", "csript.exe"),
            ("js", "csript.exe"), // ?
        ]
        .iter()
        .for_each(|&(a, b)| {
            self.file_types.insert(a.into(), Path::new(b).into());
        });
        self
    }

    /// Whether to allow directly executable files. This may allow scripts with execute
    /// permissions and a shebang (`#!`) to be executed, on some systems.
    ///
    /// Defaults to true
    pub fn direct_executables(mut self, allow: bool) -> Self {
        self.settings.set_direct_executable(allow);
        self
    }

    /// Whether to pass parameters that contain unencoded `=`
    ///
    /// The CGI spec requires this to be false, which is the default
    pub fn unencoded_equals(mut self, allow: bool) -> Self {
        self.settings.set_unencoded_equals(allow);
        self
    }

    /// Whether to allow serving unix hidden files (files starting with a `.`)
    ///
    /// Defaults to false
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").dot_files(false));
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/.simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::NotFound);
    /// ```
    pub fn dot_files(mut self, allow: bool) -> Self {
        self.settings.set_dot_files(allow);
        self
    }

    /// Whether to allow serving hidden files
    ///
    /// Defaults to false, only applies to Windows
    pub fn hidden_files(mut self, allow: bool) -> Self {
        self.settings.set_hidden_files(allow);
        self
    }

    // This is commented out, since the ability to detect write permissions are not currently
    // complete. This should likely be checked by attempting to open the file for writing (although
    // this may not be sufficient).
    // /// Whether to allow serving writable files
    // ///
    // /// Defaults to true
    // pub fn writable_files(mut self, allow: bool) -> Self {
    //     self.settings.set_writable_files(allow);
    //     self
    // }

    /// Whether to allow serving files with setuid & setgid bits set
    ///
    /// Defaults to false, only has an effect on Unix systems. Note this does not prevent a script
    /// from executing a setuid bit binary, but rather only protects against Rocket starting a
    /// setuid binary
    pub fn setuid_files(mut self, allow: bool) -> Self {
        self.settings.set_setuid(allow);
        self
    }

    /// Whether to serve GET & HEAD requests
    ///
    /// Defaults to true
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").serve_get(false));
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.get("/.simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::NotFound);
    /// ```
    pub fn serve_get(mut self, allow: bool) -> Self {
        self.settings.set_allow_get(allow);
        self
    }

    /// Whether to serve POST requests
    ///
    /// Defaults to true
    ///
    /// ```rust
    /// # use rocket::{build, http::Status};
    /// # use rocket::local::blocking::Client;
    /// # use rocket_cgi::CGIDir;
    /// let rocket = build().mount("/", CGIDir::new("test").serve_post(false));
    /// let client = Client::tracked(rocket).unwrap();
    /// let res = client.post("/.simple.sh").dispatch();
    /// assert_eq!(res.status(), Status::NotFound);
    /// ```
    pub fn serve_post(mut self, allow: bool) -> Self {
        self.settings.set_allow_post(allow);
        self
    }

    async fn locate_file<'r>(&self, r: &'r Request<'_>) -> io::Result<Child> {
        let mut path = self.path.to_path_buf();
        let prefix = r.route().unwrap().uri.as_str().trim_end_matches(PATH_DEF);
        let uri_path = r.uri().path();
        let decoded = uri_path
            .strip_prefix(prefix)
            .unwrap_or(&uri_path) // This shouldn't happen, since the URL matched
            .percent_decode()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "URL is not valid UTF-8"))?;
        let trailing = decoded.trim_start_matches(|c| c == '/' || c == '\\');
        // Final trim allows repeated `/`s in the file while
        let trailing_path = Path::new(trailing);

        if !self.settings.dot_files() && has_dot_file(trailing_path) {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "Hidden files not permitted",
            ));
        }

        if !trailing_path.is_relative() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Absolute paths not permitted",
            ));
        }
        path.push(trailing_path);
        // Sadly this allocates, but I don't think there's a way arount it
        let path = tokio::fs::canonicalize(path).await?;
        if !path.starts_with(&self.path) {
            // error_!("Path: {}", path.display());
            return Err(Error::new(
                ErrorKind::NotFound,
                "Files outside directory not permitted",
            ));
        }

        debug_!("Path: {}", path.display());
        let meta = tokio::fs::metadata(&path).await?;
        debug_!("meta: {:?}", meta);
        if !self.settings.setuid() && has_setuid(&meta) {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                "Setuid files not permitted",
            ));
        }

        if !self.settings.writable_files() && is_writable(&meta) {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Writable files not permitted",
            ));
        }

        if !allowed(&meta) {
            return Err(io::Error::new(ErrorKind::Other, "File not permitted"));
        }

        if meta.is_dir() {
            // path.push("index.pl"); // ?
            return Err(io::Error::new(
                ErrorKind::Other,
                "Directories not supported",
            ));
        }

        self.build_process(path, trailing, r)
    }

    fn build_process(&self, path: PathBuf, name: &str, r: &Request<'_>) -> io::Result<Child> {
        let mut builder = if let Some(exe) = path
            .extension()
            .and_then(|e| e.to_str())
            .and_then(|e| self.file_types.get(e))
        {
            let mut ret = Command::new(exe.as_os_str());
            ret.arg(path);
            ret
        } else if self.settings.direct_executable() {
            Command::new(path.as_os_str())
        } else {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Direct executables not permitted",
            ));
        };
        builder.env_clear();

        if let Some(query) = r.uri().query() {
            builder.env("QUERY_STRING", query.as_str());
            if self.settings.unencoded_equals() || !query.as_str().contains('=') {
                for part in query.split('+') {
                    if let Ok(decoded) = part.url_decode() {
                        builder.arg(decoded.as_ref());
                    }
                }
            }
        }
        builder.env("AUTH_TYPE", "");
        // We allow this to be empty (e.g. Transfer-Encoding: chunked), and don't set it if we
        // don't know. The Spec technically requires it to be set, but we ignore that
        if let Some(len) = r.headers().get_one("Content-Length") {
            builder.env("CONTENT_LENGTH", len);
        }
        if let Some(ty) = r.content_type() {
            builder.env("CONTENT_TYPE", ty.to_string());
        }
        builder.env("GATEWAY_INTERFACE", "CGI/1.1");

        // We don't support sub-resources
        // builder.env("PATH_INFO", "");
        // builder.env("PATH_TRANSLATED", "");

        if let Some(ip) = r.remote() {
            builder.env("REMOTE_ADDR", format!("{ip}"));
        }
        if let Some(host) = r.host() {
            builder.env("REMOTE_HOST", format!("{host}"));
        }
        builder.env("REQUEST_METHOD", r.method().as_str());
        builder.env("SCRIPT_NAME", name);
        builder.env("SERVER_NAME", r.rocket().config().address.to_string());
        builder.env("SERVER_PORT", r.rocket().config().port.to_string());
        builder.env("SERVER_PROTOCOL", "HTTP/1.1");
        builder.env("SERVER_SOFTWARE", r.rocket().config().ident.to_string());

        builder.stdin(Stdio::piped());
        builder.stdout(Stdio::piped());
        builder.kill_on_drop(true);

        info_!("Command: {:?}", builder);
        builder.spawn()
    }

    async fn generate_response<'r>(
        mut process: Child,
        request: &'r Request<'_>,
    ) -> (Outcome<'r>, impl AsyncRead + 'static, Child) {
        let mut stdout = BufReader::new(process.stdout.take().unwrap());
        let mut res = Response::new();
        let mut buf = String::new();

        res.set_status(Status::Ok);

        let mut has_body = true;
        loop {
            match stdout.read_line(&mut buf).await {
                Ok(_) => (),
                Err(_) => {
                    return (
                        Outcome::Failure(Status::InternalServerError),
                        stdout,
                        process,
                    )
                }
            }
            let line = buf.trim();
            if line == "" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if uncased::eq(key, "Content-Type") {
                    if let Some(content_type) = ContentType::parse_flexible(value) {
                        res.set_header(content_type);
                    }
                } else if uncased::eq(key, "Location") {
                    if value.starts_with("/") {
                        error_!("`local-Location` is not supported");
                        return (
                            Outcome::Failure(Status::InternalServerError),
                            stdout,
                            process,
                        );
                    } else {
                        has_body = false;
                        match Redirect::to(value.to_owned()).respond_to(request) {
                            Ok(r) => res.merge(r),
                            Err(e) => {
                                res.set_status(e);
                                let _ = process.kill().await;
                                return (Outcome::Success(res), stdout, process);
                            }
                        }
                    }
                } else if uncased::eq(key, "Status") {
                    if let Ok(code) = value
                        .split_once(char::is_whitespace)
                        .map_or(value, |(n, _)| n)
                        .parse::<u16>()
                    {
                        res.set_status(Status { code });
                    }
                } else {
                    error_!("Extension header `{key}` is not supported");
                    // Unknown headers are ignored, and not sent to the client
                }
            }
            buf.clear();
        }
        if !has_body {
            let _ = process.kill().await;
        }
        // res.set_streamed_body(stdout);
        return (Outcome::Success(res), stdout, process);
    }
}

struct Paired<R, F> {
    child: Option<Child>,
    reader: R,
    future: Option<F>,
}

impl<R, F> Paired<R, F> {
    fn new(child: Child, reader: R, future: F) -> Self {
        Self {
            child: Some(child),
            reader,
            future: Some(future),
        }
    }
}

impl<R: AsyncRead, F: Future> AsyncRead for Paired<R, F> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // SAFETY: We immediately repin interior references, except self.child
        let this = unsafe { self.get_unchecked_mut() };
        if let Some(future) = this.future.as_mut() {
            // This is a repin, and therefore meets the requirements of pinning
            match unsafe { Pin::new_unchecked(future) }.poll(cx) {
                Poll::Pending => (),
                Poll::Ready(_) => this.future = None,
            }
        }
        // This is a repin, and therefore meets the requirements of pinning
        match unsafe { Pin::new_unchecked(&mut this.reader) }.poll_read(cx, buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(res) => {
                // Pinning the child is not structural
                if let Some(mut child) = this.child.take() {
                    tokio::spawn(async move { child.kill().await });
                }
                return Poll::Ready(res);
            }
        }
    }
}

#[rocket::async_trait]
impl Handler for CGIDir {
    async fn handle<'r>(&self, request: &'r Request<'_>, data: Data<'r>) -> Outcome<'r> {
        let mut process = match self.locate_file(request).await {
            Ok(p) => p,
            Err(e) if e.kind() == ErrorKind::NotFound => return Outcome::Forward(data),
            Err(e) => {
                error_!("Error: {e}");
                return Outcome::Failure(Status::InternalServerError);
            }
        };
        let mut body = process.stdin.take().unwrap();

        let limit = request
            .rocket()
            .config()
            .limits
            .find(["cgi"])
            .unwrap_or(1.mebibytes());

        // Not ideal to box this, but we need to move it later, so...
        let generate_response = Self::generate_response(process, request);

        if request.method() == Method::Head {
            drop(body);
            let (res, _, mut process) = generate_response.await;
            let _ = process.kill().await;
            res
        } else if request.method() == Method::Get {
            drop(body);
            let (res, stdout, process) = generate_response.await;
            res.map(|mut res| {
                res.set_streamed_body(Paired::new(process, stdout, std::future::ready(())));
                res
            })
        } else if request.method() == Method::Post {
            let ensure_newline = self.settings.ensure_newline();
            let mut write_post_data = Box::pin(async move {
                let _ = tokio::io::copy(&mut data.open(limit), &mut body).await;
                if ensure_newline {
                    let _ = body.write_all(b"\n").await;
                }
            });
            tokio::pin!(generate_response);
            tokio::select! {
                biased;// Ideally we want to take the first path, so we should always try the first one
                _ = &mut write_post_data => {
                    let (res, stdout, process) = generate_response.await;
                    res.map(|mut res| { res.set_streamed_body(Paired::new(process, stdout, ready(()))); res })
                },
                res = &mut generate_response => {
                    let (res, stdout, process) = res;
                    res.map(|mut res| { res.set_streamed_body(Paired::new(process, stdout, write_post_data)); res })
                }
            }
        } else {
            unreachable!("Only Get, Head & Post supported")
        }
    }
}

impl Into<Vec<Route>> for CGIDir {
    fn into(self) -> Vec<Route> {
        let mut ret = Vec::with_capacity(3);
        if self.settings.allow_get() {
            ret.push(Route::ranked(9, Method::Get, PATH_DEF, self.clone()));
            ret.push(Route::ranked(9, Method::Head, PATH_DEF, self.clone()));
        }
        if self.settings.allow_post() {
            ret.push(Route::ranked(9, Method::Post, PATH_DEF, self.clone()));
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use rocket::local::asynchronous::Client;

    use super::*;

    async fn generate_client() -> Client {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let rocket = rocket::build().mount("/", CGIDir::new(format!("{dir}/test")));
        Client::tracked(rocket).await.unwrap()
    }

    #[rocket::async_test]
    async fn simple_script() {
        let client = generate_client().await;
        let res = client.get("/simple.sh").dispatch().await;
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.content_type(), Some(ContentType::Text));
        assert_eq!(res.into_string().await.unwrap(), "simple output\n");
    }

    #[rocket::async_test]
    async fn redirect() {
        let client = generate_client().await;
        let res = client.get("/redirect.sh").dispatch().await;
        assert_eq!(res.status(), Status::SeeOther);
        assert_eq!(
            res.headers().get_one("Location").unwrap(),
            "http://localhost:8000/simple.sh"
        );
    }

    #[rocket::async_test]
    async fn params() {
        let client = generate_client().await;
        let res = client.get("/params.sh?world").dispatch().await;
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.content_type(), Some(ContentType::Text));
        assert_eq!(res.into_string().await.unwrap(), "Hello 'world'!\n");

        // Unencoded equals
        let res = client.get("/params.sh?world=hello").dispatch().await;
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.content_type(), Some(ContentType::Text));
        assert_eq!(res.into_string().await.unwrap(), "Hello ''!\n");

        // Encoded equals
        let res = client.get("/params.sh?world%3dhello").dispatch().await;
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.content_type(), Some(ContentType::Text));
        assert_eq!(res.into_string().await.unwrap(), "Hello 'world=hello'!\n");
    }

    #[rocket::async_test]
    async fn env_vars() {
        let client = generate_client().await;
        macro_rules! var {
            ($var:literal, $val:literal) => {{
                let res = client.get(concat!("/env_vars.sh?", $var)).dispatch().await;
                assert_eq!(res.status(), Status::Ok);
                assert_eq!(res.content_type(), Some(ContentType::Text));
                assert_eq!(res.into_string().await.unwrap().trim(), $val);
            }};
        }

        var!("AUTH_TYPE", "");
        var!("CONTENT_LENGTH", "");
        var!("CONTENT_TYPE", "");
        var!("GATEWAY_INTERFACE", "CGI/1.1");
        var!("PATH_INFO", "");
        var!("PATH_TRANSLATED", "");
        var!("QUERY_STRING", "QUERY_STRING");
        var!("REMOTE_IDENT", "");
        var!("REMOTE_USER", "");
        var!("REQUEST_METHOD", "GET");
        var!("SCRIPT_NAME", "env_vars.sh");
        var!("SERVER_NAME", "127.0.0.1");
        var!("SERVER_PORT", "8000");
        var!("SERVER_PROTOCOL", "HTTP/1.1");
        var!("SERVER_SOFTWARE", "Rocket");
    }

    #[rocket::async_test]
    async fn post_body() {
        let client = generate_client().await;
        let res = client.post("/post.sh").body("something").dispatch().await;
        assert_eq!(res.status(), Status::Ok);
        assert_eq!(res.content_type(), Some(ContentType::Text));
        assert_eq!(res.into_string().await.unwrap(), "val: something\n");
    }
}
