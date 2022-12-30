#![deny(missing_docs)]
//! Implement CGI directory handler for Rocket

mod os;

use std::{
    borrow::Cow,
    collections::HashMap,
    future::{ready, Future},
    io::{self, Error, ErrorKind},
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
    log::error_,
    request::Request,
    response::{Redirect, Responder},
    route::Outcome,
};
use rocket::{http::Status, Data};
use rocket::{response::Response, route::Handler, Route};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
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
}

/// Custom handler to execute CGIScripts
///
/// This handler will execute any script within the directory
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGIDir {
    path: Cow<'static, Path>,
    settings: CGISettings,
    file_types: HashMap<Cow<'static, str>, Cow<'static, Path>>,
}

impl CGIDir {
    /// Generate a CGI script from the associated path
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let mut settings = CGISettings(0);
        settings.set_unencoded_equals(false);
        settings.set_dot_files(false);
        settings.set_hidden_files(false);
        settings.set_setuid(false);
        settings.set_direct_executable(true);
        settings.set_writable_files(true);
        Self {
            path: Cow::Owned(path.into()),
            settings,
            file_types: [("pl", "perl"), ("py", "python"), ("sh", "sh")]
                .iter()
                .map(|&(a, b)| (a.into(), Path::new(b).into()))
                .collect(),
        }
    }

    /// Clear file type associations, and disables directly running executables
    pub fn clear_file_types(mut self) -> Self {
        self.file_types.clear();
        self.settings.set_direct_executable(false);
        self
    }

    /// Add a file type association for executing a file
    pub fn add_file_type(
        mut self,
        extension: impl Into<Cow<'static, str>>,
        executable: impl Into<Cow<'static, Path>>,
    ) -> Self {
        self.file_types.insert(extension.into(), executable.into());
        self
    }

    /// Only allow executing perl scripts
    pub fn only_perl(mut self) -> Self {
        self.file_types.retain(|s, _| s == "pl");
        self
    }

    /// Only allow executing python scripts
    pub fn only_python(mut self) -> Self {
        self.file_types.retain(|s, _| s == "py");
        self
    }

    /// Only allow executing python scripts
    pub fn only_sh(mut self) -> Self {
        self.file_types.retain(|s, _| s == "sh");
        self
    }

    /// Sets the shell interpreter
    ///
    /// Default is `sh`
    pub fn shell_interpreter(mut self, executable: impl Into<Cow<'static, Path>>) -> Self {
        self.file_types.insert("sh".into(), executable.into());
        self
    }

    /// Adds default Windows Shell Script types:
    /// - cmd.exe: .cmd, .bat
    /// - powershell.exe: .ps1
    /// - cscript.exe: .wsf, .vbs, .js
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
    /// The CGI spec requires this to be false, which is the default
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
                ErrorKind::Other,
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
            return Err(Error::new(
                ErrorKind::Other,
                "Files outside directory not permitted",
            ));
        }

        let meta = tokio::fs::metadata(&path).await?;
        if !self.settings.setuid() && !has_setuid(&meta) {
            return Err(io::Error::new(
                ErrorKind::Other,
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
        // don't know.
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
            Err(_) => return Outcome::Failure(Status::InternalServerError),
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
            let mut write_post_data =
                Box::pin(async move { tokio::io::copy(&mut data.open(limit), &mut body).await });
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
        vec![
            Route::ranked(9, Method::Get, PATH_DEF, self.clone()),
            Route::ranked(9, Method::Post, PATH_DEF, self.clone()),
            Route::ranked(9, Method::Head, PATH_DEF, self.clone()),
        ]
    }
}
