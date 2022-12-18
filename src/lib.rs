#![deny(missing_docs)]
//! Implement CGI directory handler for Rocket

use std::{
    borrow::Cow,
    future::{ready, Future},
    io::{self, Error, ErrorKind},
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    task::Poll,
};

use rocket::{
    data::ToByteUnit,
    http::{uncased, ContentType, Header, Method},
    request::Request,
    route::Outcome,
};
use rocket::{http::Status, Data};
use rocket::{response::Response, route::Handler, Route};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
};

// impl FileType {
//     fn arg(&self) -> Option<&'static str> {
//         match self {
//             FileType::Bash => Some("bash"),
//             FileType::Python => Some("python"),
//             FileType::Python2 => todo!(),
//             FileType::Python3 => todo!(),
//             FileType::Perl => Some("perl"),
//             FileType::Executable => None,
//         }
//     }
// }

/// Executes CGIScript to generate response
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CGIDir {
    path: Cow<'static, Path>,
    allow_unencoded_equals: bool,
}

impl CGIDir {
    /// Generate a CGI script from the associated path
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Cow::Owned(path.into()),
            allow_unencoded_equals: false,
        }
    }

    async fn locate_file<'r>(&self, r: &'r Request<'_>) -> io::Result<(PathBuf, &'r str)> {
        let mut path = self.path.to_path_buf();
        let prefix = r
            .route()
            .unwrap()
            .uri
            .as_str()
            .trim_end_matches("<..>?<..>");
        let trailing = r.uri().path().as_str().trim_start_matches(prefix);
        path.push(trailing);
        // dbg!(&path);
        let meta = tokio::fs::metadata(&path).await?;
        if meta.is_dir() {
            path.push("index.pl"); // ?
            return Err(io::Error::new(
                ErrorKind::Other,
                "Directories not supported",
            ));
        }
        Ok((path, trailing))
    }

    fn command(program: &str, path: PathBuf) -> Command {
        let mut ret = Command::new(program);
        ret.arg(path);
        ret
    }

    fn build_process(&self, path: PathBuf, name: &str, r: &Request<'_>) -> io::Result<Child> {
        let mut builder = match path.extension().and_then(|e| e.to_str()) {
            Some("pl") => Self::command("perl", path),
            Some("py") => Self::command("python", path),
            Some("sh") => Self::command("bash", path),
            _ => Command::new(path.as_os_str()),
        };
        if let Some(query) = r.uri().query() {
            builder.env("QUERY_STRING", query.as_str());
            if self.allow_unencoded_equals || !query.as_str().contains('=') {
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

        // This is a stub implementation (since we don't support sub-resources)
        builder.env("PATH_INFO", "");
        builder.env("PATH_TRANSLATED", "");

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
        builder.spawn()
    }

    async fn generate_response<'r>(
        mut process: Child,
    ) -> (Outcome<'r>, impl AsyncRead + 'static, Child) {
        let mut stdout = BufReader::new(process.stdout.take().unwrap());
        let mut res = Response::new();
        let mut buf = String::new();
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
                    todo!("Implement redirects");
                } else if uncased::eq(key, "Status") {
                    if let Ok(code) = value
                        .split_once(char::is_whitespace)
                        .map_or(value, |(n, _)| n)
                        .parse::<u16>()
                    {
                        res.set_status(Status { code });
                    }
                } else {
                    todo!("Impl extension header `{key}`");
                }
            }
            buf.clear();
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
        let (file, name) = match self.locate_file(request).await {
            Ok(file) => file,
            Err(_e) => return Outcome::Forward(data),
        };
        let mut process = match self.build_process(file, name, request) {
            Ok(p) => p,
            Err(e) if e.kind() == ErrorKind::NotFound => return Outcome::Forward(data),
            Err(_) => return Outcome::Failure(Status::InternalServerError),
        };
        let mut body = process.stdin.take().unwrap();
        // Not ideal to box this, but we need to move it later, so...
        let mut write_post_data =
            Box::pin(
                async move { tokio::io::copy(&mut data.open(100.mebibytes()), &mut body).await },
            );
        let generate_response = Self::generate_response(process);
        tokio::pin!(generate_response);
        tokio::select! {
            biased;// Ideally we want to take the first path, so we should always try the first one
            _ = &mut write_post_data => {
                let (res, stdout, process) = generate_response.await;
                return res.map(|mut res| { res.set_streamed_body(Paired::new(process, stdout, ready(()))); res });
            },
            res = &mut generate_response => {
                let (res, stdout, process) = res;
                return res.map(|mut res| { res.set_streamed_body(Paired::new(process, stdout, write_post_data)); res });
            }
        }
    }
}

impl Into<Vec<Route>> for CGIDir {
    fn into(self) -> Vec<Route> {
        vec![Route::new(Method::Get, "/<..>?<..>", self.clone())]
    }
}
