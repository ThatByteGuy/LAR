// Reads PKGBUILD text without running it. Never invokes a shell.
use crate::error::{LarError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionBlock {
    pub name: String,
    pub start_line: u32,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct Pkgbuild {
    // kept for hashing/display, never executed
    pub raw: String,
    pub functions: Vec<FunctionBlock>,
    pub globals: String,
    pub sources: Vec<String>,
    pub install_ref: Option<String>,
}

impl Pkgbuild {
    // Structural problems return Err. Caller must treat that as REVIEW.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut functions: Vec<FunctionBlock> = Vec::new();
        let mut globals = String::new();
        let mut current: Option<(String, u32, Vec<String>)> = None;
        let mut depth: i32 = 0;

        for (idx, line) in raw.lines().enumerate() {
            let no = (idx as u32) + 1;
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                if let Some((_, _, ref mut body)) = current {
                    body.push(line.to_owned());
                } else {
                    globals.push_str(line);
                    globals.push('\n');
                }
                continue;
            }
            if current.is_none() {
                if let Some(name) = fn_header(trimmed) {
                    current = Some((name, no, Vec::new()));
                    depth = brace_delta(line);
                    continue;
                }
                globals.push_str(line);
                globals.push('\n');
            } else {
                depth += brace_delta(line);
                if depth <= 0 {
                    if !trimmed.eq("}") {
                        if let Some((_, _, ref mut body)) = current {
                            body.push(line.to_owned());
                        }
                    }
                    if let Some((name, start, body)) = current.take() {
                        functions.push(FunctionBlock {
                            name,
                            start_line: start,
                            body: body.join("\n"),
                        });
                    }
                    depth = 0;
                } else if let Some((_, _, ref mut body)) = current {
                    body.push(line.to_owned());
                }
            }
        }
        if current.is_some() {
            return Err(LarError::Parse("unclosed function block".to_owned()));
        }

        let sources = extract_sources(&globals);
        let install_ref = extract_install(&globals);
        Ok(Self {
            raw: raw.to_owned(),
            functions,
            globals,
            sources,
            install_ref,
        })
    }

    pub fn units(&self) -> Vec<(String, String)> {
        let mut out = vec![("PKGBUILD:global".to_owned(), self.globals.clone())];
        for f in &self.functions {
            out.push((
                format!("PKGBUILD:{}():{}", f.name, f.start_line),
                f.body.clone(),
            ));
        }
        out
    }
}

// `name() {`, with optional `function` prefix.
fn fn_header(trimmed: &str) -> Option<String> {
    let t = trimmed.strip_prefix("function ").unwrap_or(trimmed);
    let paren = t.find("()")?;
    let name = t[..paren].trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    let rest = t[paren + 2..].trim();
    if rest.is_empty() || rest.starts_with('{') || rest.starts_with('#') {
        Some(name.to_owned())
    } else {
        None
    }
}

// Brace count outside quotes. Best-effort on purpose.
fn brace_delta(line: &str) -> i32 {
    let mut opens = 0;
    let mut closes = 0;
    let mut sq = false;
    let mut dq = false;
    let mut esc = false;
    for ch in line.chars() {
        if esc {
            esc = false;
            continue;
        }
        if ch == '\\' {
            esc = true;
            continue;
        }
        if ch == '\'' && !dq {
            sq = !sq;
            continue;
        }
        if ch == '"' && !sq {
            dq = !dq;
            continue;
        }
        if sq || dq {
            continue;
        }
        if ch == '{' {
            opens += 1;
        } else if ch == '}' {
            closes += 1;
        }
    }
    opens - closes
}

fn extract_sources(globals: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_src = false;
    let mut buf = String::new();
    for line in globals.lines() {
        let t = line.trim();
        if !in_src {
            if t.starts_with("source") && t.contains('=') && t.contains('(') {
                in_src = true;
                if let Some(pos) = t.find('(') {
                    buf.push_str(&t[pos + 1..]);
                    buf.push('\n');
                }
                if t.contains(')') {
                    break;
                }
            }
        } else {
            buf.push_str(line);
            buf.push('\n');
            if t.contains(')') {
                break;
            }
        }
    }
    if in_src {
        let end = buf.find(')').unwrap_or(buf.len());
        let inner = buf[..end].replace(['\n', '\''], " ");
        for part in inner.split_whitespace() {
            let p = part.trim_matches('"').trim();
            if !p.is_empty() {
                out.push(p.to_owned());
            }
        }
    }
    out
}

fn extract_install(globals: &str) -> Option<String> {
    for line in globals.lines() {
        let t = line.trim();
        if t.starts_with("install") && t.contains('=') {
            let v = t.split('=').nth(1).unwrap_or("").trim();
            let v = v.trim_matches(|c| c == '"' || c == '\'').trim();
            if !v.is_empty() {
                return Some(v.to_owned());
            }
        }
    }
    None
}

// Bounded normalize: join continuations, cut comments, squeeze whitespace,
// canonicalize a few known fetch/exec spellings. Data-flow stays in analyzer.
#[must_use]
pub fn normalize(text: &str) -> String {
    let joined = text.replace("\\\n", " ");
    let mut lines: Vec<String> = Vec::new();
    for line in joined.lines() {
        let code = strip_comment(line);
        let collapsed = collapse_ws(code.trim());
        if !collapsed.is_empty() {
            lines.push(collapsed);
        }
    }
    let mut s = lines.join("\n");
    const REPLACEMENTS: &[(&str, &str)] = &[
        ("$'\x63url'", "curl"),
        ("$'\\x63url'", "curl"),
        ("wget2", "wget"),
    ];
    for (from, to) in REPLACEMENTS {
        s = s.replace(from, to);
    }
    s
}

fn strip_comment(line: &str) -> &str {
    let mut sq = false;
    let mut dq = false;
    let bytes = line.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'#' if !sq && !dq => return line[..i].trim_end(),
            _ => {}
        }
    }
    line
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
