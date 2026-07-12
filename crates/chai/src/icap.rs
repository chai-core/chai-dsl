//! ICAP server (feature = `icap`). RFC 3507 REQMOD + RESPMOD, std-only, blocking.
//!
//! ICAP is the standard way an HTTP proxy delegates content adaptation to an
//! external service. ext-authz only does allow/deny. ICAP can REWRITE the
//! message body, so this is the surface that carries our redaction through the
//! existing proxy ecosystem (Squid, enterprise DLP gateways).
//!
//!   * REQMOD inspects the encapsulated HTTP request (e.g. an MCP `tools/call`
//!     body) and returns allow (204) or block (200 + a 403 response).
//!   * RESPMOD inspects the encapsulated HTTP response body (a tool result) and
//!     returns it governed (emit verbatim / redacted / blocked).
//!
//! Scope is non-preview REQMOD/RESPMOD with chunked bodies, plus OPTIONS.
//! Preview/ieof/trailers are not handled. Known limitation.

use crate::afc::Afc;
use chai_core::ast::ChaiProgram;
use chai_core::emission::EmitAction;
use chai_core::entity::EntityStore;
use crate::mcp::{filter_tool_result, AgentSubject};
use crate::mcp_contract::{gate_intercepted_body, GateVerdict};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

const ISTAG: &str = "\"chai-1\"";

/// Cap on any single wire-driven allocation (header section or chunked body), so
/// attacker-controlled `Encapsulated:` offsets and chunk sizes cannot force a
/// memory-exhaustion allocation before the read fails.
const MAX_ICAP_SECTION: usize = 8 * 1024 * 1024;

pub struct IcapState {
    pub program: ChaiProgram,
    pub store: EntityStore,
    pub afc: Afc,
}

/// Serve ICAP on `addr`. Blocking, one thread per connection.
pub fn serve(addr: &str, state: Arc<IcapState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("Chai ICAP server on icap://{addr}/  (reqmod, respmod)");
    for stream in listener.incoming().flatten() {
        let st = state.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &st);
        });
    }
    Ok(())
}

fn handle(stream: TcpStream, state: &IcapState) -> std::io::Result<()> {
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);

    // ICAP request line and headers. CRLF-terminated, blank line ends the block.
    let mut head: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Ok(()); // connection closed
        }
        let t = line.trim_end_matches(['\r', '\n']);
        if t.is_empty() {
            break;
        }
        head.push(t.to_string());
    }
    if head.is_empty() {
        return Ok(());
    }
    let method = head[0].split_whitespace().next().unwrap_or("").to_uppercase();
    let encapsulated = head
        .iter()
        .find_map(|h| h.strip_prefix("Encapsulated:").or_else(|| h.strip_prefix("encapsulated:")))
        .map(parse_encapsulated)
        .unwrap_or_default();

    match method.as_str() {
        "OPTIONS" => write_options(&mut w),
        "REQMOD" => {
            let (_hdr, body) = read_encapsulated(&mut r, &encapsulated, &["req-hdr"], "req-body")?;
            reqmod(&mut w, state, &body)
        }
        "RESPMOD" => {
            let (_hdr, body) = read_encapsulated(&mut r, &encapsulated, &["req-hdr", "res-hdr"], "res-body")?;
            respmod(&mut w, state, &body)
        }
        _ => write_status(&mut w, "405 Method Not Allowed"),
    }
}

/// Parse `Encapsulated: req-hdr=0, req-body=44` into [("req-hdr",0),("req-body",44)].
fn parse_encapsulated(v: &str) -> Vec<(String, usize)> {
    v.split(',')
        .filter_map(|p| {
            let (k, off) = p.trim().split_once('=')?;
            Some((k.trim().to_string(), off.trim().parse().ok()?))
        })
        .collect()
}

/// Read the encapsulated payload. Header sections are raw bytes, length is the
/// gap to the next offset. Then the named body section (chunked). Returns
/// (concatenated header bytes, body bytes). A `null-body` or absent body gives
/// empty.
fn read_encapsulated(
    r: &mut impl BufRead,
    enc: &[(String, usize)],
    hdr_names: &[&str],
    body_name: &str,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut hdr = Vec::new();
    // Header sections are raw bytes spanning [offset, next_offset).
    for i in 0..enc.len() {
        let (name, off) = &enc[i];
        if hdr_names.contains(&name.as_str()) {
            let end = enc.get(i + 1).map(|(_, o)| *o).unwrap_or(*off);
            let span = end.saturating_sub(*off);
            // Offsets are attacker-controlled wire data; cap the allocation so a
            // bogus Encapsulated header cannot force a huge zero-fill (DoS).
            if span > MAX_ICAP_SECTION {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ICAP header section exceeds cap"));
            }
            let mut buf = vec![0u8; span];
            r.read_exact(&mut buf)?;
            hdr.extend_from_slice(&buf);
        }
    }
    let body = if enc.iter().any(|(n, _)| n == body_name) {
        read_chunked(r)?
    } else {
        Vec::new()
    };
    Ok((hdr, body))
}

/// Read an HTTP/1.1 chunked body to completion.
fn read_chunked(r: &mut impl BufRead) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut size_line = String::new();
        if r.read_line(&mut size_line)? == 0 {
            break;
        }
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 {
            // Consume trailing CRLF and any trailers up to the blank line.
            let mut t = String::new();
            let _ = r.read_line(&mut t);
            break;
        }
        // Cap per-chunk and cumulative size against attacker-controlled lengths.
        if size > MAX_ICAP_SECTION || out.len().saturating_add(size) > MAX_ICAP_SECTION {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ICAP body exceeds cap"));
        }
        let mut buf = vec![0u8; size];
        r.read_exact(&mut buf)?;
        out.extend_from_slice(&buf);
        let mut crlf = String::new();
        let _ = r.read_line(&mut crlf); // CRLF after the chunk
    }
    Ok(out)
}

fn write_chunked(w: &mut impl Write, body: &[u8]) -> std::io::Result<Vec<u8>> {
    // Returns the on-wire bytes so we can compute the Encapsulated offset.
    let mut buf = Vec::new();
    if !body.is_empty() {
        buf.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        buf.extend_from_slice(body);
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"0\r\n\r\n");
    w.write_all(&buf)?;
    Ok(buf)
}

// REQMOD: authorize the request body (an MCP tools/call).
fn reqmod(w: &mut impl Write, state: &IcapState, body: &[u8]) -> std::io::Result<()> {
    // Gate only tool calls (including batched ones). Other MCP plumbing passes
    // through. Fail-closed via the shared gate.
    let subject = AgentSubject::new("Agent::anonymous");
    let allow = !matches!(
        gate_intercepted_body(&state.program, &state.store, &subject, body),
        GateVerdict::Deny
    );
    if allow {
        // 204 means no modification. Forward the request unchanged.
        write_status(w, "204 No Content")
    } else {
        // Block. Return a 403 HTTP response for the proxy to serve.
        let resp_hdr = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n";
        let resp_body = b"blocked by Chai policy";
        w.write_all(b"ICAP/1.0 200 OK\r\n")?;
        w.write_all(format!("ISTag: {ISTAG}\r\n").as_bytes())?;
        w.write_all(format!("Encapsulated: res-hdr=0, res-body={}\r\n\r\n", resp_hdr.len()).as_bytes())?;
        w.write_all(resp_hdr)?;
        write_chunked(w, resp_body)?;
        Ok(())
    }
}

// RESPMOD: govern or redact the response body (a tool result).
fn respmod(w: &mut impl Write, state: &IcapState, body: &[u8]) -> std::io::Result<()> {
    let text = String::from_utf8_lossy(body);
    let subject = AgentSubject::new("Agent::anonymous");
    let rd = filter_tool_result(&state.program, &state.store, &state.afc, &subject, "mcp", &text);
    let governed: Vec<u8> = match rd.action {
        EmitAction::Emit(s) | EmitAction::Redact(s) => s.into_bytes(),
        // Withheld. Serve a blocked body.
        EmitAction::Drop | EmitAction::Buffer | EmitAction::RequireHuman => b"[withheld by Chai policy]".to_vec(),
    };
    let resp_hdr = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    w.write_all(b"ICAP/1.0 200 OK\r\n")?;
    w.write_all(format!("ISTag: {ISTAG}\r\n").as_bytes())?;
    w.write_all(format!("Encapsulated: res-hdr=0, res-body={}\r\n\r\n", resp_hdr.len()).as_bytes())?;
    w.write_all(resp_hdr)?;
    write_chunked(w, &governed)?;
    Ok(())
}

fn write_options(w: &mut impl Write) -> std::io::Result<()> {
    w.write_all(b"ICAP/1.0 200 OK\r\n")?;
    w.write_all(b"Methods: REQMOD, RESPMOD\r\n")?;
    w.write_all(format!("ISTag: {ISTAG}\r\n").as_bytes())?;
    w.write_all(b"Allow: 204\r\n")?;
    w.write_all(b"Encapsulated: null-body=0\r\n\r\n")?;
    Ok(())
}

fn write_status(w: &mut impl Write, status: &str) -> std::io::Result<()> {
    w.write_all(format!("ICAP/1.0 {status}\r\n").as_bytes())?;
    w.write_all(format!("ISTag: {ISTAG}\r\n\r\n").as_bytes())?;
    Ok(())
}
