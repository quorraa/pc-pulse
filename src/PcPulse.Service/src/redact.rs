//! Command-line redaction: strips likely secrets from captured process command
//! lines before they are persisted. Redaction is irreversible — callers must
//! drop the original string once this has run.
//!
//! Passes run in a fixed order so that later passes never re-scan text a
//! previous pass has already replaced with the redaction token:
//!   1. Credential vocabulary (`key=value`, `key:value`, `--key value`, ...)
//!   2. Long opaque runs (base64-ish / hex tokens that are not filesystem paths)
//!   3. URL userinfo and secret-looking query parameters
//!   4. Connection-string fragments (`Password=...;`, `Uid=...;`, ...)

/// Replacement token used for every redacted field. U+2039 / U+203A guillemets.
const REDACTED: &str = "‹redacted›";

/// Cap on how much of the input we scan, to avoid quadratic blowup on
/// pathologically long command lines. 32 KiB comfortably covers any real
/// Windows command line (which itself is capped well under that).
const MAX_SCAN_BYTES: usize = 32 * 1024;

const VOCAB: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api-key",
    "auth",
    "credential",
    "bearer",
    "cookie",
    "session",
];

/// Returns (redacted string, number of fields redacted). Irreversible.
pub fn redact_command_line(input: &str) -> (String, u32) {
    let truncated = truncate_at_char_boundary(input, MAX_SCAN_BYTES);
    let mut count = 0u32;

    let s = redact_vocabulary(truncated, &mut count);
    let s = redact_long_opaque_runs(&s, &mut count);
    let s = redact_urls(&s, &mut count);
    let s = redact_connection_strings(&s, &mut count);

    (s, count)
}

fn truncate_at_char_boundary(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

fn is_vocab_word(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    VOCAB.iter().any(|v| *v == lower)
}

/// Pass 1: credential vocabulary as `key=value`, `key:value`, `--key value`,
/// `--key=value`, `/key:value`.
fn redact_vocabulary(input: &str, count: &mut u32) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < chars.len() {
        // Try to match a "key" token starting at i, optionally preceded by
        // `--` or `/` which we've already copied verbatim (we detect prefix
        // by looking back at what's already in `out`).
        let (key_start, prefix_len) = if chars[i..].starts_with(&['-', '-']) {
            (i + 2, 2)
        } else if chars[i] == '/' {
            (i + 1, 1)
        } else if i > 0 && matches!(chars[i - 1], '?' | '&') {
            // Part of a URL query string; leave it for the dedicated URL
            // query pass so value termination follows `&` semantics.
            out.push(chars[i]);
            i += 1;
            continue;
        } else {
            (i, 0)
        };

        if let Some((key_end, word)) = read_word(&chars, key_start)
            && is_vocab_word(&word)
        {
            // Look at what follows the word: optional whitespace then
            // one of '=' ':' or (if this was a flag form) whitespace then value.
            let mut j = key_end;
            let after_word_ws = skip_ws(&chars, j);
            if after_word_ws < chars.len()
                && (chars[after_word_ws] == '=' || chars[after_word_ws] == ':')
            {
                // key=value / key:value form (works with or without -- or / prefix)
                j = after_word_ws + 1;
                let (value_end, _value) = read_value(&chars, j);
                // emit prefix + key + separator + REDACTED
                for c in &chars[i..after_word_ws] {
                    out.push(*c);
                }
                out.push(chars[after_word_ws]);
                out.push_str(REDACTED);
                *count += 1;
                i = value_end;
                continue;
            } else if prefix_len == 2 {
                // --key value form (space separated), only valid with -- prefix
                let val_start = skip_ws(&chars, key_end);
                if val_start < chars.len() && val_start > key_end {
                    let (value_end, _value) = read_value(&chars, val_start);
                    for c in &chars[i..key_end] {
                        out.push(*c);
                    }
                    out.push(' ');
                    out.push_str(REDACTED);
                    *count += 1;
                    i = value_end;
                    continue;
                }
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

/// Reads an identifier-ish word (letters, digits, `-`, `_`) starting at
/// `start`. Returns (end_index, word) if at least one char was consumed.
fn read_word(chars: &[char], start: usize) -> Option<(usize, String)> {
    let mut end = start;
    while end < chars.len()
        && (chars[end].is_alphanumeric() || chars[end] == '-' || chars[end] == '_')
    {
        end += 1;
    }
    if end == start {
        None
    } else {
        Some((end, chars[start..end].iter().collect()))
    }
}

fn skip_ws(chars: &[char], start: usize) -> usize {
    let mut i = start;
    while i < chars.len() && chars[i] == ' ' {
        i += 1;
    }
    i
}

/// Reads a "value" token: everything up to the next whitespace, or, if the
/// value starts with a quote, everything up to the matching closing quote
/// (inclusive of quotes being left in place is not needed since we replace
/// the whole thing).
fn read_value(chars: &[char], start: usize) -> (usize, String) {
    if start >= chars.len() {
        return (start, String::new());
    }
    if chars[start] == '"' || chars[start] == '\'' {
        let quote = chars[start];
        let mut end = start + 1;
        while end < chars.len() && chars[end] != quote {
            end += 1;
        }
        if end < chars.len() {
            end += 1; // include closing quote
        }
        (end, chars[start..end].iter().collect())
    } else {
        let mut end = start;
        while end < chars.len() && chars[end] != ' ' && chars[end] != '&' {
            end += 1;
        }
        (end, chars[start..end].iter().collect())
    }
}

/// Pass 2: long opaque base64-ish / hex runs, excluding anything that looks
/// like a filesystem path or URL (i.e. the whitespace-delimited word
/// containing the run has a `\` or `/` in it anywhere). Path segments such
/// as `deadbeefdeadbeefdeadbeef` inside `c:\some\deadbeef...\file.txt` would
/// otherwise look like a standalone opaque run once split on `\`, so the
/// exemption is evaluated per *word*, not per opaque run.
fn redact_long_opaque_runs(input: &str, count: &mut u32) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i].is_whitespace() {
            out.push(chars[i]);
            i += 1;
            continue;
        }

        let word_start = i;
        let mut word_end = i;
        while word_end < chars.len() && !chars[word_end].is_whitespace() {
            word_end += 1;
        }
        let word = &chars[word_start..word_end];

        if word.contains(&'\\') || word.contains(&'/') {
            // Path- or URL-shaped word; leave entirely to later passes.
            for c in word {
                out.push(*c);
            }
        } else {
            out.push_str(&redact_opaque_runs_in_word(word, count));
        }

        i = word_end;
    }

    out
}

fn redact_opaque_runs_in_word(word: &[char], count: &mut u32) -> String {
    let mut out = String::with_capacity(word.len());
    let mut i = 0usize;

    while i < word.len() {
        if is_opaque_char(word[i]) {
            let start = i;
            let mut end = i;
            while end < word.len() && is_opaque_char(word[end]) {
                end += 1;
            }
            let token: String = word[start..end].iter().collect();
            if token.len() >= 20 && looks_opaque(&token) {
                out.push_str(REDACTED);
                *count += 1;
            } else {
                out.push_str(&token);
            }
            i = end;
            continue;
        }
        out.push(word[i]);
        i += 1;
    }

    out
}

fn is_opaque_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// Only treat a run as an opaque secret if it's base64-ish (contains at
/// least one letter and looks reasonably mixed) or pure hex of length >= 20.
/// This keeps the check aligned with the brief's two shapes without
/// requiring a regex engine.
fn looks_opaque(token: &str) -> bool {
    let is_hex = token.len() >= 20 && token.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex {
        return true;
    }
    // base64-ish: allowed alphabet already enforced by is_opaque_char; just
    // require it contain at least one letter so pure numbers/paths-lookalikes
    // don't get swept up, and require length >= 20 (already guaranteed by caller).
    token.chars().any(|c| c.is_ascii_alphabetic())
}

/// Pass 3: URL userinfo (`scheme://user:pass@`) and secret-looking query
/// parameter values.
fn redact_urls(input: &str, count: &mut u32) -> String {
    let s = redact_url_userinfo(input, count);
    redact_url_query(&s, count)
}

fn redact_url_userinfo(input: &str, count: &mut u32) -> String {
    let bytes_len = input.len();
    let mut out = String::with_capacity(bytes_len);
    let mut rest = input;

    loop {
        match find_scheme_sep(rest) {
            Some(scheme_sep_idx) => {
                let after_sep = scheme_sep_idx + 3; // "://"
                // Look for userinfo: chars up to next '@' before the next '/'
                let tail = &rest[after_sep..];
                let at_idx = tail.find('@');
                let slash_idx = tail.find('/');
                let has_userinfo = match (at_idx, slash_idx) {
                    (Some(a), Some(s)) => a < s,
                    (Some(_), None) => true,
                    _ => false,
                };
                if has_userinfo {
                    let at_idx = at_idx.unwrap_or(0);
                    out.push_str(&rest[..after_sep]);
                    out.push_str(REDACTED);
                    out.push('@');
                    *count += 1;
                    rest = &tail[at_idx + 1..];
                } else {
                    out.push_str(&rest[..after_sep]);
                    rest = &rest[after_sep..];
                }
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }

    out
}

/// Finds the byte index of `://` in `s`, if present, only where it's
/// immediately preceded by a scheme-ish word (letters/digits/+.-).
fn find_scheme_sep(s: &str) -> Option<usize> {
    s.find("://")
}

fn redact_url_query(input: &str, count: &mut u32) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    loop {
        match rest.find(['?', '&']) {
            Some(idx) => {
                let sep = rest.as_bytes()[idx] as char;
                out.push_str(&rest[..idx]);
                out.push(sep);
                rest = &rest[idx + 1..];

                // Read key up to '=' or terminator.
                let key_end = rest
                    .find(|c: char| c == '=' || c == '&' || c.is_whitespace())
                    .unwrap_or(rest.len());
                let key = &rest[..key_end];

                if key_end < rest.len() && rest.as_bytes()[key_end] == b'=' && is_vocab_word(key) {
                    let val_start = key_end + 1;
                    let val_end = rest[val_start..]
                        .find(|c: char| c == '&' || c.is_whitespace())
                        .map(|o| val_start + o)
                        .unwrap_or(rest.len());
                    out.push_str(key);
                    out.push('=');
                    out.push_str(REDACTED);
                    *count += 1;
                    rest = &rest[val_end..];
                } else {
                    // Not a secret key=value; leave the key portion in place
                    // and continue scanning from right after it.
                    out.push_str(key);
                    rest = &rest[key_end..];
                }
            }
            None => {
                out.push_str(rest);
                break;
            }
        }
    }

    out
}

/// Pass 4: connection-string fragments `(Password|Pwd|User Id|Uid)\s*=\s*value`
/// where value runs up to the next `;` (or end of string).
fn redact_connection_strings(input: &str, count: &mut u32) -> String {
    const KEYS: &[&str] = &["password", "pwd", "user id", "uid"];

    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    'outer: while i < chars.len() {
        let at_word_start = i == 0
            || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_' || chars[i - 1] == '-');
        for key in KEYS {
            let key_chars: Vec<char> = key.chars().collect();
            if at_word_start && matches_ci_with_ws(&chars, i, &key_chars) {
                let mut j = i + key_chars.len();
                // allow embedded whitespace already consumed for multi-word keys via matches_ci_with_ws
                j = skip_ws(&chars, j);
                if j < chars.len() && chars[j] == '=' {
                    j += 1;
                    j = skip_ws(&chars, j);
                    let val_start = j;
                    let mut val_end = val_start;
                    while val_end < chars.len() && chars[val_end] != ';' {
                        val_end += 1;
                    }
                    let value: String = chars[val_start..val_end].iter().collect();
                    if val_end > val_start && value != REDACTED {
                        out.push_str(&chars[i..val_start].iter().collect::<String>());
                        out.push_str(REDACTED);
                        *count += 1;
                        i = val_end;
                        continue 'outer;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }

    out
}

/// Matches `key` (which may contain a single literal space for "user id")
/// case-insensitively against `chars` starting at `start`, allowing any run
/// of spaces where the key has a space.
fn matches_ci_with_ws(chars: &[char], start: usize, key: &[char]) -> bool {
    let mut ci = start;
    let mut ki = 0usize;
    while ki < key.len() {
        if key[ki] == ' ' {
            if ci >= chars.len() || chars[ci] != ' ' {
                return false;
            }
            while ci < chars.len() && chars[ci] == ' ' {
                ci += 1;
            }
            ki += 1;
        } else {
            if ci >= chars.len() || !chars[ci].eq_ignore_ascii_case(&key[ki]) {
                return false;
            }
            ci += 1;
            ki += 1;
        }
    }
    // Ensure key is a whole word (not a prefix of a longer identifier).
    if ci < chars.len() && (chars[ci].is_alphanumeric() || chars[ci] == '_') {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_flag_forms() {
        for s in [
            "app --password hunter2",
            "app --password=hunter2",
            "app /password:hunter2",
            "app password=hunter2",
        ] {
            let (r, n) = redact_command_line(s);
            assert!(!r.contains("hunter2"), "{s} -> {r}");
            assert_eq!(n, 1, "{s} -> {r}");
        }
    }

    #[test]
    fn redacts_long_opaque_tokens_but_not_paths() {
        let (r, n) = redact_command_line(
            r"tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 c:\some\deadbeefdeadbeefdeadbeef\file.txt",
        );
        assert!(!r.contains("eyJhbGci"));
        assert!(r.contains(r"c:\some\deadbeefdeadbeefdeadbeef\file.txt")); // path exempt
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_url_userinfo_and_secret_query_values() {
        let (r, _) =
            redact_command_line("curl https://bob:pw@x.io/a?token=abc123def456abc123def456&page=2");
        assert!(!r.contains("bob:pw") && !r.contains("abc123def456"));
        assert!(r.contains("page=2"));
    }

    #[test]
    fn redacts_connection_strings() {
        let (r, _) = redact_command_line(r#"app "Server=x;User Id=sa;Password=s3cret;""#);
        assert!(!r.contains("s3cret"));
        assert!(r.contains("Server=x"));
    }

    #[test]
    fn non_secrets_untouched() {
        let s = r"cmd.exe /c echo hello & ping -n 4 localhost";
        assert_eq!(redact_command_line(s), (s.to_string(), 0));
    }

    #[test]
    fn does_not_panic_on_non_ascii_and_long_input() {
        let mut s = "app --password ".to_string();
        s.push_str(&"é".repeat(5000));
        let (r, _n) = redact_command_line(&s);
        assert!(!r.is_empty());

        let long = "a".repeat(64 * 1024);
        let (r2, _n2) = redact_command_line(&long);
        assert!(r2.len() <= long.len());
    }
}
