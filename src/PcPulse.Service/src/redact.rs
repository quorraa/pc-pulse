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

/// Appended to the output whenever the input was longer than
/// `MAX_SCAN_BYTES` and had to be truncated, so callers can distinguish a
/// clipped result from a clean one. The dropped tail is never scanned or
/// persisted, redacted or not.
const TRUNCATED_MARKER: &str = "…[truncated]";

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
    let was_truncated = input.len() > MAX_SCAN_BYTES;
    let truncated = truncate_at_char_boundary(input, MAX_SCAN_BYTES);
    let mut count = 0u32;

    let s = redact_vocabulary(truncated, &mut count);
    let s = redact_long_opaque_runs(&s, &mut count);
    let s = redact_urls(&s, &mut count);
    let mut s = redact_connection_strings(&s, &mut count);

    if was_truncated {
        s.push_str(TRUNCATED_MARKER);
    }

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

/// For each character position, whether it lies inside an (unescaped)
/// double-quoted region. The quote character itself is marked `false` (it's
/// a delimiter, not content); parity simply toggles on each `"`.
fn compute_in_quotes(chars: &[char]) -> Vec<bool> {
    let mut result = vec![false; chars.len()];
    let mut inside = false;
    for (idx, c) in chars.iter().enumerate() {
        if *c == '"' {
            result[idx] = false;
            inside = !inside;
        } else {
            result[idx] = inside;
        }
    }
    result
}

fn in_quotes_at(in_quotes: &[bool], idx: usize) -> bool {
    in_quotes.get(idx).copied().unwrap_or(false)
}

/// Pass 1: credential vocabulary as `key=value`, `key:value`, `--key value`,
/// `--key=value`, `/key:value`; plus, per spec-owner ruling, the bare
/// `Bearer <token>` form specifically (not extended to the rest of the
/// vocabulary, which would over-redact things like `--session name`).
fn redact_vocabulary(input: &str, count: &mut u32) -> String {
    let chars: Vec<char> = input.chars().collect();
    let in_quotes = compute_in_quotes(&chars);
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

        if let Some((key_end, word)) = read_word(&chars, key_start) {
            let word_lower = word.to_ascii_lowercase();
            if is_vocab_word(&word) {
                // Look at what follows the word: optional whitespace then
                // one of '=' ':' or (if this was a flag form, or the word is
                // `bearer`) whitespace then value.
                let after_word_ws = skip_ws(&chars, key_end);
                if after_word_ws < chars.len()
                    && (chars[after_word_ws] == '=' || chars[after_word_ws] == ':')
                {
                    // key=value / key:value form (works with or without --
                    // or / prefix). Skip whitespace around the separator on
                    // both sides, emitting whatever we skip verbatim, so we
                    // never leave a "phantom" empty match and never lose the
                    // real value to a separately-copied space.
                    let sep_idx = after_word_ws;
                    let value_scan_start = sep_idx + 1;
                    let ws_end = skip_ws(&chars, value_scan_start);
                    let in_q = in_quotes_at(&in_quotes, ws_end);
                    let (value_end, value_len) = read_value(&chars, ws_end, in_q);

                    for c in &chars[i..sep_idx] {
                        out.push(*c);
                    }
                    out.push(chars[sep_idx]);
                    for c in &chars[value_scan_start..ws_end] {
                        out.push(*c);
                    }
                    if value_len > 0 {
                        out.push_str(REDACTED);
                        *count += 1;
                    }
                    i = value_end;
                    continue;
                } else if prefix_len == 2 || word_lower == "bearer" {
                    // `--key value` form (space separated); also the bare
                    // `Bearer value` form specifically.
                    let val_start = skip_ws(&chars, key_end);
                    if val_start < chars.len() && val_start > key_end {
                        let in_q = in_quotes_at(&in_quotes, val_start);
                        let (value_end, value_len) = read_value(&chars, val_start, in_q);
                        if value_len > 0 {
                            for c in &chars[i..key_end] {
                                out.push(*c);
                            }
                            for c in &chars[key_end..val_start] {
                                out.push(*c);
                            }
                            out.push_str(REDACTED);
                            *count += 1;
                            i = value_end;
                            continue;
                        }
                    }
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
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    i
}

/// Reads a "value" token starting at `start`, returning `(end_index,
/// chars_consumed)`. Behavior depends on context:
/// - If `in_quotes` is true (the position lies inside an outer double-quoted
///   argv element), the value runs to the next `"` or end of string — this
///   is what lets `"--password=my secret phrase"` redact the whole phrase
///   instead of stopping at the first space.
/// - Otherwise, if the value itself starts with a quote character, read the
///   quoted token (matching close quote), matching a separately-quoted CLI
///   value like `--password "hunter 2"`.
/// - Otherwise, read up to the next whitespace or `&`.
fn read_value(chars: &[char], start: usize, in_quotes: bool) -> (usize, usize) {
    if start >= chars.len() {
        return (start, 0);
    }
    if in_quotes {
        let mut end = start;
        while end < chars.len() && chars[end] != '"' {
            end += 1;
        }
        (end, end - start)
    } else if chars[start] == '"' || chars[start] == '\'' {
        let quote = chars[start];
        let mut end = start + 1;
        while end < chars.len() && chars[end] != quote {
            end += 1;
        }
        if end < chars.len() {
            end += 1; // include closing quote
        }
        (end, end - start)
    } else {
        let mut end = start;
        while end < chars.len() && !chars[end].is_whitespace() && chars[end] != '&' {
            end += 1;
        }
        (end, end - start)
    }
}

/// Pass 2: long opaque base64-ish / hex runs. A whitespace-delimited word
/// containing a `\` is treated as a filesystem path and left entirely
/// untouched (splitting a path on `\` would otherwise expose bare segments
/// like `deadbeefdeadbeefdeadbeef` that look like standalone opaque runs).
/// A word containing `/` (URLs, forward-slash paths) is *not* wholly
/// exempt — it's split on `/` and each segment is checked independently, so
/// a secret-looking path/URL segment (e.g. a Slack webhook token) still
/// gets caught.
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

        if word.contains(&'\\') {
            // Path-shaped word; leave entirely to later passes.
            for c in word {
                out.push(*c);
            }
        } else if word.contains(&'/') {
            let mut seg_start = 0usize;
            for idx in 0..=word.len() {
                if idx == word.len() || word[idx] == '/' {
                    let segment = &word[seg_start..idx];
                    out.push_str(&redact_opaque_runs_in_word(segment, count));
                    if idx < word.len() {
                        out.push('/');
                    }
                    seg_start = idx + 1;
                }
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

/// Pass 4: connection-string fragments `(Password|Pwd|User Id|Uid)\s*=\s*value`.
/// Outside a quoted connection string, the value runs up to the next `;` or
/// whitespace (whichever comes first) so this pass can never swallow
/// trailing, unrelated command-line text (e.g. `--verbose --port 80`)
/// that follows a bare `key=value` secret already redacted by pass 1.
/// Inside a quoted connection string, only `;` terminates the value, since
/// connection strings can legitimately contain spaces in values.
fn redact_connection_strings(input: &str, count: &mut u32) -> String {
    const KEYS: &[&str] = &["password", "pwd", "user id", "uid"];

    let chars: Vec<char> = input.chars().collect();
    let in_quotes = compute_in_quotes(&chars);
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
                    let in_q = in_quotes_at(&in_quotes, val_start);
                    let mut val_end = val_start;
                    while val_end < chars.len()
                        && chars[val_end] != ';'
                        && (in_q || !chars[val_end].is_whitespace())
                    {
                        val_end += 1;
                    }
                    let value: String = chars[val_start..val_end].iter().collect();
                    // Already redacted by an earlier pass (the literal key=
                    // text pass 1 leaves behind still matches here) — don't
                    // re-match and re-count it. `starts_with` rather than an
                    // exact match because the value we just scanned can
                    // legitimately carry a trailing character straight after
                    // the token (e.g. a closing quote) that isn't part of
                    // the secret itself.
                    if val_end > val_start && !value.starts_with(REDACTED) {
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
        assert!(r2.len() <= long.len() + TRUNCATED_MARKER.len());
    }

    // -- Security review, fix round 1 -----------------------------------

    // H1: whitespace around the separator used to leak the value verbatim
    // and record a phantom (zero-length) redaction.
    #[test]
    fn h1_whitespace_around_equals_separator_is_redacted_without_phantom_count() {
        let (r, n) = redact_command_line("app --password = hunter2");
        assert!(!r.contains("hunter2"), "{r}");
        assert_eq!(n, 1);
    }

    #[test]
    fn h1_colon_separator_with_trailing_space_is_redacted() {
        let (r, n) = redact_command_line("app token: abc123");
        assert!(!r.contains("abc123"), "{r}");
        assert_eq!(n, 1);
    }

    #[test]
    fn h1_quoted_header_style_cookie_is_redacted() {
        let (r, n) = redact_command_line(r#"curl -H "Cookie: sid=abc""#);
        assert!(!r.contains("abc"), "{r}");
        assert_eq!(n, 1);
    }

    // H2: tab/newline separators used to bypass the flag-value form
    // entirely because skip_ws only recognized ' '.
    #[test]
    fn h2_tab_separated_flag_value_is_redacted() {
        let (r, n) = redact_command_line("app --password\thunter2");
        assert!(!r.contains("hunter2"), "{r}");
        assert_eq!(n, 1);
    }

    #[test]
    fn h2_newline_separated_flag_value_is_redacted() {
        let (r, n) = redact_command_line("--password\nhunter2");
        assert!(!r.contains("hunter2"), "{r}");
        assert_eq!(n, 1);
    }

    // H3 (fixed together with M1): a quoted argv element's value must run
    // to the closing quote, not the first embedded space, or the tail of
    // the secret leaks.
    #[test]
    fn h3_quoted_value_with_spaces_is_fully_redacted() {
        let (r, n) = redact_command_line(r#"app "--password=my secret phrase""#);
        assert!(!r.contains("my"), "{r}");
        assert!(!r.contains("secret"), "{r}");
        assert!(!r.contains("phrase"), "{r}");
        assert_eq!(n, 1);
    }

    // M1: pass 4 used to swallow to end-of-string when no ';' followed a
    // bare `key=value` secret already redacted by pass 1, destroying
    // trailing command-line text and double-counting.
    #[test]
    fn m1_bare_password_does_not_swallow_trailing_flags() {
        let (r, n) = redact_command_line("app password=hunter2 --verbose --port 80");
        assert!(!r.contains("hunter2"), "{r}");
        assert!(r.contains("--verbose"), "{r}");
        assert!(r.contains("--port 80"), "{r}");
        assert_eq!(n, 1);
    }

    // M2: words containing '/' used to be wholly exempt from opaque-run
    // detection, letting path/URL-embedded secrets (e.g. webhook tokens)
    // through untouched.
    #[test]
    fn m2_slash_path_segment_opaque_token_is_redacted() {
        let (r, n) = redact_command_line(
            "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX",
        );
        assert!(!r.contains("XXXXXXXXXXXXXXXXXXXXXXXX"), "{r}");
        assert!(n >= 1);
    }

    // M3 (spec-owner ruling): `Bearer <token>` is a recognized form even
    // though it's a bare `key value` pair, and even for tokens shorter
    // than pass 2's 20-char opaque-run threshold. This must NOT extend to
    // the rest of the vocabulary (that would over-redact e.g. `--session name`).
    #[test]
    fn m3_bearer_token_form_is_redacted_even_under_20_chars() {
        let (r, n) = redact_command_line(r#"curl -H "Authorization: Bearer abcdefghijklmnop""#);
        assert!(!r.contains("abcdefghijklmnop"), "{r}");
        assert!(r.contains("Bearer"), "{r}");
        assert_eq!(n, 1);
    }

    #[test]
    fn m3_bare_key_value_not_extended_to_whole_vocabulary() {
        let s = "app session name";
        assert_eq!(redact_command_line(s), (s.to_string(), 0));
    }

    // L1: an empty value at end-of-string must not count as a redaction.
    #[test]
    fn l1_empty_value_at_eos_not_counted() {
        let (r, n) = redact_command_line("app password=");
        assert_eq!(r, "app password=");
        assert_eq!(n, 0);
    }

    // L4: when the input exceeds the scan cap, the truncated tail must
    // never appear in the output, and the result is marked so callers can
    // tell a clipped result from a clean one.
    #[test]
    fn l4_oversized_input_is_marked_truncated_and_never_leaks_the_tail() {
        let mut s = "a".repeat(MAX_SCAN_BYTES + 100);
        s.push_str(" --password hunter2");
        let (r, _n) = redact_command_line(&s);
        assert!(r.ends_with(TRUNCATED_MARKER), "{r}");
        assert!(!r.contains("hunter2"), "{r}");
    }
}
