//! A file the scan read, re-printed for the report: whole when it's short,
//! else the lines around each thing found in it, and on a very long line
//! (minified code) a window of it, with where each thing is.

use serde::Serialize;

/// A file shown in the report: a page, a script, PHP source, `robots.txt`,
/// an answer the server gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceFile {
    /// Its address, which the signals in it name as their `file`.
    pub url: String,
    /// Its path as the file explorer shows it, `/js/app.js`, or with the
    /// host first for another site's.
    pub name: String,
    /// `html`, `js`, `css`, `php`, `json`, `xml`, `http` or `text`.
    pub kind: &'static str,
    /// The parts of it shown.
    pub sections: Vec<Section>,
}

/// A run of a file's text, starting at `line` (from 1) and, on a line too
/// long to show whole, `col` characters into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    pub line: usize,
    pub col: usize,
    pub text: String,
}

/// Where something is in a file's shown text: in section `section`, `at`
/// characters in, for `len` characters. Characters are UTF-16 code units,
/// as the dashboard counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Mark {
    pub section: usize,
    pub at: usize,
    pub len: usize,
}

/// Shown whole up to this size, line count and line length.
const WHOLE_BYTES: usize = 64 * 1024;
const WHOLE_LINES: usize = 1500;
const LONG_LINE: usize = 400;
/// Lines shown before and after each thing found.
const AROUND: usize = 4;
/// Bytes shown either side of something on a very long line.
const WINDOW: usize = 240;

fn units(s: &str) -> usize {
    s.encode_utf16().count()
}

fn floor(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// The parts of `text` to show for things at byte ranges `spans`, and each
/// one's mark, in order; `None` for a span outside the text.
pub fn show(text: &str, spans: &[(usize, usize)]) -> (Vec<Section>, Vec<Option<Mark>>) {
    let starts: Vec<usize> = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(i, _)| i + 1))
        .collect();
    let line_end = |l: usize| starts.get(l + 1).map_or(text.len(), |s| s - 1);
    let line_of = |b: usize| starts.partition_point(|s| *s <= b) - 1;
    let longest = (0..starts.len())
        .map(|l| line_end(l) - starts[l])
        .max()
        .unwrap_or(0);

    // Byte ranges to show, with the line and column each begins at.
    let mut windows: Vec<(usize, usize, usize, usize)> = Vec::new();
    if text.len() <= WHOLE_BYTES && starts.len() <= WHOLE_LINES && longest <= LONG_LINE {
        windows.push((0, text.len(), 1, 0));
    } else {
        for &(s, e) in spans {
            if s >= text.len() {
                continue;
            }
            let l = line_of(s);
            if line_end(l) - starts[l] <= LONG_LINE {
                let a = l.saturating_sub(AROUND);
                let b = (line_of(e.min(text.len())) + AROUND).min(starts.len() - 1);
                windows.push((starts[a], line_end(b), a + 1, 0));
            } else {
                let from = floor(text, s.saturating_sub(WINDOW).max(starts[l]));
                let to = ceil(text, (e + WINDOW).min(line_end(l)));
                windows.push((from, to, l + 1, units(&text[starts[l]..from])));
            }
        }
        windows.sort_unstable();
    }
    let mut merged: Vec<(usize, usize, usize, usize)> = Vec::new();
    for w in windows {
        match merged.last_mut() {
            Some(last) if w.0 <= last.1 + 1 => last.1 = last.1.max(w.1),
            _ => merged.push(w),
        }
    }
    merged.truncate(60);

    let marks = spans
        .iter()
        .map(|&(s, e)| {
            let i = merged
                .iter()
                .position(|w| w.0 <= s && s < w.1.max(w.0 + 1))?;
            let (from, to, ..) = merged[i];
            let s = floor(text, s);
            let e = ceil(text, e.clamp(s, to));
            Some(Mark {
                section: i,
                at: units(&text[from..s]),
                len: units(&text[s..e]).max(1),
            })
        })
        .collect();
    let sections = merged
        .into_iter()
        .map(|(from, to, line, col)| Section {
            line,
            col,
            text: text[from..to].to_string(),
        })
        .collect();
    (sections, marks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_short_files_whole() {
        let text = "<html>\n<form action=\"/x\">\n</html>";
        let at = text.find("<form").unwrap();
        let (sections, marks) = show(text, &[(at, at + 5)]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].line, 1);
        assert_eq!(
            marks[0],
            Some(Mark {
                section: 0,
                at,
                len: 5
            })
        );
    }

    #[test]
    fn shows_lines_around_in_long_files() {
        let text = (1..=3000)
            .map(|n| format!("line {n}\n"))
            .collect::<String>();
        let at = text.find("line 2000\n").unwrap();
        let (sections, marks) = show(&text, &[(at, at + 9)]);
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].line, 1996);
        assert!(sections[0].text.starts_with("line 1996\n"));
        let m = marks[0].unwrap();
        assert_eq!(&sections[0].text[m.at..m.at + m.len], "line 2000");
    }

    #[test]
    fn shows_a_window_of_minified_code() {
        let text = format!("{}fetch(\"/api\"){}", "a;".repeat(5000), "b;".repeat(5000));
        let at = text.find("fetch").unwrap();
        let (sections, marks) = show(&text, &[(at, at + 5)]);
        assert_eq!(sections[0].line, 1);
        assert!(sections[0].col > 0);
        let m = marks[0].unwrap();
        assert_eq!(&sections[0].text[m.at..m.at + m.len], "fetch");
    }
}
