//! `--help`, as `tool_help` in `src/tool_help.c` shows it.

use std::io::Write as _;

use crate::msgs::MANUAL;
use crate::options::{CATEGORIES, HELP, HelpLine};

/// Show the help for `topic`: the default page without one, every option
/// for `all`, the list of categories for `category`, or one category.
/// `columns` is the terminal's width.
pub(crate) fn show(topic: Option<&[u8]>, columns: usize) {
    let mut out = Out::new();
    match topic {
        None => {
            out.line(b"Usage: curl [options...] <url>");
            print_category(&mut out, Some("important"), columns);
            out.line(
                b"\nThis is not the full help; this menu is split into categories.\n\
                  Use \"--help category\" to get an overview of all categories, which are:",
            );
            categories_list(&mut out, columns);
            out.line(if MANUAL {
                b"Use \"--help all\" to list all options\n\
                  Use \"--help [option]\" to view documentation for a given option"
            } else {
                b"Use \"--help all\" to list all options"
            });
        }
        Some(topic) if topic.eq_ignore_ascii_case(b"all") => {
            print_category(&mut out, None, columns)
        }
        Some(topic) if topic.eq_ignore_ascii_case(b"category") => categories(&mut out),
        Some(topic) if topic.first() == Some(&b'-') => {
            // Help on one option is read from the built-in manual.
            out.flush();
            let _ = std::io::stderr()
                .write_all(b"Cannot comply. This curl was built without built-in manual\n");
        }
        Some(topic) => match CATEGORIES
            .iter()
            .find(|(name, _)| topic.eq_ignore_ascii_case(name.as_bytes()))
        {
            Some((name, desc)) => {
                out.parts(&[name.as_bytes(), b": ", desc.as_bytes(), b"\n"]);
                print_category(&mut out, Some(name), columns);
            }
            None => {
                out.line(b"Unknown category provided, here is a list of all categories:\n");
                categories(&mut out);
            }
        },
    }
    out.flush();
}

/// `print_category`: the lines of one category, or of all, with the
/// option column as wide as the widest option unless the descriptions
/// would then wrap.
fn print_category(out: &mut Out, category: Option<&str>, columns: usize) {
    let lines = || {
        HELP.iter()
            .filter(|l| category.is_none_or(|c| l.categories.contains(&c)))
    };
    let widest = |f: fn(&HelpLine) -> usize| lines().map(f).max().unwrap_or(0).max(5);
    let mut opt_width = widest(|l| l.opt.len());
    let desc_width = widest(|l| l.desc.len());
    if desc_width > columns {
        opt_width = 0;
    } else if opt_width + desc_width > columns {
        opt_width = columns - desc_width;
    }
    for line in lines() {
        let mut width = opt_width;
        let desc = line.desc.len();
        if columns >= 2 && width + desc >= columns - 2 {
            width = if desc < columns - 2 {
                columns - 3 - desc
            } else {
                0
            };
        }
        let pad = width.saturating_sub(line.opt.len());
        out.parts(&[b" ", line.opt.as_bytes()]);
        out.spaces(pad + 2);
        out.parts(&[line.desc.as_bytes(), b"\n"]);
    }
}

/// `get_categories`: each category and its description.
fn categories(out: &mut Out) {
    for (name, desc) in CATEGORIES {
        out.parts(&[b" ", name.as_bytes()]);
        out.spaces(11usize.saturating_sub(name.len()) + 1);
        out.parts(&[desc.as_bytes(), b"\n"]);
    }
}

/// `get_categories_list`: the categories, comma-separated, filling lines
/// of `width`.
fn categories_list(out: &mut Out, width: usize) {
    let mut col = 0;
    for (i, (name, _)) in CATEGORIES.iter().enumerate() {
        let len = name.len();
        if i == CATEGORIES.len() - 1 {
            let lead: &[u8] = if col + len + 1 < width { b"" } else { b"\n" };
            out.parts(&[lead, name.as_bytes(), b".\n"]);
        } else if col + len + 2 < width {
            out.parts(&[name.as_bytes(), b", "]);
            col += len + 2;
        } else {
            out.parts(&[b"\n", name.as_bytes(), b", "]);
            col = len + 2;
        }
    }
}

/// Standard output, written in chunks from a stack buffer. A failed write
/// (a closed pipe) has nowhere to be reported, as in C.
struct Out {
    buf: [u8; 4096],
    len: usize,
}

impl Out {
    fn new() -> Self {
        Out {
            buf: [0; 4096],
            len: 0,
        }
    }

    fn parts(&mut self, parts: &[&[u8]]) {
        for part in parts {
            for chunk in part.chunks(self.buf.len()) {
                if self.len + chunk.len() > self.buf.len() {
                    self.flush();
                }
                self.buf[self.len..self.len + chunk.len()].copy_from_slice(chunk);
                self.len += chunk.len();
            }
        }
    }

    /// `puts`: the text and a newline.
    fn line(&mut self, text: &[u8]) {
        self.parts(&[text, b"\n"]);
    }

    fn spaces(&mut self, n: usize) {
        for _ in 0..n {
            self.parts(&[b" "]);
        }
    }

    fn flush(&mut self) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(&self.buf[..self.len]);
        let _ = stdout.flush();
        self.len = 0;
    }
}
