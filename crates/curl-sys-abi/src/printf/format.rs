//! The format engine of libcurl's `curl_m*printf` family.
//!
//! A port of `lib/mprintf.c`, whose output is part of the ABI: parsing
//! first types every argument (positional `%N$` ones included), then
//! rendering writes each segment to a [`Sink`]. Reading the arguments,
//! the strings they point to and formatting doubles is up to the caller's
//! [`Args`], which is where the unsafe code lives.

#![forbid(unsafe_code)]

/// The most arguments a format may use.
pub(crate) const MAX_PARAMETERS: usize = 128;
/// The most output segments a format may have.
const MAX_SEGMENTS: usize = 128;
/// Room for a formatted double: negative `DBL_MAX` is 317 characters.
pub(crate) const BUFFSIZE: usize = 326;

/// How an argument is read from the variadic list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgType {
    Str,
    Ptr,
    IntPtr,
    Int,
    Long,
    LongLong,
    UInt,
    ULong,
    ULongLong,
    Double,
    LongDouble,
    /// An `int` giving a field width.
    Width,
    /// An `int` giving a precision.
    Precision,
}

const SPACE: u32 = 1 << 0;
const SHOWSIGN: u32 = 1 << 1;
const LEFT: u32 = 1 << 2;
const ALT: u32 = 1 << 3;
const SHORT: u32 = 1 << 4;
const LONG: u32 = 1 << 5;
const LONGLONG: u32 = 1 << 6;
const LONGDOUBLE: u32 = 1 << 7;
const PAD_NIL: u32 = 1 << 8;
const UNSIGNED: u32 = 1 << 9;
const OCTAL: u32 = 1 << 10;
const HEX: u32 = 1 << 11;
const UPPER: u32 = 1 << 12;
const WIDTH: u32 = 1 << 13;
const WIDTHPARAM: u32 = 1 << 14;
const PREC: u32 = 1 << 15;
const PRECPARAM: u32 = 1 << 16;
const CHAR: u32 = 1 << 17;
const FLOATE: u32 = 1 << 18;
const FLOATG: u32 = 1 << 19;
const SUBSTR: u32 = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dollar {
    Unknown,
    Nope,
    Use,
}

/// One piece of output: literal text, then possibly a conversion.
#[derive(Clone, Copy, Default)]
struct Segment {
    /// The width, or the index of the argument giving it.
    width: i32,
    /// The precision, or the index of the argument giving it.
    precision: i32,
    flags: u32,
    input: usize,
    /// Literal format text to output first.
    start: usize,
    outlen: usize,
}

/// A parsed format: its segments and the types of the arguments it reads.
pub(crate) struct Parsed {
    segments: [Segment; MAX_SEGMENTS],
    nsegments: usize,
    inputs: [ArgType; MAX_PARAMETERS],
    ninputs: usize,
}

impl Parsed {
    /// The arguments to read, in order.
    pub(crate) fn inputs(&self) -> &[ArgType] {
        &self.inputs[..self.ninputs]
    }
}

/// The byte at `i`, or NUL past the end, as the C walks a C string.
fn at(fmt: &[u8], i: usize) -> u8 {
    fmt.get(i).copied().unwrap_or(0)
}

/// `curlx_str_number`: a decimal number at `*pos` no larger than `max`.
fn number(fmt: &[u8], pos: &mut usize, max: i64) -> Option<i64> {
    let mut p = *pos;
    if !at(fmt, p).is_ascii_digit() {
        return None;
    }
    let mut num: i64 = 0;
    while at(fmt, p).is_ascii_digit() {
        num = num * 10 + i64::from(at(fmt, p) - b'0');
        if num > max {
            return None;
        }
        p += 1;
    }
    *pos = p;
    Some(num)
}

/// A 1-based `N$` argument position, returned 0-based.
fn dollarstring(fmt: &[u8], pos: &mut usize) -> Option<usize> {
    let mut p = *pos;
    let num = number(fmt, &mut p, MAX_PARAMETERS as i64)?;
    if at(fmt, p) != b'$' || num == 0 {
        return None;
    }
    *pos = p + 1;
    Some(num as usize - 1)
}

struct Spec {
    flags: u32,
    width: i32,
    precision: i32,
}

/// Parse the flags, width and precision of a conversion at `*pos`.
fn parse_flags(fmt: &[u8], pos: &mut usize, dollar: Dollar) -> Option<Spec> {
    let mut p = *pos;
    let mut s = Spec {
        flags: 0,
        width: 0,
        precision: 0,
    };
    loop {
        let c = at(fmt, p);
        p += 1;
        match c {
            b' ' => s.flags |= SPACE,
            b'+' => s.flags |= SHOWSIGN,
            b'-' => {
                s.flags |= LEFT;
                s.flags &= !PAD_NIL;
            }
            b'#' => s.flags |= ALT,
            b'.' => {
                if at(fmt, p) == b'*' {
                    s.flags |= PRECPARAM;
                    p += 1;
                    s.precision = if dollar == Dollar::Use {
                        dollarstring(fmt, &mut p)? as i32
                    } else {
                        -1
                    };
                } else {
                    s.flags |= PREC;
                    let neg = at(fmt, p) == b'-';
                    if neg {
                        p += 1;
                    }
                    let num = number(fmt, &mut p, i64::from(i32::MAX))? as i32;
                    s.precision = if neg { -num } else { num };
                }
                if s.flags & (PREC | PRECPARAM) == PREC | PRECPARAM {
                    return None;
                }
            }
            b'h' => s.flags |= SHORT,
            b'l' => {
                if s.flags & LONG != 0 {
                    s.flags |= LONGLONG;
                } else {
                    s.flags |= LONG;
                }
            }
            b'L' => s.flags |= LONGDOUBLE,
            b'q' => s.flags |= LONGLONG,
            // `size_t` and `curl_off_t` are both `long` on LP64 targets.
            b'z' | b'O' => s.flags |= LONG,
            b'0'..=b'9' => {
                if c == b'0' && s.flags & LEFT == 0 {
                    s.flags |= PAD_NIL;
                }
                s.flags |= WIDTH;
                p -= 1;
                s.width = number(fmt, &mut p, i64::from(i32::MAX))? as i32;
            }
            b'*' => {
                s.flags |= WIDTHPARAM;
                s.width = if dollar == Dollar::Use {
                    dollarstring(fmt, &mut p)? as i32
                } else {
                    -1
                };
            }
            _ => {
                p -= 1;
                break;
            }
        }
    }
    *pos = p;
    Some(s)
}

/// The argument type and extra flags of conversion `c`, or `None` for an
/// unknown conversion, which is output as literal text.
fn parse_conversion(c: u8, flags: u32) -> Option<(ArgType, u32)> {
    let int = |signed: [ArgType; 3]| {
        if flags & LONGLONG != 0 {
            signed[2]
        } else if flags & LONG != 0 {
            signed[1]
        } else {
            signed[0]
        }
    };
    let unsigned = int([ArgType::UInt, ArgType::ULong, ArgType::ULongLong]);
    let double = if flags & LONGDOUBLE != 0 {
        ArgType::LongDouble
    } else {
        ArgType::Double
    };
    Some(match c {
        b'S' => (ArgType::Str, ALT),
        b's' => (ArgType::Str, 0),
        b'n' => (ArgType::IntPtr, 0),
        b'p' => (ArgType::Ptr, 0),
        b'd' | b'i' => (int([ArgType::Int, ArgType::Long, ArgType::LongLong]), 0),
        b'u' => (unsigned, UNSIGNED),
        b'o' => (unsigned, OCTAL | UNSIGNED),
        b'x' => (unsigned, HEX | UNSIGNED),
        b'X' => (unsigned, HEX | UPPER | UNSIGNED),
        b'c' => (ArgType::Int, CHAR),
        b'f' => (double, 0),
        b'F' => (double, UPPER),
        b'e' => (double, FLOATE),
        b'E' => (double, FLOATE | UPPER),
        b'g' => (double, FLOATG),
        b'G' => (double, FLOATG | UPPER),
        _ => return None,
    })
}

/// Parse `fmt`. `None` for a format libcurl rejects, which outputs nothing.
pub(crate) fn parse(fmt: &[u8]) -> Option<Parsed> {
    let mut parsed = Parsed {
        segments: [Segment::default(); MAX_SEGMENTS],
        nsegments: 0,
        inputs: [ArgType::Int; MAX_PARAMETERS],
        ninputs: 0,
    };
    let mut used = [false; MAX_PARAMETERS];
    let mut param_num = 0usize;
    let mut max_param: Option<usize> = None;
    let mut dollar = Dollar::Unknown;
    let mut start = 0usize;
    let mut p = 0usize;

    let push = |parsed: &mut Parsed, seg: Segment| -> Option<()> {
        if parsed.nsegments == MAX_SEGMENTS {
            return None;
        }
        parsed.segments[parsed.nsegments] = seg;
        parsed.nsegments += 1;
        Some(())
    };
    let note = |idx: usize, max: &mut Option<usize>| -> Option<()> {
        if idx >= MAX_PARAMETERS {
            return None;
        }
        if max.is_none_or(|m| idx >= m) {
            *max = Some(idx);
        }
        Some(())
    };

    while at(fmt, p) != 0 {
        if at(fmt, p) != b'%' {
            p += 1;
            continue;
        }
        p += 1;
        let outlen = p - start - 1;
        if at(fmt, p) == b'%' {
            // `%%`: the text so far, then the second `%` starts the next.
            if outlen > 0 {
                push(
                    &mut parsed,
                    Segment {
                        flags: SUBSTR,
                        start,
                        outlen,
                        ..Segment::default()
                    },
                )?;
            }
            start = p;
            p += 1;
            continue;
        }

        let mut param = None;
        if dollar != Dollar::Nope {
            match dollarstring(fmt, &mut p) {
                Some(n) => {
                    param = Some(n);
                    dollar = Dollar::Use;
                }
                None if dollar == Dollar::Use => return None,
                None => dollar = Dollar::Nope,
            }
        }

        let mut spec = parse_flags(fmt, &mut p, dollar)?;
        let Some((ty, conv_flags)) = parse_conversion(at(fmt, p), spec.flags) else {
            continue;
        };
        spec.flags |= conv_flags;

        if spec.flags & WIDTHPARAM != 0 {
            let w = if spec.width < 0 {
                param_num += 1;
                param_num - 1
            } else {
                let w = spec.width as usize;
                if used.get(w).copied().unwrap_or(false) {
                    return None;
                }
                w
            };
            note(w, &mut max_param)?;
            spec.width = w as i32;
            parsed.inputs[w] = ArgType::Width;
            used[w] = true;
        }
        if spec.flags & PRECPARAM != 0 {
            let w = if spec.precision < 0 {
                param_num += 1;
                param_num - 1
            } else {
                let w = spec.precision as usize;
                if used.get(w).copied().unwrap_or(false) {
                    return None;
                }
                w
            };
            note(w, &mut max_param)?;
            spec.precision = w as i32;
            parsed.inputs[w] = ArgType::Precision;
            used[w] = true;
        }
        let param = param.unwrap_or_else(|| {
            param_num += 1;
            param_num - 1
        });
        note(param, &mut max_param)?;
        parsed.inputs[param] = ty;
        used[param] = true;

        p += 1;
        push(
            &mut parsed,
            Segment {
                width: spec.width,
                precision: spec.precision,
                flags: spec.flags,
                input: param,
                start,
                outlen,
            },
        )?;
        start = p;
    }
    if p > start {
        push(
            &mut parsed,
            Segment {
                flags: SUBSTR,
                start,
                outlen: p - start,
                ..Segment::default()
            },
        )?;
    }

    let ninputs = max_param.map_or(0, |m| m + 1);
    if !used[..ninputs].iter().all(|&u| u) {
        return None;
    }
    parsed.ninputs = ninputs;
    Some(parsed)
}

/// Where `%n` stores the count, by its length modifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CountSize {
    Short,
    Int,
    Long,
    LongLong,
}

/// The arguments of one call, as read by [`Parsed::inputs`].
pub(crate) trait Args {
    /// Argument `i` as the C union holds it: integers sign- or
    /// zero-extended to 64 bits, doubles as their bits, pointers as
    /// addresses.
    fn bits(&self, i: usize) -> u64;
    /// The string argument `i` points to, up to its NUL or `limit` bytes,
    /// or `None` for a NULL pointer.
    fn string(&self, i: usize, limit: Option<usize>) -> Option<&[u8]>;
    /// Store `count` where pointer argument `i` points.
    fn store_count(&mut self, i: usize, count: i32, size: CountSize);
    /// Format `value` with the C conversion `spec` into `out`; returns the
    /// length written.
    fn format_double(&self, spec: &[u8], value: f64, out: &mut [u8; BUFFSIZE + 2]) -> usize;
}

/// Where formatted output goes.
pub(crate) trait Sink {
    /// Take up to `bytes.len()` bytes and return how many were taken;
    /// fewer stops formatting.
    fn write(&mut self, bytes: &[u8]) -> usize;
    /// Commit anything held back; false on failure. `%n` flushes first, as
    /// the count it stores must match what the caller can see.
    fn flush(&mut self) -> bool {
        true
    }
}

/// Counts output, and stops at the first refused byte.
struct Out<'a, S: Sink> {
    sink: &'a mut S,
    done: i32,
}

/// Formatting stopped because the sink refused output.
struct Stop;

impl<S: Sink> Out<'_, S> {
    fn run(&mut self, bytes: &[u8]) -> Result<(), Stop> {
        if bytes.is_empty() {
            return Ok(());
        }
        let n = self.sink.write(bytes);
        self.done += n as i32;
        if n == bytes.len() { Ok(()) } else { Err(Stop) }
    }

    fn pad(&mut self, byte: u8, num: i32) -> Result<(), Stop> {
        const RUN: usize = 16;
        let src = [byte; RUN];
        let mut left = num.max(0) as usize;
        while left > RUN {
            self.run(&src)?;
            left -= RUN;
        }
        self.run(&src[..left])
    }

    /// The bytes before the first NUL.
    fn zrun(&mut self, bytes: &[u8]) -> Result<(), Stop> {
        let n = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        self.run(&bytes[..n])
    }
}

struct Props {
    width: i32,
    prec: i32,
    flags: u32,
}

const NILSTR: &[u8] = b"(nil)";

fn out_number<S: Sink>(o: &mut Out<'_, S>, p: &Props, unum: u64, snum: i64) -> Result<(), Stop> {
    let flags = p.flags;
    let mut width = p.width;
    let mut prec = p.prec;
    let alt = flags & ALT != 0;

    if flags & CHAR != 0 {
        if flags & LEFT == 0 {
            o.pad(b' ', width - 1)?;
            width = 1;
        }
        o.run(&[unum as u8])?;
        if flags & LEFT != 0 {
            o.pad(b' ', width - 1)?;
        }
        return Ok(());
    }
    let (base, digits): (u64, &[u8; 16]) = if flags & OCTAL != 0 {
        (8, b"0123456789abcdef")
    } else if flags & HEX != 0 {
        (
            16,
            if flags & UPPER != 0 {
                b"0123456789ABCDEF"
            } else {
                b"0123456789abcdef"
            },
        )
    } else {
        (10, b"0123456789abcdef")
    };
    let mut num = unum;
    let mut neg = false;
    if base == 10 && flags & UNSIGNED == 0 {
        neg = snum < 0;
        if neg {
            num = snum.unsigned_abs();
        }
    }
    if prec == -1 {
        prec = 1;
    }

    // Digits are written backwards from the end of `work`.
    let mut work = [0u8; BUFFSIZE + 2];
    let workend = BUFFSIZE - 2;
    let mut w = workend as isize;
    while num > 0 {
        work[w as usize] = digits[(num % base) as usize];
        num /= base;
        w -= 1;
    }
    let ndigits = workend as isize - w;
    width -= ndigits as i32;
    prec -= ndigits as i32;
    if alt && base == 8 && prec <= 0 {
        work[w as usize] = b'0';
        w -= 1;
        width -= 1;
    }
    if prec > 0 {
        width -= prec;
        while prec > 0 && w >= 0 {
            prec -= 1;
            work[w as usize] = b'0';
            w -= 1;
        }
    }
    if alt && base == 16 {
        width -= 2;
    }
    if neg || flags & (SHOWSIGN | SPACE) != 0 {
        width -= 1;
    }
    if flags & (LEFT | PAD_NIL) == 0 {
        o.pad(b' ', width)?;
        width = 0;
    }
    if neg {
        o.run(b"-")?;
    } else if flags & SHOWSIGN != 0 {
        o.run(b"+")?;
    } else if flags & SPACE != 0 {
        o.run(b" ")?;
    }
    if alt && base == 16 {
        o.run(if flags & UPPER != 0 { b"0X" } else { b"0x" })?;
    }
    if flags & LEFT == 0 && flags & PAD_NIL != 0 {
        o.pad(b'0', width)?;
        width = 0;
    }
    o.run(&work[(w + 1) as usize..=workend])?;
    if flags & LEFT != 0 {
        o.pad(b' ', width)?;
    }
    Ok(())
}

fn out_string<S: Sink>(o: &mut Out<'_, S>, p: &Props, s: Option<&[u8]>) -> Result<(), Stop> {
    let mut flags = p.flags;
    let mut width = p.width;
    let (s, len) = match s {
        None if p.prec == -1 || p.prec >= NILSTR.len() as i32 => {
            // Quotes are not put around (nil).
            flags &= !ALT;
            (NILSTR, NILSTR.len())
        }
        None => (&b""[..], 0),
        // With a precision, the width counts the precision, not the
        // string's length, as in C.
        Some(s) if p.prec != -1 => (s, p.prec as usize),
        Some(s) => (s, s.len()),
    };
    width -= i32::try_from(len).unwrap_or(i32::MAX);
    if flags & ALT != 0 {
        o.run(b"\"")?;
    }
    if flags & LEFT == 0 {
        o.pad(b' ', width)?;
        width = 0;
    }
    o.zrun(&s[..len.min(s.len())])?;
    if flags & LEFT != 0 {
        o.pad(b' ', width)?;
    }
    if flags & ALT != 0 {
        o.run(b"\"")?;
    }
    Ok(())
}

fn out_pointer<S: Sink>(o: &mut Out<'_, S>, p: &mut Props, addr: u64) -> Result<(), Stop> {
    if addr != 0 {
        p.flags |= HEX | ALT;
        return out_number(o, p, addr, 0);
    }
    // The padding goes on the side opposite to the usual one, as in C.
    let mut width = p.width - NILSTR.len() as i32;
    if p.flags & LEFT != 0 {
        o.pad(b' ', width)?;
        width = 0;
    }
    o.run(NILSTR)?;
    if p.flags & LEFT == 0 {
        o.pad(b' ', width)?;
    }
    Ok(())
}

/// Write `n` in decimal into `buf` at `*at`.
fn push_int(buf: &mut [u8], at: &mut usize, n: i32) {
    let mut digits = [0u8; 12];
    let mut i = digits.len();
    let neg = n < 0;
    let mut v = n.unsigned_abs();
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        digits[i] = b'-';
    }
    let d = &digits[i..];
    buf[*at..*at + d.len()].copy_from_slice(d);
    *at += d.len();
}

fn out_double<S: Sink, A: Args>(
    o: &mut Out<'_, S>,
    args: &A,
    p: &Props,
    value: f64,
) -> Result<(), Stop> {
    let mut spec = [0u8; 32];
    spec[0] = b'%';
    let mut n = 1;
    for (flag, c) in [(LEFT, b'-'), (SHOWSIGN, b'+'), (SPACE, b' '), (ALT, b'#')] {
        if p.flags & flag != 0 {
            spec[n] = c;
            n += 1;
        }
    }
    let mut width = p.width;
    let mut prec = p.prec;
    if width >= 0 {
        width = width.min(BUFFSIZE as i32 - 1);
        push_int(&mut spec, &mut n, width);
    }
    if prec >= 0 {
        // Each digit of the integer part leaves room for one fewer
        // decimal.
        let mut maxprec = BUFFSIZE as i32 - 1;
        let mut val = value;
        if prec > maxprec {
            prec = maxprec - 1;
        }
        if width > 0 && prec <= width {
            maxprec -= width;
        }
        while maxprec != 0 && val >= 10.0 {
            val /= 10.0;
            maxprec -= 1;
        }
        if prec > maxprec {
            prec = maxprec - 1;
        }
        prec = prec.max(0);
        spec[n] = b'.';
        n += 1;
        push_int(&mut spec, &mut n, prec);
    }
    if p.flags & LONG != 0 {
        spec[n] = b'l';
        n += 1;
    }
    let upper = p.flags & UPPER != 0;
    spec[n] = match (p.flags & FLOATE != 0, p.flags & FLOATG != 0, upper) {
        (true, _, false) => b'e',
        (true, _, true) => b'E',
        (false, true, false) => b'g',
        (false, true, true) => b'G',
        (false, false, false) => b'f',
        (false, false, true) => b'F',
    };
    n += 1;
    let mut work = [0u8; BUFFSIZE + 2];
    let len = args.format_double(&spec[..n], value, &mut work);
    o.run(&work[..len])
}

/// Render `parsed` (from `fmt`) with `args` into `sink`; returns the number
/// of bytes written, as the C functions do.
pub(crate) fn render<A: Args, S: Sink>(
    fmt: &[u8],
    parsed: &Parsed,
    args: &mut A,
    sink: &mut S,
) -> i32 {
    let mut o = Out { sink, done: 0 };
    // Output stops at the first refused byte; the count so far stands.
    let _stopped: Result<(), Stop> = render_into(fmt, parsed, args, &mut o);
    o.done
}

fn render_into<A: Args, S: Sink>(
    fmt: &[u8],
    parsed: &Parsed,
    args: &mut A,
    o: &mut Out<'_, S>,
) -> Result<(), Stop> {
    for seg in &parsed.segments[..parsed.nsegments] {
        if seg.outlen > 0 {
            o.zrun(&fmt[seg.start..seg.start + seg.outlen])?;
            if seg.flags & SUBSTR != 0 {
                continue;
            }
        }
        let mut p = Props {
            flags: seg.flags,
            width: seg.width,
            prec: -1,
        };
        if p.flags & WIDTHPARAM != 0 {
            p.width = args.bits(seg.width as usize) as i32;
            if p.width < 0 {
                // A negative width is a `-` flag and a positive width.
                p.width = p.width.checked_neg().unwrap_or(i32::MAX);
                p.flags |= LEFT;
                p.flags &= !PAD_NIL;
            }
        }
        if p.flags & PRECPARAM != 0 {
            // A negative precision is as if there were none.
            p.prec = (args.bits(seg.precision as usize) as i32).max(-1);
        } else if p.flags & PREC != 0 {
            p.prec = seg.precision;
        }
        let i = seg.input;
        match parsed.inputs[i] {
            ArgType::UInt | ArgType::ULong | ArgType::ULongLong => {
                p.flags |= UNSIGNED;
                out_number(o, &p, args.bits(i), 0)?;
            }
            ArgType::Int | ArgType::Long | ArgType::LongLong => {
                out_number(o, &p, args.bits(i), args.bits(i) as i64)?;
            }
            ArgType::Str => {
                let limit = (p.prec >= 0).then_some(p.prec as usize);
                out_string(o, &p, args.string(i, limit))?;
            }
            ArgType::Ptr => out_pointer(o, &mut p, args.bits(i))?,
            ArgType::Double | ArgType::LongDouble => {
                out_double(o, args, &p, f64::from_bits(args.bits(i)))?;
            }
            ArgType::IntPtr => {
                if !o.sink.flush() {
                    return Err(Stop);
                }
                let size = if p.flags & LONGLONG != 0 {
                    CountSize::LongLong
                } else if p.flags & LONG != 0 {
                    CountSize::Long
                } else if p.flags & SHORT != 0 {
                    CountSize::Short
                } else {
                    CountSize::Int
                };
                args.store_count(i, o.done, size);
            }
            ArgType::Width | ArgType::Precision => {}
        }
    }
    Ok(())
}
