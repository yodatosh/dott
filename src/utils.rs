// find the first YYYY-MM-DD pattern in a string
pub fn parse_date(s: &str) -> Option<String> {
    let b = s.as_bytes();
    for i in 0..b.len().saturating_sub(9) {
        if b[i..i + 4].iter().all(|c| c.is_ascii_digit())
            && b[i + 4] == b'-'
            && b[i + 5..i + 7].iter().all(|c| c.is_ascii_digit())
            && b[i + 7] == b'-'
            && b[i + 8..i + 10].iter().all(|c| c.is_ascii_digit())
        {
            let date = &s[i..i + 10];
            let parts: Vec<i64> = date.split('-').map(|p| p.parse().unwrap()).collect();
            if valid_date(parts[0], parts[1], parts[2]) { return Some(date.to_string()); }
        }
    }
    None
}

// parse "26th February 2015" (anywhere in s) → "2015-02-26".
// whois.gg publishes dates in prose, so parse_date (ISO-only) can't read them.
pub fn parse_prose_date(s: &str) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    let lower = s.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }
    for i in 0..=tokens.len() - 3 {
        let Ok(day) = tokens[i]
            .trim_end_matches(char::is_alphabetic)
            .parse::<u32>()
        else {
            continue;
        };
        if !(1..=31).contains(&day) {
            continue;
        }
        let Some(month_idx) = MONTHS.iter().position(|m| *m == tokens[i + 1]) else {
            continue;
        };
        let Ok(year) = tokens[i + 2].parse::<u32>() else {
            continue;
        };
        if !(1900..2100).contains(&year) {
            continue;
        }
        if valid_date(year.into(), (month_idx + 1) as i64, day.into()) {
            return Some(format!("{:04}-{:02}-{:02}", year, month_idx + 1, day));
        }
    }
    None
}

pub fn date_to_epoch_days(y: i64, m: i64, d: i64) -> i64 {
    let a = (14 - m) / 12;
    let y2 = y + 4800 - a;
    let m2 = m + 12 * a - 3;
    let jdn = d + (153 * m2 + 2) / 5 + 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 - 32045;
    jdn - 2440588
}

// Inverse of date_to_epoch_days (Howard Hinnant's civil_from_days) → "YYYY-MM-DD".
pub fn epoch_days_to_date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn valid_date(y: i64, m: i64, d: i64) -> bool {
    if !(1..=9999).contains(&y) || !(1..=12).contains(&m) { return false; }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let max_day = match m {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=max_day).contains(&d)
}

pub fn days_until(date_str: &str) -> Option<i64> {
    let p: Vec<i64> = date_str
        .splitn(3, '-')
        .map(|s| s.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    if p.len() != 3 || !valid_date(p[0], p[1], p[2]) { return None; }
    let target = date_to_epoch_days(p[0], p[1], p[2]);
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64
        / 86400;
    Some(target - today)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_dates_do_not_panic_or_roll_over() {
        for date in ["2026", "2026-01", "", "2026-00-01", "2026-13-01", "2026-02-29", "2026-04-31", "999999999999-01-01"] {
            assert_eq!(days_until(date), None, "{date}");
        }
        assert!(days_until("2028-02-29").is_some());
    }

    #[test]
    fn epoch_days_round_trip() {
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2026, 10, 2), (2100, 12, 31)] {
            assert_eq!(epoch_days_to_date(date_to_epoch_days(y, m, d)), format!("{y:04}-{m:02}-{d:02}"));
        }
    }
}
