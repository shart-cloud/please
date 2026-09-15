//! Presentation of corpus metrics, preserving the corpus gate and saved-run integrity.
//! Counts come from metrics::Report; no translation into contextual bench labels.
use std::io::Write;
use std::path::Path;

use crate::bench::presentation::{html, html_start, html_table, require_terminal, safe};
use crate::metrics::{pct, Report, SliceMetrics, Tally};
use crate::run::RunStatus;
use crate::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    widgets::{Block, Paragraph, Row, Table, TableState, Tabs, Wrap},
    Frame,
};

const TABS: [&str; 5] = ["Datasets", "Source", "Technique", "Language", "Coverage"];
const HEADERS: [&str; 6] = [
    "Dataset",
    "Kind",
    "Stratum",
    "Rows",
    "Hits / issues",
    "Rate",
];
const LEGEND: &str = "Positive hits are detections; negative hits are false alarms. Rates include all supplied rows. Coverage counts are per cause and may overlap; they are not unique failed-row counts. Read source strata separately. N/A means no applicable rate.";

fn integrity(report: &Report) -> &'static str {
    match report.gate.run_integrity.status() {
        RunStatus::Complete => "COMPLETE",
        RunStatus::Incomplete => "INCOMPLETE",
        RunStatus::Unverified => "UNVERIFIED",
    }
}

fn status(report: &Report) -> String {
    let gate = if report.gate.slices.is_empty() {
        "NOT ASSESSED (no eligible negative slices)"
    } else if report.gate.failed(false, false) {
        "FAILED"
    } else {
        "PASSED"
    };
    format!(
        "Saved results: {} | Default regression gate: {} | Threshold: {}",
        integrity(report),
        gate,
        safe(&report.floor)
    )
}

fn tally_rate(t: Tally) -> String {
    if t.n == 0 {
        "N/A".into()
    } else {
        pct(t.permille())
    }
}

fn metric_cells(m: &SliceMetrics, stratum: &str, t: Tally) -> Vec<String> {
    vec![
        m.slice_id.clone(),
        m.kind.clone(),
        stratum.into(),
        t.n.to_string(),
        t.hits.to_string(),
        tally_rate(t),
    ]
}

fn rows(report: &Report, tab: usize) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for m in &report.metrics {
        match tab {
            0 => rows.push(metric_cells(m, &m.label, m.total)),
            1..=3 => {
                let map = match tab {
                    1 => &m.by_source,
                    2 => &m.by_technique,
                    _ => &m.by_language,
                };
                for (stratum, tally) in map {
                    rows.push(metric_cells(m, stratum, *tally));
                }
            }
            _ => {
                if m.incomplete.is_empty() {
                    rows.push(vec![
                        m.slice_id.clone(),
                        m.kind.clone(),
                        "no recorded coverage issues".into(),
                        m.total.n.to_string(),
                        "0".into(),
                        "N/A".into(),
                    ]);
                }
                for (cause, count) in &m.incomplete {
                    rows.push(vec![
                        m.slice_id.clone(),
                        m.kind.clone(),
                        cause.clone(),
                        m.total.n.to_string(),
                        count.to_string(),
                        "N/A".into(),
                    ]);
                }
            }
        }
    }
    rows
}

fn notes(report: &Report) -> String {
    let mut notes = Vec::new();
    for issue in report.gate.run_integrity.issues() {
        notes.push(format!(
            "{}: {}",
            issue.slice.as_deref().unwrap_or("run"),
            issue.detail
        ));
    }
    if !report.gate.unpinned.is_empty() {
        notes.push(format!("Missing regression baselines: {}. This measurement does not establish a passing default gate.", report.gate.unpinned.join(", ")));
    }
    notes.extend(report.known_gaps());
    notes.push("Previously used public benchmark data; these results are development evidence, not an independent holdout or deployment accuracy.".into());
    notes.join("\n")
}

pub fn render_table(report: &Report) -> String {
    let mut output = format!(
        "\nPLEASE corpus benchmark: {}\n{}\n{}\n\n{}\n",
        safe(&report.run),
        status(report),
        safe(&report.ruleset),
        HEADERS.join(" | ")
    );
    for row in rows(report, 0) {
        output.push_str(&row.iter().map(|c| safe(c)).collect::<Vec<_>>().join(" | "));
        output.push('\n');
    }
    output.push_str(&format!(
        "\n{LEGEND}\n{}\n",
        notes(report)
            .split('\n')
            .map(safe)
            .collect::<Vec<_>>()
            .join("\n")
    ));
    output
}

pub fn render_html(report: &Report) -> String {
    let mut output = html_start();
    output.push_str(&format!(
        "<p><b>{}</b></p><aside class=\"notice\">{}</aside>",
        html(&report.run),
        html(&status(report))
    ));
    output.push_str(&format!("<details><summary>Run identity and configuration</summary><p>Dataset: {}<br>Rule set: {}<br>Rule-set digest: {}<br>Detection threshold: {}</p></details>",
        html(&report.dataset), html(&report.ruleset), html(&report.ruleset_digest), html(&report.floor)));
    output.push_str(&format!("<p class=\"muted\">{}</p>", html(LEGEND)));
    for (tab, title) in TABS.iter().enumerate() {
        if tab == 0 {
            output.push_str("<h2>Dataset summary</h2>");
        } else {
            output.push_str(&format!("<details><summary>{title}</summary>"));
        }
        output.push_str(&html_table(&HEADERS, rows(report, tab)));
        if tab > 0 {
            output.push_str("</details>");
        }
    }
    output.push_str("<h2>Coverage by dataset</h2>");
    output.push_str(&html_table(
        &["Dataset", "Rows", "Distinct incomplete rows"],
        report.metrics.iter().map(|m| {
            vec![
                m.slice_id.clone(),
                m.total.n.to_string(),
                m.incomplete_rows.to_string(),
            ]
        }),
    ));
    output.push_str("<h2>False-positive gate</h2><p>Default gate requires complete saved results and pinned baselines. The criterion is reported separately.</p>");
    output.push_str(&html_table(
        &[
            "Dataset",
            "False positives / eligible rows",
            "Rate",
            "Baseline",
            "Regression",
            "Criterion",
        ],
        report.gate.slices.iter().map(|g| {
            vec![
                g.slice_id.clone(),
                format!("{}/{}", g.gated.hits, g.gated.n),
                tally_rate(g.gated),
                g.baseline.map(pct).unwrap_or_else(|| "UNPINNED".into()),
                if g.baseline.is_none() {
                    "N/A"
                } else if g.regressed {
                    "YES"
                } else {
                    "no"
                }
                .into(),
                if g.gated.n == 0 {
                    "N/A: empty denominator".into()
                } else {
                    format!(
                        "{} (limit {})",
                        if g.criterion_met { "met" } else { "NOT MET" },
                        pct(report.gate.max_fp_permille)
                    )
                },
            ]
        }),
    ));
    output.push_str("<h2>Excluded sources</h2>");
    output.push_str(&html_table(
        &["Dataset", "Source", "Rows", "Hits", "Reason"],
        report.metrics.iter().flat_map(|m| {
            m.excluded.iter().map(move |(source, (t, reason))| {
                vec![
                    m.slice_id.clone(),
                    source.clone(),
                    t.n.to_string(),
                    t.hits.to_string(),
                    reason.clone(),
                ]
            })
        }),
    ));
    output.push_str(&format!(
        "<h2>Coverage, integrity, and interpretation</h2><pre>{}</pre>",
        html(&notes(report))
    ));
    output.push_str(&format!(
        "<details><summary>Complete metric record (Markdown)</summary><pre>{}</pre></details>",
        html(&report.to_markdown())
    ));
    output.push_str("</main></body></html>");
    output
}

/// New derived files only; never overwrite saved rows, metadata, or existing reports.
pub fn save_bundle(report: &Report, directory: &Path) -> Result<()> {
    let outputs = [
        ("report.html", render_html(report)),
        (
            "report.json",
            format!("{}\n", serde_json::to_string_pretty(&report.to_json())?),
        ),
        ("report.md", report.to_markdown()),
    ];
    for (name, _) in &outputs {
        if directory.join(name).exists() {
            return Err(format!("report already exists: {name}").into());
        }
    }
    for (name, content) in outputs {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
    }
    Ok(())
}

pub fn show(report: &Report) -> Result<()> {
    require_terminal()?;
    let mut terminal = match ratatui::try_init() {
        Ok(t) => t,
        Err(error) => {
            ratatui::restore();
            return Err(error.into());
        }
    };
    let result = (|| -> Result<()> {
        let mut tab = 0;
        let mut selected = TableState::default().with_selected(0);
        let mut scroll = 0u16;
        loop {
            terminal.draw(|f| draw(f, report, tab, &mut selected, scroll))?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Tab | KeyCode::Right => {
                        tab = (tab + 1) % TABS.len();
                        selected = TableState::default().with_selected(0);
                        scroll = 0;
                    }
                    KeyCode::BackTab | KeyCode::Left => {
                        tab = (tab + TABS.len() - 1) % TABS.len();
                        selected = TableState::default().with_selected(0);
                        scroll = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        selected.select(Some(
                            (selected.selected().unwrap_or(0) + 1)
                                .min(rows(report, tab).len().saturating_sub(1)),
                        ));
                        scroll = 0;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected.select(Some(selected.selected().unwrap_or(0).saturating_sub(1)));
                        scroll = 0;
                    }
                    KeyCode::Home => {
                        selected.select(Some(0));
                        scroll = 0;
                    }
                    KeyCode::End => {
                        selected.select(Some(rows(report, tab).len().saturating_sub(1)));
                        scroll = 0;
                    }
                    KeyCode::PageDown => scroll = scroll.saturating_add(3),
                    KeyCode::PageUp => scroll = scroll.saturating_sub(3),
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

fn draw(frame: &mut Frame, report: &Report, tab: usize, selected: &mut TableState, scroll: u16) {
    let area = frame.area();
    if area.width < 90 || area.height < 24 {
        frame.render_widget(Paragraph::new("PLEASE corpus results\nEnlarge terminal to at least 90 x 24.\nq / Esc: quit. HTML is also available.").wrap(Wrap { trim: false }),area);
        return;
    }
    let regions = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(9),
        Constraint::Length(2),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(format!(
            "{}\n{}\n{}",
            safe(&report.run),
            status(report),
            safe(&report.ruleset)
        ))
        .block(Block::default().title(" PLEASE corpus benchmark ").bold())
        .wrap(Wrap { trim: false }),
        regions[0],
    );
    frame.render_widget(
        Tabs::new(TABS)
            .select(tab)
            .highlight_style(Style::default().fg(Color::Yellow).bold()),
        regions[1],
    );
    let values = rows(report, tab);
    frame.render_stateful_widget(
        Table::new(
            values
                .iter()
                .map(|r| Row::new(r.iter().map(|s| safe(s)).collect::<Vec<_>>())),
            [
                Constraint::Percentage(22),
                Constraint::Percentage(10),
                Constraint::Percentage(38),
                Constraint::Percentage(10),
                Constraint::Percentage(10),
                Constraint::Percentage(10),
            ],
        )
        .header(Row::new(HEADERS).style(Style::default().fg(Color::Yellow)))
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("> "),
        regions[2],
        selected,
    );
    let mut detail = String::new();
    if let Some(row) = selected.selected().and_then(|i| values.get(i)) {
        detail.push_str(&format!("{}\n", row.join(" | ")));
    }
    detail.push_str(&notes(report));
    frame.render_widget(
        Paragraph::new(detail.split('\n').map(safe).collect::<Vec<_>>().join("\n"))
            .block(Block::bordered().title(" Details and caveats | PgUp/PgDn scroll "))
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        regions[3],
    );
    frame.render_widget(Paragraph::new("Tab/arrows: view | j/k: row | Home/End | PgUp/PgDn: details | q: quit\nNegative hits = false alarms; coverage causes overlap. Integrity and gate cover the full run.")
        .style(Style::default().fg(Color::Yellow)),regions[4]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Gate;
    use crate::run::RunIntegrity;
    use ratatui::{backend::TestBackend, Terminal};

    fn sample() -> Report {
        Report {
            run: "<script>bad</script>\u{1b}[2J".into(),
            ruleset: "builtin; mode=product".into(),
            ruleset_digest: "abc".into(),
            floor: "high".into(),
            dataset: "pinned".into(),
            metrics: vec![SliceMetrics {
                slice_id: "negative-test".into(),
                kind: "negative".into(),
                label: "benign".into(),
                total: Tally { n: 3, hits: 1 },
                incomplete_rows: 2,
                incomplete: [("timeout".into(), 2), ("limit".into(), 2)].into(),
                ..Default::default()
            }],
            gate: Gate {
                run_integrity: RunIntegrity::unverified("missing record"),
                max_fp_permille: 10,
                slices: vec![],
                unpinned: vec![],
            },
        }
    }

    #[test]
    fn presentation_never_converts_unknown_integrity_or_denominators_to_success() {
        let report = sample();
        let rendered = render_html(&report);
        assert!(rendered.contains("UNVERIFIED"));
        assert!(!rendered.contains("Saved results verified"));
        assert!(!rendered.contains("<script>"));
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("33.3%"));
        assert_eq!(tally_rate(Tally::default()), "N/A");
        assert_eq!(rows(&report, 4).len(), 2);
        assert!(rows(&report, 4).iter().all(|r| r[5] == "N/A"));
    }

    #[test]
    fn terminal_handles_all_tabs_and_sizes() {
        for size in [(160, 40), (90, 24), (40, 10)] {
            let mut terminal = Terminal::new(TestBackend::new(size.0, size.1)).unwrap();
            for tab in 0..TABS.len() {
                terminal
                    .draw(|f| {
                        draw(
                            f,
                            &sample(),
                            tab,
                            &mut TableState::default().with_selected(0),
                            0,
                        )
                    })
                    .unwrap();
                let text: String = terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|c| c.symbol())
                    .collect();
                assert!(text.contains("PLEASE"));
                if size.0 >= 90 {
                    assert!(text.contains("UNVERIFIED"));
                }
            }
        }
    }

    #[test]
    fn report_bundle_cannot_overwrite_existing_evidence() {
        let dir = tempfile::tempdir().unwrap();
        save_bundle(&sample(), dir.path()).unwrap();
        let before = std::fs::read(dir.path().join("report.html")).unwrap();
        assert!(save_bundle(&sample(), dir.path()).is_err());
        assert_eq!(
            std::fs::read(dir.path().join("report.html")).unwrap(),
            before
        );
    }
}
