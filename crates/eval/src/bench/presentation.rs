//! Human views of the verified BenchReport; no execution or independent metric aggregation.
use std::io::IsTerminal;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    widgets::{Block, Paragraph, Row, Table, TableState, Tabs, Wrap},
    Frame,
};

use super::model::Surface;
use super::report::{BenchReport, MetricRecord};
use crate::Result;

const AXES: [&str; 4] = ["surface", "source", "delivery_vector", "technique"];
const LABELS: [&str; 4] = ["Summary", "Source", "Delivery", "Technique"];
const HEADERS: [&str; 10] = [
    "System",
    "Surface",
    "Stratum",
    "Rows",
    "Complete",
    "Gaps",
    "Recall",
    "False alarms",
    "Context",
    "Mean us",
];
const LEGEND: &str = "Rates show count/denominator and %. Recall includes failed attacks as misses; false alarms use all benign rows, so read with coverage. Context includes all contextual rows. N/A means no eligible denominator. Technique rows overlap; do not sum them.";

/// Neutralize controls and format characters without hiding long identities.
pub(crate) fn safe(value: &str) -> String {
    value.chars().map(|c| {
        if c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}') {
            c.escape_default().to_string()
        } else { c.to_string() }
    }).collect()
}

pub(crate) fn html(value: &str) -> String {
    value
        .split('\n')
        .map(safe)
        .collect::<Vec<_>>()
        .join("\n")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn rate(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return "N/A".into();
    }
    let per_mille = u128::from(numerator) * 1000 / u128::from(denominator);
    format!(
        "{numerator}/{denominator} ({}.{:01}%)",
        per_mille / 10,
        per_mille % 10
    )
}

fn cells(record: &MetricRecord) -> Vec<String> {
    let c = &record.counts;
    let artifact = record.surface == Surface::ArtifactDetection;
    vec![
        safe(&record.system_id),
        if artifact { "artifact" } else { "context" }.into(),
        safe(&record.value),
        c.rows.to_string(),
        rate(c.completed, c.rows),
        c.rows.saturating_sub(c.completed).to_string(),
        if artifact {
            rate(c.true_positives, c.positives)
        } else {
            "N/A".into()
        },
        if artifact {
            rate(c.false_positives, c.negatives)
        } else {
            "N/A".into()
        },
        if artifact {
            "N/A".into()
        } else {
            rate(c.contextual_correct, c.contextual_rows)
        },
        c.elapsed_micros
            .checked_div(c.rows)
            .map_or_else(|| "N/A".into(), |mean| mean.to_string()),
    ]
}

fn details(record: &MetricRecord) -> String {
    let c = &record.counts;
    format!(
        "{} / {} / {}\nCoverage: unsupported {} | abstained {} | timeout {} | crashed {} | invalid {} | unavailable {}\nArtifact: TP {} | FN {} | TN {} | FP {} | ambiguous {}. Context: correct {} / {}.\nTime: total {} us | max {} us | runner overhead {} us. Remote requests {} | declared cost {} microUSD.",
        safe(&record.system_id), record.surface.as_str(), safe(&record.value),
        c.unsupported, c.abstained, c.timeout, c.crashed, c.invalid_output, c.unavailable,
        c.true_positives, c.false_negatives, c.true_negatives, c.false_positives, c.ambiguous,
        c.contextual_correct, c.contextual_rows, c.elapsed_micros, c.max_elapsed_micros,
        c.runner_overhead_micros, c.remote_requests, c.declared_cost_microusd,
    )
}

pub fn render_table(report: &BenchReport) -> String {
    let mut output = format!(
        "\nPLEASE benchmark | saved results verified\nPack: {}\nRun: {}\n{}\n{}\n\n",
        safe(&report.pack_id),
        safe(&report.run_id),
        safe(&report.execution_posture),
        safe(&report.caveat),
    );
    output.push_str(&HEADERS.join(" | "));
    output.push('\n');
    for row in report.strata.iter().filter(|row| row.axis == "surface") {
        output.push_str(&cells(row).join(" | "));
        output.push('\n');
    }
    output.push_str(&format!("\n{LEGEND}\n"));
    output
}

pub(crate) fn html_table(headers: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> String {
    let mut output = String::from("<div class=\"scroll\"><table><thead><tr>");
    for header in headers {
        output.push_str(&format!("<th scope=\"col\">{}</th>", html(header)));
    }
    output.push_str("</tr></thead><tbody>");
    for row in rows {
        output.push_str("<tr>");
        for cell in row {
            output.push_str(&format!("<td>{}</td>", html(&cell)));
        }
        output.push_str("</tr>");
    }
    output.push_str("</tbody></table></div>");
    output
}

/// Standalone, script-free report. Every data value is escaped as text, never HTML.
pub(crate) fn html_start() -> String {
    String::from(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>PLEASE benchmark report</title><style>
:root{color-scheme:dark;--bg:#10151c;--panel:#18212c;--line:#304151;--text:#e6edf3;--muted:#aabbcc;--accent:#f4c95d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}
main{max-width:1600px;margin:auto;padding:36px}h1{font-size:38px;line-height:1.15;margin:8px 0 20px}
h2{margin-top:36px}h3{color:var(--accent)}.eyebrow{color:var(--accent);letter-spacing:.14em;font-size:12px;text-transform:uppercase}
.meta,.notice,details{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin:16px 0}
.notice{border-left:4px solid var(--accent)}p{overflow-wrap:anywhere}.muted,small{color:var(--muted)}
nav{display:flex;gap:18px;flex-wrap:wrap}a{color:var(--accent)}.scroll{overflow:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums;font-size:13px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#243140;white-space:nowrap}tr:nth-child(even){background:#151e28}td{max-width:420px;overflow-wrap:anywhere}
summary{cursor:pointer;color:var(--accent)}pre{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:700px){main{padding:16px}h1{font-size:28px}}
@media print{:root{color-scheme:light;--bg:white;--panel:white;--line:#bbb;--text:black;--muted:#333;--accent:#765600}th,tr:nth-child(even){background:#eee}.scroll{overflow:visible}main{padding:0}nav{display:none}}
</style></head><body><main><div class="eyebrow">PLEASE / evaluation bench</div>
<h1>Benchmark results</h1>"#,
    )
}
pub fn render_html(report: &BenchReport) -> String {
    let mut output = html_start();
    output.push_str("<p class=\"muted\">Saved results verified. This is an evidence report, not a release gate.</p>");
    output.push_str(&format!(
        "<details class=\"meta\"><summary>Run identity and execution</summary><p><b>Pack</b> {}<br><b>Run</b> {}<br><b>Pack digest</b> {}</p><p>{}</p></details><aside class=\"notice\">{}</aside>",
        html(&report.pack_id), html(&report.run_id), html(&report.pack_digest),
        html(&report.execution_posture), html(&report.caveat),
    ));
    output.push_str("<nav><a href=\"#summary\">Summary</a><a href=\"#systems\">Systems</a><a href=\"#breakdowns\">Breakdowns</a><a href=\"#context\">Context</a></nav>");
    output.push_str(&format!(
        "<h2 id=\"summary\">System summary</h2><p class=\"muted\">{}</p>",
        html(LEGEND)
    ));
    for (index, axis) in AXES.iter().enumerate() {
        if index == 1 {
            output.push_str("<h2 id=\"breakdowns\">Breakdowns</h2>");
        }
        if index > 0 {
            output.push_str(&format!("<details><summary>By {}</summary>", LABELS[index]));
        }
        output.push_str(&html_table(
            &HEADERS,
            report
                .strata
                .iter()
                .filter(|row| row.axis == *axis)
                .map(cells),
        ));
        if index > 0 {
            output.push_str("</details>");
        }
    }
    output.push_str("<h2>Coverage and timing details</h2>");
    for row in report.strata.iter().filter(|row| row.axis == "surface") {
        output.push_str(&format!(
            "<details><summary>{} / {}</summary><pre>{}</pre></details>",
            html(&row.system_id),
            row.surface.as_str(),
            html(&details(row))
        ));
    }
    output.push_str("<h2 id=\"systems\">Systems and operating points</h2>");
    output.push_str(&html_table(
        &[
            "System",
            "Digest",
            "Adapter",
            "Threshold",
            "Description",
            "Normalizers",
        ],
        report.systems.iter().map(|system| {
            vec![
                system.system_id.clone(),
                system.system_digest.clone(),
                system.adapter_version.clone(),
                system.operating_point.threshold.clone(),
                system.operating_point.description.clone(),
                system.normalizers.join(", "),
            ]
        }),
    ));
    output.push_str("<h2 id=\"context\">Contextual relation matrix</h2><p class=\"muted\">Completed contextual decisions only. Coverage gaps remain in the tables above. Zero cells are retained.</p>");
    output.push_str(&html_table(
        &["System", "Expected", "Observed", "Rows"],
        report.contextual_matrix.iter().map(|cell| {
            vec![
                cell.system_id.clone(),
                cell.expected.as_str().into(),
                cell.observed.as_str().into(),
                cell.rows.to_string(),
            ]
        }),
    ));
    output.push_str("<details><summary>Paired contextual changes</summary>");
    output.push_str(&html_table(
        &[
            "System",
            "Group",
            "Repetition",
            "Case A",
            "Case B",
            "Expected",
            "Observed",
        ],
        report.paired_changes.iter().map(|pair| {
            vec![
                pair.system_id.clone(),
                pair.group_id.clone(),
                pair.repetition.to_string(),
                pair.case_a.clone(),
                pair.case_b.clone(),
                pair.expected_change.clone(),
                pair.observed_change
                    .clone()
                    .unwrap_or_else(|| "unavailable".into()),
            ]
        }),
    ));
    output.push_str("</details><details><summary>Subprocess diagnostics</summary>");
    output.push_str(&html_table(
        &[
            "System",
            "Spawn",
            "stderr bytes",
            "Overflow",
            "Exit",
            "Runner terminated",
        ],
        report.processes.iter().map(|process| {
            vec![
                process.system_id.clone(),
                process.spawn_index.to_string(),
                process.stderr_bytes.to_string(),
                process.stderr_overflow.to_string(),
                process.exit_status.map_or("N/A".into(), |n| n.to_string()),
                process.terminated_by_runner.to_string(),
            ]
        }),
    ));
    output.push_str("</details><footer><p class=\"muted\">Generated from verified saved rows. Reopen the run with please-eval bench view --run PATH. JSON and Markdown exports remain available.</p></footer></main></body></html>");
    output
}

pub fn require_terminal() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err("interactive results require terminal stdin and stdout; use bench report --format table or --format html instead".into());
    }
    Ok(())
}

pub fn show(report: &BenchReport) -> Result<()> {
    require_terminal()?;
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(error) => {
            ratatui::restore();
            return Err(error.into());
        }
    };
    let result = (|| -> Result<()> {
        let mut axis = 0;
        let mut state = TableState::default().with_selected(0);
        loop {
            terminal.draw(|frame| draw(frame, report, axis, &mut state))?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Tab | KeyCode::Right => {
                        axis = (axis + 1) % AXES.len();
                        state = TableState::default().with_selected(0);
                    }
                    KeyCode::BackTab | KeyCode::Left => {
                        axis = (axis + AXES.len() - 1) % AXES.len();
                        state = TableState::default().with_selected(0);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let len = report
                            .strata
                            .iter()
                            .filter(|row| row.axis == AXES[axis])
                            .count();
                        state.select(Some(
                            (state.selected().unwrap_or(0) + 1).min(len.saturating_sub(1)),
                        ));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        state.select(Some(state.selected().unwrap_or(0).saturating_sub(1)));
                    }
                    KeyCode::Home => state.select(Some(0)),
                    KeyCode::End => {
                        let len = report
                            .strata
                            .iter()
                            .filter(|row| row.axis == AXES[axis])
                            .count();
                        state.select(Some(len.saturating_sub(1)));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

fn draw(frame: &mut Frame, report: &BenchReport, axis: usize, state: &mut TableState) {
    let area = frame.area();
    if area.width < 90 || area.height < 24 {
        frame.render_widget(Paragraph::new("PLEASE results\nEnlarge terminal to at least 90 columns x 24 rows.\nq / Esc: quit. HTML report is also available.").wrap(Wrap { trim: false }), area);
        return;
    }
    let regions = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(8),
        Constraint::Length(3),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(format!(
            "Pack: {}\nRun: {}\n{}",
            safe(&report.pack_id),
            safe(&report.run_id),
            safe(&report.execution_posture)
        ))
        .block(
            Block::default()
                .title(" PLEASE benchmark | saved results verified ")
                .bold(),
        ),
        regions[0],
    );
    frame.render_widget(
        Tabs::new(LABELS)
            .select(axis)
            .highlight_style(Style::default().fg(Color::Yellow).bold()),
        regions[1],
    );
    let records: Vec<_> = report
        .strata
        .iter()
        .filter(|row| row.axis == AXES[axis])
        .collect();
    let widths = [
        Constraint::Percentage(17),
        Constraint::Percentage(7),
        Constraint::Percentage(16),
        Constraint::Percentage(4),
        Constraint::Percentage(12),
        Constraint::Percentage(4),
        Constraint::Percentage(11),
        Constraint::Percentage(11),
        Constraint::Percentage(11),
        Constraint::Percentage(7),
    ];
    let table = Table::new(
        records.iter().map(|row| {
            Row::new(
                cells(row)
                    .into_iter()
                    .map(|cell| cell.split(" (").next().unwrap_or(&cell).to_owned())
                    .collect::<Vec<_>>(),
            )
        }),
        widths,
    )
    .header(
        Row::new(HEADERS)
            .style(Style::default().fg(Color::Yellow))
            .height(2),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("> ");
    frame.render_stateful_widget(table, regions[2], state);
    let mut detail = state
        .selected()
        .and_then(|index| records.get(index))
        .map_or_else(|| "No results for this view.".into(), |row| details(row));
    if let Some(row) = state.selected().and_then(|index| records.get(index)) {
        if let Some(system) = report
            .systems
            .iter()
            .find(|system| system.system_id == row.system_id)
        {
            detail.push_str(&format!(
                "\nOperating point: {} | {}",
                safe(&system.operating_point.threshold),
                safe(&system.operating_point.description)
            ));
        }
    }
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::bordered().title(" Selected row (full values) "))
            .wrap(Wrap { trim: false }),
        regions[3],
    );
    frame.render_widget(Paragraph::new(format!(
        "Tab / arrows: view | j/k / up/down: row | Home/End | q: quit | Rates: count/denominator; gaps stay in denominator; N/A: no denominator\n{}",
        safe(&report.caveat)
    )).style(Style::default().fg(Color::Yellow)).wrap(Wrap { trim: false }), regions[4]);
}

#[cfg(test)]
mod tests {
    use super::super::report::MetricCounts;
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn sample() -> BenchReport {
        BenchReport {
            schema_version: "please-bench-report/v1".into(),
            run_id: "r".repeat(64),
            pack_id: "pilot".into(),
            pack_digest: "p".repeat(64),
            caveat: "Development evidence only".into(),
            execution_posture: "declared offline".into(),
            systems: vec![],
            processes: vec![],
            contextual_matrix: vec![],
            paired_changes: vec![],
            strata: vec![MetricRecord {
                system_id: "test-system".into(),
                surface: Surface::ArtifactDetection,
                axis: "surface".into(),
                value: "artifact_detection".into(),
                counts: MetricCounts {
                    rows: 10,
                    completed: 7,
                    positives: 6,
                    true_positives: 3,
                    false_negatives: 3,
                    negatives: 4,
                    false_positives: 1,
                    true_negatives: 3,
                    timeout: 3,
                    ..Default::default()
                },
            }],
        }
    }

    #[test]
    fn rates_preserve_denominators_and_zero_is_not_success() {
        assert_eq!(rate(1, 3), "1/3 (33.3%)");
        assert_eq!(rate(0, 0), "N/A");
        assert_eq!(
            rate(u64::MAX, u64::MAX),
            format!("{0}/{0} (100.0%)", u64::MAX)
        );
        let row = cells(&sample().strata[0]);
        assert_eq!(
            &row[4..9],
            &["7/10 (70.0%)", "3", "3/6 (50.0%)", "1/4 (25.0%)", "N/A"]
        );
    }

    #[test]
    fn html_and_terminal_neutralize_hostile_metadata() {
        let mut report = sample();
        report.pack_id = "<script>alert('x')</script>\u{1b}[2J\u{202e}".into();
        let output = render_html(&report);
        assert!(!output.contains("<script>"));
        assert!(output.contains("&lt;script&gt;"));
        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains('\u{202e}'));
        assert!(!render_table(&report).contains('\u{1b}'));
        assert!(output.contains("default-src 'none'"));
    }

    #[test]
    fn terminal_renders_summary_details_and_handles_small_sizes() {
        for (width, height) in [(160, 40), (90, 24), (40, 10)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    draw(
                        frame,
                        &sample(),
                        0,
                        &mut TableState::default().with_selected(0),
                    )
                })
                .unwrap();
            let buffer = terminal.backend().buffer();
            let text: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
            assert!(text.contains("PLEASE"));
            if width >= 90 {
                assert!(text.contains("test-system"));
                assert!(text.contains("timeout 3"));
            } else {
                assert!(text.contains("Enlarge"));
            }
        }
    }

    #[test]
    fn summary_does_not_double_count_overlapping_axes() {
        let mut report = sample();
        let mut duplicate = report.strata[0].clone();
        duplicate.axis = "technique".into();
        duplicate.value = "override".into();
        report.strata.push(duplicate);
        assert_eq!(render_table(&report).matches("test-system").count(), 1);
        assert!(render_html(&report).contains("override"));
    }
}
