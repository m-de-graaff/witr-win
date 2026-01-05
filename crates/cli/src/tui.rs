//! Interactive TUI mode for witr-win
//!
//! Provides a terminal user interface for browsing processes,
//! searching, filtering, and viewing details.

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::io;
use witr_platform_windows::{list_processes, ProcessEntry};

/// Application state
struct App {
    /// All processes
    processes: Vec<ProcessEntry>,
    /// Filtered processes (based on search)
    filtered: Vec<usize>,
    /// Current table selection state
    table_state: TableState,
    /// Search query
    search: String,
    /// Is search input active
    search_active: bool,
    /// Selected process for detail view
    detail_pid: Option<u32>,
    /// Should quit
    should_quit: bool,
    /// Status message
    status: String,
    /// Sort column (0=PID, 1=Name, 2=Memory)
    sort_column: usize,
    /// Sort ascending
    sort_ascending: bool,
}

impl App {
    fn new() -> Result<Self, String> {
        let process_map =
            list_processes().map_err(|e| format!("Failed to list processes: {}", e))?;
        let mut processes: Vec<ProcessEntry> = process_map.into_values().collect();
        processes.sort_by_key(|p| p.pid);

        let filtered: Vec<usize> = (0..processes.len()).collect();

        let mut app = App {
            processes,
            filtered,
            table_state: TableState::default(),
            search: String::new(),
            search_active: false,
            detail_pid: None,
            should_quit: false,
            status: "Press '/' to search, Enter to analyze, 'q' to quit".to_string(),
            sort_column: 0,
            sort_ascending: true,
        };

        if !app.filtered.is_empty() {
            app.table_state.select(Some(0));
        }

        Ok(app)
    }

    fn refresh(&mut self) -> Result<(), String> {
        let process_map =
            list_processes().map_err(|e| format!("Failed to list processes: {}", e))?;
        self.processes = process_map.into_values().collect();
        self.apply_sort();
        self.apply_filter();
        self.status = format!("Refreshed: {} processes", self.processes.len());
        Ok(())
    }

    fn apply_filter(&mut self) {
        if self.search.is_empty() {
            self.filtered = (0..self.processes.len()).collect();
        } else {
            let query = self.search.to_lowercase();
            self.filtered = self
                .processes
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    p.exe_name.to_lowercase().contains(&query) || p.pid.to_string().contains(&query)
                })
                .map(|(i, _)| i)
                .collect();
        }

        // Reset selection
        if self.filtered.is_empty() {
            self.table_state.select(None);
        } else {
            self.table_state.select(Some(0));
        }
    }

    fn apply_sort(&mut self) {
        match self.sort_column {
            0 => {
                if self.sort_ascending {
                    self.processes.sort_by_key(|p| p.pid);
                } else {
                    self.processes.sort_by_key(|p| std::cmp::Reverse(p.pid));
                }
            }
            1 => {
                if self.sort_ascending {
                    self.processes
                        .sort_by(|a, b| a.exe_name.to_lowercase().cmp(&b.exe_name.to_lowercase()));
                } else {
                    self.processes
                        .sort_by(|a, b| b.exe_name.to_lowercase().cmp(&a.exe_name.to_lowercase()));
                }
            }
            2 => {
                if self.sort_ascending {
                    self.processes.sort_by_key(|p| p.thread_count);
                } else {
                    self.processes
                        .sort_by_key(|p| std::cmp::Reverse(p.thread_count));
                }
            }
            _ => {}
        }
    }

    fn toggle_sort(&mut self, column: usize) {
        if self.sort_column == column {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = column;
            self.sort_ascending = true;
        }
        self.apply_sort();
        self.apply_filter();
    }

    fn next(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.filtered.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn previous(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn page_down(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => (i + 20).min(self.filtered.len() - 1),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn page_up(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => i.saturating_sub(20),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn selected_process(&self) -> Option<&ProcessEntry> {
        self.table_state
            .selected()
            .and_then(|i| self.filtered.get(i))
            .and_then(|&idx| self.processes.get(idx))
    }
}

/// Run the interactive TUI
#[allow(dead_code)]
pub fn run_interactive() -> Result<(), String> {
    // Setup terminal
    enable_raw_mode().map_err(|e| format!("Failed to enable raw mode: {}", e))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| format!("Failed to enter alternate screen: {}", e))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("Failed to create terminal: {}", e))?;

    // Create app state
    let mut app = App::new()?;

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    result
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), String> {
    loop {
        terminal
            .draw(|f| ui(f, app))
            .map_err(|e| format!("Failed to draw: {}", e))?;

        if let Event::Key(key) =
            event::read().map_err(|e| format!("Failed to read event: {}", e))?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            if app.search_active {
                match key.code {
                    KeyCode::Esc => {
                        app.search_active = false;
                        app.status = "Search cancelled".to_string();
                    }
                    KeyCode::Enter => {
                        app.search_active = false;
                        app.apply_filter();
                        app.status = format!("Found {} matches", app.filtered.len());
                    }
                    KeyCode::Backspace => {
                        app.search.pop();
                        app.apply_filter();
                    }
                    KeyCode::Char(c) => {
                        app.search.push(c);
                        app.apply_filter();
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('/') => {
                        app.search_active = true;
                        app.search.clear();
                        app.status = "Type to search...".to_string();
                    }
                    KeyCode::Char('r') => {
                        if let Err(e) = app.refresh() {
                            app.status = format!("Refresh failed: {}", e);
                        }
                    }
                    KeyCode::Char('1') => app.toggle_sort(0),
                    KeyCode::Char('2') => app.toggle_sort(1),
                    KeyCode::Char('3') => app.toggle_sort(2),
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    KeyCode::PageDown => app.page_down(),
                    KeyCode::PageUp => app.page_up(),
                    KeyCode::Home => app.table_state.select(Some(0)),
                    KeyCode::End => {
                        if !app.filtered.is_empty() {
                            app.table_state.select(Some(app.filtered.len() - 1));
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(proc) = app.selected_process() {
                            // Return the selected PID for analysis
                            app.detail_pid = Some(proc.pid);
                            app.should_quit = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Table
            Constraint::Length(3), // Status/Search
        ])
        .split(f.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "witr-win ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("Interactive Mode", Style::default().fg(Color::White)),
        Span::raw(" │ "),
        Span::styled(
            format!("{} processes", app.filtered.len()),
            Style::default().fg(Color::Green),
        ),
        Span::raw(" │ "),
        Span::styled(
            "↑↓:Navigate  Enter:Analyze  /:Search  r:Refresh  1-3:Sort  q:Quit",
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title(""));
    f.render_widget(header, chunks[0]);

    // Process table
    let sort_indicator = |col: usize| {
        if app.sort_column == col {
            if app.sort_ascending {
                " ▲"
            } else {
                " ▼"
            }
        } else {
            ""
        }
    };

    let header_cells = [
        format!("PID{}", sort_indicator(0)),
        format!("Name{}", sort_indicator(1)),
        format!("Threads{}", sort_indicator(2)),
        "Parent".to_string(),
    ];
    let header_row = Row::new(header_cells.iter().map(|h| Cell::from(h.as_str())))
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .height(1);

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .filter_map(|&idx| app.processes.get(idx))
        .map(|proc| {
            let cells = vec![
                Cell::from(proc.pid.to_string()),
                Cell::from(proc.exe_name.clone()),
                Cell::from(proc.thread_count.to_string()),
                Cell::from(proc.ppid.to_string()),
            ];
            Row::new(cells).height(1)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Min(30),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(" Processes "))
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, chunks[1], &mut app.table_state.clone());

    // Status bar / Search input
    let status_content = if app.search_active {
        Line::from(vec![
            Span::styled("Search: ", Style::default().fg(Color::Yellow)),
            Span::styled(&app.search, Style::default().fg(Color::White)),
            Span::styled(
                "█",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
        ])
    } else if !app.search.is_empty() {
        Line::from(vec![
            Span::styled("Filter: ", Style::default().fg(Color::Cyan)),
            Span::styled(&app.search, Style::default().fg(Color::White)),
            Span::raw(" │ "),
            Span::styled(&app.status, Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(Span::styled(
            &app.status,
            Style::default().fg(Color::DarkGray),
        ))
    };

    let status = Paragraph::new(status_content).block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[2]);
}

/// Get the selected PID from interactive mode (if any)
pub fn run_interactive_and_get_pid() -> Result<Option<u32>, String> {
    enable_raw_mode().map_err(|e| format!("Failed to enable raw mode: {}", e))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| format!("Failed to enter alternate screen: {}", e))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("Failed to create terminal: {}", e))?;

    let mut app = App::new()?;
    let _ = run_app(&mut terminal, &mut app);

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    Ok(app.detail_pid)
}
