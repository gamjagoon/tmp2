use std::process::{Command, Output};
use std::str;
use std::io;
use std::fs::File;
use std::io::Write;
use chrono::Local;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::layout::{Layout, Constraint, Direction};
use ratatui::style::{Style, Color};

fn main() -> Result<(), io::Error> {
    // 터미널 초기화
    enable_raw_mode()?;
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut devices = Vec::new();
    let mut selected_device = 0;

    loop {
        // ADB 디바이스 목록 업데이트
        devices = get_connected_devices("adb").unwrap_or_else(|_| vec![]);
        
        terminal.draw(|f| {
            // 레이아웃 설정
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Percentage(80)].as_ref())
                .split(f.size());

            // 디바이스 목록 표시
            let items: Vec<ListItem> = devices.iter()
                .map(|d| ListItem::new(d.clone()))
                .collect();
            
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Devices"))
                .highlight_style(Style::default().bg(Color::LightGreen));

            // 명령어 입력 안내
            let help = Paragraph::new("Press 'a' for ADB command, 'f' for Fastboot command, 'p' for PowerShell command, 'q' to quit")
                .block(Block::default().borders(Borders::ALL).title("Help"));

            // 렌더링
            f.render_widget(list, chunks[1]);
            f.render_widget(help, chunks[0]);
        })?;

        // 입력 이벤트 처리
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => {
                    // 'q' 키로 종료
                    disable_raw_mode()?;
                    terminal.show_cursor()?;
                    break;
                }
                KeyCode::Char('a') => {
                    if !devices.is_empty() {
                        // ADB 명령어 실행
                        execute_command("adb", &devices[selected_device]);
                    }
                }
                KeyCode::Char('f') => {
                    if !devices.is_empty() {
                        // Fastboot 명령어 실행
                        execute_command("fastboot", &devices[selected_device]);
                    }
                }
                KeyCode::Char('p') => {
                    if !devices.is_empty() {
                        // PowerShell 명령어 실행 및 로그 파일 생성
                        execute_powershell_command(&devices[selected_device]);
                    }
                }
                KeyCode::Down => {
                    if selected_device < devices.len() - 1 {
                        selected_device += 1;
                    }
                }
                KeyCode::Up => {
                    if selected_device > 0 {
                        selected_device -= 1;
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn get_connected_devices(command: &str) -> Result<Vec<String>, io::Error> {
    let output = Command::new(command)
        .arg("devices")
        .output()?;

    let output_str = str::from_utf8(&output.stdout).unwrap();
    let mut devices = Vec::new();

    for line in output_str.lines() {
        if line.ends_with("device") {
            devices.push(line.split_whitespace().next().unwrap().to_string());
        }
    }

    Ok(devices)
}

fn execute_command(command: &str, serial: &str) {
    let mut input = String::new();
    println!("Enter {} command for device {}: ", command, serial);
    io::stdin().read_line(&mut input).expect("Failed to read input");

    let output = Command::new(command)
        .args(&["-s", serial, &input.trim()])
        .output()
        .expect("Failed to execute command");

    println!("{}", str::from_utf8(&output.stdout).unwrap());
}

fn execute_powershell_command(serial: &str) {
    let mut input = String::new();
    println!("Enter PowerShell command for device {}: ", serial);
    io::stdin().read_line(&mut input).expect("Failed to read input");

    let timestamp = Local::now().format("%m%d_%H%M%S").to_string();
    let filename = format!("{}_{}_{}.log", serial, input.trim(), timestamp);
    let command = format!("{} > {}", input.trim(), filename);

    Command::new("powershell")
        .args(&["-NoExit", "-Command", &format!("Start-Process powershell -ArgumentList '-NoExit', '-Command', \"{}\"", command)])
        .spawn()
        .expect("Failed to start PowerShell");

    println!("Output will be logged to {}", filename);
}
