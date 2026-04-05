/*
 * Copyright (C) 2026 yuki
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use dumpsys_rs::Dumpsys;
use inotify::{Inotify, WatchMask};
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::config::{self, RulesConfig};
use crate::common::DaemonEvent;
use crate::fluent_args;
use crate::i18n::{t, t_with_args};
use crate::utils;

static CURRENT_PID: AtomicI32 = AtomicI32::new(0);

// 获取系统已启用的输入法列表
fn get_system_ime_packages() -> HashSet<String> {
    let mut imes = HashSet::new();

    let output = Command::new("settings")
        .arg("get")
        .arg("secure")
        .arg("enabled_input_methods")
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for entry in stdout.split(':') {
            if let Some(pkg) = entry.split('/').next() {
                let clean_pkg = pkg.trim();
                if !clean_pkg.is_empty() {
                    imes.insert(clean_pkg.to_string());
                    debug!(
                        "{}",
                        t_with_args("app-detect-ime-auto", &fluent_args!("pkg" => clean_pkg))
                    );
                }
            }
        }
    }

    if imes.is_empty() {
        warn!("{}", t("app-detect-ime-fallback"));
        imes.insert("com.sohu.inputmethod.sogou.xiaomi".to_string());
        imes.insert("com.sohu.inputmethod.sogouoem".to_string());
        imes.insert("com.google.android.inputmethod.latin".to_string());
        imes.insert("com.baidu.input_mi".to_string());
        imes.insert("com.iflytek.inputmethod.miui".to_string());
    }

    imes
}

lazy_static::lazy_static! {
    static ref CURRENT_PACKAGE: Arc<Mutex<String>> = Arc::new(Mutex::new("".to_string()));
    static ref IME_BLOCKLIST: HashSet<String> = get_system_ime_packages();
}

pub fn get_current_pid() -> i32 {
    CURRENT_PID.load(Ordering::Relaxed)
}

// 在检测到新包名时更新它
fn set_current_package(pkg: &str, pid: i32) {
    *CURRENT_PACKAGE.lock().unwrap() = pkg.to_string();
    CURRENT_PID.store(pid, Ordering::Relaxed);
}

// ==================== [核心：纯 Dumpsys 检测逻辑] ====================

#[derive(Default)]
struct WindowsInfo {
    pub visible_freeform_window: bool,
    pub pid: i32,
}

impl WindowsInfo {
    pub fn new(dump: &str) -> Self {
        let pid = Self::parse_top_app(dump);
        let visible_freeform_window = dump.contains("freeform")
            || dump.contains("FlexibleTaskCaptionView")
            || dump.contains("FlexibleTaskIndicatorView");

        Self {
            visible_freeform_window,
            pid,
        }
    }

    fn parse_top_app(dump: &str) -> i32 {
        let Some(focused_app_line) = dump
            .lines()
            .find(|line| line.trim().starts_with("mFocusedApp="))
        else {
            return 0;
        };
        let Some(package_name) = Self::extract_package_name(focused_app_line) else {
            return 0;
        };

        // Try modern parser, if it fails, fall back to legacy parser.
        let pid = Self::parse_a16_format(dump, package_name)
            .or_else(|| Self::parse_a15_format(dump, package_name));

        pid.unwrap_or(0)
    }

    fn extract_package_name(line: &str) -> Option<&str> {
        line.split_whitespace()
            .find(|p| p.contains('/'))?
            .split('/')
            .next()
    }

    // Modern Parser (Android 16+)
    // Parses the PID from the `WINDOW MANAGER WINDOWS` section.
    fn parse_a16_format(dump: &str, package_name: &str) -> Option<i32> {
        let mut in_target_window_section = false;
        for line in dump.lines() {
            if in_target_window_section {
                if line.contains("mSession=") {
                    let session_part = line.split("mSession=").nth(1)?;
                    let content_start = session_part.find('{')? + 1;
                    let content_end = session_part.find('}')?;
                    let content = &session_part[content_start..content_end];
                    let pid_part = content.split_whitespace().nth(1)?;
                    let pid_str = pid_part.split(':').next()?;
                    return pid_str.parse::<i32>().ok();
                }

                if line.contains("Window #") {
                    return None;
                }
            } else if line.contains("Window #") && line.contains(package_name) {
                in_target_window_section = true;
            }
        }
        None
    }

    // Legacy Parser (Android 15 and older)
    // Parses the PID from the `WINDOW MANAGER SESSIONS` section.
    fn parse_a15_format(dump: &str, package_name: &str) -> Option<i32> {
        let mut last_pid_found: Option<i32> = None;
        for line in dump.lines() {
            if line.starts_with("  Session Session{") {
                let content_start = line.find('{')? + 1;
                let content_end = line.find('}')?;
                let content = &line[content_start..content_end];
                let pid_part = content.split_whitespace().nth(1)?;
                let pid_str = pid_part.split(':').next()?;
                last_pid_found = pid_str.parse::<i32>().ok();
            }

            let trimmed_line = line.trim();
            if trimmed_line.starts_with("mPackageName=")
                && let Some(pkg) = trimmed_line.split('=').nth(1)
                && pkg == package_name
            {
                return last_pid_found;
            }
        }
        None
    }
}

fn get_focused_app(ignored_apps: &[String]) -> Result<(String, i32, bool), Box<dyn Error>> {
    let mut dumper = loop {
        match Dumpsys::new() {
            Ok(b) => break b,
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    };
    dumper.insert_service("window")?;
    let dump = dumper.dump("window", &["visible-apps"])?;
    let info = WindowsInfo::new(&dump);
    let pkg = utils::get_process_name(info.pid)?;

    if ignored_apps.iter().any(|s| s != &pkg) || !IME_BLOCKLIST.contains(&pkg) {
        Ok((pkg, info.pid, info.visible_freeform_window))
    } else {
        Err("No valid app found".into())
    }
}

// ==================== [辅助函数] ====================

fn determine_mode(config: &RulesConfig, current_package: &str) -> String {
    if !config.dynamic_enabled {
        return config.global_mode.clone();
    }
    config
        .app_modes
        .get(current_package)
        .cloned()
        .unwrap_or_else(|| config.global_mode.clone())
}

pub fn get_default_rules() -> RulesConfig {
    RulesConfig {
        yumi_scheduler: true,
        dynamic_enabled: true,
        global_mode: "balance".to_string(),
        app_modes: HashMap::new(),
        ignored_apps: Vec::new(),
        fas_rules: super::config::FasRulesConfig::default(),
    }
}

pub fn watch_config_file(
    config_arc: Arc<Mutex<RulesConfig>>,
    force_refresh_arc: Arc<AtomicBool>,
    tx: Sender<DaemonEvent>,
) -> Result<(), Box<dyn Error>> {
    let mut inotify = Inotify::init()?;
    let rules_path = config::get_rules_path();
    if !rules_path.exists() {
        let _ = utils::try_write_file(&rules_path, "");
    }
    inotify
        .watches()
        .add(&rules_path, WatchMask::MODIFY | WatchMask::CLOSE_WRITE)?;
    info!(
        "{}",
        t_with_args(
            "app-detect-config-watch",
            &fluent_args!("path" => format!("{:?}", rules_path))
        )
    );
    let mut buffer = [0u8; 1024];
    loop {
        let events = inotify.read_events_blocking(&mut buffer)?;
        if events.peekable().peek().is_some() {
            info!("{}", t("app-detect-change-detected"));
            thread::sleep(Duration::from_millis(100));
            while let Ok(events) = inotify.read_events(&mut buffer) {
                if events.peekable().peek().is_none() {
                    break;
                }
            }
            info!("{}", t("app-detect-reloading"));

            let new_config =
                config::read_config::<RulesConfig, _>(&rules_path).unwrap_or_else(|e| {
                    warn!(
                        "{}",
                        t_with_args(
                            "app-detect-load-failed",
                            &fluent_args!("error" => e.to_string())
                        )
                    );
                    get_default_rules()
                });

            *config_arc.lock().unwrap() = new_config.clone();

            if let Err(e) = tx.send(DaemonEvent::ConfigReload(new_config)) {
                warn!("[Config] Failed to send ConfigReload event: {}", e);
            }

            info!("{}", t("app-detect-reload-success"));
            force_refresh_arc.store(true, Ordering::SeqCst);
        }
    }
}

pub fn app_detection_loop(
    config_arc: Arc<Mutex<RulesConfig>>,
    screen_state_arc: Arc<Mutex<bool>>,
    force_refresh_arc: Arc<AtomicBool>,
    tx: Sender<DaemonEvent>,
) -> Result<(), Box<dyn Error>> {
    info!("{}", t("app-detect-loop-started"));

    let temp_sensor_path = utils::find_cpu_temp_path().unwrap_or_default();
    let mut last_package = String::new();
    let mut last_mode = String::new();
    let mut last_screen_state = true;

    // 状态机变量：用于无阻塞防抖
    let mut pending_package = String::new();
    let mut pending_pid = 0;
    let mut debounce_start = Instant::now();

    loop {
        let force_refresh = force_refresh_arc.swap(false, Ordering::SeqCst);
        let current_screen_state = { *screen_state_arc.lock().unwrap() };

        if current_screen_state != last_screen_state {
            info!(
                "{}",
                t_with_args(
                    "app-detect-screen-changed",
                    &fluent_args!("old" => last_screen_state.to_string(), "new" => current_screen_state.to_string())
                )
            );
            last_screen_state = current_screen_state;
            let _ = tx.send(DaemonEvent::ScreenStateChange(current_screen_state));

            if current_screen_state {
                last_package.clear();
                pending_package.clear();
                last_mode.clear();
                force_refresh_arc.store(true, Ordering::SeqCst);
            }
        }

        if !current_screen_state {
            thread::sleep(Duration::from_secs(1));
            continue;
        }

        // 合并锁获取：一次拿完所有需要的数据
        let config_snapshot = config_arc.lock().unwrap().clone();
        let ignored_apps = config_snapshot.ignored_apps.clone();

        let (detected_pkg, detected_pid, visible_freeform_window) = get_focused_app(&ignored_apps)
            .unwrap_or_else(|_| (last_package.clone(), get_current_pid(), false));

        let mut final_pkg = last_package.clone();
        let mut final_pid = get_current_pid();

        // 无阻塞防抖逻辑
        if detected_pkg != last_package && !detected_pkg.is_empty() {
            if detected_pkg != pending_package {
                pending_package = detected_pkg.clone();
                pending_pid = detected_pid;
                debounce_start = Instant::now();
            } else if debounce_start.elapsed() >= Duration::from_millis(500) {
                final_pkg = pending_package.clone();
                final_pid = pending_pid;
                pending_package.clear();
            }
        } else {
            pending_package.clear();
        }

        let current_temp = if !temp_sensor_path.is_empty() {
            utils::read_file_content(&temp_sensor_path)?
                .parse::<f64>()
                .unwrap_or(0.0)
                / 1000.0
        } else {
            0.0
        };

        if (last_package != final_pkg || force_refresh) && !final_pkg.is_empty() {
            set_current_package(&final_pkg, final_pid);
            // 使用已获取的 config_snapshot，不再重复加锁
            let new_mode = determine_mode(&config_snapshot, &final_pkg);

            if last_mode != new_mode || force_refresh {
                info!(
                    "{}",
                    t_with_args(
                        "app-detect-mode-change-pkg",
                        &fluent_args!("old" => last_mode.clone(), "new" => new_mode.as_str(), "pkg" => final_pkg.as_str())
                    )
                );
                // ModeChange 事件现在携带 pid 字段
                let _ = tx.send(DaemonEvent::ModeChange {
                    package_name: final_pkg.clone(),
                    pid: final_pid,
                    mode: new_mode.clone(),
                    temperature: current_temp,
                    visible_freeform_window,
                });
                last_mode = new_mode;
            }
            last_package = final_pkg;
        }

        thread::sleep(Duration::from_millis(1500));
    }
}
