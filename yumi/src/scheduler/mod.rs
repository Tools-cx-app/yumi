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

use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::Instant;
use anyhow::Result;

pub mod config;
pub mod scheduler;
pub mod fas;
pub mod cpu_load_governor;

use crate::i18n::{t, load_language, t_with_args};
use crate::fluent_args; 
use crate::utils; 
use crate::common::DaemonEvent; 
use config::Config;
use scheduler::CpuScheduler;
use crate::logger;
use crate::common;

// 动态获取系统中实际可用的 CPU Policy
pub fn get_cpu_policies() -> Vec<i32> {
    let mut policies = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu/cpufreq") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("policy") {
                    if let Ok(pid) = name["policy".len()..].parse::<i32>() {
                        policies.push(pid);
                    }
                }
            }
        }
    }
    policies.sort_unstable();
    policies
}

pub fn start_scheduler_thread(rx: mpsc::Receiver<DaemonEvent>) -> Result<()> {
    let root = common::get_module_root();
    let config_path = root.join("config/config.yaml");
    let config_dir = root.join("config"); 

    let config = Config::from_file(config_path.to_str().unwrap()).unwrap_or_default();

    let shared_config = Arc::new(RwLock::new(config));
    let shared_mode_name = Arc::new(Mutex::new("balance".to_string())); 
    let sys_path_exist = Arc::new(utils::SysPathExist::new());

    // Config Watcher 线程
    let config_clone = shared_config.clone();
    let mode_clone = shared_mode_name.clone();
    let sys_path_clone = sys_path_exist.clone();
    
    thread::Builder::new()
        .name("config_watcher".to_string())
        .spawn(move || {
            loop {
                if let Err(e) = utils::watch_path(&config_dir) {
                    log::error!("{}", t_with_args("config-watch-error", &fluent_args!("error" => e.to_string())));
                    continue;
                }
                log::info!("{}", t("config-reloading"));

                let old_lang = config_clone.read().unwrap().meta.language.clone();
                
                match Config::from_file(config_path.to_str().unwrap()) {
                    Ok(new_config) => {
                        logger::update_level(&new_config.meta.loglevel);
                        *config_clone.write().unwrap() = new_config;
                        
                        let new_lang = config_clone.read().unwrap().meta.language.clone();
                        if old_lang != new_lang { load_language(&new_lang); }

                        log::info!("{}", t("config-reloaded-success"));

                        let scheduler = CpuScheduler::new(config_clone.clone(), mode_clone.clone(), sys_path_clone.clone());
                        if let Err(e) = scheduler.apply_all_settings() {
                            log::error!("{}", t_with_args("config-apply-mode-failed", &fluent_args!("error" => e.to_string())));
                        }
                        if let Err(e) = scheduler.apply_system_tweaks() {
                            log::error!("{}", t_with_args("config-apply-tweaks-failed", &fluent_args!("error" => e.to_string())));
                        }
                    }
                    Err(load_err) => log::error!("{}", t_with_args("config-reload-fail", &fluent_args!("error" => load_err.to_string()))),
                }
            }
        })?;
    
    log::info!("{}", t("main-config-watch-thread-create"));

    // IPC 监听主线程
    let config_clone = shared_config.clone();
    let mode_clone = shared_mode_name.clone();
    let sys_path_clone = sys_path_exist.clone();

    thread::Builder::new()
        .name("scheduler_ipc".to_string())
        .spawn(move || {
            log::info!("{}", t("scheduler-ipc-started"));
            
            let root = common::get_module_root();
            let mode_file_path = root.join("current_mode.txt");
            
            let mut fas_controller = crate::scheduler::fas::FasController::new();
            let mut cpu_governor = crate::scheduler::cpu_load_governor::CpuLoadGovernor::new();

            let rules_path = crate::monitor::config::get_rules_path();
            let mut current_rules = crate::monitor::config::read_config::<crate::monitor::config::RulesConfig, _>(&rules_path).unwrap_or_default();

            // FAS 挂起状态现在完全作为本地变量管理
            let mut fas_suspended_at: Option<Instant> = None;
            let mut fas_suspended_package = String::new();
            const FAS_SUSPEND_GRACE_SECS: u64 = 5;

            let temp_sensor_path = crate::utils::find_cpu_temp_path().unwrap_or_default();
            let mut last_temp_update = Instant::now();

            let apply_static_mode = |config: &Arc<RwLock<Config>>, mode: &Arc<Mutex<String>>, sys_path: &Arc<utils::SysPathExist>| {
                let scheduler = CpuScheduler::new(config.clone(), mode.clone(), sys_path.clone());
                if let Err(e) = scheduler.apply_all_settings() { log::error!("{}", t_with_args("scheduler-apply-failed", &fluent_args!("error" => e.to_string()))); }
            };

            // 从 Scheduler Config 中提取当前性能模式对应的 CLG 配置
            let get_clg_cfg = |config: &Config, mode: &str| -> config::CpuLoadGovernorConfig {
                config.get_mode(mode).map(|m| m.cpu_load_governor.clone()).unwrap_or_default()
            };

            {
                let current_mode = mode_clone.lock().unwrap().clone();
                if current_mode != "fas" {
                    let config_lock = config_clone.read().unwrap();
                    let clg_cfg = get_clg_cfg(&config_lock, &current_mode);
                    if clg_cfg.enabled {
                        cpu_governor.init_policies(&clg_cfg);
                        log::info!("CPU Load Governor: initialized at startup (mode={})", current_mode);
                    }
                }
            }
            
            for msg in rx {
                match msg {
                    DaemonEvent::ModeChange { package_name, pid, mode, temperature } => {
                        let mut current_mode_lock = mode_clone.lock().unwrap();
                        let old_mode = current_mode_lock.clone();
                        
                        if old_mode != mode {
                            log::info!("{}", t_with_args("scheduler-mode-change-request", &fluent_args!(
                                "old" => old_mode.clone(), "new" => mode.as_str(), "pkg" => package_name.as_str(), "temp" => temperature
                            )));
                            
                            *current_mode_lock = mode.clone();
                            drop(current_mode_lock); 

                            let _ = utils::try_write_file(&mode_file_path, mode.as_bytes());

                            if mode == "fas" {
                                cpu_governor.release();

                                let can_resume = fas_suspended_at.map_or(false, |at| {
                                    at.elapsed().as_secs() < FAS_SUSPEND_GRACE_SECS && fas_suspended_package == package_name && !fas_controller.policies.is_empty()
                                });

                                if can_resume {
                                    fas_suspended_at = None;
                                    fas_suspended_package.clear();
                                    for policy in &mut fas_controller.policies { policy.force_reapply(); }
                                    fas_controller.set_game(pid, &package_name);
                                    fas_controller.set_temperature(temperature);
                                    fas_controller.set_temp_threshold(current_rules.fas_rules.core_temp_threshold);
                                } else {
                                    fas_suspended_at = None;
                                    fas_suspended_package.clear();
                                    fas_controller.load_policies(&current_rules.fas_rules);
                                    fas_controller.set_game(pid, &package_name);
                                    fas_controller.set_temperature(temperature);
                                    fas_controller.set_temp_threshold(current_rules.fas_rules.core_temp_threshold);
                                }
                            } else {
                                if fas_suspended_at.is_some() {
                                    fas_controller.reset_all_freqs();
                                    fas_controller.clear_game();
                                    fas_controller.policies.clear();
                                    fas_suspended_at = None;
                                    fas_suspended_package.clear();
                                }

                                if old_mode == "fas" && !fas_controller.policies.is_empty() {
                                    fas_suspended_at = Some(Instant::now());
                                    fas_suspended_package = package_name.clone();
                                } else if old_mode == "fas" {
                                    fas_controller.clear_game();
                                    fas_controller.policies.clear();
                                    fas_suspended_at = None;
                                    fas_suspended_package.clear();
                                }

                                apply_static_mode(&config_clone, &mode_clone, &sys_path_clone);

                                let config_lock = config_clone.read().unwrap();
                                let clg_cfg = get_clg_cfg(&config_lock, &mode);
                                if clg_cfg.enabled {
                                    cpu_governor.init_policies(&clg_cfg);
                                } else {
                                    cpu_governor.release();
                                }
                            }
                        } else if mode == "fas" {
                            fas_controller.set_temperature(temperature);
                        }
                    },
                    DaemonEvent::SystemLoadUpdate { core_utils, foreground_max_util } => {
                        let current_mode = mode_clone.lock().unwrap().clone();
                        // 仅当当前是 fas 且未被挂起时，才将负载投喂给 FAS
                        if current_mode == "fas" && fas_suspended_at.is_none() {
                            fas_controller.update_cpu_util(foreground_max_util);
                            fas_controller.update_core_utils(&core_utils);
                        }
                        if cpu_governor.is_active() {
                            cpu_governor.on_load_update(&core_utils);
                        }
                    },
                    DaemonEvent::FrameUpdate { fps: _, frame_delta_ns } => {
                        let current_mode = mode_clone.lock().unwrap().clone();
                        if current_mode == "fas" {
                            if !temp_sensor_path.is_empty() && last_temp_update.elapsed().as_secs() >= 3 {
                                if let Ok(raw_temp) = crate::utils::read_f64_from_file(&temp_sensor_path) { fas_controller.set_temperature(raw_temp / 1000.0); }
                                last_temp_update = Instant::now();
                            }
                            fas_controller.update_frame(frame_delta_ns);
                        }
                    }
                    DaemonEvent::ConfigReload(new_rules) => {
                        current_rules = new_rules;
                        let current_mode = mode_clone.lock().unwrap().clone();
                        
                        if current_mode == "fas" {
                            if fas_controller.policies.is_empty() {
                                fas_controller.load_policies(&current_rules.fas_rules);
                            } else {
                                fas_controller.reload_rules(&current_rules.fas_rules);
                            }
                        } else {
                            let config_lock = config_clone.read().unwrap();
                            let clg_cfg = get_clg_cfg(&config_lock, &current_mode);
                            if clg_cfg.enabled {
                                if cpu_governor.is_active() { cpu_governor.reload_config(&clg_cfg); } 
                                else { cpu_governor.init_policies(&clg_cfg); }
                            } else if cpu_governor.is_active() {
                                cpu_governor.release();
                                apply_static_mode(&config_clone, &mode_clone, &sys_path_clone);
                            }
                        }
                    }
                }

                if let Some(suspended_at) = fas_suspended_at {
                    if suspended_at.elapsed().as_secs() >= FAS_SUSPEND_GRACE_SECS {
                        fas_controller.reset_all_freqs();
                        fas_controller.clear_game();
                        fas_controller.policies.clear();
                        fas_suspended_at = None;
                        fas_suspended_package.clear();
                    }
                }
            }
            log::warn!("{}", t("scheduler-channel-closed"));
        })?;

    Ok(())
}