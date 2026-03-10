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

use aya::{Ebpf, include_bytes_aligned, programs::TracePoint};
use aya::maps::{PerCpuArray, HashMap as BpfHashMap};
use aya::util::online_cpus;
use std::sync::mpsc::Sender;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use crate::common::DaemonEvent;
use crate::monitor::app_detect;
use log::{info, warn, debug};

/// 获取与 BPF ktime_get_ns() 绝对对齐的单调时钟时间 (纳秒)
fn get_ktime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn get_thread_tids(pid: u32) -> Vec<u32> {
    let task_dir = format!("/proc/{}/task", pid);
    let mut tids = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&task_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(tid) = name.parse::<u32>() {
                    tids.push(tid);
                }
            }
        }
    }
    tids
}

pub async fn start_cpu_loop(tx: Sender<DaemonEvent>) -> Result<(), anyhow::Error> {
    static BPF_DATA: &[u8] = include_bytes_aligned!(env!("BPF_CPU_OBJ_PATH"));
    
    let bpf = Box::leak(Box::new(Ebpf::load(BPF_DATA)?));
    let program: &mut TracePoint = bpf.program_mut("handle_sched_switch").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;
    info!("eBPF System Load monitor started (Long-task blind spot fixed).");

    // 获取准确的物理在线核心列表
    let online_cpus_list = online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?;
    let max_cpu_id = online_cpus_list.iter().copied().max().unwrap_or(0) as usize;
    info!("Detected online CPU core IDs: {:?}", online_cpus_list);

    let bpf_ptr = bpf as *mut Ebpf;

    let core_idle_map: PerCpuArray<_, u64> = PerCpuArray::try_from(
        unsafe { &mut *bpf_ptr }.map_mut("core_idle_time").unwrap()
    )?;
    let core_busy_map: PerCpuArray<_, u64> = PerCpuArray::try_from(
        unsafe { &mut *bpf_ptr }.map_mut("core_busy_time").unwrap()
    )?;
    // [新增] 用于读取最后切换时间
    let core_last_time_map: PerCpuArray<_, u64> = PerCpuArray::try_from(
        unsafe { &mut *bpf_ptr }.map_mut("core_last_time").unwrap()
    )?;
    // [新增] 用于读取当前跑的 TID
    let core_current_tid_map: PerCpuArray<_, u32> = PerCpuArray::try_from(
        unsafe { &mut *bpf_ptr }.map_mut("core_current_tid").unwrap()
    )?;
    let thread_run_map: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(
        unsafe { &mut *bpf_ptr }.map_mut("thread_run_time").unwrap()
    )?;

    let shared_pid = Arc::new(AtomicU32::new(app_detect::get_current_pid() as u32));
    let pid_arc = shared_pid.clone();

    tokio::spawn(async move {
        let mut last_pid: u32 = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let current_pid = app_detect::get_current_pid() as u32;
            if current_pid != last_pid && current_pid > 0 {
                pid_arc.store(current_pid, Ordering::Relaxed);
                debug!("CPU monitor: foreground PID updated {} \u{2192} {}", last_pid, current_pid);
                last_pid = current_pid;
            }
        }
    });

    tokio::spawn(async move {
        // 根据最大 CPU ID 初始化历史记录向量，避免越界
        let mut last_idle_times = vec![0u64; max_cpu_id + 1];
        let mut last_busy_times = vec![0u64; max_cpu_id + 1];
        let mut last_check_time = get_ktime_ns();
        let mut last_thread_run: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
        let mut log_counter: u32 = 0;
        
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));
        
        loop {
            interval.tick().await;
            let now_ktime = get_ktime_ns();
            let real_delta_ns = now_ktime.saturating_sub(last_check_time);
            last_check_time = now_ktime;

            if real_delta_ns == 0 { continue; }

            let zero_key: u32 = 0;
            let per_cpu_idle_values = core_idle_map.get(&zero_key, 0);
            let per_cpu_busy_values = core_busy_map.get(&zero_key, 0);
            let per_cpu_last_time = core_last_time_map.get(&zero_key, 0);
            let per_cpu_current_tid = core_current_tid_map.get(&zero_key, 0);

            let mut core_utils = Vec::with_capacity(online_cpus_list.len());

            // 1. 全局单核利用率计算（带有实时状态补偿）
            for &cpu_id in &online_cpus_list {
                let idx = cpu_id as usize;
                
                let raw_idle = per_cpu_idle_values.as_ref().ok().and_then(|v| v.get(idx)).copied().unwrap_or(0);
                let raw_busy = per_cpu_busy_values.as_ref().ok().and_then(|v| v.get(idx)).copied().unwrap_or(0);
                let last_switch_time = per_cpu_last_time.as_ref().ok().and_then(|v| v.get(idx)).copied().unwrap_or(0);
                let current_tid = per_cpu_current_tid.as_ref().ok().and_then(|v| v.get(idx)).copied().unwrap_or(0);

                let mut adj_idle = raw_idle;
                let mut adj_busy = raw_busy;

                // 计算当前正在执行的任务积累但未触发 sched_switch 的时间
                let mut pending_delta = now_ktime.saturating_sub(last_switch_time);
                if pending_delta > 1_000_000_000 { 
                    pending_delta = 0; // 防御性保护，剔除极大异常值
                }

                if current_tid == 0 {
                    adj_idle += pending_delta;
                } else {
                    adj_busy += pending_delta;
                }

                let idle_diff = adj_idle.saturating_sub(last_idle_times[idx]);
                let busy_diff = adj_busy.saturating_sub(last_busy_times[idx]);
                let total_diff = idle_diff + busy_diff;

                let util = if total_diff > 0 {
                    (busy_diff as f32 / total_diff as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };

                core_utils.push(util);
                last_idle_times[idx] = adj_idle;
                last_busy_times[idx] = adj_busy;
            }

            // 2. 前台应用最重线程的利用率计算（带有实时状态补偿）
            let foreground_max_util = {
                let fg_pid = shared_pid.load(Ordering::Relaxed);
                if fg_pid == 0 {
                    0.0_f32
                } else {
                    let tids = get_thread_tids(fg_pid);
                    let mut max_util: f32 = 0.0;
                    let mut current_thread_run = std::collections::HashMap::with_capacity(tids.len());

                    for &tid in &tids {
                        let mut adj_thread_time = thread_run_map.get(&tid, 0).unwrap_or(0);

                        // 如果该线程正在某个核心上跑，补上它的 Pending Delta
                        for &cpu_id in &online_cpus_list {
                            let idx = cpu_id as usize;
                            let current_tid_on_core = per_cpu_current_tid.as_ref().ok().and_then(|v| v.get(idx)).copied().unwrap_or(0);
                            
                            if current_tid_on_core == tid {
                                let last_switch_time = per_cpu_last_time.as_ref().ok().and_then(|v| v.get(idx)).copied().unwrap_or(0);
                                let pending_delta = now_ktime.saturating_sub(last_switch_time);
                                if pending_delta < 1_000_000_000 {
                                    adj_thread_time += pending_delta;
                                }
                            }
                        }

                        current_thread_run.insert(tid, adj_thread_time);

                        if let Some(&last_run) = last_thread_run.get(&tid) {
                            if adj_thread_time >= last_run {
                                let thread_delta = adj_thread_time - last_run;
                                let util = (thread_delta as f32 / real_delta_ns as f32).clamp(0.0, 1.0);
                                if util > max_util {
                                    max_util = util;
                                }
                            }
                        }
                    }
                    
                    last_thread_run = current_thread_run;
                    max_util
                }
            };

            log_counter += 1;
            if log_counter % 25 == 0 {
                debug!("CPU monitor: cores=[{}] fg_pid={} fg_max_util={:.1}% threads_tracked={} delta={}ms",
                    core_utils.iter()
                        .map(|u| format!("{:.0}%", u * 100.0))
                        .collect::<Vec<_>>()
                        .join(", "),
                    shared_pid.load(Ordering::Relaxed),
                    foreground_max_util * 100.0,
                    last_thread_run.len(),
                    real_delta_ns / 1_000_000);
            }

            if tx.send(DaemonEvent::SystemLoadUpdate {
                core_utils,
                foreground_max_util,
            }).is_err() {
                warn!("CPU monitor: channel closed, exiting loop.");
                break;
            }
        }
    });

    std::future::pending::<()>().await;
    Ok(())
}