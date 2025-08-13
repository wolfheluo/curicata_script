#!/usr/bin/env python3
"""
Suricata PCAP 分析腳本
這個腳本會掃描 pcap 目錄中的所有 .pcap 文件，
使用 Suricata 進行分析，並將結果合併到一個 fast.log 文件中。
包含日誌過濾功能，可以去除低優先級和重複的記錄。
"""

import os
import glob
import subprocess
import shutil
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def extract_key_fields(line):
    """
    從日誌行中提取關鍵字段，用於去重和過濾
    返回 None 表示該行應該被過濾掉
    """
    # 過濾 Priority 3 的記錄
    if "Priority: 3" in line:
        return None
    
    # 過濾特定的 ET INFO 記錄
    if "ET INFO HTTP Request to a" in line and ".tw domain" in line:
        return None
    
    # 過濾 ET DNS Query for .cc TLD 記錄
    if "ET DNS Query for .cc TLD" in line:
        return None

    # 尋找事件開始標記
    event_start = line.find("[**]")
    if event_start == -1:
        return None
    event = line[event_start:]

    # 提取源IP和目標IP
    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+", line)
    if not ip_match:
        return None
    src_ip, dst_ip = ip_match.groups()

    return (event, src_ip, dst_ip)

def filter_log_file(input_file, output_file):
    """
    過濾日誌文件，去除低優先級和重複記錄
    """
    if not os.path.exists(input_file):
        print(f"找不到檔案：{input_file}")
        return False

    seen = set()
    count = 0

    try:
        with open(input_file, "r", encoding="utf-8") as infile, \
             open(output_file, "w", encoding="utf-8") as outfile:

            for line in infile:
                key = extract_key_fields(line)
                if key and key not in seen:
                    seen.add(key)
                    outfile.write(line)
                    count += 1

        print(f"✅ 過濾完成，共保留 {count} 筆 Priority: 1 和 2 的唯一記錄")
        print(f"📄 過濾結果已儲存至：{output_file}")
        return True
        
    except Exception as e:
        print(f"錯誤: 過濾日誌文件時發生異常: {e}")
        return False

def process_pcap_file(pcap_file, out_base, suricata_exe):
    """
    處理單個 PCAP 文件的函數
    """
    pcap_path = Path(pcap_file)
    name = pcap_path.stem  # 不含副檔名的文件名
    out_dir = os.path.join(out_base, name)
    
    # 創建輸出子目錄
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception as e:
        return f"錯誤: 無法創建目錄 {out_dir}: {e}"
    
    thread_id = threading.current_thread().name
    print(f"[線程 {thread_id}] 開始處理 {pcap_file}...")
    
    # 執行 Suricata
    try:
        cmd = [suricata_exe, "-r", pcap_file, "-l", out_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        
        if result.returncode == 0:
            message = f"[線程 {thread_id}] ✓ 成功分析 {pcap_file}"
            print(message)
            return message
        else:
            error_msg = f"[線程 {thread_id}] ✗ 分析失敗 {pcap_file}\n錯誤輸出: {result.stderr}"
            print(error_msg)
            return error_msg
            
    except Exception as e:
        error_msg = f"[線程 {thread_id}] 錯誤: 執行 Suricata 時發生異常: {e}"
        print(error_msg)
        return error_msg

def main():
    # 從用戶獲取代碼
    code = input("請輸入代碼: ")
    pcap_dir = input("請輸入 pcap 目錄: ")
    
    filter_logs = True


    # 設定路徑
    suricata_exe = r"C:\Program Files\Suricata\suricata.exe"
    pcap_dir = pcap_dir.strip()  # 去除首尾空格
    out_base = os.path.join("project", code)
    
    # 檢查 Suricata 是否存在
    if not os.path.exists(suricata_exe):
        print(f"錯誤: 找不到 Suricata 執行檔 {suricata_exe}")
        return
    
    # 檢查 pcap 目錄是否存在
    if not os.path.exists(pcap_dir):
        print(f"錯誤: 找不到 pcap 目錄 {pcap_dir}")
        return
    
    # 創建輸出目錄
    try:
        os.makedirs(out_base, exist_ok=True)
        print(f"創建輸出目錄: {out_base}")
    except Exception as e:
        print(f"錯誤: 無法創建輸出目錄 {out_base}: {e}")
        return
    
    # 尋找所有 .pcap 文件
    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap"))
    
    if not pcap_files:
        print(f"警告: 在 {pcap_dir} 目錄中沒有找到 .pcap 文件")
        return
    
    print(f"找到 {len(pcap_files)} 個 PCAP 文件")
    
    # 決定使用的線程數量
    max_workers = min(4, len(pcap_files)) if len(pcap_files) > 4 else 1
    
    if max_workers > 1:
        print(f"使用 {max_workers} 個線程同時處理 PCAP 文件...")
        
        # 使用線程池處理多個 PCAP 文件
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任務
            future_to_pcap = {
                executor.submit(process_pcap_file, pcap_file, out_base, suricata_exe): pcap_file 
                for pcap_file in pcap_files
            }
            
            # 等待所有任務完成並收集結果
            results = []
            for future in as_completed(future_to_pcap):
                pcap_file = future_to_pcap[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    error_msg = f"處理 {pcap_file} 時發生異常: {exc}"
                    print(error_msg)
                    results.append(error_msg)
    else:
        print("單線程處理 PCAP 文件...")
        # 單線程處理
        results = []
        for pcap_file in pcap_files:
            result = process_pcap_file(pcap_file, out_base, suricata_exe)
            results.append(result)
    
    print("分析完成，正在合併結果...")
    
    # 合併所有 fast.log 文件
    merged_fast_path = os.path.join(out_base, "merged_fast.log")
    
    try:
        with open(merged_fast_path, 'w', encoding='utf-8') as merged_file:
            # 尋找所有 fast.log 文件
            fast_log_files = glob.glob(os.path.join(out_base, "*", "fast.log"))
            
            if fast_log_files:
                for fast_log in fast_log_files:
                    print(f"合併 {fast_log}")
                    try:
                        with open(fast_log, 'r', encoding='utf-8') as f:
                            merged_file.write(f.read())
                    except Exception as e:
                        print(f"警告: 讀取 {fast_log} 時發生錯誤: {e}")
                
                print(f"✓ 合併完成，結果儲存於 {merged_fast_path}")
                
                # 如果用戶選擇過濾日誌，則進行過濾
                if filter_logs:
                    print("開始過濾日誌文件...")
                    filtered_path = os.path.join(out_base, "filtered_merged_fast.log")
                    if filter_log_file(merged_fast_path, filtered_path):
                        print(f"✓ 日誌過濾完成")
                    else:
                        print("✗ 日誌過濾失敗")
            else:
                print("警告: 沒有找到任何 fast.log 文件進行合併")
                
    except Exception as e:
        print(f"錯誤: 無法創建合併文件 {merged_fast_path}: {e}")

if __name__ == "__main__":
    main()
