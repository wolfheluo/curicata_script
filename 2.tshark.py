#!/usr/bin/env python3
import os
import glob
import subprocess
import shutil
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading



def process_pcap_file(pcap_file, out_base, tshark_exe):
    """
    處理單個 PCAP 文件的函數
    """
    pcap_path = Path(pcap_file)
    name = pcap_path.stem  # 不含副檔名的文件名
    out_dir = os.path.join(out_base, name)




def main():
    # 從用戶獲取代碼
    code = input("請輸入代碼: ")
    pcap_dir = input("請輸入 pcap 目錄: ")
    

    # 設定路徑
    tshark_exe = r"C:\Program Files\Wireshark\tshark.exe"
    pcap_dir = pcap_dir.strip()  # 去除首尾空格
    out_base = os.path.join("project", code)

    # 檢查 tshark 是否存在
    if not os.path.exists(tshark_exe):
        print(f"錯誤: 找不到 tshark 執行檔 {tshark_exe}")
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
                executor.submit(process_pcap_file, pcap_file, out_base, tshark_exe): pcap_file 
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
            result = process_pcap_file(pcap_file, out_base, tshark_exe)
            results.append(result)
    
    print("分析完成...")