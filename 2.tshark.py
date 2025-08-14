#!/usr/bin/env python3
import os
import glob
import subprocess
import shutil
import sys
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests
import geoip2.database
import geoip2.errors
from collections import defaultdict, Counter
import ipaddress




def download_geoip_database():
    """下載 GeoLite2-City 資料庫"""
    print("📡 開始下載 GeoLite2-City 資料庫...")
    
    # MaxMind 免費資料庫的直接連結 (需要註冊才能取得)
    # 這裡提供一個替代方案的示例
    db_url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
    
    try:
        response = requests.get(db_url, stream=True)
        response.raise_for_status()
        
        with open('GeoLite2-City.mmdb', 'wb') as f:
            shutil.copyfileobj(response.raw, f)
        
        print("✅ GeoLite2-City.mmdb 下載完成")
        return True
        
    except Exception as e:
        print(f"❌ 下載失敗: {e}")
        print("💡 請手動下載 GeoLite2-City.mmdb 並放置在專案根目錄")
        print("   下載位置: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        return False


def parse_time_intervals(total_duration_seconds):
    """將總時長分割成 10 分鐘區間"""
    intervals = []
    interval_seconds = 600  # 10 分鐘
    
    for start in range(0, int(total_duration_seconds) + 1, interval_seconds):
        end = min(start + interval_seconds, total_duration_seconds)
        intervals.append({
            'start_seconds': start,
            'end_seconds': end,
            'duration_minutes': (end - start) / 60
        })
    
    return intervals


def run_tshark_command(tshark_exe, pcap_file, fields, filter_expr=""):
    """執行 tshark 命令並返回結果"""
    cmd = [
        tshark_exe,
        "-r", pcap_file,
        "-T", "fields",
        "-E", "separator=|"
    ]
    
    # 添加字段
    for field in fields:
        cmd.extend(["-e", field])
    
    # 添加過濾器
    if filter_expr:
        cmd.extend(["-Y", filter_expr])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        if result.returncode != 0:
            print(f"⚠️ tshark 警告: {result.stderr}")
        return result.stdout.strip().split('\n') if result.stdout.strip() else []
    except Exception as e:
        print(f"❌ 執行 tshark 命令失敗: {e}")
        return []


def analyze_pcap_basic_info(tshark_exe, pcap_file):
    """分析 PCAP 文件的基本信息：時長、封包數、總流量"""
    print(f"📊 分析基本信息: {os.path.basename(pcap_file)}")
    
    # 獲取基本統計信息，包含IP和端口信息
    fields = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)
    
    if not lines or lines == ['']:
        return None
    
    timestamps = []
    total_bytes = 0
    packet_count = 0
    
    # 用於儲存每個10分鐘區間的統計
    per_10_minutes = {}
    per_10_minutes_ip_traffic = {}
    
    for line in lines:
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 8:
                try:
                    timestamp = float(parts[0])
                    frame_len = int(parts[1])
                    src_ip = parts[2] if parts[2] else ''
                    dst_ip = parts[3] if parts[3] else ''
                    tcp_src_port = parts[4] if parts[4] else ''
                    tcp_dst_port = parts[5] if parts[5] else ''
                    udp_src_port = parts[6] if parts[6] else ''
                    udp_dst_port = parts[7] if parts[7] else ''
                    
                    timestamps.append(timestamp)
                    total_bytes += frame_len
                    packet_count += 1
                    
                    # 將時間戳轉換為 datetime
                    dt = datetime.fromtimestamp(timestamp)
                    
                    # 計算10分鐘邊界：將分鐘數向下取整到10的倍數
                    minute_boundary = (dt.minute // 10) * 10
                    time_key = dt.replace(minute=minute_boundary, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M')
                    
                    # 初始化時間區間統計
                    if time_key not in per_10_minutes:
                        per_10_minutes[time_key] = 0
                        per_10_minutes_ip_traffic[time_key] = defaultdict(int)
                    
                    # 累加此時間區間的流量
                    per_10_minutes[time_key] += frame_len
                    
                    # 統計此時間區間的IP連接流量（包含端口）
                    if src_ip and dst_ip:
                        # 確定使用的端口
                        src_port = tcp_src_port or udp_src_port or ''
                        dst_port = tcp_dst_port or udp_dst_port or ''
                        
                        if src_port and dst_port:
                            connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                        else:
                            connection = f"{src_ip} -> {dst_ip}"
                        
                        per_10_minutes_ip_traffic[time_key][connection] += frame_len
                    
                except (ValueError, IndexError):
                    continue
    
    if not timestamps:
        return None
    
    start_time = min(timestamps)
    end_time = max(timestamps)
    
    # 按時間排序 per_10_minutes
    sorted_per_10_minutes = dict(sorted(per_10_minutes.items()))
    
    # 為每個10分鐘區間生成前5名IP流量統計
    top_ip_per_10_minutes = {}
    for time_key in sorted(per_10_minutes_ip_traffic.keys()):
        ip_traffic = per_10_minutes_ip_traffic[time_key]
        # 排序並取前5名
        top_connections = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ip_per_10_minutes[time_key] = [
            {
                'connection': connection,
                'bytes': bytes_count
            }
            for connection, bytes_count in top_connections
        ]
    
    return {
        'start_time': datetime.fromtimestamp(start_time).isoformat(),
        'end_time': datetime.fromtimestamp(end_time).isoformat(),
        'total_bytes': total_bytes,
        'per_10_minutes': sorted_per_10_minutes,
        'top_ip_per_10_minutes': top_ip_per_10_minutes
    }


def analyze_ip_traffic(tshark_exe, pcap_file):
    """分析 IP 之間的流量（前10名，包含 port），並記錄每個連接在不同時間段的流量"""
    print(f"🌐 分析 IP 流量: {os.path.basename(pcap_file)}")
    
    fields = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)
    
    connection_stats = defaultdict(int)
    connection_time_stats = defaultdict(lambda: defaultdict(int))
    
    for line in lines:
        if '|' in line and line.strip():
            parts = line.split('|')
            if len(parts) >= 8:
                try:
                    timestamp = float(parts[0]) if parts[0] else 0
                    src_ip = parts[1] if parts[1] else 'N/A'
                    dst_ip = parts[2] if parts[2] else 'N/A'
                    tcp_src_port = parts[3] if parts[3] else ''
                    tcp_dst_port = parts[4] if parts[4] else ''
                    udp_src_port = parts[5] if parts[5] else ''
                    udp_dst_port = parts[6] if parts[6] else ''
                    frame_len = int(parts[7]) if parts[7] else 0
                    
                    # 確定使用的端口
                    src_port = tcp_src_port or udp_src_port or ''
                    dst_port = tcp_dst_port or udp_dst_port or ''
                    
                    if src_ip != 'N/A' and dst_ip != 'N/A' and src_port and dst_port:
                        connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                        connection_stats[connection] += frame_len
                        
                        # 計算10分鐘時間段
                        if timestamp > 0:
                            dt = datetime.fromtimestamp(timestamp)
                            minute_boundary = (dt.minute // 10) * 10
                            time_key = dt.replace(minute=minute_boundary, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M')
                            connection_time_stats[connection][time_key] += frame_len
                        
                except (ValueError, IndexError):
                    continue
    
    # 排序並取前10名
    sorted_connections = sorted(connection_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    
    result = []
    for connection, bytes_total in sorted_connections:
        # 獲取該連接的前三個最高流量時間段
        time_stats = connection_time_stats[connection]
        top_time_periods = sorted(time_stats.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # 格式化前三名時間段資訊
        top_periods_info = []
        for i, (time_period, period_bytes) in enumerate(top_time_periods, 1):
            period_percentage = (period_bytes / bytes_total * 100) if bytes_total > 0 else 0
            top_periods_info.append({
                'rank': i,
                'time_period': time_period,
                'bytes': period_bytes,
                'percentage_of_total': round(period_percentage, 2)
            })
        
        result.append({
            'connection': connection,
            'bytes': bytes_total,
            'top_3_time_periods': top_periods_info
        })
    
    return result


def analyze_protocols(tshark_exe, pcap_file):
    """分析所有協議出現次數和前5名連接統計"""
    print(f"🔍 分析協議統計: {os.path.basename(pcap_file)}")
    
    # 定義需要追蹤的協議列表
    target_protocols = {
        'DNS', 'DHCP', 'SMTP', 'TCP', 'TLS', 'SNMP', 
        'HTTP', 'FTP', 'SMB3', 'SMB2', 'SMB', 'HTTPS', 'ICMP'
    }
    
    # 獲取協議統計
    fields = ["frame.protocols", "ip.src", "ip.dst", "frame.len"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)
    
    protocol_stats = {}
    other_stats = {
        'count': 0,
        'top_ip': '',
        'ip_stats': defaultdict(int),
        'connections': defaultdict(lambda: {'packet_count': 0, 'packet_size': 0})
    }
    
    for line in lines:
        if '|' in line and line.strip():
            parts = line.split('|')
            if len(parts) >= 4:
                try:
                    protocols = parts[0].split(':') if parts[0] else []
                    src_ip = parts[1] if parts[1] else 'N/A'
                    dst_ip = parts[2] if parts[2] else 'N/A'
                    frame_len = int(parts[3]) if parts[3] else 0
                    
                    # 找出最高層協議（通常是最後一個）
                    main_protocol = None
                    if protocols:
                        # 檢查協議鏈中是否有目標協議，從後往前找（優先高層協議）
                        found_protocol = None
                        for protocol in reversed(protocols):
                            protocol_upper = protocol.upper()
                            if protocol_upper in target_protocols:
                                found_protocol = protocol_upper
                                break
                        
                        # 如果找到目標協議，使用它；否則歸類為 other
                        if found_protocol:
                            main_protocol = found_protocol
                        else:
                            main_protocol = 'OTHER'
                        
                        # 初始化協議統計
                        if main_protocol != 'OTHER':
                            if main_protocol not in protocol_stats:
                                protocol_stats[main_protocol] = {
                                    'count': 0,
                                    'top_ip': '',
                                    'ip_stats': defaultdict(int),
                                    'connections': defaultdict(lambda: {'packet_count': 0, 'packet_size': 0})
                                }
                            target_stats = protocol_stats[main_protocol]
                        else:
                            target_stats = other_stats
                        
                        target_stats['count'] += 1
                        
                        # 統計 IP 出現次數，找出 top_ip
                        if src_ip != 'N/A':
                            target_stats['ip_stats'][src_ip] += 1
                        if dst_ip != 'N/A':
                            target_stats['ip_stats'][dst_ip] += 1
                        
                        # 統計連接
                        if src_ip != 'N/A' and dst_ip != 'N/A':
                            conn_key = f"{src_ip} -> {dst_ip}"
                            target_stats['connections'][conn_key]['packet_count'] += 1
                            target_stats['connections'][conn_key]['packet_size'] += frame_len
                            
                except (ValueError, IndexError):
                    continue
    
    # 將 other 統計加入結果
    if other_stats['count'] > 0:
        protocol_stats['OTHER'] = other_stats
    
    # 整理結果
    result = {}
    for protocol, stats in protocol_stats.items():
        # 找出出現最多次的 IP 作為 top_ip
        top_ip = ''
        if stats['ip_stats']:
            top_ip = max(stats['ip_stats'].items(), key=lambda x: x[1])[0]
        
        # 獲取前5名連接
        connections_list = []
        for conn_key, conn_stats in stats['connections'].items():
            src_ip, dst_ip = conn_key.split(' -> ')
            connections_list.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_count': conn_stats['packet_count'],
                'packet_size': conn_stats['packet_size']
            })
        
        # 按流量大小排序取前5名
        connections_list.sort(key=lambda x: x['packet_size'], reverse=True)
        
        result[protocol] = {
            'count': stats['count'],
            'top_ip': top_ip,
            'detailed_stats': connections_list[:5]
        }
    
    return result


def analyze_ip_countries(tshark_exe, pcap_file, geo_reader):
    """統計所有 IP 的國別，使用國家代碼並統計流量"""
    print(f"🗺️ 分析 IP 國別: {os.path.basename(pcap_file)}")
    
    fields = ["ip.src", "ip.dst", "frame.len"]
    lines = run_tshark_command(tshark_exe, pcap_file, fields)
    
    country_bytes = defaultdict(int)
    
    for line in lines:
        if '|' in line and line.strip():
            parts = line.split('|')
            if len(parts) >= 3:
                try:
                    src_ip = parts[0] if parts[0] else None
                    dst_ip = parts[1] if parts[1] else None
                    frame_len = int(parts[2]) if parts[2] else 0
                    
                    # 處理來源 IP
                    if src_ip:
                        country_code = get_country_code(geo_reader, src_ip)
                        if country_code:
                            country_bytes[country_code] += frame_len
                    
                    # 處理目標 IP
                    if dst_ip:
                        country_code = get_country_code(geo_reader, dst_ip)
                        if country_code:
                            country_bytes[country_code] += frame_len
                            
                except (ValueError, IndexError):
                    continue
    
    # 轉換為所需格式並排序
    result = dict(sorted(country_bytes.items(), key=lambda x: x[1], reverse=True))
    
    return result


def get_country_code(geo_reader, ip_address):
    """獲取 IP 地址的國家代碼"""
    if not geo_reader or not ip_address:
        return None
    
    try:
        # 檢查是否為私有 IP
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return 'LOCAL'  # 本地網路統一使用 LOCAL
        
        response = geo_reader.city(ip_address)
        if response.country.iso_code:
            return response.country.iso_code
        else:
            return 'UNKNOWN'
    except (geoip2.errors.AddressNotFoundError, ValueError, Exception):
        return 'UNKNOWN'




def process_pcap_file(pcap_file, out_base, tshark_exe, geo_reader):
    """
    處理單個 PCAP 文件的函數
    """
    print(f"\n🔍 開始處理: {os.path.basename(pcap_file)}")
    
    try:
        # 1. 分析基本信息（總流量、總時長、總封包數）
        flow_info = analyze_pcap_basic_info(tshark_exe, pcap_file)
        if not flow_info:
            return f"❌ 無法分析 {pcap_file} 的基本信息"
        
        # 2. 分析 IP 流量 (top connections)
        top_connections = analyze_ip_traffic(tshark_exe, pcap_file)
        
        # 3. 分析協議統計 (events)
        events = analyze_protocols(tshark_exe, pcap_file)
        
        # 4. 分析 IP 國別 (geo)
        geo = analyze_ip_countries(tshark_exe, pcap_file, geo_reader)
        
        # 組合結果為新格式
        result = {
            'flow': flow_info,
            'top_ip': top_connections,
            'event': events,
            'geo': geo,
            'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 保存結果到 JSON 文件
        pcap_name = Path(pcap_file).stem
        output_file = os.path.join(out_base, f"{pcap_name}_analysis.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"✅ 完成處理: {os.path.basename(pcap_file)} -> {output_file}")
        return result
        
    except Exception as e:
        error_msg = f"❌ 處理 {pcap_file} 時發生錯誤: {e}"
        print(error_msg)
        return error_msg


def merge_all_results(results, out_base):
    """合併所有結果並生成總結報告"""
    print("\n📊 生成總結報告...")
    
    # 初始化總結數據
    merged_flow = {
        'start_time': None,
        'end_time': None,
        'total_bytes': 0,
        'per_10_minutes': defaultdict(int),
        'top_ip_per_10_minutes': defaultdict(lambda: defaultdict(int))
    }
    
    merged_top_ip = defaultdict(int)
    merged_top_ip_time_stats = defaultdict(lambda: defaultdict(int))  # 新增：合併時間段統計
    merged_events = {}
    merged_geo = defaultdict(int)
    
    processed_count = 0
    
    for result in results:
        if isinstance(result, dict) and 'flow' in result:
            processed_count += 1
            
            # 合併 flow 數據
            flow = result['flow']
            
            # 設定開始和結束時間
            if merged_flow['start_time'] is None or flow['start_time'] < merged_flow['start_time']:
                merged_flow['start_time'] = flow['start_time']
            if merged_flow['end_time'] is None or flow['end_time'] > merged_flow['end_time']:
                merged_flow['end_time'] = flow['end_time']
            
            # 累加總流量
            merged_flow['total_bytes'] += flow['total_bytes']
            
            # 合併 10 分鐘統計
            for time_key, bytes_val in flow['per_10_minutes'].items():
                merged_flow['per_10_minutes'][time_key] += bytes_val
            
            # 合併每個10分鐘區間的前5名IP統計
            if 'top_ip_per_10_minutes' in flow:
                for time_key, top_conn_list in flow['top_ip_per_10_minutes'].items():
                    for conn_info in top_conn_list:
                        connection = conn_info['connection']
                        bytes_count = conn_info['bytes']
                        merged_flow['top_ip_per_10_minutes'][time_key][connection] += bytes_count
            
            # 合併 top_ip 數據（包含時間段統計）
            for conn_info in result['top_ip']:
                connection = conn_info['connection']
                merged_top_ip[connection] += conn_info['bytes']
                
                # 合併時間段統計
                if 'top_3_time_periods' in conn_info:
                    for period_info in conn_info['top_3_time_periods']:
                        time_period = period_info['time_period']
                        period_bytes = period_info['bytes']
                        merged_top_ip_time_stats[connection][time_period] += period_bytes
            
            # 合併 event 數據
            for protocol, protocol_data in result['event'].items():
                if protocol not in merged_events:
                    merged_events[protocol] = {
                        'count': 0,
                        'top_ip': protocol_data['top_ip'],
                        'ip_stats': defaultdict(int),
                        'connections': defaultdict(lambda: {'packet_count': 0, 'packet_size': 0})
                    }
                
                merged_events[protocol]['count'] += protocol_data['count']
                
                # 合併詳細統計
                for stat in protocol_data['detailed_stats']:
                    conn_key = f"{stat['src_ip']} -> {stat['dst_ip']}"
                    merged_events[protocol]['connections'][conn_key]['packet_count'] += stat['packet_count']
                    merged_events[protocol]['connections'][conn_key]['packet_size'] += stat['packet_size']
            
            # 合併 geo 數據
            for country_code, bytes_val in result['geo'].items():
                merged_geo[country_code] += bytes_val
    
    # 整理最終結果
    # Top IP connections (前10名) - 重新計算前三名時間段
    top_connections = []
    for connection, total_bytes in sorted(merged_top_ip.items(), key=lambda x: x[1], reverse=True)[:10]:
        # 重新計算該連接的前三個最高流量時間段
        time_stats = merged_top_ip_time_stats[connection]
        top_time_periods = sorted(time_stats.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # 格式化前三名時間段資訊
        top_periods_info = []
        for i, (time_period, period_bytes) in enumerate(top_time_periods, 1):
            period_percentage = (period_bytes / total_bytes * 100) if total_bytes > 0 else 0
            top_periods_info.append({
                'rank': i,
                'time_period': time_period,
                'bytes': period_bytes,
                'percentage_of_total': round(period_percentage, 2)
            })
        
        top_connections.append({
            'connection': connection,
            'bytes': total_bytes,
            'top_3_time_periods': top_periods_info
        })
    
    # Events - 重新整理每個協議的前5名連接
    final_events = {}
    for protocol, data in merged_events.items():
        connections_list = []
        for conn_key, conn_stats in data['connections'].items():
            src_ip, dst_ip = conn_key.split(' -> ')
            connections_list.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packet_count': conn_stats['packet_count'],
                'packet_size': conn_stats['packet_size']
            })
        
        # 按流量大小排序取前5名
        connections_list.sort(key=lambda x: x['packet_size'], reverse=True)
        
        final_events[protocol] = {
            'count': data['count'],
            'top_ip': data['top_ip'],
            'detailed_stats': connections_list[:5]
        }
    
    # Geo - 按流量排序
    final_geo = dict(sorted(merged_geo.items(), key=lambda x: x[1], reverse=True))
    
    # 轉換 per_10_minutes 為普通 dict 並按時間排序
    sorted_per_10_minutes = dict(sorted(merged_flow['per_10_minutes'].items()))
    merged_flow['per_10_minutes'] = sorted_per_10_minutes
    
    # 處理每個10分鐘區間的前5名IP統計
    final_top_ip_per_10_minutes = {}
    for time_key in sorted(merged_flow['top_ip_per_10_minutes'].keys()):
        ip_traffic = merged_flow['top_ip_per_10_minutes'][time_key]
        # 排序並取前5名
        top_interval_connections = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:5]
        final_top_ip_per_10_minutes[time_key] = [
            {
                'connection': connection,
                'bytes': bytes_count
            }
            for connection, bytes_count in top_interval_connections
        ]
    
    merged_flow['top_ip_per_10_minutes'] = final_top_ip_per_10_minutes
    
    total_summary = {
        'summary': {
            'total_files_processed': processed_count,
            'analysis_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        'flow': merged_flow,
        'top_ip': top_connections,
        'event': final_events,
        'geo': final_geo
    }
    
    # 保存總結報告
    summary_file = os.path.join(out_base, "analysis_summary.json")
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(total_summary, f, ensure_ascii=False, indent=2)
    
    print(f"✅ 總結報告已保存: {summary_file}")
    return total_summary




def main():
    # 從用戶獲取代碼
    code = input("請輸入代碼: ")
    pcap_dir = input("請輸入 pcap 目錄: ")
    
    # 設定路徑
    tshark_exe = r"C:\Program Files\Wireshark\tshark.exe"
    pcap_dir = pcap_dir.strip()  # 去除首尾空格
    out_base = os.path.join("project", code)

    # 檢查 GeoIP 資料庫是否存在，若不存在則下載
    if not os.path.exists('GeoLite2-City.mmdb'):
        download_geoip_database()
    else:
        print("✅ GeoIP 資料庫已存在")

    # 初始化 GeoIP 讀取器
    geo_reader = None
    try:
        geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        print("✅ GeoIP 資料庫載入成功")
    except Exception as e:
        print(f"⚠️ 無法載入 GeoIP 資料庫: {e}")
        print("將跳過國別分析功能")

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
    max_workers = min(8, len(pcap_files)) if len(pcap_files) > 1 else 1

    print(f"\n🚀 開始分析 PCAP 文件...")
    print(f"📋 分析項目:")
    print(f"   1. 總流量、總時長、總封包數（每10分鐘統計）")
    print(f"   2. IP間流量統計（前10名，含端口）")
    print(f"   3. 協議統計（含前5名連接）")
    print(f"   4. IP國別統計（使用GeoLite2）")
    print(f"   📤 結果將匯出為JSON格式\n")
    
    start_time = time.time()
    
    if max_workers > 1:
        print(f"使用 {max_workers} 個線程同時處理 PCAP 文件...")
        
        # 使用線程池處理多個 PCAP 文件
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任務
            future_to_pcap = {
                executor.submit(process_pcap_file, pcap_file, out_base, tshark_exe, geo_reader): pcap_file 
                for pcap_file in pcap_files
            }
            
            # 等待所有任務完成並收集結果
            results = []
            completed = 0
            for future in as_completed(future_to_pcap):
                pcap_file = future_to_pcap[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    print(f"進度: {completed}/{len(pcap_files)} 完成")
                except Exception as exc:
                    error_msg = f"處理 {pcap_file} 時發生異常: {exc}"
                    print(error_msg)
                    results.append(error_msg)
                    completed += 1
    else:
        print("單線程處理 PCAP 文件...")
        # 單線程處理
        results = []
        for i, pcap_file in enumerate(pcap_files, 1):
            print(f"進度: {i}/{len(pcap_files)}")
            result = process_pcap_file(pcap_file, out_base, tshark_exe, geo_reader)
            results.append(result)
    
    # 生成總結報告
    summary = merge_all_results(results, out_base)
    
    end_time = time.time()
    processing_time = end_time - start_time
    
    print(f"\n🎉 分析完成!")
    print(f"⏱️ 總處理時間: {processing_time:.2f} 秒")
    print(f"📁 結果保存在: {out_base}")
    print(f"📊 處理了 {summary['summary']['total_files_processed']} 個文件")
    print(f" 總流量: {summary['flow']['total_bytes']:,} bytes ({summary['flow']['total_bytes']/1024/1024:.2f} MB)")
    
    # 關閉 GeoIP 讀取器
    if geo_reader:
        geo_reader.close()


if __name__ == "__main__":
    main()