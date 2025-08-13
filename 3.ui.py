#!/usr/bin/env python3
"""
PCAP 分析器 Web UI
基於 Flask + Bootstrap 5 + Chart.js 構建的網路封包分析介面

功能包括：
- 任務總覽：管理分析任務，查看狀態
- 流量趨勢：折線圖顯示流量變化
- Top IP：長條圖與表格展示流量排行
- 國別統計：圓餅圖顯示連線來源分布
- 事件分析：網路事件統計與來源分析
- 異常警示：安全威脅清單與詳細說明
"""

import os
import json
import glob
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import subprocess
import threading
import time
from collections import defaultdict, Counter
import ipaddress
import re


app = Flask(__name__)
app.secret_key = 'suricata_pcap_analyzer_secret_key_2025'

# 配置
PCAP_DIR = "pcaps"
PROJECT_DIR = "project"
TSHARK_EXE = r"C:\Program Files\Wireshark\tshark.exe"

# 確保目錄存在
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(PROJECT_DIR, exist_ok=True)


def get_tasks():
    """取得所有分析任務"""
    tasks = []
    
    # 掃描 pcaps 目錄下的資料夾
    if os.path.exists(PCAP_DIR):
        for item in os.listdir(PCAP_DIR):
            item_path = os.path.join(PCAP_DIR, item)
            if os.path.isdir(item_path):
                # 檢查是否有 .pcap 檔案
                pcap_files = glob.glob(os.path.join(item_path, "*.pcap"))
                if pcap_files:
                    task = {
                        'name': item,
                        'path': item_path,
                        'pcap_count': len(pcap_files),
                        'created_time': datetime.fromtimestamp(os.path.getctime(item_path)),
                        'analyzed': False,
                        'total_bytes': None,
                        'total_events': None,
                        'anomaly_count': 0,
                        'start_time': None,
                        'end_time': None
                    }
                    
                    # 檢查是否已分析
                    project_dir = os.path.join(PROJECT_DIR, item)
                    summary_file = os.path.join(project_dir, "analysis_summary.json")
                    
                    if os.path.exists(summary_file):
                        try:
                            with open(summary_file, 'r', encoding='utf-8') as f:
                                summary = json.load(f)
                            
                            task['analyzed'] = True
                            task['total_bytes'] = summary.get('flow', {}).get('total_bytes', 0)
                            task['start_time'] = summary.get('flow', {}).get('start_time', '')
                            task['end_time'] = summary.get('flow', {}).get('end_time', '')
                            
                            # 計算總事件數
                            events = summary.get('event', {})
                            total_events = sum(event.get('count', 0) for event in events.values())
                            task['total_events'] = total_events
                            
                            # 計算異常數（這裡可以根據實際需求定義異常判斷邏輯）
                            task['anomaly_count'] = detect_anomalies(summary)
                            
                        except Exception as e:
                            print(f"讀取分析結果失敗: {e}")
                    
                    tasks.append(task)
    
    # 按建立時間排序
    tasks.sort(key=lambda x: x['created_time'], reverse=True)
    return tasks


def detect_anomalies(summary):
    """檢測異常行為（示例邏輯）"""
    anomaly_count = 0
    
    try:
        # 1. 檢查是否有可疑的大流量連接
        top_ip = summary.get('top_ip', [])
        if top_ip and len(top_ip) > 0:
            # 如果最大流量超過100MB，視為可疑
            max_bytes = top_ip[0].get('bytes', 0)
            if max_bytes > 100 * 1024 * 1024:  # 100MB
                anomaly_count += 1
        
        # 2. 檢查是否有異常協議比例
        events = summary.get('event', {})
        total_events = sum(event.get('count', 0) for event in events.values())
        
        if total_events > 0:
            # 檢查 TLS 流量是否過多（超過總流量的80%）
            tls_count = events.get('TLS', {}).get('count', 0)
            if tls_count / total_events > 0.8:
                anomaly_count += 1
        
        # 3. 檢查是否有來自可疑國家的大量流量
        geo = summary.get('geo', {})
        total_geo_bytes = sum(geo.values())
        
        if total_geo_bytes > 0:
            # 檢查非本地和台灣以外的流量比例
            suspicious_bytes = 0
            for country, bytes_val in geo.items():
                if country not in ['LOCAL', 'TW', 'US']:  # 可調整信任清單
                    suspicious_bytes += bytes_val
            
            if suspicious_bytes / total_geo_bytes > 0.3:  # 超過30%來自其他國家
                anomaly_count += 1
        
    except Exception as e:
        print(f"異常檢測錯誤: {e}")
    
    return anomaly_count


def run_analysis(task_name):
    """執行分析任務"""
    def analysis_thread():
        try:
            print(f"開始分析任務: {task_name}")
            
            # 準備執行 2.tshark.py
            pcap_path = os.path.join(PCAP_DIR, task_name)
            
            # 使用 subprocess 執行分析腳本
            result = subprocess.run([
                'python', '2.tshark.py'
            ], input=f"{task_name}\n{pcap_path}\n", 
               text=True, capture_output=True)
            
            if result.returncode == 0:
                print(f"分析任務 {task_name} 完成")
            else:
                print(f"分析任務 {task_name} 失敗: {result.stderr}")
                
        except Exception as e:
            print(f"執行分析任務失敗: {e}")
    
    # 在背景執行分析
    thread = threading.Thread(target=analysis_thread)
    thread.daemon = True
    thread.start()


@app.route('/')
def index():
    """任務總覽頁面"""
    tasks = get_tasks()
    return render_template('index.html', tasks=tasks)


@app.route('/analyze/<task_name>')
def analyze_task(task_name):
    """開始分析任務"""
    # 檢查任務是否存在
    tasks = get_tasks()
    task = next((t for t in tasks if t['name'] == task_name), None)
    
    if not task:
        flash('任務不存在', 'error')
        return redirect(url_for('index'))
    
    # 如果已經分析過，直接跳到結果頁面
    if task['analyzed']:
        return redirect(url_for('dashboard', task_name=task_name))
    
    # 開始分析
    run_analysis(task_name)
    flash(f'已開始分析任務「{task_name}」，請稍後重新整理查看結果', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard/<task_name>')
def dashboard(task_name):
    """分析結果儀表板"""
    # 檢查分析結果是否存在
    summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
    
    if not os.path.exists(summary_file):
        flash('分析結果不存在，請先進行分析', 'error')
        return redirect(url_for('index'))
    
    return render_template('dashboard.html', task_name=task_name)


# API 路由：提供分析資料給前端JavaScript

@app.route('/api/flow/<task_name>')
def api_flow(task_name):
    """流量趨勢 API"""
    try:
        summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        flow_data = summary.get('flow', {})
        return jsonify(flow_data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/top_ip/<task_name>')
def api_top_ip(task_name):
    """Top IP API"""
    try:
        summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        top_ip_data = summary.get('top_ip', [])
        return jsonify(top_ip_data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/geo/<task_name>')
def api_geo(task_name):
    """國別統計 API"""
    try:
        summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        geo_data = summary.get('geo', {})
        return jsonify(geo_data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<task_name>')
def api_events(task_name):
    """事件統計 API"""
    try:
        summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        events_data = summary.get('event', {})
        return jsonify(events_data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/event_details/<task_name>/<protocol>')
def api_event_details(task_name, protocol):
    """協議詳細統計 API"""
    try:
        summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        events_data = summary.get('event', {})
        protocol_data = events_data.get(protocol, {})
        
        if not protocol_data:
            return jsonify({'error': f'找不到協議 {protocol} 的資料'}), 404
        
        result = {
            'protocol': protocol,
            'total_count': protocol_data.get('count', 0),
            'top_connections': protocol_data.get('detailed_stats', [])
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/anomaly/<task_name>')
def api_anomaly(task_name):
    """異常警示 API"""
    try:
        summary_file = os.path.join(PROJECT_DIR, task_name, "analysis_summary.json")
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        # 生成異常警示資料
        anomalies = generate_anomaly_alerts(summary)
        return jsonify(anomalies)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def generate_anomaly_alerts(summary):
    """生成異常警示資料"""
    alerts = []
    
    try:
        # 1. 大流量連接警示
        top_ip = summary.get('top_ip', [])
        for i, conn in enumerate(top_ip[:5]):  # 檢查前5名
            bytes_val = conn.get('bytes', 0)
            if bytes_val > 50 * 1024 * 1024:  # 超過50MB
                # 解析連接字串
                connection = conn.get('connection', '')
                if ' -> ' in connection:
                    src_part, dst_part = connection.split(' -> ')
                    src_ip = src_part.split(':')[0] if ':' in src_part else src_part
                    
                    alerts.append({
                        'type': 'high_traffic',
                        'severity': 'high' if bytes_val > 200 * 1024 * 1024 else 'medium',
                        'title': '大流量連接警示',
                        'description': f'偵測到異常大流量連接：{format_bytes(bytes_val)}',
                        'ip': src_ip,
                        'connection': connection,
                        'time': summary.get('flow', {}).get('start_time', ''),
                        'details': {
                            'bytes': bytes_val,
                            'rank': i + 1,
                            'percentage': round((bytes_val / summary.get('flow', {}).get('total_bytes', 1)) * 100, 2)
                        }
                    })
        
        # 2. 異常協議比例警示
        events = summary.get('event', {})
        total_events = sum(event.get('count', 0) for event in events.values())
        
        if total_events > 0:
            for protocol, event_data in events.items():
                count = event_data.get('count', 0)
                percentage = (count / total_events) * 100
                
                # 檢查是否有異常比例
                if protocol == 'OTHER' and percentage > 50:
                    alerts.append({
                        'type': 'protocol_anomaly',
                        'severity': 'medium',
                        'title': '未識別協議過多',
                        'description': f'未識別協議佔總流量 {percentage:.1f}%，可能存在惡意流量',
                        'ip': event_data.get('top_ip', ''),
                        'time': summary.get('flow', {}).get('start_time', ''),
                        'details': {
                            'protocol': protocol,
                            'count': count,
                            'percentage': round(percentage, 2)
                        }
                    })
                
                elif protocol in ['TLS', 'TCP'] and percentage > 70:
                    alerts.append({
                        'type': 'protocol_anomaly',
                        'severity': 'low',
                        'title': f'{protocol} 協議流量過多',
                        'description': f'{protocol} 協議佔總流量 {percentage:.1f}%，建議進一步檢查',
                        'ip': event_data.get('top_ip', ''),
                        'time': summary.get('flow', {}).get('start_time', ''),
                        'details': {
                            'protocol': protocol,
                            'count': count,
                            'percentage': round(percentage, 2)
                        }
                    })
        
        # 3. 可疑國家流量警示
        geo = summary.get('geo', {})
        total_geo_bytes = sum(geo.values())
        
        if total_geo_bytes > 0:
            suspicious_countries = []
            for country, bytes_val in geo.items():
                percentage = (bytes_val / total_geo_bytes) * 100
                
                # 定義可疑國家清單（可根據需求調整）
                if country in ['RU', 'CN', 'KP', 'IR'] and percentage > 5:
                    suspicious_countries.append({
                        'country': country,
                        'bytes': bytes_val,
                        'percentage': percentage
                    })
            
            if suspicious_countries:
                for country_info in suspicious_countries:
                    alerts.append({
                        'type': 'geo_anomaly',
                        'severity': 'medium',
                        'title': '可疑國家流量警示',
                        'description': f'偵測到來自 {country_info["country"]} 的大量流量：{format_bytes(country_info["bytes"])} ({country_info["percentage"]:.1f}%)',
                        'ip': '',
                        'time': summary.get('flow', {}).get('start_time', ''),
                        'details': {
                            'country': country_info['country'],
                            'bytes': country_info['bytes'],
                            'percentage': round(country_info['percentage'], 2)
                        }
                    })
        
        # 4. 時間異常警示（深夜大流量）
        per_10_minutes = summary.get('flow', {}).get('per_10_minutes', {})
        if per_10_minutes:
            for time_str, bytes_val in per_10_minutes.items():
                try:
                    # 解析時間
                    time_obj = datetime.strptime(time_str, '%Y-%m-%d %H:%M')
                    hour = time_obj.hour
                    
                    # 檢查是否為深夜時段（22:00-06:00）且流量過大
                    if (hour >= 22 or hour <= 6) and bytes_val > 100 * 1024 * 1024:  # 100MB
                        alerts.append({
                            'type': 'time_anomaly',
                            'severity': 'medium',
                            'title': '深夜異常流量',
                            'description': f'在 {time_str} 偵測到異常大流量：{format_bytes(bytes_val)}',
                            'ip': '',
                            'time': time_str,
                            'details': {
                                'time_period': time_str,
                                'bytes': bytes_val,
                                'hour': hour
                            }
                        })
                except ValueError:
                    continue
    
    except Exception as e:
        print(f"生成異常警示時發生錯誤: {e}")
    
    return alerts


def format_bytes(bytes_val):
    """格式化位元組大小"""
    if bytes_val == 0:
        return '0 B'
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    
    while bytes_val >= 1024 and unit_index < len(units) - 1:
        bytes_val /= 1024
        unit_index += 1
    
    return f"{bytes_val:.1f} {units[unit_index]}"


def generate_ten_minute_stats(per_minute_data, start_time, end_time):
    """從每分鐘資料生成每10分鐘統計"""
    if not per_minute_data or not start_time or not end_time:
        return {}
    
    try:
        start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
    except:
        return {}
    
    per_10_minutes = {}
    
    for time_str, bytes_val in per_minute_data.items():
        try:
            # 解析時間
            time_dt = datetime.strptime(time_str, '%Y-%m-%d %H:%M')
            
            # 計算10分鐘邊界
            minute_boundary = (time_dt.minute // 10) * 10
            boundary_dt = time_dt.replace(minute=minute_boundary, second=0, microsecond=0)
            boundary_str = boundary_dt.strftime('%Y-%m-%d %H:%M')
            
            if boundary_str not in per_10_minutes:
                per_10_minutes[boundary_str] = 0
            
            per_10_minutes[boundary_str] += bytes_val
            
        except ValueError:
            continue
    
    return per_10_minutes


def get_sorted_flow_data(flow_data, start_time, end_time):
    """生成排序後的流量資料用於圖表顯示"""
    if not flow_data:
        return {'labels': [], 'values': []}
    
    # 按時間排序
    sorted_items = sorted(flow_data.items())
    
    labels = []
    values = []
    
    for time_str, bytes_val in sorted_items:
        try:
            # 格式化時間標籤（只顯示時間部分）
            time_obj = datetime.strptime(time_str, '%Y-%m-%d %H:%M')
            formatted_time = time_obj.strftime('%H:%M')
            labels.append(formatted_time)
            values.append(bytes_val)
        except ValueError:
            continue
    
    return {'labels': labels, 'values': values}


if __name__ == '__main__':
    print("🌐 啟動 PCAP 分析器 Web UI")
    print("📋 功能清單：")
    print("   ✅ 任務總覽 - 管理分析任務，查看狀態")
    print("   📈 流量趨勢 - 折線圖顯示流量變化")
    print("   🏆 Top IP - 長條圖與表格展示流量排行")
    print("   🌍 國別統計 - 圓餅圖顯示連線來源分布")
    print("   🔍 事件分析 - 網路事件統計與來源分析")
    print("   🚨 異常警示 - 安全威脅清單與詳細說明")
    print("\n🚀 正在啟動伺服器...")
    print("🔗 請在瀏覽器中開啟: http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
