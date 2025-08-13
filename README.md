# curicata_script


使用　GeoLite2-City.mmdb　判斷地理位置
Example:
``` python

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


# 確保 src 目錄在 Python 路徑中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# 若沒有 pcaps 資料夾則生成一個
pcap_dir = os.path.abspath('pcaps')
if not os.path.exists(pcap_dir):
    os.makedirs(pcap_dir)
# 檢查 GeoIP 資料庫是否存在，若不存在則下載
if not os.path.exists('GeoLite2-City.mmdb'):
    download_geoip_database()
else:
    print("✅ GeoIP 資料庫已存在")


        # 嘗試載入 GeoIP 資料庫
        try:
            # 假設 GeoLite2-City.mmdb 在專案根目錄
            self.geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except FileNotFoundError:
            print("警告: 找不到 GeoIP 資料庫檔案")

```
---
我需要統計eve.json裡面的event_type
每種網路事件有多少數量

協議：XXX
總封包數：XXX

前5名連接統計
排名	來源 IP	目標 IP	封包數	封包大小 (Bytes)

---

每10分鐘流量統計

---

前10的流量排行圖

---

總分析時長

---

總流量大小

---