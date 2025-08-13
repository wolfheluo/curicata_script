import sys
import re
import os

def extract_key_fields(line):
    if "Priority: 3" in line:
        return None
    if "ET INFO HTTP Request to a" in line and ".tw domain" in line:
        return None
    if "ET DNS Query for .cc TLD" in line:
        return None

    event_start = line.find("[**]")
    if event_start == -1:
        return None
    event = line[event_start:]

    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+", line)
    if not ip_match:
        return None
    src_ip, dst_ip = ip_match.groups()

    return (event, src_ip, dst_ip)

def main():
    if len(sys.argv) < 2:
        print("請指定輸入檔案，例如：python filter_logs.py test.log")
        sys.exit(1)

    input_file = sys.argv[1]

    if not os.path.exists(input_file):
        print(f"找不到檔案：{input_file}")
        sys.exit(1)

    output_file = f"filtered_{os.path.basename(input_file)}"
    seen = set()
    count = 0

    with open(input_file, "r", encoding="utf-8") as infile, \
         open(output_file, "w", encoding="utf-8") as outfile:

        for line in infile:
            key = extract_key_fields(line)
            if key and key not in seen:
                seen.add(key)
                outfile.write(line)
                count += 1

    print(f"✅ 處理完成，共保留 {count} 筆 Priority: 1 和 2 的唯一記錄")
    print(f"📄 結果已儲存至：{output_file}")

if __name__ == "__main__":
    main()

