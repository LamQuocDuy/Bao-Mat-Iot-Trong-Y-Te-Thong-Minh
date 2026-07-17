import json
import os
import csv
import urllib.request
import urllib.error

# Khởi tạo dữ liệu lưu trữ
os.makedirs("data-folder", exist_ok=True)
CSV_FILE_PATH = os.path.join("data-folder", "data-cung-cap-den-docter.csv")

def load_config():
    with open("configs.json", "r") as f:
        return json.load(f)

config = load_config()
CLOUD_PORT = config["CLOUD"]["SERVER_PORT"]

def save_to_csv(records):
    # Ghi đè hoặc lưu trữ cập nhật dữ liệu của bác sĩ
    with open(CSV_FILE_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Patient_ID", "Device_ID", "Heart_Rate", "Location"])
        for r in records:
            writer.writerow([r["timestamp"], r["patient_id"], r["device_id"], r["heart_rate"], r["location"]])

def authenticate_and_get_token():
    """
    Thực hiện gửi thông tin đăng nhập lên Cloud để lấy Token JWT bảo mật
    """
    login_url = f"http://localhost:{CLOUD_PORT}/login"
    credentials = {
        "username": input("Nhap mat tai khoan truy cap: "),
        "password": input("Nhap mat khau truy cap: ")
    }
    try:
        req_data = json.dumps(credentials).encode('utf-8')
        req = urllib.request.Request(login_url, data=req_data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            res = json.loads(response.read().decode('utf-8'))
            return res.get("token")
    except Exception as e:
        print(f"[DASHBOARD] Xác thực bác sĩ không thành công: {e}")
        return None

def main():
    config_current = load_config()
    security_mode = config_current["SECURITY_MODE"]
    print(f"=== [DASHBOARD] Bắt đầu kết nối tới Cloud Y Tế ở chế độ: {security_mode} ===")

    headers = {}
    
    if security_mode == "STANDARD":
        # Tiến hành Chặng 3 an toàn: Gửi yêu cầu đăng nhập, lấy JWT làm phương thức xác thực
        print("[DASHBOARD] Đang kết nối xác thực tài khoản bác sĩ qua MFA/RBAC...")
        token = authenticate_and_get_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
            print("[DASHBOARD] Nhận và lưu Token JWT thành công để xác thực thông tin.")
        else:
            print("[DASHBOARD] Từ chối: Không thể truy cập hệ thống bảo mật.")
            return
    else:
        print("[DASHBOARD] Truy cập trực tiếp không cần cơ chế xác thực danh tính.")

    # Lấy thông tin bệnh nhân từ máy chủ Cloud
    get_data_url = f"http://localhost:{CLOUD_PORT}/get-data"
    try:
        req = urllib.request.Request(get_data_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            records = json.loads(response.read().decode('utf-8'))
            
            print(f"\n[DASHBOARD DOCTOR] --- THÔNG TIN THEO DÕI SỨC KHỎE BỆNH NHÂN (Có {len(records)} Bản Ghi) ---")
            print(f"{'Thời Gian':<21}{'ID Bệnh Nhân':<15}{'Mã Thiết Bị':<15}{'Nhịp Tim (BPM)':<15}{'Tọa độ Vị Trí GPS'}")
            print("-" * 80)
            
            for r in records:
                print(f"{r['timestamp']:<21}{r['patient_id']:<15}{r['device_id']:<15}{r['heart_rate']:<15}{r['location']}")
            
            # Ghi nhận tập tin dữ liệu cung cấp cho bác sĩ
            save_to_csv(records)
            print(f"\n[DASHBOARD] Dữ liệu hiển thị đã đồng bộ về tệp: {CSV_FILE_PATH}")

    except urllib.error.HTTPError as e:
        print(f"[DASHBOARD ERROR] Máy chủ Cloud từ chối truy xuất (Mã lỗi: {e.code}) - {e.reason}")
    except urllib.error.URLError as e:
        print(f"[DASHBOARD ERROR] Máy chủ Cloud đang ngoại tuyến: {e}")

if __name__ == "__main__":
    main()