import json
import random
import time
import os
import csv
from datetime import datetime
import urllib.request
import urllib.error

# Khởi tạo thư mục data-folder nếu chưa tồn tại
os.makedirs("data-folder", exist_ok=True)
CSV_FILE_PATH = os.path.join("data-folder", "data-mo-phong-nhip-tim.csv")

# Đọc cấu hình tập trung
def load_config():
    with open("configs.json", "r") as f:
        return json.load(f)

config = load_config()
SECURITY_MODE = config["SECURITY_MODE"]
PATIENT_ID = config["DEVICE"]["PATIENT_ID"]
DEVICE_ID = config["DEVICE"]["DEVICE_ID"]
APP_PORT = config["DEVICE"]["SERVER_PORT"]

# Thiết lập thư viện AES-CCM mô phỏng Mbed TLS
HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    pass

def encrypt_data(payload_str, key_str):
    """
    Mô phỏng quy trình mã hóa AES-CCM từ thư viện Mbed TLS
    """
    if not HAS_CRYPTOGRAPHY:
        # Cơ chế mã hóa dự phòng (mock) nếu người dùng chưa cài đặt cryptography
        return "MOCK_CIPHER_" + payload_str
    
    key = key_str.encode('utf-8')[:32] # Cắt khóa về đúng 32 bytes (AES-256)
    aesccm = AESCCM(key)
    nonce = os.urandom(12) # Sinh nonce ngẫu nhiên 12-byte
    encrypted = aesccm.encrypt(nonce, payload_str.encode('utf-8'), None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": encrypted.hex()
    }

def save_to_csv(data):
    file_exists = os.path.isfile(CSV_FILE_PATH)
    with open(CSV_FILE_PATH, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Patient_ID", "Device_ID", "Heart_Rate", "Location", "Status"])
        writer.writerow([
            data["timestamp"],
            data["patient_id"],
            data["device_id"],
            data["heart_rate"],
            data.get("location", "N/A"),
            "Chưa mã hóa" if SECURITY_MODE == "BASIC" else "Đã mã hóa (AES-CCM/MbedTLS)"
        ])

def main():
    print(f"=== [DEVICE] Đang hoạt động ở chế độ: {SECURITY_MODE} ===")
    
    if not HAS_CRYPTOGRAPHY and SECURITY_MODE == "STANDARD":
        print("[LƯU Ý] Hãy cài đặt gói 'cryptography' để trải nghiệm mã hóa AES-CCM chính xác nhất: pip install cryptography")

    while True:
        # Sinh ngẫu nhiên dữ liệu nhịp tim và vị trí giả lập
        heart_rate = random.randint(65, 110)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        location = "10.776, 106.701" # Tọa độ định vị GPS nhạy cảm

        payload = {
            "timestamp": timestamp,
            "patient_id": PATIENT_ID,
            "device_id": DEVICE_ID,
            "heart_rate": heart_rate,
            "location": location
        }

        # Lưu lại nhật ký gốc tại thiết bị đo
        save_to_csv(payload)
        print(f"\n[DEVICE] Sinh dữ liệu nhịp tim: {heart_rate} bpm tại {timestamp}")

        # Chuẩn bị gói tin gửi đi dựa trên chế độ bảo mật
        if SECURITY_MODE == "STANDARD":
            # Chặng 1: BLE Secure Connections + AES-CCM
            raw_payload_str = json.dumps(payload)
            encrypted_payload = encrypt_data(raw_payload_str, config["AES_CCM_KEY"])
            transmission_payload = {
                "security": "STANDARD",
                "encrypted_data": encrypted_payload
            }
            print("[DEVICE -> APP] Gửi dữ liệu an toàn (Mã hóa AES-CCM/Mbed TLS)")
        else:
            # Chặng 1: BLE Just Works (Không mã hóa dữ liệu nhạy cảm)
            transmission_payload = {
                "security": "BASIC",
                "raw_data": payload
            }
            print("[DEVICE -> APP] Cảnh báo: Gửi dữ liệu thô nhạy cảm qua kênh không an toàn (BLE Just Works)")

        # Gửi dữ liệu tới App di động qua mạng HTTP
        try:
            req_data = json.dumps(transmission_payload).encode('utf-8')
            req = urllib.request.Request(
                f"http://localhost:{APP_PORT}/device-data", 
                data=req_data, 
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req) as response:
                resp_text = response.read().decode('utf-8')
                print(f"[DEVICE] Phản hồi từ App: {resp_text}")
        except urllib.error.URLError as e:
            print(f"[DEVICE] Lỗi kết nối tới App: {e}. Vui lòng khởi động app-user.py")

        time.sleep(5) # Thực hiện đo định kỳ mỗi 5 giây

if __name__ == "__main__":
    main()