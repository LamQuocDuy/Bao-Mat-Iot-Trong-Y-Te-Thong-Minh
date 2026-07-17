import json
import os
import csv
import hmac
import hashlib
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Khởi tạo dữ liệu lưu trữ
os.makedirs("data-folder", exist_ok=True)
CSV_FILE_PATH = os.path.join("data-folder", "data-luu-tru-tai-cloud.csv")
LOG_FILE_PATH = os.path.join("data-folder", "log-tai-cloud.json")

def load_config():
    with open("configs.json", "r") as f:
        return json.load(f)

config = load_config()
PORT = config["CLOUD"]["SERVER_PORT"]

# Hàm mã hóa dữ liệu tĩnh
def encrypt_local(plain_text, key_str):
    aesgcm = AESGCM(key_str.encode('utf-8')[:32])
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
    return f"{nonce.hex()}:{ct.hex()}"

# Hàm giải mã dữ liệu tĩnh
def decrypt_local(cipher_text_str, key_str):
    if ":" not in cipher_text_str:
        return cipher_text_str
    try:
        aesgcm = AESGCM(key_str.encode('utf-8')[:32])
        nonce_hex, ct_hex = cipher_text_str.split(":")
        nonce = bytes.fromhex(nonce_hex)
        ct = bytes.fromhex(ct_hex)
        return aesgcm.decrypt(nonce, ct, None).decode('utf-8')
    except Exception:
        return "[Lỗi giải mã]"

# Chức năng tạo log bảo mật (Audit Logs)
def log_event(event_type, status, details, requester_ip):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "status": status,
        "details": details,
        "requester_ip": requester_ip
    }
    
    logs = []
    if os.path.isfile(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            logs = []
            
    logs.append(log_entry)
    with open(LOG_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)

def verify_hmac(data_str, received_hmac, key_str):
    key = key_str.encode('utf-8')
    computed = hmac.new(key, data_str.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, received_hmac)

def save_to_csv(data, security_state):
    config_current = load_config()
    file_exists = os.path.isfile(CSV_FILE_PATH)
    
    # Chuẩn bị dữ liệu ghi
    heart_rate_to_save = str(data["heart_rate"])
    location_to_save = data.get("location", "N/A")
    
    # Nếu là chế độ STANDARD, tiến hành mã hóa tĩnh AES-256
    if security_state == "STANDARD":
        key = config_current["AES_CCM_KEY"]
        heart_rate_to_save = encrypt_local(heart_rate_to_save, key)
        location_to_save = encrypt_local(location_to_save, key)

    with open(CSV_FILE_PATH, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Patient_ID", "Device_ID", "Heart_Rate", "Location", "Chặng_2_Security"])
        writer.writerow([
            data["timestamp"],
            data["patient_id"],
            data["device_id"],
            heart_rate_to_save,
            location_to_save,
            security_state
        ])

class CloudServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return # Tắt log console mặc định

    def do_POST(self):
        client_ip = self.client_address[0]
        config_current = load_config()

        # Endpoint 1: Nhận luồng dữ liệu từ thiết bị
        if self.path == "/cloud-data":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            packet = json.loads(post_data.decode('utf-8'))
            
            security_state = packet.get("security", "BASIC")
            data = packet.get("data", {})

            if security_state == "STANDARD":
                # Kiểm tra tính toàn vẹn bằng khóa HMAC
                data_str = json.dumps(data)
                is_valid = verify_hmac(data_str, packet.get("hmac", ""), config_current["HMAC_KEY"])
                
                if not is_valid:
                    print("\n[CLOUD ALERT] Sự cố toàn vẹn: Chữ ký HMAC sai lệch! Có thể dữ liệu đã bị tấn công thay đổi.")
                    log_event("RECEIVE_DATA", "FAILED", "Sai khớp chữ ký HMAC bảo mật dữ liệu nhạy cảm", client_ip)
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Toan ven du lieu bi vi pham!")
                    return
                print("\n[CLOUD] Xác thực thành công tính toàn vẹn dữ liệu thông qua chữ ký HMAC.")
            else:
                print("\n[CLOUD WARNING] Nhận dữ liệu không được bảo vệ tính toàn vẹn (Không có HMAC).")

            # Lưu vào bộ nhớ đám mây của hệ thống y tế
            save_to_csv(data, security_state)
            log_event("RECEIVE_DATA", "SUCCESS", f"Lưu thành công nhịp tim bệnh nhân {data.get('patient_id')}", client_ip)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Cloud ghi nhan thanh cong!")

        # Endpoint 2: Mô phỏng phát hành JWT (Login)
        elif self.path == "/login":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            credentials = json.loads(post_data.decode('utf-8'))

            stored_credentials = config_current["CLOUD"]["DOCTOR_CREDENTIALS"]
            if (credentials.get("username") == stored_credentials["username"] and 
                credentials.get("password") == stored_credentials["password"]):
                
                # Tạo chuỗi chữ ký JWT đại diện
                header = '{"alg":"HS256","typ":"JWT"}'
                payload = f'{{"sub":"{credentials.get("username")}","role":"{stored_credentials["role"]}"}}'
                
                # Ký số lên token
                sig_input = f"{header}.{payload}"
                sig = hmac.new(config_current["JWT_SECRET"].encode('utf-8'), sig_input.encode('utf-8'), hashlib.sha256).hexdigest()
                jwt_token = f"{header}.{payload}.{sig}"
                
                log_event("DOCTOR_LOGIN", "SUCCESS", f"Bác sĩ {credentials.get('username')} đăng nhập thành công", client_ip)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"token": jwt_token}).encode('utf-8'))
            else:
                log_event("DOCTOR_LOGIN", "FAILED", f"Thử đăng nhập sai tài khoản: {credentials.get('username')}", client_ip)
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized")

    def do_GET(self):
        client_ip = self.client_address[0]
        config_current = load_config()

        # Endpoint 3: Cung cấp dữ liệu cho Dashboard của bác sĩ (Chặng 3)
        if self.path == "/get-data":
            security_mode = config_current["SECURITY_MODE"]

            if security_mode == "STANDARD":
                # Kiểm tra JWT Token trong Header nhằm phân quyền (RBAC)
                auth_header = self.headers.get('Authorization', '')
                if not auth_header.startswith("Bearer "):
                    log_event("ACCESS_ATTEMPT", "BLOCKED", "Cố gắng truy xuất thông tin thiếu Token xác thực", client_ip)
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Yeu cau phai co Token xac thuc!")
                    return
                
                token = auth_header.split(" ")[1]
                try:
                    # Kiểm tra chữ ký của JWT
                    parts = token.split(".")
                    sig_input = f"{parts[0]}.{parts[1]}"
                    expected_sig = hmac.new(config_current["JWT_SECRET"].encode('utf-8'), sig_input.encode('utf-8'), hashlib.sha256).hexdigest()
                    
                    if not hmac.compare_digest(expected_sig, parts[2]):
                        raise ValueError("Chu ky JWT sai")
                        
                    # Phân quyền bác sĩ (Role-Based Access Control)
                    payload_data = json.loads(parts[1])
                    if payload_data.get("role") != "doctor":
                        log_event("ACCESS_ATTEMPT", "BLOCKED", f"Quyền truy cập bị từ chối với vai trò: {payload_data.get('role')}", client_ip)
                        self.send_response(403)
                        self.end_headers()
                        self.wfile.write(b"Quyen rieng tu: Ban khong phai bac si duoc phan quyen!")
                        return
                    
                    print(f"\n[CLOUD] Chứng thực JWT hợp lệ. Bác sĩ '{payload_data.get('sub')}' được quyền truy xuất.")
                    log_event("ACCESS_DATA", "SUCCESS", f"Bác sĩ {payload_data.get('sub')} lấy dữ liệu nhịp tim thành công", client_ip)

                except Exception as e:
                    log_event("ACCESS_ATTEMPT", "BLOCKED", f"Token JWT không hợp lệ: {str(e)}", client_ip)
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Token khong hop le hoac bi sua doi!")
                    return
            else:
                print("\n[CLOUD WARNING] Chế độ BASIC: Cung cấp trực tiếp dữ liệu nhạy cảm không cần kiểm tra quyền truy cập.")
                log_event("ACCESS_DATA", "SUCCESS", "Truy cập dữ liệu trực tiếp ở chế độ BASIC (Thiết lập ban đầu)", client_ip)

            # Đọc và trả về dữ liệu lưu trữ
            records = []
            if os.path.isfile(CSV_FILE_PATH):
                with open(CSV_FILE_PATH, "r", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    for row in reader:
                        if len(row) >= 5:
                            hr_raw = row[3]
                            loc_raw = row[4]
                            
                            # Nếu dữ liệu đang bị mã hóa ở STANDARD, tiến hành giải mã
                            if security_mode == "STANDARD":
                                key = config_current["AES_CCM_KEY"]
                                hr_raw = decrypt_local(hr_raw, key)
                                loc_raw = decrypt_local(loc_raw, key)
                            
                            records.append({
                                "timestamp": row[0],
                                "patient_id": row[1],
                                "device_id": row[2],
                                "heart_rate": int(hr_raw) if hr_raw.isdigit() else hr_raw,
                                "location": loc_raw
                            })
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(records).encode('utf-8'))

def run():
    print(f"=== [HE THONG CLOUD] Cloud Y Tế đang hoạt động tại cổng {PORT} ===")
    server = HTTPServer(('localhost', PORT), CloudServerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐóng Cloud Server.")
        server.server_close()

if __name__ == '__main__':
    run()