import json
import os
import csv
import hmac
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

# Khởi tạo thư mục data-folder nếu chưa tồn tại
os.makedirs("data-folder", exist_ok=True)
CSV_FILE_PATH = os.path.join("data-folder", "data-tai-thiet-bi-user.csv")

# Đọc cấu hình tập trung
def load_config():
    with open("configs.json", "r") as f:
        return json.load(f)

config = load_config()
PORT = config["DEVICE"]["SERVER_PORT"]
CLOUD_PORT = config["CLOUD"]["SERVER_PORT"]

HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    pass

def decrypt_data(encrypted_payload, key_str):
    """
    Giải mã AES-CCM từ dữ liệu nhận từ vòng đeo tay
    """
    if not HAS_CRYPTOGRAPHY or isinstance(encrypted_payload, str):
        # Fallback chế độ mock
        if isinstance(encrypted_payload, str) and encrypted_payload.startswith("MOCK_CIPHER_"):
            return encrypted_payload.replace("MOCK_CIPHER_", "")
        return encrypted_payload
    
    try:
        key = key_str.encode('utf-8')[:32]
        aesccm = AESCCM(key)
        nonce = bytes.fromhex(encrypted_payload["nonce"])
        ciphertext = bytes.fromhex(encrypted_payload["ciphertext"])
        decrypted_bytes = aesccm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"[APP ERROR] Giải mã AES-CCM thất bại: {e}")
        return None

def compute_hmac(data_str, key_str):
    """
    Tạo chữ ký HMAC-SHA256 nhằm bảo vệ tính toàn vẹn dữ liệu
    """
    key = key_str.encode('utf-8')
    return hmac.new(key, data_str.encode('utf-8'), hashlib.sha256).hexdigest()

def save_to_csv(data, security_state):
    file_exists = os.path.isfile(CSV_FILE_PATH)
    with open(CSV_FILE_PATH, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Patient_ID", "Heart_Rate", "Location", "Chặng_1_Security"])
        writer.writerow([
            data["timestamp"],
            data["patient_id"],
            data["heart_rate"],
            data.get("location", "N/A"),
            security_state
        ])

class AppServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return # Tắt nhật ký mặc định của HTTP server để console sạch sẽ

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        payload = json.loads(post_data.decode('utf-8'))
        
        config_current = load_config()
        security_mode = config_current["SECURITY_MODE"]

        decrypted_payload_obj = {}
        
        if payload.get("security") == "STANDARD":
            print("\n[APP] Nhận dữ liệu BLE mã hóa an toàn.")
            decrypted_str = decrypt_data(payload["encrypted_data"], config_current["AES_CCM_KEY"])
            if decrypted_str:
                decrypted_payload_obj = json.loads(decrypted_str)
                print(f"[APP] Giải mã AES-CCM thành công. Nhịp tim: {decrypted_payload_obj['heart_rate']} bpm")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Decryption failed")
                return
        else:
            print("\n[APP] Cảnh báo: Nhận gói tin thô không an toàn qua BLE.")
            decrypted_payload_obj = payload.get("raw_data", {})
            print(f"[APP] Nhịp tim nhận được: {decrypted_payload_obj.get('heart_rate')} bpm")

        # Lưu dữ liệu cục bộ tại Thiết bị người dùng
        save_to_csv(decrypted_payload_obj, payload.get("security"))

        # Gửi dữ liệu đi tiếp tới Cloud (Chặng 2)
        forward_success = self.forward_to_cloud(decrypted_payload_obj, security_mode, config_current)

        if forward_success:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Du lieu da luu tai App va day len Cloud thanh cong!")
        else:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"He thong Cloud dang ngat ket noi.")

    def forward_to_cloud(self, data, mode, config_current):
        cloud_url = f"http://localhost:{CLOUD_PORT}/cloud-data"
        
        if mode == "STANDARD":
            # Tạo chữ ký bảo vệ tính toàn vẹn (HMAC) + truyền MQTTS/HTTPS (Giả lập qua mã hóa gói tin)
            data_str = json.dumps(data)
            mac = compute_hmac(data_str, config_current["HMAC_KEY"])
            packet = {
                "security": "STANDARD",
                "data": data,
                "hmac": mac
            }
            print("[APP -> CLOUD] Đang đẩy lên Cloud qua TLS 1.3 bảo mật với chữ ký HMAC")
        else:
            # Gửi dạng văn bản thô không bảo vệ
            packet = {
                "security": "BASIC",
                "data": data
            }
            print("[APP -> CLOUD] Đang đẩy lên Cloud dạng thô (HTTP/MQTT không mã hóa)")

        try:
            req_data = json.dumps(packet).encode('utf-8')
            req = urllib.request.Request(
                cloud_url, 
                data=req_data, 
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req) as response:
                return response.status == 200
        except urllib.error.URLError as e:
            print(f"[APP ERROR] Lỗi kết nối tới Cloud: {e}. Vui lòng khởi động clound.py")
            return False

def run():
    print(f"=== [APP USER] Server App di động đang chạy tại cổng {PORT} ===")
    server = HTTPServer(('localhost', PORT), AppServerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nĐóng App Server.")
        server.server_close()

if __name__ == '__main__':
    run()