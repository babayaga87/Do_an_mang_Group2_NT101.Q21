import string
import customtkinter as ctk
from tkinter import messagebox
from Crypto.Util.number import getPrime, inverse

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ==========================================
# CỐT LÕI THUẬT TOÁN PLAYFAIR (ĐÃ SỬA LỖI)
# ==========================================
def prepare_key_matrix(key, size):
    key = key.upper()
    if size == 5:
        key = key.replace('J', 'I')
        alphabet = string.ascii_uppercase.replace('J', '')
    else:
        alphabet = string.ascii_uppercase + string.digits
        
    matrix = []
    seen = set()
    
    for char in key:
        if char in alphabet and char not in seen:
            seen.add(char)
            matrix.append(char)
            
    for char in alphabet:
        if char not in seen:
            seen.add(char)
            matrix.append(char)
            
    return [matrix[i:i+size] for i in range(0, size*size, size)]

def find_position(matrix, char, size):
    for r in range(size):
        for c in range(size):
            if matrix[r][c] == char:
                return r, c
    return None

def playfair_process(text, key, size, action):
    matrix = prepare_key_matrix(key, size)
    text = text.upper()
    
    if size == 5:
        text = text.replace('J', 'I')
        alphabet = string.ascii_uppercase.replace('J', '')
    else:
        alphabet = string.ascii_uppercase + string.digits
        
    cleaned_text = "".join([c for c in text if c in alphabet])
    if not cleaned_text:
        return ""
        
    digraphs = []
    i = 0
    while i < len(cleaned_text):
        char1 = cleaned_text[i]
        if i + 1 < len(cleaned_text):
            char2 = cleaned_text[i+1]
            if char1 == char2:
                digraphs.append(char1 + 'X')
                i += 1
            else:
                digraphs.append(char1 + char2)
                i += 2
        else:
            digraphs.append(char1 + 'X')
            i += 1

    result_text = ""
    shift = 1 if action == 'encrypt' else -1
    
    for pair in digraphs:
        r1, c1 = find_position(matrix, pair[0], size)
        r2, c2 = find_position(matrix, pair[1], size)
        
        if r1 == r2:
            result_text += matrix[r1][(c1 + shift) % size] + matrix[r2][(c2 + shift) % size]
        elif c1 == c2:
            result_text += matrix[(r1 + shift) % size][c1] + matrix[(r2 + shift) % size][c2]
        else:
            result_text += matrix[r1][c2] + matrix[r2][c1]
            
    return result_text

# ==========================================
# CỐT LÕI THUẬT TOÁN RSA
# ==========================================
class RSACipher:
    def __init__(self):
        self.p = self.q = self.n = self.e = self.d = None
        self.generate_keys()

    def generate_keys(self):
        self.p = getPrime(256)
        self.q = getPrime(256)
        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)
        self.e = 65537
        self.d = inverse(self.e, phi)

    def encrypt(self, message):
        encoded = [pow(ord(char), self.e, self.n) for char in message]
        return ",".join(map(str, encoded))

    def decrypt(self, cipher_text):
        try:
            cipher_list = list(map(int, cipher_text.split(",")))
            decoded = [chr(pow(char, self.d, self.n)) for char in cipher_list]
            return "".join(decoded)
        except:
            return "Lỗi giải mã: Dữ liệu mã hóa không hợp lệ!"

rsa_instance = RSACipher()

# ==========================================
# GIAO DIỆN CHÍNH (GUI)
# ==========================================
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("HỆ THỐNG MÃ HÓA BẢO MẬT THÔNG TIN - LỚP AN TOÀN MẠNG")
        self.geometry("950x680")
        self.resizable(False, False)

        title_label = ctk.CTkLabel(self, text="ỨNG DỤNG GIẢI MÃ MÔN AN TOÀN MẠNG MÁY TÍNH", font=ctk.CTkFont(size=22, weight="bold"))
        title_label.pack(pady=15)

        self.tabview = ctk.CTkTabview(self, width=910, height=590)
        self.tabview.pack(padx=20, pady=10, fill="both", expand=True)
        self.tabview.add("Mã hóa Playfair")
        self.tabview.add("Mã hóa RSA")

        self.current_pf_size = 5
        self.matrix_labels = []

        self.setup_playfair_tab()
        self.setup_rsa_tab()

    def setup_playfair_tab(self):
        tab = self.tabview.tab("Mã hóa Playfair")
        
        left_frame = ctk.CTkFrame(tab, width=450, fg_color="transparent")
        left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        self.right_frame = ctk.CTkFrame(tab, width=400)
        self.right_frame.pack(side="right", fill="both", padx=15, pady=15)

        ctk.CTkLabel(left_frame, text="Cấu hình kích thước ma trận:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=2)
        self.size_switch = ctk.CTkSegmentedButton(left_frame, values=["Ma trận 5x5 (Chữ)", "Ma trận 6x6 (Chữ & Số)"], command=self.change_matrix_size)
        self.size_switch.set("Ma trận 5x5 (Chữ)")
        self.size_switch.pack(anchor="w", pady=5)

        ctk.CTkLabel(left_frame, text="Khóa Bí Mật (Key):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=2)
        self.entry_pf_key = ctk.CTkEntry(left_frame, placeholder_text="Nhập khóa tại đây...", width=380)
        self.entry_pf_key.insert(0, "SECURITY")
        self.entry_pf_key.pack(anchor="w", pady=5)
        self.entry_pf_key.bind("<KeyRelease>", lambda e: self.update_matrix_visual())

        ctk.CTkLabel(left_frame, text="Văn bản cần xử lý:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=2)
        self.txt_pf_input = ctk.CTkTextbox(left_frame, width=380, height=100)
        self.txt_pf_input.pack(anchor="w", pady=5)

        btn_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        btn_frame.pack(anchor="w", pady=10)
        
        ctk.CTkButton(btn_frame, text="🔒 Mã hóa", width=120, command=lambda: self.process_pf('encrypt')).grid(row=0, column=0, padx=5)
        ctk.CTkButton(btn_frame, text="🔓 Giải mã", width=120, fg_color="#2b7a78", hover_color="#17252a", command=lambda: self.process_pf('decrypt')).grid(row=0, column=1, padx=5)

        ctk.CTkLabel(left_frame, text="Kết quả đầu ra:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=2)
        self.txt_pf_output = ctk.CTkTextbox(left_frame, width=380, height=100, fg_color="#1e1e1e")
        self.txt_pf_output.pack(anchor="w", pady=5)

        self.matrix_title = ctk.CTkLabel(self.right_frame, text="MA TRẬN PLAYFAIR TRỰC QUAN", font=ctk.CTkFont(size=14, weight="bold"))
        self.matrix_title.pack(pady=10)
        
        self.matrix_grid_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        self.matrix_grid_frame.pack(padx=15, pady=5, expand=True)
        
        self.build_matrix_grid()

    def build_matrix_grid(self):
        for row in self.matrix_labels:
            for lbl in row:
                lbl.destroy()
        self.matrix_labels.clear()

        size = self.current_pf_size
        self.matrix_title.configure(text=f"MA TRẬN PLAYFAIR TRỰC QUAN {size}x{size}")
        
        box_side = 45 if size == 5 else 40
        font_size = 16 if size == 5 else 15
        padding = 4 if size == 5 else 3

        for r in range(size):
            row_labels = []
            for c in range(size):
                lbl = ctk.CTkLabel(self.matrix_grid_frame, text="-", width=box_side, height=box_side, 
                                   fg_color="#242424", corner_radius=6, font=ctk.CTkFont(size=font_size, weight="bold"))
                lbl.grid(row=r, column=c, padx=padding, pady=padding)
                row_labels.append(lbl)
            self.matrix_labels.append(row_labels)
        
        self.update_matrix_visual()

    def change_matrix_size(self, value):
        if "5x5" in value:
            self.current_pf_size = 5
        else:
            self.current_pf_size = 6
        self.build_matrix_grid()

    def update_matrix_visual(self):
        key = self.entry_pf_key.get()
        size = self.current_pf_size
        matrix = prepare_key_matrix(key if key else " ", size)
        for r in range(size):
            for c in range(size):
                self.matrix_labels[r][c].configure(text=matrix[r][c])

    def process_pf(self, action):
        key = self.entry_pf_key.get()
        text = self.txt_pf_input.get("1.0", "end-1c").strip()
        if not key or not text:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập đầy đủ thông tin khóa và văn bản!")
            return
        res = playfair_process(text, key, self.current_pf_size, action)
        self.txt_pf_output.delete("1.0", "end")
        self.txt_pf_output.insert("1.0", res)

    def setup_rsa_tab(self):
        tab = self.tabview.tab("Mã hóa RSA")
        
        key_dashboard = ctk.CTkFrame(tab)
        key_dashboard.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(key_dashboard, text="CẤU HÌNH KHÓA TỰ ĐỘNG KHÔNG ĐỐI XỨNG (RSA)", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=15, pady=10)
        ctk.CTkButton(key_dashboard, text="🔄 Tạo Cặp Khóa Ngẫu Nhiên", width=220, fg_color="#d9534f", hover_color="#c9302c", command=self.refresh_rsa).pack(side="right", padx=15, pady=10)

        ctk.CTkLabel(tab, text="Khóa Công Khai Hiện Tại (Public Key n):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=20, pady=2)
        self.txt_rsa_pub = ctk.CTkTextbox(tab, height=60, fg_color="#1e1e1e")
        self.txt_rsa_pub.pack(fill="x", padx=20, pady=2)
        
        io_frame = ctk.CTkFrame(tab, fg_color="transparent")
        io_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        input_col = ctk.CTkFrame(io_frame)
        input_col.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        ctk.CTkLabel(input_col, text="Nhập chuỗi văn bản cần mã hóa:", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.txt_rsa_in = ctk.CTkTextbox(input_col, height=130)
        self.txt_rsa_in.pack(fill="both", expand=True, padx=10, pady=5)
        ctk.CTkButton(input_col, text="🔒 Mã hóa dữ liệu bằng Public Key", command=lambda: self.process_rsa('encrypt')).pack(fill="x", padx=10, pady=10)

        output_col = ctk.CTkFrame(io_frame)
        output_col.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        ctk.CTkLabel(output_col, text="Kết quả / Nhập chuỗi mã để giải mã:", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.txt_rsa_out = ctk.CTkTextbox(output_col, height=130, fg_color="#1e1e1e")
        self.txt_rsa_out.pack(fill="both", expand=True, padx=10, pady=5)
        ctk.CTkButton(output_col, text="🔓 Giải mã dữ liệu bằng Private Key", fg_color="#2b7a78", hover_color="#17252a", command=lambda: self.process_rsa('decrypt')).pack(padx=10, pady=10)

        self.load_rsa_keys_text()

    def load_rsa_keys_text(self):
        self.txt_rsa_pub.delete("1.0", "end")
        self.txt_rsa_pub.insert("1.0", f"e: {rsa_instance.e}\nN (Modulo): {rsa_instance.n}")

    def refresh_rsa(self):
        rsa_instance.generate_keys()
        self.load_rsa_keys_text()
        messagebox.showinfo("Thành công", "Đã khởi tạo và làm mới hệ thống khóa RSA tự động thành công!")

    def process_rsa(self, action):
        if action == 'encrypt':
            text = self.txt_rsa_in.get("1.0", "end-1c").strip()
            if not text: return
            res = rsa_instance.encrypt(text)
            self.txt_rsa_out.delete("1.0", "end")
            self.txt_rsa_out.insert("1.0", res)
        else:
            text = self.txt_rsa_out.get("1.0", "end-1c").strip()
            if not text: return
            res = rsa_instance.decrypt(text)
            self.txt_rsa_in.delete("1.0", "end")
            self.txt_rsa_in.insert("1.0", res)

if __name__ == "__main__":
    app = App()
    app.mainloop()