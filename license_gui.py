import customtkinter as ctk
import license  # 导入你的 license.py

# ！！请在此处替换为你通过 python license.py genkey 生成的实际私钥！！
PRIVATE_KEY_HEX = os.environ.get("CUSTOM_LICENSE_PRIVATE_KEY", "CUSTOM_LICENSE_PRIVATE_KEY_HERE")

# 设置主题风格
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class KeyGenApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("License Key Gen")
        self.geometry("420x650")
        self.configure(fg_color="#1E232D") # 深灰色背景，贴近图片

        # --- 标题 ---
        self.title_label = ctk.CTkLabel(
            self, text="License Key Gen", 
            font=ctk.CTkFont(size=30, weight="bold"), 
            text_color="#4da8da" # 浅蓝色字体
        )
        self.title_label.pack(pady=(35, 25))

        # --- 下拉框区域 (RouterOS / Level) ---
        self.combo_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.combo_frame.pack(fill="x", padx=40, pady=(0, 15))
        self.combo_frame.grid_columnconfigure(0, weight=1)
        self.combo_frame.grid_columnconfigure(1, weight=1)

        self.os_combo = ctk.CTkComboBox(
            self.combo_frame, 
            values=["RouterOS", "CHR"], 
            command=self.update_levels,
            fg_color="#181B22", border_color="#374151"
        )
        self.os_combo.grid(row=0, column=0, padx=(0, 10), sticky="ew")

        self.level_combo = ctk.CTkComboBox(
            self.combo_frame, 
            values=["Level 6", "Level 5", "Level 4"],
            fg_color="#181B22", border_color="#374151"
        )
        self.level_combo.grid(row=0, column=1, padx=(10, 0), sticky="ew")

        # --- ID 输入框 ---
        self.id_entry = ctk.CTkEntry(
            self, 
            placeholder_text="Software/System ID (e.g. C8FV-5V1J)", 
            height=45,
            fg_color="#181B22", border_color="#374151"
        )
        self.id_entry.pack(fill="x", padx=40, pady=(0, 20))

        # --- 生成按钮 ---
        self.gen_btn = ctk.CTkButton(
            self, text="Generate License", 
            font=ctk.CTkFont(size=14, weight="bold"), 
            height=45, 
            fg_color="#2585f6", hover_color="#1a63c6", # 蓝色按钮
            command=self.generate_license
        )
        self.gen_btn.pack(fill="x", padx=40, pady=(0, 25))

        # --- 输出文本框 ---
        self.output_textbox = ctk.CTkTextbox(
            self, height=180, 
            fg_color="#000000", # 纯黑背景
            text_color="#00FF00", # 亮绿色字体
            font=ctk.CTkFont(family="Consolas", size=13),
            border_color="#10B981", border_width=1 # 绿色边框
        )
        self.output_textbox.pack(fill="x", padx=40, pady=(0, 20))

        # --- 复制到剪贴板按钮 ---
        self.copy_btn = ctk.CTkButton(
            self, text="Copy to Clipboard", 
            font=ctk.CTkFont(size=14, weight="bold"), 
            height=45, 
            fg_color="#10B981", hover_color="#059669", # 绿色按钮
            command=self.copy_to_clipboard
        )
        self.copy_btn.pack(fill="x", padx=40, pady=(0, 30))

        # --- 底部版权 ---
        self.footer_label = ctk.CTkLabel(
            self, text="Powered by 红尘有爱", 
            text_color="#6B7280", font=ctk.CTkFont(size=12)
        )
        self.footer_label.pack(side="bottom", pady=20)

    def update_levels(self, choice):
        """当选择不同系统时，更新 Level 下拉菜单"""
        if choice == "RouterOS":
            self.level_combo.configure(values=["Level 6", "Level 5", "Level 4"])
            self.level_combo.set("Level 6")
        else:
            self.level_combo.configure(values=["P-Unlimited", "P10", "P1"])
            self.level_combo.set("P-Unlimited")

    def generate_license(self):
        target_id = self.id_entry.get().strip()
        os_type = self.os_combo.get()

        if not target_id:
            self.show_message("Please enter a Software/System ID.", "#FF0000")
            return

        if PRIVATE_KEY_HEX == "YOUR_PRIVATE_KEY_HERE":
            self.show_message("Please configure PRIVATE_KEY_HEX in gui.py", "#FF0000")
            return

        try:
            pk_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
            
            # 调用 license.py 的函数
            # 注意: 原 license.py 中的级别是硬编码的，若需要下拉框动态修改级别，
            # 需要自行去 license.py 的 lic_gen_ros 中把 varb8 和 lic_gen_chr 中的 varb13 改为参数传入。
            if os_type == "RouterOS":
                result = license.lic_gen_ros(target_id, pk_bytes)
            else:
                result = license.lic_gen_chr(target_id, pk_bytes)

            self.show_message(result, "#00FF00")
        except Exception as e:
            self.show_message(f"Error:\n{str(e)}", "#FF0000")

    def show_message(self, message, color):
        self.output_textbox.configure(text_color=color)
        self.output_textbox.delete("0.0", "end")
        self.output_textbox.insert("0.0", message)

    def copy_to_clipboard(self):
        text = self.output_textbox.get("0.0", "end").strip()
        if text and "Error" not in text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update() # 确保剪贴板刷新
            
            # 按钮临时显示反馈
            self.copy_btn.configure(text="Copied!")
            self.after(1500, lambda: self.copy_btn.configure(text="Copy to Clipboard"))

if __name__ == "__main__":
    app = KeyGenApp()
    app.mainloop()
