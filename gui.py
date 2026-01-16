import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import zt_encrypt  # import script crypto langsung

class SecureEncryptGUI:
    def __init__(self, root):
        self.root = root
        root.title("Zero-Trust File Encryption")
        root.geometry("520x360")
        root.resizable(False, False)

        self.mode = tk.StringVar(value="encrypt")
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.password = tk.StringVar()

        self.build_ui()

    def build_ui(self):
        ttk.Label(self.root, text="Mode").pack(pady=5)
        ttk.Radiobutton(self.root, text="Encrypt", variable=self.mode, value="encrypt").pack()
        ttk.Radiobutton(self.root, text="Decrypt", variable=self.mode, value="decrypt").pack()

        ttk.Label(self.root, text="Input File").pack(pady=5)
        ttk.Entry(self.root, textvariable=self.input_file, width=60).pack()
        ttk.Button(self.root, text="Browse", command=self.browse_input).pack(pady=2)

        ttk.Label(self.root, text="Output File").pack(pady=5)
        ttk.Entry(self.root, textvariable=self.output_file, width=60).pack()
        ttk.Button(self.root, text="Browse", command=self.browse_output).pack(pady=2)

        ttk.Label(self.root, text="Password / Passphrase").pack(pady=5)
        ttk.Entry(self.root, textvariable=self.password, show="*", width=40).pack()

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", pady=10)

        ttk.Button(self.root, text="Start", command=self.start).pack(pady=10)

    def browse_input(self):
        self.input_file.set(filedialog.askopenfilename())

    def browse_output(self):
        self.output_file.set(filedialog.asksaveasfilename())

    def start(self):
        if not all([self.input_file.get(), self.output_file.get(), self.password.get()]):
            messagebox.showerror("Error", "All fields are required")
            return

        self.progress.start()
        threading.Thread(target=self.run_crypto, daemon=True).start()

    def run_crypto(self):
        try:
            if self.mode.get() == "encrypt":
                zt_encrypt.encrypt_file(
                    self.input_file.get(),
                    self.output_file.get(),
                    self.password.get()
                )
            else:
                zt_encrypt.decrypt_file(
                    self.input_file.get(),
                    self.output_file.get(),
                    self.password.get()
                )

            messagebox.showinfo("Success", "Operation completed successfully")

        except Exception as e:
            messagebox.showerror("Error", str(e))

        finally:
            self.secure_wipe()
            self.progress.stop()

    def secure_wipe(self):
        # best-effort memory wipe
        self.password.set("")
        self.root.clipboard_clear()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureEncryptGUI(root)
    root.mainloop()
