import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import zt_encrypt  # backend crypto (aman, tanpa CLI)

class ZeroTrustEncryptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Zero-Trust AES-256 File Encryptor")
        self.root.geometry("560x420")
        self.root.resizable(False, False)

        self.mode = tk.StringVar(value="encrypt")
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.password = tk.StringVar()
        self.password_confirm = tk.StringVar()

        self._build_ui()

    # ================= UI =================
    def _build_ui(self):
        main = ttk.Frame(self.root, padding=16)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text="Zero-Trust File Encryption",
            font=("TkDefaultFont", 13, "bold")
        ).pack(pady=(0, 10))

        # Mode
        ttk.Label(main, text="Mode").pack(anchor="w")
        ttk.Radiobutton(
            main, text="Encrypt",
            variable=self.mode, value="encrypt",
            command=self._update_action_button
        ).pack(anchor="w")
        ttk.Radiobutton(
            main, text="Decrypt",
            variable=self.mode, value="decrypt",
            command=self._update_action_button
        ).pack(anchor="w")

        ttk.Separator(main).pack(fill="x", pady=10)

        # Input file
        ttk.Label(main, text="Input File").pack(anchor="w")
        ttk.Entry(main, textvariable=self.input_file).pack(fill="x")
        ttk.Button(main, text="Browse…", command=self._browse_input).pack(anchor="w", pady=4)

        # Output file
        ttk.Label(main, text="Output File").pack(anchor="w", pady=(6, 0))
        ttk.Entry(main, textvariable=self.output_file).pack(fill="x")
        ttk.Button(main, text="Browse…", command=self._browse_output).pack(anchor="w", pady=4)

        # Password
        ttk.Label(main, text="Passphrase").pack(anchor="w", pady=(6, 0))
        ttk.Entry(main, textvariable=self.password, show="*").pack(anchor="w", fill="x")

        ttk.Label(main, text="Confirm Passphrase").pack(anchor="w", pady=(6, 0))
        ttk.Entry(main, textvariable=self.password_confirm, show="*").pack(anchor="w", fill="x")

        # Progress
        self.progress = ttk.Progressbar(main, mode="indeterminate")
        self.progress.pack(fill="x", pady=12)

        # Action button (CLEAR & BIG)
        self.action_button = ttk.Button(
            main,
            text="ENCRYPT FILE",
            command=self._start
        )
        self.action_button.pack(fill="x", pady=6)

        # Warning
        ttk.Label(
            main,
            text="⚠ Wrong password or corruption = PERMANENT DATA LOSS",
            foreground="red"
        ).pack(pady=(8, 0))

    # ================= Helpers =================
    def _browse_input(self):
        path = filedialog.askopenfilename()
        if path:
            self.input_file.set(path)

    def _browse_output(self):
        path = filedialog.asksaveasfilename()
        if path:
            self.output_file.set(path)

    def _update_action_button(self):
        if self.mode.get() == "encrypt":
            self.action_button.config(text="ENCRYPT FILE")
        else:
            self.action_button.config(text="DECRYPT FILE")

    # ================= Core =================
    def _start(self):
        if not self._validate():
            return

        if self.mode.get() == "encrypt":
            if not messagebox.askyesno(
                "Confirm Encryption",
                "Encryption is irreversible without the passphrase.\n\nContinue?"
            ):
                return

        self.action_button.config(state="disabled")
        self.progress.start()
        threading.Thread(target=self._run_crypto, daemon=True).start()

    def _run_crypto(self):
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

            messagebox.showinfo("Success", "Operation completed successfully.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

        finally:
            self._secure_cleanup()
            self.progress.stop()
            self.action_button.config(state="normal")

    # ================= Security =================
    def _validate(self):
        if not self.input_file.get():
            messagebox.showerror("Error", "Input file is required.")
            return False

        if not self.output_file.get():
            messagebox.showerror("Error", "Output file is required.")
            return False

        if not self.password.get():
            messagebox.showerror("Error", "Passphrase is required.")
            return False

        if self.password.get() != self.password_confirm.get():
            messagebox.showerror("Error", "Passphrases do not match.")
            return False

        return True

    def _secure_cleanup(self):
        # best-effort wipe
        self.password.set("")
        self.password_confirm.set("")
        self.root.clipboard_clear()


# ================= Entry =================
if __name__ == "__main__":
    root = tk.Tk()
    app = ZeroTrustEncryptorGUI(root)
    root.mainloop()
