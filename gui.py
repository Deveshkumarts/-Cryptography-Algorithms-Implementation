import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from math import gcd

# Import AES + SHA modules
from aes_module import aes_encrypt, aes_decrypt
from sha_module import sha256_hash, sha512_hash


# ============================================================
# Helper: Modular Inverse for RSA (Extended Euclid Algorithm)
# ============================================================
def mod_inverse(a, m):
    m0 = m
    x0, x1 = 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


# ============================================================
# MAIN GUI CLASS
# ============================================================
class CryptoSuiteGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureCryptX")
        self.root.geometry("1000x700")

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.tab_aes = ttk.Frame(notebook)
        self.tab_sha = ttk.Frame(notebook)
        self.tab_rsa = ttk.Frame(notebook)

        notebook.add(self.tab_aes, text="AES Encryption / Decryption")
        notebook.add(self.tab_sha, text="SHA Hashing")
        notebook.add(self.tab_rsa, text="RSA (Concept-Based)")

        self.build_aes_tab()
        self.build_sha_tab()
        self.build_rsa_tab()

    # ============================================================
    # AES TAB
    # ============================================================
    def build_aes_tab(self):
        f = self.tab_aes

        tk.Label(f, text="AES File Encryption / Decryption",
                 font=("Arial", 16, "bold")).pack(pady=10)

        tk.Label(f, text="Password:").pack()
        self.aes_password = tk.Entry(f, width=40, show="*")
        self.aes_password.pack()

        tk.Button(f, text="Select File", command=self.select_aes_file).pack(pady=5)
        tk.Button(f, text="Encrypt File", bg="green", fg="white",
                  command=self.encrypt_aes, width=20).pack(pady=5)
        tk.Button(f, text="Decrypt File", bg="blue", fg="white",
                  command=self.decrypt_aes, width=20).pack(pady=5)

        self.aes_log = scrolledtext.ScrolledText(f, width=120, height=18)
        self.aes_log.pack(pady=10)

        self.aes_file_path = None

    def select_aes_file(self):
        self.aes_file_path = filedialog.askopenfilename()
        self.aes_log.insert(tk.END, f"[+] Selected: {self.aes_file_path}\n")

    def encrypt_aes(self):
        if not self.aes_file_path:
            return messagebox.showerror("Error", "Select file first")

        password = self.aes_password.get()
        if not password:
            return messagebox.showerror("Error", "Enter password")

        data = open(self.aes_file_path, "rb").read()
        blob = aes_encrypt(password, data)

        out_path = self.aes_file_path + ".scx"
        open(out_path, "wb").write(blob)
        self.aes_log.insert(tk.END, f"\n[✔] Encrypted → {out_path}\n")

    def decrypt_aes(self):
        if not self.aes_file_path:
            return messagebox.showerror("Error", "Select file first")

        password = self.aes_password.get()
        blob = open(self.aes_file_path, "rb").read()

        try:
            plaintext = aes_decrypt(password, blob)
        except:
            return messagebox.showerror("Error", "Wrong password or corrupted file")

        out_path = self.aes_file_path.replace(".scx", "_decrypted.txt")
        open(out_path, "wb").write(plaintext)
        self.aes_log.insert(tk.END, f"\n[✔] Decrypted → {out_path}\n")

    # ============================================================
    # SHA TAB
    # ============================================================
    def build_sha_tab(self):
        f = self.tab_sha

        tk.Label(f, text="SHA Hashing", font=("Arial", 16, "bold")).pack(pady=10)

        tk.Button(f, text="Select File", command=self.select_sha_file).pack()

        tk.Button(f, text="SHA-256 Hash", width=20,
                  command=self.hash_sha256).pack(pady=5)
        tk.Button(f, text="SHA-512 Hash", width=20,
                  command=self.hash_sha512).pack(pady=5)

        self.sha_log = scrolledtext.ScrolledText(f, width=120, height=18)
        self.sha_log.pack(pady=10)

        self.sha_file_path = None

    def select_sha_file(self):
        self.sha_file_path = filedialog.askopenfilename()
        self.sha_log.insert(tk.END, f"[+] Selected: {self.sha_file_path}\n")

    def hash_sha256(self):
        data = open(self.sha_file_path, "rb").read()
        h = sha256_hash(data)
        self.sha_log.insert(tk.END, f"\n[SHA-256]: {h}\n")

    def hash_sha512(self):
        data = open(self.sha_file_path, "rb").read()
        h = sha512_hash(data)
        self.sha_log.insert(tk.END, f"\n[SHA-512]: {h}\n")

    # ============================================================
    # RSA TAB (p & q → keys → encryption/decryption)
    # ============================================================
    def build_rsa_tab(self):
        f = self.tab_rsa

        tk.Label(f, text="RSA – Enter p and q (Concept-Based RSA)",
                 font=("Arial", 16, "bold")).pack(pady=10)

        # Inputs p and q
        frame = tk.Frame(f)
        frame.pack()

        tk.Label(frame, text="Prime p:").grid(row=0, column=0)
        self.p_val = tk.Entry(frame, width=20)
        self.p_val.grid(row=0, column=1, padx=5)

        tk.Label(frame, text="Prime q:").grid(row=0, column=2)
        self.q_val = tk.Entry(frame, width=20)
        self.q_val.grid(row=0, column=3, padx=5)

        # Button
        tk.Button(f, text="Generate RSA Keys", width=20,
                  command=self.generate_rsa_keys).pack(pady=10)

        # Output area
        self.rsa_info = scrolledtext.ScrolledText(f, width=120, height=14)
        self.rsa_info.pack(pady=10)

        # Encryption/Decryption
        frame2 = tk.Frame(f)
        frame2.pack()

        tk.Label(frame2, text="Plaintext (integer):").grid(row=0, column=0)
        self.rsa_plain = tk.Entry(frame2, width=40)
        self.rsa_plain.grid(row=1, column=0, padx=10)

        tk.Label(frame2, text="Ciphertext (integer):").grid(row=0, column=1)
        self.rsa_cipher = tk.Entry(frame2, width=40)
        self.rsa_cipher.grid(row=1, column=1, padx=10)

        tk.Button(f, text="Encrypt", width=20,
                  command=self.rsa_encrypt).pack(pady=5)
        tk.Button(f, text="Decrypt", width=20,
                  command=self.rsa_decrypt).pack(pady=5)

    # ============================================================
    # Generate RSA Keys using p and q
    # ============================================================
    def generate_rsa_keys(self):
        try:
            p = int(self.p_val.get())
            q = int(self.q_val.get())
        except:
            return messagebox.showerror("Error", "Enter valid integers for p and q")

        if p == q:
            return messagebox.showerror("Error", "p and q must be different primes")

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        if gcd(e, phi) != 1:
            e = 17

        d = mod_inverse(e, phi)

        self.RSA_N = n
        self.RSA_E = e
        self.RSA_D = d

        self.rsa_info.delete("1.0", tk.END)
        self.rsa_info.insert(tk.END, f"p = {p}\nq = {q}\n\n")
        self.rsa_info.insert(tk.END, f"n = {n}\nφ(n) = {phi}\n\n")
        self.rsa_info.insert(tk.END, f"Public Key (n, e):\n({n}, {e})\n\n")
        self.rsa_info.insert(tk.END, f"Private Key (n, d):\n({n}, {d})\n")

    # ============================================================
    # RSA Encryption
    # ============================================================
    def rsa_encrypt(self):
        try:
            m = int(self.rsa_plain.get())
        except:
            return messagebox.showerror("Error", "Plaintext must be an integer")

        c = pow(m, self.RSA_E, self.RSA_N)
        self.rsa_cipher.delete(0, tk.END)
        self.rsa_cipher.insert(0, str(c))

    # ============================================================
    # RSA Decryption
    # ============================================================
    def rsa_decrypt(self):
        try:
            c = int(self.rsa_cipher.get())
        except:
            return messagebox.showerror("Error", "Ciphertext must be an integer")

        m = pow(c, self.RSA_D, self.RSA_N)
        self.rsa_plain.delete(0, tk.END)
        self.rsa_plain.insert(0, str(m))


# ============================================================
# RUN GUI
# ============================================================
if __name__ == "__main__":
    root = tk.Tk()
    CryptoSuiteGUI(root)
    root.mainloop()
