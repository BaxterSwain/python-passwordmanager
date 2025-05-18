import tkinter as tk
from tkinter import filedialog
import os
import random
import string
import pyotp
import zxcvbn
from cryptography.fernet import Fernet
from python_passwordmanager import PasswordManager


class PasswordManagerUI:
    def __init__(self, root):
        root.title("Baxter's Awesome Password Manager")
        root.geometry("960x600")
        root.configure(bg="#2c2c2c")

        self.pm = PasswordManager()
        self.project_dir = os.path.dirname(os.path.abspath(__file__))

        font = ("Segoe UI", 10)
        self.font = font
        self.button_color = "#3a3a3a"
        self.button_fg = "#ffffff"
        self.hover_color = "#4a4a4a"
        self.scrollbar_color = "#4a4a4a"  # Scrollbar styling color

        title = tk.Label(root, text="Baxter’s Awesome Password Manager", font=("Segoe UI", 16), bg="#2c2c2c", fg="#e0e0e0")
        title.pack(pady=(10, 0))

        button_frame = tk.Frame(root, bg="#2c2c2c")
        button_frame.pack(pady=10)

        buttons = [
            ("Create Key", self.create_key),
            ("Load Key", self.load_key),
            ("Load Password File", self.load_password_file),
            ("Save Password File", self.save_password_file),
            ("Add password", self.add_password),
            ("Retrieve Password", self.retrieve_password),
            ("Generate Password", self.show_generated_password),
            ("View All", self.view_passwords)
        ]

        for text, command in buttons:
            btn = tk.Label(button_frame, text=text, font=font, bg=self.button_color, fg=self.button_fg,
                          padx=10, pady=5, bd=0, relief="flat", cursor="hand2")
            btn.pack(side="left", padx=5)
            btn.bind("<Button-1>", lambda e, cmd=command: cmd())
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.hover_color))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=self.button_color))

        tk.Frame(root, height=2, bg="#1a1a1a").pack(fill="x", pady=10)

        search_frame = tk.Frame(root, bg="#2c2c2c")
        search_frame.pack(pady=5)

        tk.Label(search_frame, text="Search:", bg="#2c2c2c", fg="#ffffff", font=font).pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, bg="#3a3a3a", fg="#ffffff",
                                insertbackground="white", relief="flat", width=30)
        search_entry.pack(side="left", padx=10)
        search_entry.bind('<KeyRelease>', self.filter_passwords)

        content_frame = tk.Frame(root, bg="#2c2c2c")
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create a scrollable frame for the passwords and copy buttons
        self.scroll_frame = tk.Frame(content_frame, bg="#2c2c2c")
        self.scroll_frame.grid(row=0, column=0, sticky="nsew")
        
        self.canvas = tk.Canvas(self.scroll_frame, bg="#2c2c2c")
        self.scrollbar = tk.Scrollbar(self.scroll_frame, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.scrollable_frame = tk.Frame(self.canvas, bg="#2c2c2c")
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=1)

    def show_generated_password(self):
        # Show password generator dialog
        top = tk.Toplevel()
        top.title("Generate Custom Password")
        top.configure(bg="#2c2c2c")
        top.geometry("350x250")
        top.grab_set()

        length_var = tk.IntVar(value=12)
        top.include_numbers_var = tk.BooleanVar(value=True)
        top.include_special_chars_var = tk.BooleanVar(value=True)
        top.exclude_ambiguous_var = tk.BooleanVar(value=True)

        def update_generated_password():
            length = length_var.get()
            include_numbers = top.include_numbers_var.get()
            include_special_chars = top.include_special_chars_var.get()
            exclude_ambiguous = top.exclude_ambiguous_var.get()

            # Generate password with the given parameters
            generated_password = self.generate_password(length, include_numbers, include_special_chars, exclude_ambiguous)
            generated_label.config(text=f"Generated Password: {generated_password}")

        tk.Label(top, text="Password Length:", bg="#2c2c2c", fg="#ffffff").pack(pady=5)
        tk.Entry(top, textvariable=length_var, bg="#3a3a3a", fg="#ffffff", insertbackground="white", relief="flat", width=10).pack(pady=5)

        tk.Checkbutton(
            top,
            text="Include Numbers",
            variable=top.include_numbers_var,
            bg="#2c2c2c",
            fg="#ffffff",
            activebackground="#2c2c2c",
            selectcolor="#3a3a3a"
        ).pack()

        tk.Checkbutton(
            top,
            text="Include Special Characters",
            variable=top.include_special_chars_var,
            bg="#2c2c2c",
            fg="#ffffff",
            activebackground="#2c2c2c",
            selectcolor="#3a3a3a"
        ).pack()

        tk.Checkbutton(
            top,
            text="Exclude Ambiguous Characters",
            variable=top.exclude_ambiguous_var,
            bg="#2c2c2c",
            fg="#ffffff",
            activebackground="#2c2c2c",
            selectcolor="#3a3a3a"
        ).pack()

        generated_label = tk.Label(top, text="Generated Password: ", bg="#2c2c2c", fg="#ffffff")
        generated_label.pack(pady=10)

        tk.Button(top, text="Generate", command=update_generated_password, bg="#3a3a3a", fg="#ffffff").pack(pady=10)
        update_generated_password()  # Generate initially


    def generate_password(self, length=12, include_numbers=True, include_special_chars=True, exclude_ambiguous=True):
        # Password generation logic with user-defined parameters
        chars = string.ascii_letters
        if include_numbers:
            chars += string.digits
        if include_special_chars:
            chars += string.punctuation
        if exclude_ambiguous:
            chars = chars.translate(str.maketrans('', '', 'l1I0O'))

        return ''.join(random.choice(chars) for _ in range(length))

    def password_strength(self, password):
        # Score ranges from 0 (weak) to 4 (strong)
        score = 0

        # Length check
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1

        # Check for lowercase letters
        if any(c.islower() for c in password):
            score += 1

        # Check for uppercase letters
        if any(c.isupper() for c in password):
            score += 1

        # Check for digits
        if any(c.isdigit() for c in password):
            score += 1

        # Check for special characters
        if any(c in string.punctuation for c in password):
            score += 1

        # Check for common patterns (e.g. "12345", "password")
        common_patterns = ["12345", "password", "qwerty", "letmein"]
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 1  # Deduct points for common patterns

        # Return strength category based on score
        if score < 3:
            return "Weak"
        elif score < 5:
            return "Moderate"
        elif score < 7:
            return "Strong"
        else:
            return "Very Strong"

    def edit_password(self, site, current_pw):
        # Create the dialog for editing the password
        top = tk.Toplevel()
        top.title(f"Edit Password for {site}")
        top.configure(bg="#2c2c2c")
        top.geometry("350x300")
        top.grab_set()

        tk.Label(top, text=f"Edit Password for {site}", font=("Segoe UI", 14), fg="#ffffff", bg="#2c2c2c").pack(pady=10)

        new_pw_var = tk.StringVar()
        confirm_pw_var = tk.StringVar()

        def update_strength(*_):
            strength = self.password_strength(new_pw_var.get())
            strength_label.config(text=f"Strength: {strength}")

        tk.Label(top, text="New Password:", bg="#2c2c2c", fg="#ffffff").pack(pady=5)
        new_pw_entry = tk.Entry(top, textvariable=new_pw_var, show='*', bg="#3a3a3a", fg="#ffffff", insertbackground="white", relief="flat", width=30)
        new_pw_entry.pack(pady=5)
        new_pw_var.trace_add('write', update_strength)

        tk.Label(top, text="Confirm Password:", bg="#2c2c2c", fg="#ffffff").pack(pady=5)
        confirm_pw_entry = tk.Entry(top, textvariable=confirm_pw_var, show='*', bg="#3a3a3a", fg="#ffffff", insertbackground="white", relief="flat", width=30)
        confirm_pw_entry.pack(pady=5)

        strength_label = tk.Label(top, text="Strength: Unknown", bg="#2c2c2c", fg="#ffffff")
        strength_label.pack(pady=5)

        def submit():
            if new_pw_var.get() != confirm_pw_var.get():
                self.show_custom_dialog("Mismatch", "Passwords do not match.", "error")
                return
            try:
                self.pm.add_password(site, new_pw_var.get())  # Overwrite old password
                self.show_custom_dialog("Success", f"Password for {site} updated.")
                self.view_passwords()  # Refresh password list
                top.destroy()
            except Exception as e:
                self.show_custom_dialog("Error", f"Failed to update password: {str(e)}", "error")

        tk.Button(top, text="Save", command=submit, bg="#3a3a3a", fg="#ffffff").pack(pady=10)

    def view_passwords(self):
        # Clear previous content in the scrollable frame
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        # Add passwords and copy buttons dynamically
        for site, pw in self.pm.password_dict.items():
            row_frame = tk.Frame(self.scrollable_frame, bg="#2c2c2c")
            row_frame.pack(fill="x", pady=5)

            # Display the site and password
            password_label = tk.Label(row_frame, text=f"{site}: {pw}", font=("Consolas", 11), bg="#2c2c2c", fg="#e0e0e0")
            password_label.pack(side="left")

            # Copy button for each password
            copy_button = tk.Button(row_frame, text="Copy", command=lambda pw=pw: self.copy_to_clipboard(pw),
                                    bg=self.button_color, fg=self.button_fg, relief="flat")
            copy_button.pack(side="right", padx=10)

            # Edit button for each password
            edit_button = tk.Button(row_frame, text="Edit", command=lambda site=site, pw=pw: self.edit_password(site, pw),
                                    bg="#ff5c5c", fg="#ffffff", relief="flat")
            edit_button.pack(side="right", padx=10)

    def copy_to_clipboard(self, password):
        self.scrollable_frame.clipboard_clear()
        self.scrollable_frame.clipboard_append(password)
        self.show_custom_dialog("Copied", "Password copied to clipboard.")

    def show_custom_dialog(self, title, message, dialog_type="info"):
        top = tk.Toplevel()
        top.title(title)
        top.configure(bg="#2c2c2c")
        top.geometry("300x150")
        top.grab_set()

        fg = "#00ffe7" if dialog_type == "info" else "#ff5c5c"

        tk.Label(top, text=title, font=("Segoe UI", 12, "bold"), fg=fg, bg="#2c2c2c").pack(pady=(10, 5))
        tk.Label(top, text=message, font=self.font, fg="#ffffff", bg="#2c2c2c", wraplength=280).pack(pady=5)
        tk.Button(top, text="OK", command=top.destroy, bg="#3a3a3a", fg="#ffffff",
                  activebackground="#4a4a4a", relief="flat", padx=10, pady=4).pack(pady=10)

    def create_key(self):
        path = filedialog.asksaveasfilename(title="Save Key File", defaultextension=".key", initialdir=self.project_dir)
        if path:
            top = tk.Toplevel()
            top.title("Create Master Password")
            top.configure(bg="#2c2c2c")

            tk.Label(top, text="Enter Master Password:", bg="#2c2c2c", fg="#ffffff").pack(pady=5)
            pwd_var = tk.StringVar()
            confirm_var = tk.StringVar()

            def update_strength(*_):
                strength = self.password_strength(pwd_var.get())
                strength_label.config(text=f"Strength: {strength}")

            tk.Entry(top, textvariable=pwd_var, show='*').pack()
            pwd_var.trace_add('write', update_strength)

            tk.Label(top, text="Confirm Password:", bg="#2c2c2c", fg="#ffffff").pack()
            tk.Entry(top, textvariable=confirm_var, show='*').pack()

            strength_label = tk.Label(top, text="Strength: Unknown", bg="#2c2c2c", fg="#ffffff")
            strength_label.pack(pady=5)

            def submit():
                if pwd_var.get() != confirm_var.get():
                    self.show_custom_dialog("Mismatch", "Passwords do not match.", "error")
                    return
                try:
                    self.pm.create_key(path, pwd_var.get())
                    self.show_custom_dialog("Success", f"Key created and saved to {path}")
                    top.destroy()
                except Exception as e:
                    self.show_custom_dialog("Error", f"Failed to create key: {str(e)}", "error")

            tk.Button(top, text="Save", command=submit, bg="#3a3a3a", fg="#ffffff").pack(pady=10)

    def load_key(self):
        path = filedialog.askopenfilename(title="Select Key File", initialdir=self.project_dir)
        if path:
            master = self.prompt_password("Master Password", "Enter your master password:")
            try:
                self.pm.load_key(path, master)
                self.show_custom_dialog("Success", "Key loaded successfully.")
            except Exception as e:
                self.show_custom_dialog("Error", f"Failed to load key: {str(e)}", "error")

    def load_password_file(self):
        if not self.pm.key:
            self.show_custom_dialog("Error", "Load a key first.", "error")
            return
        path = filedialog.askopenfilename(title="Select Password File", initialdir=self.project_dir)
        if path:
            self.pm.load_password_file(path)
            self.pm.password_file = path
            self.show_custom_dialog("Loaded", f"Loaded passwords from {path}")

    def save_password_file(self):
        if not self.pm.key:
            self.show_custom_dialog("Error", "Load a key first.", "error")
            return
        path = filedialog.asksaveasfilename(title="Save Password File", defaultextension=".txt", initialdir=self.project_dir)
        if path:
            self.pm.password_file = path
            with open(path, 'w') as f:
                for site, password in self.pm.password_dict.items():
                    encrypted = Fernet(self.pm.key).encrypt(password.encode())
                    f.write(f"{site}:{encrypted.decode()}\n")
            self.show_custom_dialog("Saved", f"Passwords saved to {path}")

    def add_password(self):
        if not self.pm.key:
            self.show_custom_dialog("Error", "Load a key first.", "error")
            return
        site = self.prompt_string("Site", "Enter site name:")
        if not site:
            return

        choice = self.prompt_string("Password Choice", "Type 'generate' to generate a password or leave blank to input manually:")
        if choice and choice.lower() == "generate":
            password = self.generate_password()
            self.show_custom_dialog("Generated", f"Generated password: {password}")
        else:
            password = self.prompt_password("Password", f"Enter password for {site}:")

        # Confirm the password strength
        strength = self.password_strength(password)
        self.show_custom_dialog("Password Strength", f"Password strength: {strength}")

        # Confirm with the user
        confirm = self.prompt_string("Confirm", f"Are you sure you want to save the password for {site}? (yes/no)")
        if confirm.lower() == "yes":
            self.pm.add_password(site, password)
            self.view_passwords()
            self.show_custom_dialog("Saved", f"Password for '{site}' saved.")
        else:
            self.show_custom_dialog("Canceled", "Password saving canceled.")

    def retrieve_password(self):
        site = self.prompt_string("Retrieve", "Enter site to retrieve:")
        if site:
            pw = self.pm.get_password(site)
            self.show_custom_dialog("Password Retrieved", f"{site}: {pw}")

    def prompt_string(self, title, prompt):
        return self._prompt_input(title, prompt, show=None)

    def prompt_password(self, title, prompt):
        return self._prompt_input(title, prompt, show='*')

    def _prompt_input(self, title, prompt, show):
        top = tk.Toplevel()
        top.title(title)
        top.configure(bg="#2c2c2c")
        top.geometry("350x150")
        top.grab_set()

        tk.Label(top, text=prompt, font=self.font, fg="#ffffff", bg="#2c2c2c").pack(pady=10)
        entry_var = tk.StringVar()
        entry = tk.Entry(top, textvariable=entry_var, show=show, bg="#3a3a3a", fg="#ffffff",
                         insertbackground="white", relief="flat", width=30)
        entry.pack()
        entry.focus()

        result = []

        def on_submit():
            result.append(entry_var.get())
            top.destroy()

        tk.Button(top, text="OK", command=on_submit, bg="#3a3a3a", fg="#ffffff", relief="flat", padx=10, pady=4).pack(pady=10)
        top.wait_window()
        return result[0] if result else None

    def generate_password(self, length=12, include_numbers=True, include_special_chars=True, exclude_ambiguous=True):
        # Password generation logic with user-defined parameters
        chars = string.ascii_letters
        if include_numbers:
            chars += string.digits
        if include_special_chars:
            chars += string.punctuation
        if exclude_ambiguous:
            chars = chars.translate(str.maketrans('', '', 'l1I0O'))

        return ''.join(random.choice(chars) for _ in range(length))

        def password_strength(self, password):
        # Use zxcvbn to evaluate the strength of the password
            result = zxcvbn.zxcvbn(password)  # Correct function call
            return result['score']  # Score ranges from 0 (weak) to 4 (strong)


    def filter_passwords(self, event=None):
        query = self.search_var.get().lower()
        self.view_passwords()  # Refresh the password view based on search query
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        for site, pw in self.pm.password_dict.items():
            if query in site.lower():
                row_frame = tk.Frame(self.scrollable_frame, bg="#2c2c2c")
                row_frame.pack(fill="x", pady=5)
                password_label = tk.Label(row_frame, text=f"{site}: {pw}", font=("Consolas", 11), bg="#2c2c2c", fg="#e0e0e0")
                password_label.pack(side="left")
                copy_button = tk.Button(row_frame, text="Copy", command=lambda pw=pw: self.copy_to_clipboard(pw),
                                        bg=self.button_color, fg=self.button_fg, relief="flat")
                copy_button.pack(side="right", padx=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerUI(root)
    root.mainloop()
    