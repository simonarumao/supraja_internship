import tkinter as tk
from tkinter import simpledialog, messagebox
import sqlite3
import winreg as reg
import ctypes
import sys
from datetime import datetime

# Database setup
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')
conn.commit()

cursor.execute('''
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
''')
conn.commit()

# Function to check if script is run with admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Function to restart the script with admin privileges
def restart_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

def log_activity(user_id, action):
    username = cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()[0]
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO activity_log (user_id, action, timestamp) VALUES (?, ?, ?)", (user_id, action, timestamp))
    conn.commit()

# Function to enable and disable USB ports
def disable_usb():
    global logged_in_user

    # Check if a user is logged in
    if logged_in_user:
        # Prompt for the password to confirm action
        password = CustomDialog(main_window, "Confirm Action", "Enter your password to disable USB ports:")
        if password.result == logged_in_user[2]:  # logged_in_user[2] is the password stored in the database
            try:
                key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, reg.KEY_SET_VALUE)
                reg.SetValueEx(key, "Start", 0, reg.REG_DWORD, 4)
                reg.CloseKey(key)
                messagebox.showinfo("Success", "USB ports have been disabled.", parent=main_window)
                log_activity(logged_in_user[0], "Disabled USB ports")
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=main_window)
        else:
            messagebox.showerror("Error", "Incorrect password. Action aborted.", parent=main_window)
    else:
        messagebox.showerror("Error", "You must be logged in to disable USB ports.", parent=main_window)

def enable_usb():
    global logged_in_user
    if logged_in_user:
        try:
            key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, reg.KEY_SET_VALUE)
            reg.SetValueEx(key, "Start", 0, reg.REG_DWORD, 3)
            reg.CloseKey(key)
            messagebox.showinfo("Success", "USB ports have been enabled.", parent=main_window)
            log_activity(logged_in_user[0], "Enabled USB ports")
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=main_window)
    else:
        messagebox.showerror("Error", "You must be logged in to enable USB ports.", parent=main_window)

# Custom Dialog class for larger input dialogs
class CustomDialog(simpledialog.Dialog):
    def __init__(self, parent, title, prompt):
        self.prompt = prompt
        super().__init__(parent, title)

    def body(self, master):
        tk.Label(master, text=self.prompt, font=('Arial', 14)).pack(pady=10)
        self.entry = tk.Entry(master, show='*', font=('Arial', 14))
        self.entry.pack(pady=10, padx=10)
        self.geometry("400x200")  # Set size of dialog

    def apply(self):
        self.result = self.entry.get()

# Function to handle user sign-up
def signup():
    username = CustomDialog(login_signup_window, "Sign Up", "Enter a new username:").result
    password = CustomDialog(login_signup_window, "Sign Up", "Enter a new password:").result
    if username and password:
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            messagebox.showinfo("Success", "User registered successfully.", parent=login_signup_window)
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.", parent=login_signup_window)

# Function to handle user login
def login():
    global logged_in_user
    username = CustomDialog(login_signup_window, "Login", "Enter your username:").result
    password = CustomDialog(login_signup_window, "Login", "Enter your password:").result
    if username and password:
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            logged_in_user = user
            messagebox.showinfo("Success", "Logged in successfully.", parent=login_signup_window)
            login_signup_window.destroy()
            show_main_window()
        else:
            messagebox.showerror("Error", "Invalid username or password.", parent=login_signup_window)

# Function to show the main application window
def show_main_window():
    global main_window
    main_window = tk.Tk()
    main_window.title("USB Port Manager")

    # Styling
    main_window.configure(bg='#e0e0e0')
    main_window.geometry('800x600')  # Set initial window size

    # Header
    header = tk.Frame(main_window, bg='#4d4d4d', height=50)
    header.pack(side=tk.TOP, fill=tk.X)

    header_label = tk.Label(header, text="USB Port Manager", bg='#4d4d4d', fg='white', font=('Arial', 20, 'bold'))
    header_label.pack(pady=10)

    frame = tk.Frame(main_window, padx=20, pady=20, bg='#f0f0f0')
    frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    enable_button = tk.Button(frame, text="Enable USB Ports", command=enable_usb, width=25, bg='#4CAF50', fg='white', font=('Arial', 14, 'bold'))
    enable_button.grid(row=0, column=0, pady=20, padx=10, sticky='ew')

    disable_button = tk.Button(frame, text="Disable USB Ports", command=check_login_and_disable_usb, width=25, bg='#f44336', fg='white', font=('Arial', 14, 'bold'))
    disable_button.grid(row=1, column=0, pady=20, padx=10, sticky='ew')

    log_button = tk.Button(frame, text="View Log", command=show_log_window, width=25, bg='#2196F3', fg='white', font=('Arial', 14, 'bold'))
    log_button.grid(row=2, column=0, pady=20, padx=10, sticky='ew')

    # Footer
    footer = tk.Frame(main_window, bg='#4d4d4d', height=30)
    footer.pack(side=tk.BOTTOM, fill=tk.X)

    footer_label = tk.Label(footer, text="Developed by [Your Name]", bg='#4d4d4d', fg='white', font=('Arial', 12))
    footer_label.pack(pady=5)

    main_window.mainloop()

# Function to check if user is logged in before disabling USB ports
def check_login_and_disable_usb():
    if logged_in_user:
        disable_usb()
    else:
        messagebox.showerror("Error", "You must be logged in to disable USB ports.", parent=main_window)

# Function to display log window
def show_log_window():
    log_window = tk.Toplevel(main_window)
    log_window.title("Activity Log")
    log_window.geometry('800x600')  # Set initial window size

    # Styling
    log_window.configure(bg='#e0e0e0')
    frame = tk.Frame(log_window, padx=20, pady=20, bg='#f0f0f0')
    frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    log_label = tk.Label(frame, text="Activity Log", font=('Arial', 18, 'bold'), bg='#f0f0f0', fg='black')
    log_label.grid(row=0, column=0, pady=10, padx=10, sticky='w')

    scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
    log_text = tk.Text(frame, height=15, width=80, yscrollcommand=scrollbar.set, bg='#ffffff', fg='black', font=('Arial', 12))
    scrollbar.config(command=log_text.yview)
    scrollbar.grid(row=1, column=1, sticky=tk.NS)
    log_text.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')

    # Fetch and display log entries
    cursor.execute("SELECT u.username, a.action, a.timestamp FROM activity_log a JOIN users u ON a.user_id = u.id ORDER BY a.timestamp DESC")
    log_entries = cursor.fetchall()
    for entry in log_entries:
        log_text.insert(tk.END, f"Username: {entry[0]}\nAction: {entry[1]}\nTimestamp: {entry[2]}\n\n")

    log_text.config(state=tk.DISABLED)  # Disable editing of log text

    log_window.mainloop()

# Function to create the login/signup GUI
def create_login_signup_gui():
    global login_signup_window
    login_signup_window = tk.Tk()
    login_signup_window.title("Login/Sign Up")

    # Styling
    login_signup_window.configure(bg='#e0e0e0')
    login_signup_window.geometry('500x300')  # Set initial window size

    # Header
    header = tk.Frame(login_signup_window, bg='#4d4d4d', height=50)
    header.pack(side=tk.TOP, fill=tk.X)

    header_label = tk.Label(header, text="Welcome to USB Port Manager", bg='#4d4d4d', fg='white', font=('Arial', 20, 'bold'))
    header_label.pack(pady=10)

    frame = tk.Frame(login_signup_window, padx=20, pady=20, bg='#f0f0f0')
    frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    login_button = tk.Button(frame, text="Login", command=login, width=25, bg='#2196F3', fg='white', font=('Arial', 14, 'bold'))
    login_button.grid(row=0, column=0, pady=20, padx=10, sticky='ew')

    signup_button = tk.Button(frame, text="Sign Up", command=signup, width=25, bg='#4CAF50', fg='white', font=('Arial', 14, 'bold'))
    signup_button.grid(row=1, column=0, pady=20, padx=10, sticky='ew')

    # Footer
    footer = tk.Frame(login_signup_window, bg='#4d4d4d', height=30)
    footer.pack(side=tk.BOTTOM, fill=tk.X)

    footer_label = tk.Label(footer, text="Developed by [Your Name]", bg='#4d4d4d', fg='white', font=('Arial', 12))
    footer_label.pack(pady=5)

    login_signup_window.mainloop()

if __name__ == "__main__":
    logged_in_user = None
    restart_as_admin()
    create_login_signup_gui()
