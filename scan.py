import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import hashlib
import threading
import time
import os

class VirusDetectionSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Virus Detection System")
        self.root.geometry("600x400")  
        self.create_ui()
        
        self.virus_signature = "bad_signature"
        self.running_thread = None
        self.scan_history = []
    
    def create_ui(self):
        self.file_label = tk.Label(self.root, text="Selected File:")
        self.file_label.pack(pady=10)
        
        self.file_path = tk.StringVar()
        self.file_path_entry = tk.Entry(self.root, textvariable=self.file_path, state="readonly", width=40)
        self.file_path_entry.pack()
        
        self.browse_button = tk.Button(self.root, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)
        
        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)
        
        self.result_text = scrolledtext.ScrolledText(self.root, width=60, height=10, wrap=tk.WORD)
        self.result_text.pack(pady=10)
        
        self.scan_history_button = tk.Button(self.root, text="Show Scan History", command=self.show_scan_history)
        self.scan_history_button.pack(pady=5)
        
        self.schedule_button = tk.Button(self.root, text="Schedule Daily Scan", command=self.schedule_scan)
        self.schedule_button.pack(pady=5)
        
        self.real_time_protection_button = tk.Button(self.root, text="Enable Real-time Protection", command=self.enable_real_time_protection)
        self.real_time_protection_button.pack(pady=5)
        
        self.real_time_protection = False
        
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)
            self.result_text.delete(1.0, tk.END)
    
    def start_scan(self):
        if self.running_thread and self.running_thread.is_alive():
            messagebox.showinfo("Info", "Scan is already running.")
            return
        
        file_path = self.file_path.get()
        
        if not file_path:
            messagebox.showerror("Error", "Please select a file before starting the scan.")
            return
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Scanning...\n")
        self.running_thread = threading.Thread(target=self.scan_viruses, args=(file_path,))
        self.running_thread.start()
    
    def scan_viruses(self, file_path):
        try:
            time.sleep(2)  
            virus_detected = self.detect_virus(file_path)
            
            if virus_detected:
                self.result_text.insert(tk.END, "Virus Detected: The file contains a virus.\n")
                self.save_scan_history(file_path, "Infected")
            else:
                self.result_text.insert(tk.END, "No Virus Found: The file is clean.\n")
                self.save_scan_history(file_path, "Clean")
        except Exception as e:
            self.result_text.insert(tk.END, "Error: " + str(e) + "\n")
    
    def detect_virus(self, file_path):
        with open(file_path, "rb") as file:
            content = file.read()
            content_hash = hashlib.md5(content).hexdigest()
            
            if content_hash == self.virus_signature:
                return True
            else:
                return False
    
    def save_scan_history(self, file_path, result):
        scan_info = f"File: {file_path} - Result: {result} - Time: {time.ctime()}"
        self.scan_history.append(scan_info)
    
    def show_scan_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Scan History")
        
        history_text = scrolledtext.ScrolledText(history_window, width=60, height=10, wrap=tk.WORD)
        history_text.pack(padx=10, pady=10)
        
        for scan_info in self.scan_history:
            history_text.insert(tk.END, scan_info + "\n")
    
    def schedule_scan(self):
        messagebox.showinfo("Scheduled Scan", "Scheduled daily scan initiated.")
    
    def enable_real_time_protection(self):
        if not self.real_time_protection:
            self.real_time_protection = True
            self.real_time_protection_button.config(text="Disable Real-time Protection")
            self.result_text.insert(tk.END, "Real-time protection enabled.\n")
        else:
            self.real_time_protection = False
            self.real_time_protection_button.config(text="Enable Real-time Protection")
            self.result_text.insert(tk.END, "Real-time protection disabled.\n")

def main():
    root = tk.Tk()
    app = VirusDetectionSystem(root)
    root.mainloop()

if __name__ == "__main__":
    main()
