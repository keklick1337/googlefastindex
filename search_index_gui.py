import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from tkinter import StringVar, BooleanVar, IntVar
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import BatchHttpRequest
import random
import time
import json
import datetime
import threading

class GoogleIndexingApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Google Indexing API URL Submission")
        self.master.geometry("900x700")
        
        # Data storage
        self.json_files = []
        self.json_stats = {}  # Track usage and errors for each JSON file
        self.urls_to_process = []
        self.processing = False
        self.use_local_db = BooleanVar(value=True)
        self.url_count = IntVar(value=0)
        self.processed_count = IntVar(value=0)
        self.total_urls = 0
        
        # Database file
        self.db_file = 'indexed_urls.db'
        self.ensure_db_exists()
        
        # Create UI
        self.create_widgets()
        
    def ensure_db_exists(self):
        """Create database file if it doesn't exist"""
        if not os.path.exists(self.db_file):
            with open(self.db_file, 'w') as f:
                f.write("# Indexed URLs database file\n")
                f.write("# Format: URL|STATUS|TIMESTAMP|ERROR_MESSAGE\n")

    def create_widgets(self):
        # Create tabs
        self.tab_control = ttk.Notebook(self.master)
        
        # Main tab
        self.main_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.main_tab, text='Main')
        
        # JSON tab
        self.json_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.json_tab, text='JSON Files')
        
        # Results tab
        self.results_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.results_tab, text='Results')
        
        self.tab_control.pack(expand=1, fill="both")
        
        # Configure main tab
        self.setup_main_tab()
        
        # Configure JSON tab
        self.setup_json_tab()
        
        # Configure results tab
        self.setup_results_tab()

    def paste_cmd(self, event):
        self.urls_text.event_generate("<<Paste>>")
        return "break"

    def selectall(self, event):
        event.widget.tag_add("sel","1.0","end")

    def setup_main_tab(self):
        # JSON files frame
        json_frame = ttk.LabelFrame(self.main_tab, text="JSON Key Files")
        json_frame.pack(fill="x", padx=10, pady=5)
        
        self.json_button = ttk.Button(json_frame, text="Select JSON Key Files", command=self.select_json_files)
        self.json_button.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.json_count_label = ttk.Label(json_frame, text="No JSON files selected")
        self.json_count_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # URLs input frame
        urls_frame = ttk.LabelFrame(self.main_tab, text="URLs Input")
        urls_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.urls_text = scrolledtext.ScrolledText(urls_frame, width=80, height=10)
        self.urls_text.pack(fill="both", expand=True, padx=5, pady=5)
        # Bind paste on macOS and Windows
        self.urls_text.bind("<Command-v>", self.paste_cmd)
        self.urls_text.bind("<Control-v>", self.paste_cmd)
        self.urls_text.bind_class("Text","<Control-a>", self.selectall)

        self.urls_text.bind("<KeyRelease>", self.update_url_count)
        
        # URL count display
        self.url_count_label = ttk.Label(urls_frame, textvariable=self.url_count)
        self.url_count_label.pack(side=tk.RIGHT, padx=10, pady=5)
        ttk.Label(urls_frame, text="URLs detected:").pack(side=tk.RIGHT, padx=0, pady=5)
        
        # Database option
        db_frame = ttk.Frame(self.main_tab)
        db_frame.pack(fill="x", padx=10, pady=2)
        
        ttk.Checkbutton(db_frame, text="Use local database (prevent re-indexing URLs)", 
                       variable=self.use_local_db).pack(side=tk.LEFT, padx=10)
        
        # Control frame
        control_frame = ttk.Frame(self.main_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.submit_button = ttk.Button(control_frame, text="Submit URLs", command=self.prepare_submission)
        self.submit_button.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.progress_var = StringVar(value="Ready")
        self.progress_label = ttk.Label(control_frame, textvariable=self.progress_var)
        self.progress_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(control_frame, orient="horizontal", 
                                           length=300, mode="determinate")
        self.progress_bar.pack(side=tk.LEFT, padx=10, pady=10, fill="x", expand=True)
        
        self.progress_text = StringVar(value="0/0")
        ttk.Label(control_frame, textvariable=self.progress_text).pack(side=tk.LEFT, padx=10)
        
        # Log frame
        log_frame = ttk.LabelFrame(self.main_tab, text="Logs")
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.status_display = scrolledtext.ScrolledText(log_frame, width=80, height=10)
        self.status_display.pack(fill="both", expand=True, padx=5, pady=5)

    def setup_json_tab(self):
        # JSON files list
        self.json_tree = ttk.Treeview(self.json_tab, columns=("Path", "Usage", "Errors", "Status"), show="headings")
        self.json_tree.heading("Path", text="JSON File Path")
        self.json_tree.heading("Usage", text="Usage Count")
        self.json_tree.heading("Errors", text="Error Count")
        self.json_tree.heading("Status", text="Status")
        self.json_tree.column("Path", width=400)
        self.json_tree.column("Usage", width=100)
        self.json_tree.column("Errors", width=100)
        self.json_tree.column("Status", width=100)
        self.json_tree.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_results_tab(self):
        # Results treeview
        self.results_tree = ttk.Treeview(self.results_tab, columns=("URL", "Status", "Error"), show="headings")
        self.results_tree.heading("URL", text="URL")
        self.results_tree.heading("Status", text="Status")
        self.results_tree.heading("Error", text="Error Message")
        self.results_tree.column("URL", width=400)
        self.results_tree.column("Status", width=100)
        self.results_tree.column("Error", width=300)
        self.results_tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add context menu for copying error
        self.results_menu = tk.Menu(self.results_tree, tearoff=0)
        self.results_menu.add_command(label="Copy URL", command=self.copy_url)
        self.results_menu.add_command(label="Copy Error", command=self.copy_error)
        
        self.results_tree.bind("<Button-3>", self.show_context_menu)
        
        # Add buttons for filtering
        filter_frame = ttk.Frame(self.results_tab)
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(filter_frame, text="Show All", 
                  command=lambda: self.filter_results("all")).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Show Successful", 
                  command=lambda: self.filter_results("success")).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Show Errors", 
                  command=lambda: self.filter_results("error")).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Export Results", 
                  command=self.export_results).pack(side=tk.LEFT, padx=5)

    def update_url_count(self, event=None):
        """Update URL count when text changes"""
        url_text = self.urls_text.get("1.0", tk.END).strip()
        if not url_text:
            self.url_count.set(0)
        else:
            urls = [url.strip() for url in url_text.split('\n') if url.strip()]
            self.url_count.set(len(urls))

    def select_json_files(self):
        files = filedialog.askopenfilenames(title="Select JSON Key Files", filetypes=[("JSON files", "*.json")])
        if files:
            self.json_files = list(files)
            self.json_count_label.config(text=f"{len(self.json_files)} JSON file(s) selected")
            
            # Initialize stats for each file
            for file in self.json_files:
                self.json_stats[file] = {"usage": 0, "errors": 0, "active": True}
            
            self.update_json_tree()
            self.log_status(f"Selected JSON files: {', '.join(os.path.basename(f) for f in self.json_files)}")

    def update_json_tree(self):
        # Clear existing items
        for item in self.json_tree.get_children():
            self.json_tree.delete(item)
        
        # Add JSON files to treeview
        for file in self.json_files:
            stats = self.json_stats[file]
            status = "Active" if stats["active"] else "Disabled"
            self.json_tree.insert("", "end", values=(file, stats["usage"], stats["errors"], status))

    def prepare_submission(self):
        if self.processing:
            messagebox.showwarning("Processing", "Already processing URLs. Please wait.")
            return
            
        if not self.json_files:
            messagebox.showerror("Error", "Please select at least one JSON key file.")
            return
        
        url_text = self.urls_text.get("1.0", tk.END).strip()
        if not url_text:
            messagebox.showerror("Error", "Please enter URLs to process.")
            return
        
        # Extract URLs from text area
        self.urls_to_process = list(set([url.strip() for url in url_text.split('\n') if url.strip()]))
        
        if not self.urls_to_process:
            messagebox.showerror("Error", "No valid URLs found.")
            return
        
        # Reset progress bar
        self.processed_count.set(0)
        self.total_urls = len(self.urls_to_process)
        self.progress_bar["maximum"] = self.total_urls
        self.progress_bar["value"] = 0
        self.progress_text.set(f"0/{self.total_urls}")
            
        # Clear results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Add all URLs to results with "Pending" status
        for url in self.urls_to_process:
            self.results_tree.insert("", "end", values=(url, "Pending", ""))
        
        # Switch to results tab
        #self.tab_control.select(2)  # Index 2 is the results tab
        
        # Disable input while processing
        self.processing = True
        self.submit_button.config(state="disabled")
        self.urls_text.config(state="disabled")
        self.json_button.config(state="disabled")
        
        # Start processing in a separate thread
        processing_thread = threading.Thread(target=self.submit_urls)
        processing_thread.daemon = True
        processing_thread.start()

    def submit_urls(self):
        # Check for active JSON files
        active_json_files = [f for f in self.json_files if self.json_stats[f]["active"]]
        
        if not active_json_files:
            self.master.after(0, lambda: messagebox.showerror("Error", "No active JSON key files available."))
            self.master.after(0, self.finish_processing)
            return
            
        self.log_status(f"Starting to process {len(self.urls_to_process)} URLs")
        
        # Check for already indexed URLs if using local database
        filtered_urls = []
        if self.use_local_db.get():
            already_indexed = self.get_indexed_urls()
            
            for url in self.urls_to_process:
                if url in already_indexed:
                    # Update on the main thread
                    self.master.after(0, lambda u=url: self.update_url_status(u, "ALREADY INDEXED", ""))
                else:
                    filtered_urls.append(url)
                    
            # Update progress bar for skipped URLs
            skipped = len(self.urls_to_process) - len(filtered_urls)
            if skipped > 0:
                self.master.after(0, lambda: self.update_progress(skipped))
        else:
            filtered_urls = self.urls_to_process.copy()
        
        if not filtered_urls:
            self.master.after(0, lambda: messagebox.showinfo("Info", "All URLs have already been indexed. Nothing to process."))
            self.master.after(0, self.finish_processing)
            return
            
        self.log_status(f"Processing {len(filtered_urls)} URLs after filtering already indexed ones")
        
        # Process URLs in batches of 100
        batch_size = 100
        total_batches = (len(filtered_urls) + batch_size - 1) // batch_size
        
        for batch_idx in range(total_batches):
            if not self.processing:  # Check if processing was stopped
                break
                
            start_idx = batch_idx * batch_size
            end_idx = min(start_idx + batch_size, len(filtered_urls))
            batch_urls = filtered_urls[start_idx:end_idx]
            
            # Select a random active JSON file with the minimum usage count
            active_json_files = [f for f in self.json_files if self.json_stats[f]["active"]]
            if not active_json_files:
                self.log_status("No active JSON files available. Stopping processing.")
                break
                
            min_usage = min(self.json_stats[f]["usage"] for f in active_json_files)
            candidates = [f for f in active_json_files 
                         if self.json_stats[f]["usage"] == min_usage]
            
            json_file = random.choice(candidates)
            
            self.master.after(0, lambda b=batch_idx, t=total_batches: 
                             self.progress_var.set(f"Processing batch {b + 1}/{t}"))
            self.log_status(f"Processing batch {batch_idx + 1} with {json_file}")
            
            # Process this batch with the selected JSON file
            self.process_urls_batch(json_file, batch_urls)
            
            # Small delay between batches
            time.sleep(1)
        
        self.log_status('All batches processed.')
        self.master.after(0, self.finish_processing)

    def process_urls_batch(self, json_file, urls):
        SCOPES = ['https://www.googleapis.com/auth/indexing']
        
        try:
            credentials = service_account.Credentials.from_service_account_file(json_file, scopes=SCOPES)
            service = build('indexing', 'v3', credentials=credentials)
            
            # Create batch request
            batch = service.new_batch_http_request(callback=self.create_callback(json_file))
            
            for url in urls:
                request = service.urlNotifications().publish(body={
                    'url': url,
                    'type': 'URL_UPDATED'
                })
                batch.add(request, request_id=url)
                
            # Execute batch
            batch.execute()
            
        except Exception as e:
            self.log_status(f'Error with JSON file {json_file}: {str(e)}')
            self.json_stats[json_file]["errors"] += 1
            
            # Check if we should disable this JSON file
            if self.json_stats[json_file]["errors"] > 3:
                self.json_stats[json_file]["active"] = False
                self.log_status(f"Disabled {json_file} due to too many errors")
                
            self.master.after(0, self.update_json_tree)
            
            # Mark all URLs in this batch as failed
            for url in urls:
                self.master.after(0, lambda u=url, err=str(e): self.update_url_status(u, "ERROR", err))
                self.master.after(0, self.update_progress)

    def create_callback(self, json_file):
        def callback(request_id, response, exception):
            url = request_id
            timestamp = datetime.datetime.now().isoformat()
            
            if exception:
                status = "ERROR"
                error_message = str(exception)
                self.log_status(f'Failed to submit {url}: {error_message}')
                
                # Increment error count for JSON file
                self.json_stats[json_file]["errors"] += 1
                if self.json_stats[json_file]["errors"] > 3:
                    self.json_stats[json_file]["active"] = False
                    self.log_status(f"Disabled {json_file} due to too many errors")
            else:
                status = "SUCCESS"
                error_message = ""
                self.log_status(f'Successfully submitted {url}')
                
                # Only increment usage count on success
                self.json_stats[json_file]["usage"] += 1

            # Only store successfully indexed URLs in the DB
            if status == "SUCCESS" and self.use_local_db.get():
                self.save_url_to_db(url, status, timestamp, error_message)
            
            # Update UI (from the main thread)
            self.master.after(0, lambda: self.update_url_status(url, status, error_message))
            self.master.after(0, self.update_json_tree)
            self.master.after(0, self.update_progress)
            
        return callback

    def update_url_status(self, url, status, error=""):
        for item in self.results_tree.get_children():
            if self.results_tree.item(item)['values'][0] == url:
                self.results_tree.item(item, values=(url, status, error))
                break

    def update_progress(self, increment=1):
        """Update the progress bar"""
        current = self.processed_count.get() + increment
        self.processed_count.set(current)
        self.progress_bar["value"] = current
        self.progress_text.set(f"{current}/{self.total_urls}")
        
        # Force update
        self.master.update_idletasks()

    def finish_processing(self):
        self.processing = False
        self.submit_button.config(state="normal")
        self.urls_text.config(state="normal")
        self.json_button.config(state="normal")
        self.progress_var.set("Processing complete")
        
        # Write logs to file
        self.write_logs()

    def get_indexed_urls(self):
        """Read successfully indexed URLs from the database file"""
        indexed = set()
        if os.path.exists(self.db_file):
            # Specify encoding and replace invalid characters
            with open(self.db_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    parts = line.strip().split('|')
                    if len(parts) >= 2 and parts[1] == "SUCCESS":
                        indexed.add(parts[0])
        return indexed

    def save_url_to_db(self, url, status, timestamp, error_message=""):
        """Save URL to database file"""
        # Sanitize values to avoid issues with | delimiter
        url = url.replace('|', '%7C')
        error_message = error_message.replace('|', ' ').replace('\n', ' ')
        
        with open(self.db_file, 'a') as f:
            f.write(f"{url}|{status}|{timestamp}|{error_message}\n")

    def write_logs(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Write all logs
        with open(f"indexing_log_{timestamp}.txt", "w") as f:
            f.write(self.status_display.get("1.0", tk.END))
        
        # Write success logs
        with open(f"indexing_success_{timestamp}.txt", "w") as f:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as db:
                    for line in db:
                        if line.startswith('#'):
                            continue
                        parts = line.strip().split('|')
                        if len(parts) >= 2 and parts[1] == "SUCCESS":
                            f.write(f"{parts[0]}\n")
        
        # Write error logs
        with open(f"indexing_errors_{timestamp}.txt", "w") as f:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as db:
                    for line in db:
                        if line.startswith('#'):
                            continue
                        parts = line.strip().split('|')
                        if len(parts) >= 4 and parts[1] == "ERROR":
                            f.write(f"{parts[0]} - {parts[3]}\n")
        
        self.log_status(f"Logs written to files with timestamp {timestamp}")

    def filter_results(self, filter_type):
        # Clear the tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        if not os.path.exists(self.db_file):
            return
            
        with open(self.db_file, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                    
                parts = line.strip().split('|')
                if len(parts) < 4:
                    continue
                    
                url, status, timestamp, error = parts[0], parts[1], parts[2], parts[3]
                
                if filter_type == "all" or \
                   (filter_type == "success" and status == "SUCCESS") or \
                   (filter_type == "error" and status == "ERROR"):
                    self.results_tree.insert("", "end", values=(url, status, error))

    def export_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        with open(file_path, "w") as f:
            f.write("URL,Status,Error Message\n")
            
            for item in self.results_tree.get_children():
                values = self.results_tree.item(item)['values']
                url = values[0].replace(",", " ")
                status = values[1].replace(",", " ")
                error = (values[2] or "").replace(",", " ").replace("\n", " ")
                f.write(f'"{url}","{status}","{error}"\n')
        
        self.log_status(f"Results exported to {file_path}")

    def show_context_menu(self, event):
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.results_menu.post(event.x_root, event.y_root)

    def copy_url(self):
        selection = self.results_tree.selection()
        if selection:
            item = selection[0]
            url = self.results_tree.item(item)['values'][0]
            self.master.clipboard_clear()
            self.master.clipboard_append(url)

    def copy_error(self):
        selection = self.results_tree.selection()
        if selection:
            item = selection[0]
            error = self.results_tree.item(item)['values'][2]
            self.master.clipboard_clear()
            self.master.clipboard_append(error)

    def log_status(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Make sure to update UI from main thread
        if threading.current_thread() is threading.main_thread():
            self.status_display.insert(tk.END, f"[{timestamp}] {message}\n")
            self.status_display.see(tk.END)
        else:
            self.master.after(0, lambda msg=message, ts=timestamp: self.status_display.insert(
                tk.END, f"[{ts}] {msg}\n") or self.status_display.see(tk.END))

if __name__ == '__main__':
    root = tk.Tk()
    app = GoogleIndexingApp(root)
    root.mainloop()