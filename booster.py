import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import sqlite3
from PIL import Image, ImageTk
import re
import json
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from plyer import notification
import threading
import time
import webbrowser
import requests
from functools import partial
from win10toast import ToastNotifier
from winotify import Notification, audio
import sys
import argparse

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class DatabaseManager:
    def __init__(self):
        self.db_file = "authentication.db"
        self.initialize_database()
    
    def initialize_database(self):
        """Create the database and tables if they don't exist"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Rename users table to accounts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Rename remember_tokens table to auth_tokens
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    token TEXT NOT NULL,
                    expires_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES accounts (id)
                )
            ''')

            # Create words table with meaning column
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS word_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    word TEXT NOT NULL,
                    meaning TEXT,
                    searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    
                )
            ''')
            
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()
    
    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return password_hash, salt
    
    def word_history(self,username,word,meaning):
        """Add a word to the history"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO word_history (username, word, meaning)
                VALUES (?, ?, ?)
            ''', (username, word, meaning))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()
            

    def create_user(self, username, email, password):
        """Create a new user"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Hash password with salt
            password_hash, salt = self.hash_password(password)
            
            # Update table name to accounts
            cursor.execute('''
                INSERT INTO accounts (username, email, password, salt)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, salt))
            
            conn.commit()
            return True, "User created successfully!"
        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                return False, "Username already exists!"
            elif "email" in str(e):
                return False, "Email already exists!"
            return False, "An error occurred!"
        except sqlite3.Error as e:
            return False, f"Database error: {e}"
        finally:
            conn.close()
    
    def verify_user(self, username, password):
        """Verify user credentials"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Update table name to accounts
            cursor.execute('SELECT id, password, salt FROM accounts WHERE username = ?', 
                          (username,))
            result = cursor.fetchone()
            
            if result:
                user_id, stored_hash, salt = result
                # Hash the provided password with stored salt
                password_hash, _ = self.hash_password(password, salt)
                
                # Compare hashes
                if password_hash == stored_hash:
                    return True, user_id
            return False, None
        except sqlite3.Error as e:
            return False, None
        finally:
            conn.close()
    
    def create_remember_token(self, user_id):
        """Create a remember me token for the user"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Generate a secure token
            token = secrets.token_hex(32)
            # Token expires in 30 days
            expires_at = datetime.now() + timedelta(days=30)
            
            # Delete any existing tokens for this user
            cursor.execute('DELETE FROM auth_tokens WHERE user_id = ?', (user_id,))
            
            # Insert new token
            cursor.execute('''
                INSERT INTO auth_tokens (user_id, token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, token, expires_at))
            
            conn.commit()
            return token
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None
        finally:
            conn.close()
    
    def verify_remember_token(self, token):
        """Verify a remember me token"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Get token info
            cursor.execute('''
                SELECT a.id, a.username, t.expires_at 
                FROM auth_tokens t
                JOIN accounts a ON t.user_id = a.id
                WHERE t.token = ? AND t.expires_at > ?
            ''', (token, datetime.now()))
            
            result = cursor.fetchone()
            
            if result:
                user_id, username, expires_at = result
                return True, username
            return False, None
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False, None
        finally:
            conn.close()
    
    def delete_remember_token(self, token):
        """Delete a remember me token"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM auth_tokens WHERE token = ?', (token,))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        finally:
            conn.close()
    

class AuthenticationApp:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("Modern Authentication")
        self.window.geometry("1100x600")
        self.window.resizable(True, True)
        
        # Add window close handler
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.container = ctk.CTkFrame(self.window, fg_color="transparent")
        self.container.pack(fill="both", expand=True)
        
        self.current_page = None
        self.show_login_page()
    
    def on_closing(self):
        # Stop any active notifications
        if hasattr(self.current_page, 'notification_active'):
            self.current_page.notification_active = False
            if hasattr(self.current_page, 'notification_thread'):
                if self.current_page.notification_thread:
                    self.current_page.notification_thread.join(timeout=1)
        self.window.destroy()
    
    def show_login_page(self):
        if self.current_page:
            self.current_page.destroy()
        self.current_page = LoginPage(self.container, self.show_signup_page)
        self.window.title("Login - Modern Authentication")
        
    def show_signup_page(self):
        if self.current_page:
            self.current_page.destroy()
        self.current_page = SignupPage(self.container, self.show_login_page)
        
    def run(self):
        self.window.mainloop()

class LoginPage(ctk.CTkFrame):
    def save_remember_token(self, token):
        """Save remember me token to a file"""
        try:
            with open('remember.token', 'w') as f:
                f.write(token)
        except Exception as e:
            print(f"Error saving token: {e}")
    
    def load_remember_token(self):
        """Load remember me token from file"""
        try:
            if os.path.exists('remember.token'):
                with open('remember.token', 'r') as f:
                    return f.read().strip()
        except Exception as e:
            print(f"Error loading token: {e}")
        return None
    
    def delete_remember_token(self):
        """Delete the remember me token file"""
        try:
            if os.path.exists('remember.token'):
                os.remove('remember.token')
        except Exception as e:
            print(f"Error deleting token: {e}")
    
    def __init__(self, parent, show_signup_callback):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        
        # Check for remember me token
        token = self.load_remember_token()
        if token:
            db = DatabaseManager()
            success, username = db.verify_remember_token(token)
            if success:
                self.destroy()
                WelcomePage(self.master, username)
                return
            else:
                self.delete_remember_token()
        
        # Create two frames for split screen
        left_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=0)
        left_frame.pack(side="left", fill="both", expand=True)
        
        right_frame = ctk.CTkFrame(self, fg_color="#2b2b2b", corner_radius=0)
        right_frame.pack(side="right", fill="both", expand=True)
        
        # Left side - Login Form
        form_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        form_frame.pack(pady=20, padx=40, expand=True)
        
        # Title
        title = ctk.CTkLabel(form_frame, text="Welcome Back!", 
                           font=("Helvetica", 32, "bold"))
        title.pack(pady=20)
        
        subtitle = ctk.CTkLabel(form_frame, text="Login to your account", 
                             font=("Helvetica", 14))
        subtitle.pack(pady=(0, 20))
        
        # Username
        self.username = ctk.CTkEntry(form_frame, placeholder_text="Username",
                                   height=45, corner_radius=10, width=300)
        self.username.pack(pady=10)
        
        # Password
        self.password = ctk.CTkEntry(form_frame, placeholder_text="Password",
                                   height=45, corner_radius=10, width=300, show="•")
        self.password.pack(pady=10)
        
        # Remember me checkbox
        self.remember = ctk.CTkCheckBox(form_frame, text="Remember me")
        self.remember.pack(pady=10)
        
        # Login button
        login_button = ctk.CTkButton(form_frame, text="Login", height=45,
                                   corner_radius=10, width=300,
                                   command=self.login)
        login_button.pack(pady=20)
        
        # Signup link
        signup_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        signup_frame.pack(pady=10)
        
        signup_label = ctk.CTkLabel(signup_frame, text="Don't have an account?",
                                  font=("Helvetica", 12))
        signup_label.pack(side="left", padx=5)
        
        signup_button = ctk.CTkButton(signup_frame, text="Sign Up",
                                    command=show_signup_callback,
                                    fg_color="transparent", hover_color="#1f538d",
                                    width=100)
        signup_button.pack(side="left")
        
        # Right side - Image
        try:
            image = Image.open("login_image.png")  # Replace with your image path
            image = image.resize((500, 600))
            photo = ImageTk.PhotoImage(image)
            image_label = tk.Label(right_frame, image=photo, bg="#2b2b2b")
            image_label.image = photo
            image_label.pack(expand=True)
        except:
            # Fallback text if image is not found
            ctk.CTkLabel(right_frame, text="Welcome Back!\nTo Our Community",
                        font=("Helvetica", 24, "bold"),
                        text_color="#ffffff").pack(expand=True)
    
    def login(self):
        username = self.username.get()
        password = self.password.get()
        
        db = DatabaseManager()
        success, user_id = db.verify_user(username, password)
        
        if success:
            # Handle remember me
            if self.remember.get():
                token = db.create_remember_token(user_id)
                if token:
                    self.save_remember_token(token)
            
            self.destroy()
            WelcomePage(self.master, username)
        else:
            messagebox.showerror("Error", "Invalid username or password!")

class SignupPage(ctk.CTkFrame):
    def __init__(self, parent, show_login_callback):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.show_login_callback = show_login_callback  # Store the callback
        
        # Create two frames for split screen
        left_frame = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=0)
        left_frame.pack(side="left", fill="both", expand=True)
        
        right_frame = ctk.CTkFrame(self, fg_color="#2b2b2b", corner_radius=0)
        right_frame.pack(side="right", fill="both", expand=True)
        
        # Left side - Signup Form
        form_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        form_frame.pack(pady=20, padx=40, expand=True)
        
        # Title
        title = ctk.CTkLabel(form_frame, text="Create Account", 
                           font=("Helvetica", 32, "bold"))
        title.pack(pady=20)
        
        subtitle = ctk.CTkLabel(form_frame, text="Sign up to get started", 
                             font=("Helvetica", 14))
        subtitle.pack(pady=(0, 20))
        
        # Username
        self.username = ctk.CTkEntry(form_frame, placeholder_text="Username",
                                   height=45, corner_radius=10, width=300)
        self.username.pack(pady=10)
        
        # Email
        self.email = ctk.CTkEntry(form_frame, placeholder_text="Email",
                                height=45, corner_radius=10, width=300)
        self.email.pack(pady=10)
        
        # Password
        self.password = ctk.CTkEntry(form_frame, placeholder_text="Password",
                                   height=45, corner_radius=10, width=300, show="•")
        self.password.pack(pady=10)
        
        # Confirm Password
        self.confirm_password = ctk.CTkEntry(form_frame, placeholder_text="Confirm Password",
                                          height=45, corner_radius=10, width=300, show="•")
        self.confirm_password.pack(pady=10)
        
        # Sign up button
        signup_button = ctk.CTkButton(form_frame, text="Sign Up", height=45,
                                    corner_radius=10, width=300,
                                    command=self.signup)
        signup_button.pack(pady=20)
        
        # Login link
        login_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        login_frame.pack(pady=10)
        
        login_label = ctk.CTkLabel(login_frame, text="Already have an account?",
                                 font=("Helvetica", 12))
        login_label.pack(side="left", padx=5)
        
        login_button = ctk.CTkButton(login_frame, text="Login",
                                   command=show_login_callback,
                                   fg_color="transparent", hover_color="#1f538d",
                                   width=100)
        login_button.pack(side="left")
        
        # Right side - Image
        # Load and display image
        try:
            image = Image.open("signup_image.png")  # Replace with your image path
            image = image.resize((500, 600))
            photo = ImageTk.PhotoImage(image)
            image_label = tk.Label(right_frame, image=photo, bg="#2b2b2b")
            image_label.image = photo
            image_label.pack(expand=True)
        except:
            # Fallback text if image is not found
            ctk.CTkLabel(right_frame, text="Join Our Community\nTo Get Started",
                        font=("Helvetica", 24, "bold"),
                        text_color="#ffffff").pack(expand=True)
        
    def signup(self):
        username = self.username.get()
        email = self.email.get()
        password = self.password.get()
        confirm_password = self.confirm_password.get()
        
        # Basic validation
        if not all([username, email, password, confirm_password]):
            messagebox.showerror("Error", "All fields are required!")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
            
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Invalid email format!")
            return
        
        # Create user in database
        db = DatabaseManager()
        success, message = db.create_user(username, email, password)
        
        if success:
            messagebox.showinfo("Success", "Account created successfully!")
            self.show_login_callback()  # Use stored callback
        else:
            messagebox.showerror("Error", message)

class WelcomePage(ctk.CTkFrame):
    def __init__(self, parent, username):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.username = username
        
        # Create main container
        main_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Welcome header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(40, 20))
        
        welcome_text = ctk.CTkLabel(
            header_frame,
            text=f"Welcome, {username}!",
            font=("Helvetica", 36, "bold")
        )
        welcome_text.pack()
        
        # Content area
        content_frame = ctk.CTkFrame(main_frame, fg_color="#2b2b2b")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Add some sample content
        ctk.CTkLabel(
            content_frame,
            text="You've successfully logged in!",
            font=("Helvetica", 16)
        ).pack(pady=20)
        
        # Add some buttons
        button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        button_frame.pack(pady=30)
        
        # Profile button
        profile_btn = ctk.CTkButton(
            button_frame,
            text="My Profile",
            width=200,
            height=40,
            command=self.show_profile
        )
        profile_btn.pack(pady=10)
        
        # Settings button
        settings_btn = ctk.CTkButton(
            button_frame,
            text="See My Dictionary",
            width=200,
            height=40,
            command=self.show_settings
        )
        settings_btn.pack(pady=10)
        
        # Logout button
        logout_btn = ctk.CTkButton(
            button_frame,
            text="Logout",
            width=200,
            height=40,
            fg_color="#FF5252",
            hover_color="#FF1A1A",
            command=self.logout
        )
        logout_btn.pack(pady=20)

    def show_profile(self):
        self.destroy()
        ProfilePage(self.master, self.username)

    def show_settings(self):
        self.destroy()
        DictionaryPage(self.master, self.username)

    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # Delete remember me token
            try:
                if os.path.exists('remember.token'):
                    with open('remember.token', 'r') as f:
                        token = f.read().strip()
                    db = DatabaseManager()
                    db.delete_remember_token(token)
                    os.remove('remember.token')
            except Exception as e:
                print(f"Error removing token: {e}")
            
            # Stop any active notifications if they exist
            if hasattr(self, 'notification_active'):
                self.notification_active = False
            
            # Destroy the current page
            self.destroy()
            
            # Show login page
            LoginPage(self.master, lambda: None)

class ProfilePage(ctk.CTkFrame):
    def __init__(self, parent, username):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.username = username
        self.notification_thread = None
        self.notification_active = False
        
        # Main container
        main_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Profile header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(40, 20))
        
        profile_title = ctk.CTkLabel(
            header_frame,
            text="Profile Settings",
            font=("Helvetica", 36, "bold")
        )
        profile_title.pack()
        
        # Content area
        content_frame = ctk.CTkFrame(main_frame, fg_color="#2b2b2b")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Notification settings
        notification_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        notification_frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(
            notification_frame,
            text="Desktop Notifications",
            font=("Helvetica", 18, "bold")
        ).pack(anchor="w", pady=(0, 10))
        
        # Notification interval
        interval_frame = ctk.CTkFrame(notification_frame, fg_color="transparent")
        interval_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            interval_frame,
            text="Notification Interval (minutes):"
        ).pack(side="left", padx=(0, 10))
        
        self.interval_var = tk.StringVar(value="30")
        self.interval_entry = ctk.CTkEntry(
            interval_frame,
            width=100,
            textvariable=self.interval_var
        )
        self.interval_entry.pack(side="left")
        
        # Notification message
        message_frame = ctk.CTkFrame(notification_frame, fg_color="transparent")
        message_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            message_frame,
            text="Notification Message:"
        ).pack(anchor="w", pady=(0, 5))
        
        self.message_var = tk.StringVar(value="Time for a break!")
        self.message_entry = ctk.CTkEntry(
            message_frame,
            width=300,
            textvariable=self.message_var
        )
        self.message_entry.pack(anchor="w")
        
        # Toggle button
        self.toggle_btn = ctk.CTkButton(
            notification_frame,
            text="Start Notifications",
            width=200,
            command=self.toggle_notifications
        )
        self.toggle_btn.pack(pady=20)
        
        # Back button
        back_btn = ctk.CTkButton(
            content_frame,
            text="Back to Dashboard",
            width=200,
            command=self.back_to_dashboard
        )
        back_btn.pack(pady=20)
    
    def toggle_notifications(self):
        if not self.notification_active:
            try:
                interval = float(self.interval_var.get())
                if interval <= 0:
                    raise ValueError
                
                self.notification_active = True
                self.toggle_btn.configure(
                    text="Stop Notifications",
                    fg_color="#FF5252",
                    hover_color="#FF1A1A"
                )
                
                # Create scheduled task
                self.create_scheduled_task(interval)
                
                # Start notification thread
                self.notification_thread = threading.Thread(
                    target=self.send_notifications,
                    daemon=True
                )
                self.notification_thread.start()
                
            except ValueError:
                messagebox.showerror(
                    "Error",
                    "Please enter a valid positive number for the interval!"
                )
        else:
            self.notification_active = False
            self.toggle_btn.configure(
                text="Start Notifications",
                fg_color=["#3B8ED0", "#1F6AA5"],
                hover_color=["#36719F", "#144870"]
            )
            # Remove scheduled task
            self.remove_scheduled_task()
    
    def create_scheduled_task(self, interval):
        """Create Windows scheduled task"""
        try:
            import subprocess
            
            # Get the path to the Python interpreter and current script
            python_path = sys.executable
            script_path = os.path.abspath(__file__)
            
            # Create task command
            task_cmd = (
                f'schtasks /create /tn "VocabularyBooster_{self.username}" /tr "'
                f'"{python_path}" "{script_path}" --notify "{self.username}"" '
                f'/sc minute /mo {int(interval)} /f'
            )
            
            subprocess.run(task_cmd, shell=True, check=True)
            
        except Exception as e:
            print(f"Error creating scheduled task: {e}")
    
    def remove_scheduled_task(self):
        """Remove Windows scheduled task"""
        try:
            import subprocess
            task_cmd = f'schtasks /delete /tn "VocabularyBooster_{self.username}" /f'
            subprocess.run(task_cmd, shell=True, check=True)
        except Exception as e:
            print(f"Error removing scheduled task: {e}")
    
    def send_notifications(self):
        while self.notification_active:
            try:
                # Show custom notification
                CustomNotification(self.username, self.message_var.get(), self)
                
                # Sleep for the interval
                interval_minutes = float(self.interval_var.get())
                time.sleep(interval_minutes * 60)
                
            except Exception as e:
                messagebox.showerror("Notification Error", 
                    f"Failed to send notification: {str(e)}")
                self.notification_active = False
                self.toggle_btn.configure(
                    text="Start Notifications",
                    fg_color=["#3B8ED0", "#1F6AA5"],
                    hover_color=["#36719F", "#144870"]
                )
                break
    
    def back_to_dashboard(self):
        self.notification_active = False  # Stop notifications
        self.destroy()
        WelcomePage(self.master, self.username)
    
    def show_word_learning(self):
        self.notification_active = False  # Stop notifications
        self.destroy()
        WordLearningPage(self.master, self.username)
    
    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # Stop notifications
            self.notification_active = False
            if self.notification_thread:
                self.notification_thread.join(timeout=1)
            
            # Destroy the current page
            self.destroy()
            
            # Show login page
            LoginPage(self.master, lambda: None)

class WordLearningPage(ctk.CTkFrame):
    def __init__(self, parent, username):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.username = username
        self.db = DatabaseManager()  # Add database instance
        
        # Main container
        main_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(40, 20))
        
        title = ctk.CTkLabel(
            header_frame,
            text="Word of the Moment",
            font=("Helvetica", 36, "bold")
        )
        title.pack()
        
        # Content area
        content_frame = ctk.CTkFrame(main_frame, fg_color="#2b2b2b")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Word display
        self.word_label = ctk.CTkLabel(
            content_frame,
            text="Generating word...",  # Changed initial text
            font=("Helvetica", 24)
        )
        self.word_label.pack(pady=30)
        
        # Buttons frame
        button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        button_frame.pack(pady=20)
        
        # Generate button
        self.generate_btn = ctk.CTkButton(  # Made instance variable
            button_frame,
            text="Generate New Word",
            width=200,
            command=self.generate_word
        )
        self.generate_btn.pack(pady=10)
        
        # Search button
        self.search_btn = ctk.CTkButton(
            button_frame,
            text="Search Meaning",
            width=200,
            command=self.search_word,
            state="disabled"
        )
        self.search_btn.pack(pady=10)
        
        # Back button
        back_btn = ctk.CTkButton(
            button_frame,
            text="Back to Profile",
            width=200,
            command=self.back_to_profile
        )
        back_btn.pack(pady=20)
        
        self.current_word = None
        
        # Automatically generate word when page opens
        self.master.after(100, self.generate_word)  # Short delay to ensure UI is ready
    
    def generate_word(self):
        try:
            # Using the Random Word API with timeout
            response = requests.get(
                "https://random-word-api.herokuapp.com/word",
                timeout=5  # Add timeout
            )
            if response.status_code == 200:
                self.current_word = response.json()[0]
                self.word_label.configure(
                    text=f"Word: {self.current_word}"
                )
                self.search_btn.configure(state="normal")
            else:
                messagebox.showerror(
                    "Error", 
                    f"Failed to fetch random word. Status code: {response.status_code}"
                )
        except requests.Timeout:
            messagebox.showerror(
                "Error", 
                "Connection timed out while fetching word. Please try again."
            )
        except requests.RequestException as e:
            messagebox.showerror(
                "Error", 
                f"Network error while fetching word: {str(e)}"
            )
        except Exception as e:
            messagebox.showerror(
                "Error", 
                f"Failed to generate word: {str(e)}"
            )
    
    def search_word(self):
        if self.current_word:
            # Save word to history before opening Google search
            self.db.word_history(
                username=self.username,
                word=self.current_word,
                meaning=""  # Initially empty meaning, can be updated later
            )
            
            # Open Google search for the word meaning without showing popup
            search_url = f"https://www.google.com/search?q={self.current_word}+meaning"
            webbrowser.open(search_url)
    
    def back_to_profile(self):
        self.destroy()
        ProfilePage(self.master, self.username)
    
    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # Destroy the current page
            self.destroy()
            
            # Show login page
            LoginPage(self.master, lambda: None)

class CustomNotification(tk.Toplevel):
    def __init__(self, username, message, parent=None):
        super().__init__()
        
        # Window settings
        self.overrideredirect(True)  # Remove window decorations
        self.attributes('-topmost', True)  # Keep window on top
        
        # Get screen width and height
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        
        # Window size
        width = 300
        height = 100
        
        # Position in bottom-right corner
        x = screen_width - width - 20
        y = screen_height - height - 60
        
        self.geometry(f'{width}x{height}+{x}+{y}')
        self.configure(bg='#2b2b2b')
        
        # Add border
        border = tk.Frame(self, bg='#1f538d', width=width, height=height)
        border.place(x=0, y=0)
        
        # Content frame
        content = tk.Frame(border, bg='#2b2b2b')
        content.place(x=2, y=2, width=width-4, height=height-4)
        
        # Title
        title = tk.Label(
            content,
            text=f"Reminder for {username}",
            fg='white',
            bg='#2b2b2b',
            font=('Helvetica', 10, 'bold')
        )
        title.pack(pady=(10, 5))
        
        # Message
        msg = tk.Label(
            content,
            text=message,
            fg='white',
            bg='#2b2b2b',
            font=('Helvetica', 9)
        )
        msg.pack()
        
        # Store parent reference
        self.parent = parent
        
        # Bind click event
        self.bind('<Button-1>', self.on_click)
        title.bind('<Button-1>', self.on_click)
        msg.bind('<Button-1>', self.on_click)
        content.bind('<Button-1>', self.on_click)
        
        # Auto-close timer
        self.after(10000, self.destroy)  # Close after 10 seconds
    
    def on_click(self, event=None):
        if self.parent and hasattr(self.parent, 'show_word_learning'):
            self.parent.show_word_learning()
        self.destroy()

class DictionaryPage(ctk.CTkFrame):
    def __init__(self, parent, username):
        super().__init__(parent, fg_color="transparent")
        self.pack(fill="both", expand=True)
        self.username = username
        
        # Main container
        main_frame = ctk.CTkFrame(self, fg_color="#1a1a1a")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(40, 20))
        
        title = ctk.CTkLabel(
            header_frame,
            text="My Dictionary",
            font=("Helvetica", 36, "bold")
        )
        title.pack()
        
        # Content area
        content_frame = ctk.CTkFrame(main_frame, fg_color="#2b2b2b")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Add word entry
        word_entry_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        word_entry_frame.pack(fill="x", padx=10, pady=10)
        
        self.word_entry = ctk.CTkEntry(
            word_entry_frame,
            placeholder_text="Enter a word",
            width=200
        )
        self.word_entry.pack(side="left", padx=5)

        self.meaning_entry = ctk.CTkEntry(
            word_entry_frame,
            placeholder_text="Enter meaning",
            width=300
        )
        self.meaning_entry.pack(side="left", padx=5)

        add_btn = ctk.CTkButton(
            word_entry_frame,
            text="Add Word",
            width=100,
            command=self.add_word
        )
        add_btn.pack(side="left", padx=5)

        # Create scrollable frame for word history
        self.scroll_frame = ctk.CTkScrollableFrame(content_frame, fg_color="transparent")
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=(0, 20))

        # Load and display words
        self.load_words()
        
        # Back button
        back_btn = ctk.CTkButton(
            content_frame,
            text="Back to Dashboard",
            width=200,
            command=self.back_to_dashboard
        )
        back_btn.pack(pady=20)

    def load_words(self):
        # Clear existing widgets in scroll frame
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        try:
            # Get word history from database
            db = DatabaseManager()
            conn = sqlite3.connect(db.db_file)
            cursor = conn.cursor()

            # Get words for this user, ordered by most recent first
            cursor.execute('''
                SELECT word, meaning, searched_at  
                FROM word_history 
                WHERE username = ? 
                ORDER BY searched_at DESC
            ''', (self.username,))
            words = cursor.fetchall()
            
            if not words:
                no_words_label = ctk.CTkLabel(
                    self.scroll_frame,
                    text="No words added yet",
                    font=("Helvetica", 14)
                )
                no_words_label.pack(pady=20)
            else:
                # Display each word with meaning and timestamp
                for word, meaning, searched_at in words:
                    word_frame = ctk.CTkFrame(self.scroll_frame, fg_color="#1a1a1a")
                    word_frame.pack(fill="x", pady=5)
                    
                    # Create word label with click handler to search meaning
                    word_label = ctk.CTkLabel(
                        word_frame,
                        text=word,
                        font=("Helvetica", 14, "bold"),
                        cursor="hand2"  # Show hand cursor on hover
                    )
                    word_label.pack(side="left", padx=10, pady=5)
                    word_label.bind("<Button-1>", lambda e, w=word: self.search_word(w))
                    
                    meaning_label = ctk.CTkLabel(
                        word_frame,
                        text=f"Meaning: {meaning}" if meaning else "Click word to search meaning",
                        font=("Helvetica", 12)
                    )
                    meaning_label.pack(side="left", padx=10, pady=5)
                    
                    search_time = datetime.fromisoformat(searched_at)
                    time_str = search_time.strftime("%Y-%m-%d %H:%M")
                    
                    time_label = ctk.CTkLabel(
                        word_frame,
                        text=time_str,
                        font=("Helvetica", 12)
                    )
                    time_label.pack(side="right", padx=10, pady=5)

        except sqlite3.Error as e:
            error_label = ctk.CTkLabel(
                self.scroll_frame,
                text=f"Database error: {e}",
                font=("Helvetica", 14)
            )
            error_label.pack(pady=20)
        finally:
            if 'conn' in locals():
                conn.close()

    def add_word(self):
        word = self.word_entry.get().strip()
        meaning = self.meaning_entry.get().strip()
        
        if word:
            try:
                db = DatabaseManager()
                db.word_history(self.username, word, meaning)
                
                # Clear entries
                self.word_entry.delete(0, 'end')
                self.meaning_entry.delete(0, 'end')
                
                # Reload words display
                self.load_words()
                
            except Exception as e:
                print(f"Error adding word: {e}")
    
    def back_to_dashboard(self):
        self.destroy()
        WelcomePage(self.master, self.username)

    def search_word(self, word):
        """Open Google search for a word's meaning"""
        search_url = f"https://www.google.com/search?q={word}+meaning"
        webbrowser.open(search_url)

def handle_command_line():
    """Handle command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--notify", help="Username to show notification")
    args = parser.parse_args()
    
    if args.notify:
        # Show notification
        notification = CustomNotification(args.notify, "Time to learn a new word!")
        notification.mainloop()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        handle_command_line()
    else:
        app = AuthenticationApp()
        app.run()
