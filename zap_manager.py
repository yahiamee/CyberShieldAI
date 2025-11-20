"""
ZAP Manager - إدارة وتشغيل OWASP ZAP تلقائياً
ZAP Manager - Automatic OWASP ZAP management and startup
"""

import subprocess
import sys
import os
import time
import requests
import threading
from pathlib import Path
from database import get_setting, update_setting

class ZAPManager:
    """مدير ZAP لتشغيله تلقائياً"""
    """ZAP Manager for automatic startup"""
    
    def __init__(self):
        self.zap_process = None
        self.zap_thread = None
        self.is_running = False
        
    def find_zap_executable(self):
        """البحث عن ملف تشغيل ZAP"""
        """Find ZAP executable"""
        
        possible_paths = [
            # Windows
            r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
            r"C:\Users\{}\OWASP\Zed Attack Proxy\zap.bat".format(os.getenv('USERNAME', '')),
            # Linux/Mac
            "/usr/bin/zap.sh",
            "/opt/zap/zap.sh",
            "zap.sh",  # إذا كان في PATH
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def check_zap_running(self, url=None):
        """التحقق من أن ZAP يعمل"""
        """Check if ZAP is running"""
        if url is None:
            url = get_setting('zap_proxy_url', 'http://127.0.0.1:8080')
        
        try:
            # محاولة الوصول إلى API
            # Try accessing the API
            api_url = url.rstrip('/') + '/JSON/core/view/version/'
            response = requests.get(api_url, timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def start_zap_daemon(self):
        """تشغيل ZAP في وضع daemon"""
        """Start ZAP in daemon mode"""
        
        # التحقق من الإعدادات
        # Check settings
        zap_enabled = get_setting('zap_enabled', 'true').lower() == 'true'
        if not zap_enabled:
            print("ℹ️  ZAP is disabled in settings")
            return False
        
        zap_auto_start = get_setting('zap_auto_start', 'true').lower() == 'true'
        if not zap_auto_start:
            print("ℹ️  ZAP auto-start is disabled in settings")
            return False
        
        zap_url = get_setting('zap_proxy_url', 'http://127.0.0.1:8080')
        zap_api_key = get_setting('zap_api_key', '')
        
        # التحقق من أن ZAP غير قيد التشغيل
        # Check if ZAP is not already running
        if self.check_zap_running(zap_url):
            print(f"✅ ZAP is already running on {zap_url}")
            self.is_running = True
            return True
        
        zap_path = self.find_zap_executable()
        if zap_path is None:
            print("⚠️  ZAP executable not found. Please install ZAP or disable auto-start in admin settings.")
            return False
        
        print(f"🚀 Starting ZAP on {zap_url}...")
        
        try:
            # بناء الأمر
            # Build command
            port = zap_url.split(':')[-1] if ':' in zap_url else '8080'
            host = '0.0.0.0'
            
            cmd = [zap_path, "-daemon", "-host", host, "-port", port]
            
            if zap_api_key:
                cmd.extend(["-config", f"api.key={zap_api_key}"])
            else:
                # تعطيل مفتاح API
                # Disable API key
                cmd.extend(["-config", "api.disablekey=true"])
            
            # تشغيل ZAP في الخلفية
            # Run ZAP in background
            if sys.platform == "win32":
                # Windows - استخدام CREATE_NO_WINDOW لتشغيل بدون نافذة
                # Windows - use CREATE_NO_WINDOW to run without window
                self.zap_process = subprocess.Popen(
                    cmd,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                # Linux/Mac
                self.zap_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            # انتظار حتى يبدأ ZAP
            # Wait for ZAP to start
            print("⏳ Waiting for ZAP to start...")
            
            for i in range(30):  # انتظار حتى 30 ثانية
                time.sleep(1)
                if self.check_zap_running(zap_url):
                    print(f"✅ ZAP started successfully on {zap_url}")
                    self.is_running = True
                    return True
                if i % 5 == 0:
                    print(f"   Waiting... ({i+1}/30)")
            
            print("❌ Failed to start ZAP. Please check if ZAP is installed correctly.")
            return False
            
        except Exception as e:
            print(f"❌ Error starting ZAP: {e}")
            return False
    
    def stop_zap(self):
        """إيقاف ZAP"""
        """Stop ZAP"""
        if self.zap_process:
            try:
                self.zap_process.terminate()
                self.zap_process.wait(timeout=5)
                self.is_running = False
                print("✅ ZAP stopped")
                return True
            except:
                try:
                    self.zap_process.kill()
                    self.is_running = False
                    return True
                except:
                    pass
        return False
    
    def start_in_background(self):
        """تشغيل ZAP في thread منفصل"""
        """Start ZAP in a separate thread"""
        if self.zap_thread is None or not self.zap_thread.is_alive():
            self.zap_thread = threading.Thread(target=self.start_zap_daemon, daemon=True)
            self.zap_thread.start()
            return True
        return False

# Global ZAP Manager instance
zap_manager = ZAPManager()

def init_zap():
    """تهيئة ZAP عند بدء النظام"""
    """Initialize ZAP on system startup"""
    zap_manager.start_in_background()
    return zap_manager



