"""
OWASP ZAP Scanner Integration for CyberShield AI
This module provides advanced security scanning using OWASP ZAP
"""

import json
import time
import requests
from typing import Dict, List, Optional, Tuple

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None
    print("Warning: python-owasp-zap-v2.4 not installed. ZAP scanning will be disabled.")


class ZAPScanner:
    """OWASP ZAP Scanner wrapper for CyberShield AI"""
    
    def __init__(self, zap_proxy_url: str = "http://127.0.0.1:8080", zap_api_key: str = None):
        """
        Initialize ZAP Scanner
        
        Args:
            zap_proxy_url: URL of ZAP proxy (default: http://127.0.0.1:8080)
            zap_api_key: ZAP API key (optional, if ZAP is configured with API key)
        """
        self.zap_proxy_url = zap_proxy_url
        self.zap_api_key = zap_api_key
        self.zap = None
        self.is_available = False
        
        if ZAPv2 is not None:
            try:
                self.zap = ZAPv2(proxies={'http': zap_proxy_url, 'https': zap_proxy_url}, apikey=zap_api_key)
                # Test connection
                self.zap.core.version()
                self.is_available = True
            except Exception as e:
                print(f"ZAP not available: {e}")
                self.is_available = False
        else:
            self.is_available = False
    
    def is_zap_running(self) -> bool:
        """Check if ZAP is running and accessible"""
        if not self.is_available:
            return False
        
        try:
            self.zap.core.version()
            return True
        except:
            return False
    
    def spider_scan(self, target_url: str, max_children: int = 10, recurse: bool = True) -> str:
        """
        Start a spider scan on the target URL
        
        Args:
            target_url: URL to scan
            max_children: Maximum number of children to scan
            recurse: Whether to recurse into subdirectories
            
        Returns:
            Scan ID
        """
        if not self.is_zap_running():
            raise Exception("ZAP is not running. Please start ZAP proxy first.")
        
        try:
            scan_id = self.zap.spider.scan(target_url, maxchildren=max_children, recurse=recurse)
            return scan_id
        except Exception as e:
            raise Exception(f"Failed to start spider scan: {str(e)}")
    
    def wait_for_spider_completion(self, scan_id: str, timeout: int = 300) -> Dict:
        """
        Wait for spider scan to complete
        
        Args:
            scan_id: Spider scan ID
            timeout: Maximum time to wait in seconds
            
        Returns:
            Scan status dictionary
        """
        start_time = time.time()
        while int(self.zap.spider.status(scan_id)) < 100:
            if time.time() - start_time > timeout:
                raise Exception("Spider scan timeout")
            time.sleep(2)
        
        return {
            'status': 'completed',
            'progress': 100,
            'results': self.zap.spider.results(scan_id)
        }
    
    def active_scan(self, target_url: str) -> str:
        """
        Start an active scan on the target URL
        
        Args:
            target_url: URL to scan
            
        Returns:
            Scan ID
        """
        if not self.is_zap_running():
            raise Exception("ZAP is not running. Please start ZAP proxy first.")
        
        try:
            scan_id = self.zap.ascan.scan(target_url)
            return scan_id
        except Exception as e:
            raise Exception(f"Failed to start active scan: {str(e)}")
    
    def wait_for_active_scan_completion(self, scan_id: str, timeout: int = 600) -> Dict:
        """
        Wait for active scan to complete
        
        Args:
            scan_id: Active scan ID
            timeout: Maximum time to wait in seconds
            
        Returns:
            Scan status dictionary
        """
        start_time = time.time()
        while int(self.zap.ascan.status(scan_id)) < 100:
            if time.time() - start_time > timeout:
                raise Exception("Active scan timeout")
            time.sleep(5)
        
        return {
            'status': 'completed',
            'progress': 100
        }
    
    def get_alerts(self, baseurl: str = None, riskid: str = None) -> List[Dict]:
        """
        Get security alerts from ZAP
        
        Args:
            baseurl: Base URL to filter alerts (optional)
            riskid: Risk ID to filter (0=Informational, 1=Low, 2=Medium, 3=High)
            
        Returns:
            List of alert dictionaries
        """
        if not self.is_zap_running():
            return []
        
        try:
            alerts = self.zap.core.alerts(baseurl=baseurl, riskid=riskid)
            return alerts if alerts else []
        except Exception as e:
            print(f"Error getting alerts: {e}")
            return []
    
    def get_scan_summary(self, target_url: str) -> Dict:
        """
        Get a summary of scan results
        
        Args:
            target_url: Target URL that was scanned
            
        Returns:
            Summary dictionary with vulnerability counts
        """
        alerts = self.get_alerts(baseurl=target_url)
        
        summary = {
            'total_alerts': len(alerts),
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'informational': 0,
            'alerts': []
        }
        
        risk_mapping = {
            'High': 'high_risk',
            'Medium': 'medium_risk',
            'Low': 'low_risk',
            'Informational': 'informational'
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            if risk in risk_mapping:
                summary[risk_mapping[risk]] += 1
            
            summary['alerts'].append({
                'name': alert.get('name', 'Unknown'),
                'risk': risk,
                'description': alert.get('description', ''),
                'solution': alert.get('solution', ''),
                'url': alert.get('url', ''),
                'param': alert.get('param', '')
            })
        
        return summary
    
    def quick_scan(self, target_url: str, spider_timeout: int = 120, active_scan_timeout: int = 300) -> Dict:
        """
        Perform a quick security scan (spider + active scan)
        
        Args:
            target_url: URL to scan
            spider_timeout: Timeout for spider scan in seconds
            active_scan_timeout: Timeout for active scan in seconds
            
        Returns:
            Complete scan results dictionary
        """
        if not self.is_zap_running():
            raise Exception("ZAP is not running. Please start ZAP proxy first.")
        
        results = {
            'target_url': target_url,
            'spider_scan': None,
            'active_scan': None,
            'alerts': [],
            'summary': {}
        }
        
        try:
            # Step 1: Spider scan
            print(f"Starting spider scan for {target_url}...")
            spider_id = self.spider_scan(target_url)
            spider_status = self.wait_for_spider_completion(spider_id, timeout=spider_timeout)
            results['spider_scan'] = spider_status
            print("Spider scan completed.")
            
            # Step 2: Active scan
            print(f"Starting active scan for {target_url}...")
            active_id = self.active_scan(target_url)
            active_status = self.wait_for_active_scan_completion(active_id, timeout=active_scan_timeout)
            results['active_scan'] = active_status
            print("Active scan completed.")
            
            # Step 3: Get alerts
            results['alerts'] = self.get_alerts(baseurl=target_url)
            results['summary'] = self.get_scan_summary(target_url)
            
        except Exception as e:
            results['error'] = str(e)
            print(f"Scan error: {e}")
        
        return results
    
    def passive_scan_only(self, target_url: str) -> Dict:
        """
        Perform only passive scanning (faster, less intrusive)
        This method uses ZAP's passive scanning capabilities
        
        Args:
            target_url: URL to scan
            
        Returns:
            Scan results dictionary
        """
        if not self.is_zap_running():
            raise Exception("ZAP is not running. Please start ZAP proxy first.")
        
        try:
            # Access the URL through ZAP proxy to trigger passive scanning
            proxies = {
                'http': self.zap_proxy_url,
                'https': self.zap_proxy_url
            }
            
            response = requests.get(target_url, proxies=proxies, timeout=30, verify=False)
            
            # Wait a bit for passive scanning to process
            time.sleep(5)
            
            # Get alerts
            alerts = self.get_alerts(baseurl=target_url)
            summary = self.get_scan_summary(target_url)
            
            return {
                'target_url': target_url,
                'status_code': response.status_code,
                'alerts': alerts,
                'summary': summary,
                'scan_type': 'passive'
            }
        except Exception as e:
            return {
                'target_url': target_url,
                'error': str(e),
                'scan_type': 'passive'
            }


def create_zap_scanner(zap_proxy_url: str = "http://127.0.0.1:8080", zap_api_key: str = None) -> Optional[ZAPScanner]:
    """
    Factory function to create a ZAP scanner instance
    
    Args:
        zap_proxy_url: ZAP proxy URL
        zap_api_key: ZAP API key (optional)
        
    Returns:
        ZAPScanner instance or None if ZAP is not available
    """
    try:
        scanner = ZAPScanner(zap_proxy_url, zap_api_key)
        return scanner if scanner.is_available else None
    except:
        return None



