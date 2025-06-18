#!/usr/bin/env python3
import os
import re
import zipfile
import subprocess
import tempfile
import shutil
import json
from datetime import datetime
from pathlib import Path
import sys
import time
import logging
from xml.dom.minidom import parseString
import html

# Suppress Androguard debug logs
logging.getLogger("androguard").setLevel(logging.WARNING)

# Also suppress loguru logs (used by newer versions of androguard)
try:
    from loguru import logger
    logger.remove()  # Remove default handler
    logger.add(sys.stderr, level="WARNING")  # Add handler with WARNING level only
except ImportError:
    pass

from androguard.misc import AnalyzeAPK

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Regular expressions for pattern matching
PATTERNS = {
    'urls': re.compile(
        r'https?://'  # Match http:// or https://
        r'(?!android\.googlesource\.com|schemas\.android\.com|www\.tensorflow\.org|developer\.mozilla\.org|dartbug\.com|www\.w3\.org|www\.unicode\.org|www\.example\.com|www\.googleapis\.com)'
        r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'  # Domain and TLD
        r'(?:\:\d{2,5})?'                    # Optional port
        r'(?:/[^\s"\'<>]*)?',                # Optional path
        re.IGNORECASE
    ),
    'ip_addresses': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    'secrets': re.compile(
        r'(?i)(password|passwd|pwd|secret|token|api[_-]?key|auth|credential)'
        r'\s*[:=]\s*'
        r'["\']?([A-Za-z0-9@#$%^&+=]{8,})["\']?'),
    'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*'),
    'aws_keys': re.compile(r'(?i)AKIA[0-9A-Z]{16}'),
    'google_api': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'firebase': re.compile(r'[a-z0-9.-]+\.firebaseio\.com'),
    'private_keys': re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
    'generic_keys': re.compile(r'(?i)(key|secret)[=:]\s*[\'"][0-9a-f]{16,}[\'"]'),
    'hardcoded_creds': re.compile(r'(?i)(username|user|login|email)[=:]\s*[\'"][^\'"]+[\'"]\s*[,;]\s*(password|pass|pwd)[=:]\s*[\'"][^\'"]+[\'"]'),
    'xml_creds': re.compile(
        r'<UsernameToken[^>]*>(.*?)</UsernameToken>\s*'  # Match UsernameToken content
        r'[\s\S]*?'  # Non-greedy match of any characters (including newlines) between tags
        r'<PasswordText[^>]*>(.*?)</PasswordText>',  # Match PasswordText content
        re.MULTILINE
    )
}

def html_escape(text):
    """Escape HTML special characters to prevent XSS."""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text)

def clean_url(url):
    """Clean up and validate URLs."""
    if not isinstance(url, str):
        return url
    for char in ['"', "'", ",", ";", ")", "]", "}", ">", " "]:
        if url.endswith(char):
            url = url[:-1]
    
    if url.startswith('www.') and not url.startswith('http'):
        url = 'http://' + url
    
    return url

def analyze_content(content, file_path, findings, is_binary=False):
    """Analyze content for sensitive patterns."""
    if not content:
        return
        
    for pattern_name, pattern in PATTERNS.items():
        matches = pattern.findall(content)
        if matches:
            unique_matches = []
            if pattern_name == 'xml_creds':
                # For xml_creds, matches are tuples of (username, password)
                unique_matches = [f"Username: {html_escape(match[0])}, Password: {html_escape(match[1])}" for match in set(matches)]
            else:
                unique_matches = list(set(match if isinstance(match, str) else str(match) for match in matches))
            
            if pattern_name == 'urls':
                unique_matches = [clean_url(url) for url in unique_matches]
                unique_matches = [url for url in unique_matches 
                                if isinstance(url, str) and re.match(r'^https?://[^\s/$.?#].[^\s]*$', url, re.I)]
            
            findings[pattern_name].extend({
                'file': file_path,
                'match': match,
                'is_binary': is_binary
            } for match in unique_matches)

def analyze_exported_components(decompiled_dir, verbose):
    """Analyze AndroidManifest.xml for exported activities, broadcast receivers, and services."""
    exported_components = []
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    
    if not os.path.exists(manifest_path):
        if verbose:
            print_status("AndroidManifest.xml not found in decompiled directory", "error")
        return exported_components
    
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            data = f.read()
        
        dom = parseString(data)
        component_types = [
            ('activity', 'Activity'),
            ('receiver', 'Broadcast Receiver'),
            ('service', 'Service')
        ]
        
        for tag, component_type in component_types:
            components = dom.getElementsByTagName(tag)
            for component in components:
                if not component.hasAttribute('android:name'):
                    continue
                name = component.attributes['android:name'].value
                is_exported = False
                exported_attr = component.getAttribute('android:exported').lower()
                
                # Component is exported if android:exported="true" or if it has an intent-filter
                if exported_attr == 'true':
                    is_exported = True
                elif exported_attr != 'false':  # If not explicitly false, check for intent-filters
                    intent_filters = component.getElementsByTagName('intent-filter')
                    if intent_filters:
                        is_exported = True
                
                if is_exported:
                    exported_components.append({
                        'file': f"{component_type}: {name}",
                        'match': f"Exported [{component_type}] - {name}",
                        'is_binary': False
                    })
        
        return exported_components
    except Exception as e:
        if verbose:
            print_status(f"Error analyzing exported components: {str(e)}", "error")
        return exported_components

def print_banner():
    """Print the persistent banner."""
    banner = rf"""
{Colors.CYAN}{Colors.BOLD}
   ___   _  _____  ___  ____  __  __________  ___ 
  / _ | / |/ / _ \/ _ \/ __ \/  |/  / __/ _ \/ _ |
 / __ |/    / // / , _/ /_/ / /|_/ / _// // / __ |
/_/ |_/_/|_/____/_/|_|\____/_/  /_/___/____/_/ |_|.py
                                 
{Colors.RESET}{Colors.YELLOW}Android APK Security Analyzer - Max Muxammil{Colors.RESET}
{Colors.WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
"""
    print(banner)

def print_status(message, status_type="info"):
    """Print status messages with appropriate colors."""
    if status_type == "info":
        print(f"{Colors.BLUE}[*] {message}{Colors.RESET}")
    elif status_type == "success":
        print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")
    elif status_type == "error":
        print(f"{Colors.RED}[-] {message}{Colors.RESET}")
    elif status_type == "warning":
        print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")

def print_progress_bar(progress, total, task_name="Processing", width=50):
    """Print a progress bar with task name."""
    percent = progress / total * 100
    filled = int(width * progress // total)
    bar = '█' * filled + '░' * (width - filled)
    sys.stdout.write(f'\r{Colors.CYAN}[*] {task_name}: [{bar}] {percent:.1f}%{Colors.RESET}')
    sys.stdout.flush()

def extract_apk(apk_path, output_dir, verbose):
    """Extract APK contents to a directory."""
    if verbose:
        print_status("Extracting APK...")
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            total_files = len(zip_ref.infolist())
            for i, file in enumerate(zip_ref.infolist()):
                zip_ref.extract(file, output_dir)
                if not verbose:
                    print_progress_bar(i + 1, total_files, "Extracting APK")
        
        if verbose:
            print_status("APK extracted successfully", "success")
        else:
            print()  # New line after progress bar
            print_status("APK extracted successfully", "success")
            
        return True
    except Exception as e:
        if verbose:
            print_status(f"Error extracting APK: {str(e)}", "error")
        return False

def decompile_apk(apk_path, output_dir, verbose):
    """Decompile APK using apktool."""
    if verbose:
        print_status("Decompiling APK with apktool...")
    
    try:
        apktool_path = shutil.which('apktool')
        if not apktool_path:
            if verbose:
                print_status("apktool not found, cannot decompile", "error")
            return False
            
        cmd = ['apktool', 'd', apk_path, '-o', output_dir, '-f']
        
        if verbose:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
        else:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
            for i in range(100):
                if process.poll() is not None:
                    break
                time.sleep(0.1)
                print_progress_bar(i + 1, 100, "Decompiling APK")
            
            process.wait()
        
        if process.returncode == 0:
            if verbose:
                print_status("APK decompiled successfully with apktool", "success")
            else:
                print()  # New line after progress bar
                print_status("APK decompiled successfully with apktool", "success")
            return True
        else:
            if verbose:
                print_status(f"Error decompiling APK with apktool: {stderr}", "error")
            return False
    except Exception as e:
        if verbose:
            print_status(f"Error during apktool decompilation: {str(e)}", "error")
        return False

def decompile_with_jadx(apk_path, output_dir, verbose):
    """Decompile APK using jadx for other analyses."""
    if verbose:
        print_status("Decompiling APK with jadx...")
    
    try:
        jadx_path = shutil.which('jadx')
        if not jadx_path:
            if verbose:
                print_status("jadx not found, skipping jadx decompilation", "warning")
            return False
            
        cmd = ['jadx', '-d', output_dir, apk_path]
        
        if verbose:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
        else:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
            for i in range(100):
                if process.poll() is not None:
                    break
                time.sleep(0.1)
                print_progress_bar(i + 1, 100, "Decompiling APK with jadx")
            
            process.wait()
        
        if process.returncode == 0:
            if verbose:
                print_status("APK decompiled successfully with jadx", "success")
            else:
                print()  # New line after progress bar
                print_status("APK decompiled successfully with jadx", "success")
            return True
        else:
            if verbose:
                print_status(f"Error decompiling APK with jadx: {stderr}", "error")
            return False
    except Exception as e:
        if verbose:
            print_status(f"Error during jadx decompilation: {str(e)}", "error")
        return False

def load_string_resources(decompiled_dir, verbose):
    """Load all string resources from various values directories."""
    string_resources = {}
    values_dirs = []
    res_dir = os.path.join(decompiled_dir, 'res')
    
    if os.path.exists(res_dir):
        for dir_name in os.listdir(res_dir):
            if dir_name.startswith('values'):
                values_dirs.append(os.path.join(res_dir, dir_name))
    
    for values_dir in values_dirs:
        strings_path = os.path.join(values_dir, 'strings.xml')
        if os.path.exists(strings_path):
            try:
                with open(strings_path, 'r', encoding='utf-8') as f:
                    strdata = f.read()
                strdom = parseString(strdata)
                strings = strdom.getElementsByTagName('string')
                
                for string_elem in strings:
                    if string_elem.hasAttribute("name"):
                        name = string_elem.attributes["name"].value
                        text = ''
                        for node in string_elem.childNodes:
                            if node.nodeType in [node.TEXT_NODE, node.CDATA_SECTION_NODE]:
                                text += node.data
                        text = text.strip().replace("\\'", "'").replace('\\"', '"').replace('\\n', '\n')
                        string_resources[name] = text
            except Exception as e:
                if verbose:
                    print_status(f"Error parsing strings file {strings_path}: {str(e)}", "error")
    
    return string_resources

def resolve_string_reference(reference, string_resources, resolution_stack, verbose):
    """Resolve a string reference, handling nested references."""
    if not reference.startswith('@string/'):
        return reference
    
    resource_name = reference.replace('@string/', '')
    if resource_name in resolution_stack:
        if verbose:
            print_status(f"Warning: Circular reference detected for '{resource_name}'", "warning")
        return None
    
    resolution_stack.add(resource_name)
    try:
        if resource_name not in string_resources:
            if verbose:
                print_status(f"Warning: String resource '{resource_name}' not found", "warning")
            return None
        value = string_resources[resource_name]
        if value.startswith('@string/'):
            value = resolve_string_reference(value, string_resources, resolution_stack, verbose)
        return value
    finally:
        resolution_stack.remove(resource_name)

def process_intent_filter_data(data_tags, string_resources, verbose):
    """Process data tags in an intent filter to construct deeplinks."""
    urls = []
    schemes = set()
    hosts = set()
    path_prefixes = set()
    path_patterns = set()
    
    for data in data_tags:
        resolution_stack = set()
        scheme = host = path_prefix = path_pattern = None
        
        if data.hasAttribute("android:scheme"):
            scheme_value = data.attributes["android:scheme"].value
            scheme = resolve_string_reference(scheme_value, string_resources, resolution_stack, verbose) if "@string" in scheme_value else scheme_value
            if scheme:
                schemes.add(scheme)
        
        if data.hasAttribute("android:host"):
            host_value = data.attributes["android:host"].value
            host = resolve_string_reference(host_value, string_resources, resolution_stack, verbose) if "@string" in host_value else host_value
            if host:
                hosts.add(host)
        
        if data.hasAttribute("android:pathPrefix"):
            path_value = data.attributes["android:pathPrefix"].value
            path_prefix = resolve_string_reference(path_value, string_resources, resolution_stack, verbose) if "@string" in path_value else path_value
            if path_prefix:
                path_prefix = path_prefix.rstrip('.*')
                path_prefixes.add(path_prefix)
        
        if data.hasAttribute("android:pathPattern"):
            path_value = data.attributes["android:pathPattern"].value
            path_pattern = resolve_string_reference(path_value, string_resources, resolution_stack, verbose) if "@string" in path_value else path_value
            if path_pattern:
                path_pattern = path_pattern.replace(".*", "{wildcard}").replace("/.*", "{wildcard}/")
                path_patterns.add(path_pattern)
    
    for scheme in schemes:
        for host in hosts:
            base_url = f"{scheme}://{host}"
            for prefix in path_prefixes:
                if not prefix.startswith('/'):
                    prefix = '/' + prefix
                urls.append(f"{base_url}{prefix}")
            for pattern in path_patterns:
                if not pattern.startswith('/'):
                    pattern = '/' + pattern
                urls.append(f"{base_url}{pattern}")
            if not path_prefixes and not path_patterns:
                urls.append(base_url)
    
    return sorted(list(set(urls)))

def analyze_deeplinks(decompiled_dir, verbose):
    """Analyze deeplinks from AndroidManifest.xml."""
    deeplinks = []
    string_resources = load_string_resources(decompiled_dir, verbose)
    
    manifest_path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest_path):
        if verbose:
            print_status("AndroidManifest.xml not found in decompiled directory", "error")
        return deeplinks
    
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            data = f.read()
        
        dom = parseString(data)
        activities = dom.getElementsByTagName('activity') + dom.getElementsByTagName('activity-alias')
        
        for activity in activities:
            activity_deeplinks = []
            intent_filters = activity.getElementsByTagName("intent-filter")
            if intent_filters:
                activity_name = activity.attributes["android:name"].value
                for intent in intent_filters:
                    data_tags = intent.getElementsByTagName("data")
                    if data_tags:
                        deeplink_urls = process_intent_filter_data(data_tags, string_resources, verbose)
                        activity_deeplinks.extend(deeplink_urls)
                if activity_deeplinks:
                    deeplinks.append({
                        'file': f"Activity: {activity_name}",
                        'matches': list(set(activity_deeplinks)),
                        'is_binary': False
                    })
        
        return deeplinks
    except Exception as e:
        if verbose:
            print_status(f"Error processing deeplinks: {str(e)}", "error")
        return deeplinks

def analyze_with_androguard(apk_path, verbose):
    """Analyze APK using Androguard."""
    if verbose:
        print_status("Analyzing with Androguard...")
    
    findings = {key: [] for key in PATTERNS.keys()}
    findings['deeplinks'] = []
    findings['exported_components'] = []
    
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        
        # Analyze AndroidManifest.xml
        manifest = a.get_android_manifest_axml().get_xml()
        if manifest:
            from lxml import etree
            manifest_str = etree.tostring(manifest, encoding='unicode', pretty_print=True)
            analyze_content(manifest_str, "AndroidManifest.xml", findings)
        
        # Analyze resources
        try:
            resources = a.get_android_resources()
            if resources:
                total_resources = len(resources.get_strings()) + len(resources.get_files())
                current = 0
                for resource in resources.get_strings():
                    analyze_content(resource, "resources/strings", findings)
                    current += 1
                    if not verbose:
                        print_progress_bar(current, total_resources, "Analyzing resources")
                for resource in resources.get_files():
                    try:
                        content = resources.get_file(resource).decode('utf-8', errors='ignore')
                        analyze_content(content, f"resources/files/{resource}", findings)
                    except:
                        pass
                    current += 1
                    if not verbose:
                        print_progress_bar(current, total_resources, "Analyzing resources")
        except AttributeError:
            try:
                resources = a.get_resources()
                if resources:
                    total_resources = len(resources.values())
                    for i, resource in enumerate(resources.values()):
                        if isinstance(resource, str):
                            analyze_content(resource, "resources", findings)
                        if not verbose:
                            print_progress_bar(i + 1, total_resources, "Analyzing resources")
            except:
                pass
        
        # Analyze decompiled code
        total_classes = sum(1 for dex in d for cls in dex.get_classes())
        current = 0
        for dex in d:
            for cls in dex.get_classes():
                try:
                    source = cls.get_source()
                    if source:
                        analyze_content(source, f"class:{cls.get_name()}", findings)
                except:
                    pass
                current += 1
                if not verbose:
                    print_progress_bar(current, total_classes, "Analyzing classes")
        
        if verbose:
            print_status("Androguard analysis complete", "success")
        else:
            print()  # New line after progress bar
            print_status("Androguard analysis complete", "success")
            
        return findings
        
    except Exception as e:
        if verbose:
            print_status(f"Error analyzing with Androguard: {str(e)}", "error")
        return findings

def analyze_files(directory, verbose, file_patterns=None):
    """Analyze files in directory for sensitive patterns."""
    if file_patterns is None:
        file_patterns = ['*.xml', '*.json', '*.properties', '*.smali']
    
    findings = {key: [] for key in PATTERNS.keys()}
    findings['deeplinks'] = []
    findings['exported_components'] = []
    
    if verbose:
        print_status(f"Analyzing files in {directory}...")
    
    total_files = sum(1 for root, _, files in os.walk(directory) for file in files 
                     if any(file.endswith(p.replace('*.', '')) for p in file_patterns))
    
    current = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if not any(file.endswith(p.replace('*.', '')) for p in file_patterns):
                continue
                
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    analyze_content(content, file_path, findings)
            except UnicodeDecodeError:
                try:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        content = f.read()
                        analyze_content(content, file_path, findings)
                except:
                    pass
            current += 1
            if not verbose:
                print_progress_bar(current, total_files, "Analyzing files")
    
    if verbose:
        print_status("File analysis complete", "success")
    else:
        print()  # New line after progress bar
        print_status("File analysis complete", "success")
        
    return findings

def analyze_native_library(lib_path, findings, verbose):
    """Analyze native library (.so) for sensitive strings."""
    try:
        strings_cmd = ['strings', lib_path]
        result = subprocess.run(strings_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            content = result.stdout
            analyze_content(content, lib_path, findings, is_binary=True)
    except Exception as e:
        if verbose:
            print_status(f"Error analyzing {lib_path}: {str(e)}", "error")

def print_findings(findings, verbose):
    """Print the findings in a structured way."""
    print(f"\n{Colors.WHITE}{'='*120}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}                                    ANALYSIS RESULTS{Colors.RESET}")
    print(f"{Colors.WHITE}{'='*120}{Colors.RESET}\n")
    
    if not any(findings.values()):
        print(f"{Colors.GREEN}[+] No sensitive patterns or vulnerabilities found in the APK{Colors.RESET}")
        return
    
    for pattern_name, matches in findings.items():
        if not matches:
            continue
            
        print(f"{Colors.MAGENTA}{Colors.BOLD}=== {pattern_name.upper().replace('_', ' ')} ({len(matches)} found) ==={Colors.RESET}")
        for match_info in matches:
            file_display = match_info['file']
            if match_info['is_binary']:
                file_display += " (binary)"
            print(f"{Colors.CYAN}File: {file_display}{Colors.RESET}")
            print(f"{Colors.YELLOW}Match: {match_info['match']}{Colors.RESET}")
            print(f"{Colors.WHITE}{'-'*80}{Colors.RESET}")
        print()

def generate_html_report(findings, apk_path, report_path, verbose):
    """Generate an interactive HTML report with dark mode toggle."""
    if verbose:
        print_status("Generating HTML report...")
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    apk_name = os.path.basename(apk_path)
    
    finding_counts = {k: len(v) for k, v in findings.items() if v}
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Analysis Report - {html_escape(apk_name)}</title>
    <style>
        :root {{
            --bg-color: #f5f5f5;
            --text-color: #333;
            --card-bg: #fff;
            --border-color: #ddd;
            --primary-color: #2563eb;
            --secrets-color: #dc2626; /* Red */
            --private-keys-color: #facc15; /* Yellow */
            --urls-color: #16a34a; /* Green */
            --hardcoded-creds-color: #3b82f6; /* Blue */
            --deeplinks-color: #7e22ce; /* Purple */
            --exported-components-color: #ea580c; /* Orange */
            --xml-creds-color: #d946ef; /* Fuchsia */
            --firebase-color: #22d3ee; /* Cyan */
            --ip-addresses-color: #6b7280; /* Gray */
            --google-api-color: #db2777; /* Pink */
        }}
        
        .dark-mode {{
            --bg-color: #222222;
            --text-color: #e0e0e0;
            --card-bg: #333;
            --border-color: #444;
            --primary-color: #93c5fd;
            --secrets-color: #f87171;
            --private-keys-color: #fde047;
            --urls-color: #22c55e;
            --hardcoded-creds-color: #60a5fa;
            --deeplinks-color: #c084fc;
            --exported-components-color: #fb923c;
            --xml-creds-color: #e879f9;
            --firebase-color: #22d3ee;
            --ip-addresses-color: #9ca3af;
            --google-api-color: #f472b6;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 0;
            line-height: 1.6;
            transition: all 0.3s ease;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        h1, h2, h3 {{
            color: var(--primary-color);
        }}
        
        .mode-toggle {{
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }}
        
        .summary-card:hover {{
            background-color: rgba(0, 0, 0, 0.05);
        }}
        
        .summary-card.secrets {{
            border-left: 4px solid var(--secrets-color);
        }}
        
        .summary-card.secrets .count {{
            color: var(--secrets-color);
        }}
        
        .summary-card.private-keys {{
            border-left: 4px solid var(--private-keys-color);
        }}
        
        .summary-card.private-keys .count {{
            color: var(--private-keys-color);
        }}
        
        .summary-card.urls {{
            border-left: 4px solid var(--urls-color);
        }}
        
        .summary-card.urls .count {{
            color: var(--urls-color);
        }}
        
        .summary-card.hardcoded-creds {{
            border-left: 4px solid var(--hardcoded-creds-color);
        }}
        
        .summary-card.hardcoded-creds .count {{
            color: var(--hardcoded-creds-color);
        }}
        
        .summary-card.deeplinks {{
            border-left: 4px solid var(--deeplinks-color);
        }}
        
        .summary-card.deeplinks .count {{
            color: var(--deeplinks-color);
        }}
        
        .summary-card.exported-components {{
            border-left: 4px solid var(--exported-components-color);
        }}
        
        .summary-card.exported-components .count {{
            color: var(--exported-components-color);
        }}
        
        .summary-card.xml-creds {{
            border-left: 4px solid var(--xml-creds-color);
        }}
        
        .summary-card.xml-creds .count {{
            color: var(--xml-creds-color);
        }}
        
        .summary-card.firebase {{
            border-left: 4px solid var(--firebase-color);
        }}
        
        .summary-card.firebase .count {{
            color: var(--firebase-color);
        }}
        
        .summary-card.ip-addresses {{
            border-left: 4px solid var(--ip-addresses-color);
        }}
        
        .summary-card.ip-addresses .count {{
            color: var(--ip-addresses-color);
        }}
        
        .summary-card.google-api {{
            border-left: 4px solid var(--google-api-color);
        }}
        
        .summary-card.google-api .count {{
            color: var(--google-api-color);
        }}
        
        .count {{
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .findings-section {{
            margin-bottom: 40px;
        }}
        
        .finding-card {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            border-left: 4px solid var(--primary-color);
        }}
        
        .finding-card.secrets {{
            border-left-color: var(--secrets-color);
        }}
        
        .finding-card.secrets .finding-content {{
            color: var(--secrets-color);
        }}
        
        .finding-card.private-keys {{
            border-left-color: var(--private-keys-color);
        }}
        
        .finding-card.private-keys .finding-content {{
            color: var(--private-keys-color);
        }}
        
        .finding-card.urls {{
            border-left-color: var(--urls-color);
        }}
        
        .finding-card.urls .finding-content {{
            color: var(--urls-color);
        }}
        
        .finding-card.hardcoded-creds {{
            border-left-color: var(--hardcoded-creds-color);
        }}
        
        .finding-card.hardcoded-creds .finding-content {{
            color: var(--hardcoded-creds-color);
        }}
        
        .finding-card.deeplinks {{
            border-left-color: var(--deeplinks-color);
        }}
        
        .finding-card.deeplinks .finding-content {{
            color: var(--deeplinks-color);
        }}
        
        .finding-card.exported-components {{
            border-left-color: var(--exported-components-color);
        }}
        
        .finding-card.exported-components .finding-content {{
            color: var(--exported-components-color);
        }}
        
        .finding-card.xml-creds {{
            border-left-color: var(--xml-creds-color);
        }}
        
        .finding-card.xml-creds .finding-content {{
            color: var(--xml-creds-color);
        }}
        
        .finding-card.firebase {{
            border-left-color: var(--firebase-color);
        }}
        
        .finding-card.firebase .finding-content {{
            color: var(--firebase-color);
        }}
        
        .finding-card.ip-addresses {{
            border-left-color: var(--ip-addresses-color);
        }}
        
        .finding-card.ip-addresses .finding-content {{
            color: var(--ip-addresses-color);
        }}
        
        .finding-card.google-api {{
            border-left-color: var(--google-api-color);
        }}
        
        .finding-card.google-api .finding-content {{
            color: var(--google-api-color);
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .finding-title {{
            font-weight: bold;
            color: var(--primary-color);
        }}
        
        .finding-content {{
            font-family: monospace;
            white-space: pre-wrap;
            background: rgba(0,0,0,0.05);
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            overflow-x: auto;
        }}
        
        .dark-mode .finding-content {{
            background: rgba(255,255,255,0.1);
        }}
        
        .file-path {{
            color: var(--text-color);
            opacity: 0.8;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 20px;
            color: var(--text-color);
            opacity: 0.7;
        }}
        
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            font-size: 0.9em;
            opacity: 0.7;
        }}
        
        @media (max-width: 768px) {{
            .summary {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>APK Security Analysis Report</h1>
                <p>Analyzed: {html_escape(apk_name)} at {timestamp}</p>
            </div>
            <button class="mode-toggle" onclick="toggleDarkMode()">Dark Mode</button>
        </header>
        
        <section class="summary">
            <a href="#secrets" style="text-decoration: none;"><div class="summary-card secrets">
                <h3>Secrets</h3>
                <div class="count">{finding_counts.get('secrets', 0)}</div>
            </div></a>
            <a href="#private-keys" style="text-decoration: none;"><div class="summary-card private-keys">
                <h3>Private Keys</h3>
                <div class="count">{finding_counts.get('private_keys', 0)}</div>
            </div></a>
            <a href="#urls" style="text-decoration: none;"><div class="summary-card urls">
                <h3>URLs</h3>
                <div class="count">{finding_counts.get('urls', 0)}</div>
            </div></a>
            <a href="#hardcoded-creds" style="text-decoration: none;"><div class="summary-card hardcoded-creds">
                <h3>Hardcoded Creds</h3>
                <div class="count">{finding_counts.get('hardcoded_creds', 0)}</div>
            </div></a>
            <a href="#deeplinks" style="text-decoration: none;"><div class="summary-card deeplinks">
                <h3>Deeplinks</h3>
                <div class="count">{finding_counts.get('deeplinks', 0)}</div>
            </div></a>
            <a href="#exported_components" style="text-decoration: none;"><div class="summary-card exported-components">
                <h3>Exported Components</h3>
                <div class="count">{finding_counts.get('exported_components', 0)}</div>
            </div></a>
            <a href="#xml_creds" style="text-decoration: none;"><div class="summary-card xml-creds">
                <h3>XML Credentials</h3>
                <div class="count">{finding_counts.get('xml_creds', 0)}</div>
            </div></a>
            <a href="#firebase" style="text-decoration: none;"><div class="summary-card firebase">
                <h3>Firebase URLs</h3>
                <div class="count">{finding_counts.get('firebase', 0)}</div>
            </div></a>
            <a href="#ip_addresses" style="text-decoration: none;"><div class="summary-card ip-addresses">
                <h3>IP Addresses</h3>
                <div class="count">{finding_counts.get('ip_addresses', 0)}</div>
            </div></a>
            <a href="#google_api" style="text-decoration: none;"><div class="summary-card google-api">
                <h3>Google API Keys</h3>
                <div class="count">{finding_counts.get('google_api', 0)}</div>
            </div></a>
        </section>
    """
    
    for pattern_name, matches in sorted(findings.items()):
        if not matches:
            continue
        
        # Map pattern_name to CSS class and ID for anchor links
        css_class = pattern_name.replace('_', '-')
        section_id = pattern_name
        
        html_content += f"""
        <section class="findings-section" id="{section_id}">
            <h2>{pattern_name.replace('_', ' ').title()}</h2>
            <p>Found {len(matches)} instances</p>
        """
        
        for match_info in matches:
            file_display = html_escape(match_info['file'])
            if match_info['is_binary']:
                file_display += " (binary)"
            
            # Handle URLs with hyperlinks
            if pattern_name in ['urls', 'firebase']:
                match_content = f'<a href="{html_escape(match_info["match"])}" target="_blank" rel="noopener noreferrer">{html_escape(match_info["match"])}</a>'
            else:
                match_content = html_escape(match_info['match'])
            
            html_content += f"""
            <div class="finding-card {css_class}">
                <div class="finding-header">
                    <div class="finding-title">Match Found</div>
                </div>
                <div class="finding-content">{match_content}</div>
                <div class="file-path">File: {file_display}</div>
            </div>
            """
        
        html_content += "</section>"
    
    if not any(findings.values()):
        html_content += """
        <div class="no-findings">
            <h2>No sensitive patterns or vulnerabilities found!</h2>
            <p>The analysis didn't detect any of the configured sensitive patterns or exported components.</p>
        </div>
        """
    
    html_content += f"""
        <footer>
            <p>Report generated by APK Security Analyzer at {timestamp}</p>
        </footer>
    </div>

    <script>
        function toggleDarkMode() {{
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        }}
        
        if (localStorage.getItem('darkMode') === 'true') {{
            document.body.classList.add('dark-mode');
        }}
    </script>
</body>
</html>
    """
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    if verbose:
        print_status("HTML report generated successfully", "success")
    else:
        print_status("HTML report generated successfully", "success")

def analyze_apk(apk_path, verbose):
    """Main function to analyze an APK."""
    print_banner()
    
    if not os.path.isfile(apk_path):
        print_status(f"File not found: {apk_path}", "error")
        return
    
    print_status(f"Starting analysis of: {os.path.basename(apk_path)}", "info")
    
    all_findings = {key: [] for key in PATTERNS.keys()}
    all_findings['deeplinks'] = []
    all_findings['exported_components'] = []
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            extracted_dir = os.path.join(temp_dir, 'extracted')
            apktool_dir = os.path.join(temp_dir, 'apktool_decompiled')
            jadx_dir = os.path.join(temp_dir, 'jadx_decompiled')
            
            os.makedirs(extracted_dir, exist_ok=True)
            os.makedirs(apktool_dir, exist_ok=True)
            os.makedirs(jadx_dir, exist_ok=True)
            
            # Step 1: Extract APK
            if not extract_apk(apk_path, extracted_dir, verbose):
                return
            
            # Step 2: Analyze native libraries (.so files)
            if verbose:
                print_status("Analyzing native libraries (.so files)...")
            
            native_findings = {key: [] for key in PATTERNS.keys()}
            native_findings['deeplinks'] = []
            native_findings['exported_components'] = []
            
            so_files = []
            for root, _, files in os.walk(extracted_dir):
                for file in files:
                    if file.endswith('.so'):
                        so_files.append(os.path.join(root, file))
            
            total_so_files = len(so_files)
            for i, lib_path in enumerate(so_files):
                analyze_native_library(lib_path, native_findings, verbose)
                if not verbose and total_so_files > 0:
                    print_progress_bar(i + 1, total_so_files, "Analyzing native libraries")
            
            if verbose:
                print_status("Native library analysis complete", "success")
            else:
                if total_so_files > 0:
                    print()  # New line after progress bar
                print_status("Native library analysis complete", "success")
            
            for key in all_findings:
                all_findings[key].extend(native_findings.get(key, []))
            
            # Step 3: Decompile with apktool and analyze its output
            if not decompile_apk(apk_path, apktool_dir, verbose):
                print_status("APK decompilation failed, cannot proceed with pattern analysis", "error")
                return
            
            # Analyze apktool output for patterns
            apktool_findings = analyze_files(apktool_dir, verbose)
            for key in all_findings:
                all_findings[key].extend(apktool_findings.get(key, []))
            
            # Analyze deeplinks and exported components from apktool output
            deeplink_results = analyze_deeplinks(apktool_dir, verbose)
            for result in deeplink_results:
                all_findings['deeplinks'].extend({
                    'file': result['file'],
                    'match': match,
                    'is_binary': False
                } for match in result['matches'])
            
            exported_component_results = analyze_exported_components(apktool_dir, verbose)
            all_findings['exported_components'].extend(exported_component_results)
            
            # Step 4: Perform additional analyses
            decompile_with_jadx(apk_path, jadx_dir, verbose)
            
            androguard_findings = analyze_with_androguard(apk_path, verbose)
            for key in PATTERNS:
                all_findings[key].extend(androguard_findings.get(key, []))
            
            extracted_findings = analyze_files(extracted_dir, verbose)
            jadx_findings = analyze_files(jadx_dir, verbose, file_patterns=['*.xml', '*.json', '*.properties', '*.java', '*.kt'])
            
            for key in all_findings:
                all_findings[key].extend(extracted_findings.get(key, []))
                all_findings[key].extend(jadx_findings.get(key, []))
            
            print_status("Analysis complete", "success")
            print_findings(all_findings, verbose)
            
            report_path = os.path.join(os.getcwd(), f"apk_analysis_report_{os.path.splitext(os.path.basename(apk_path))[0]}.html")
            generate_html_report(all_findings, apk_path, report_path, verbose)
            
            print(f"\n{Colors.GREEN}[+] Report saved to: {Colors.CYAN}{report_path}{Colors.RESET}")
            
    except Exception as e:
        print_status(f"Unexpected error during analysis: {str(e)}", "error")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Analyze Android APK for sensitive information and vulnerabilities',
        usage='%(prog)s [-h] [-v] file.apk'
    )
    parser.add_argument(
        'apk_path',
        help='Path to the APK file to analyze'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    args = parser.parse_args()
    
    analyze_apk(args.apk_path, args.verbose)