"""
CTF Session Manager
Handles session memory, flag tracking, and IOC accumulation
"""

import json
import os
from datetime import datetime
from color_support import Fore

class SessionMemory:
    def __init__(self, scenario_name="ctf_hunt", project_name=None):
        self.scenario_name = scenario_name
        self.project_name = project_name or scenario_name
        self.session_dir = "ctf_sessions/"
        
        # Ensure directory exists
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Create sanitized filename from project name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = self._sanitize_filename(self.project_name)
        
        # File paths with meaningful names
        self.event_log = f"{self.session_dir}{safe_name}_{timestamp}.jsonl"
        self.state_file = f"{self.session_dir}{safe_name}_summary.json"
        self.report_file = f"{self.session_dir}{safe_name}_report.md"
        
        # Initialize state
        self.state = {
            "session_id": f"{safe_name}_{timestamp}",
            "scenario": scenario_name,
            "project_name": self.project_name,
            "started_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "status": "in_progress",
            "current_flag": 1,
            "total_flags": 0,
            "flags_completed": 0,
            "flags_captured": [],
            "accumulated_iocs": {
                "ips": [],
                "accounts": [],
                "devices": [],
                "binaries": [],
                "file_paths": [],
                "registry_keys": [],
                "scheduled_tasks": []
            },
            "attack_chain": []
        }
    
    def _sanitize_filename(self, name):
        """Convert project name to safe filename"""
        # Remove special characters, replace spaces with underscores
        import re
        safe = re.sub(r'[^\w\s-]', '', name)  # Remove special chars except space and dash
        safe = re.sub(r'[-\s]+', '_', safe)  # Replace spaces/dashes with underscore
        safe = safe.strip('_')[:100]  # Limit length
        return safe if safe else "ctf_hunt"
    
    def append_event(self, event_type, data):
        """Append event to immutable audit log"""
        event = {
            "event": event_type,
            "timestamp": datetime.now().isoformat(),
            **data
        }
        with open(self.event_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    
    def save_state(self):
        """Save current state to JSON file"""
        self.state["last_updated"] = datetime.now().isoformat()
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)
    
    def load_state(self):
        """Load state from file or return current"""
        if os.path.exists(self.state_file):
            with open(self.state_file, "r", encoding="utf-8") as f:
                self.state = json.load(f)
        return self.state
    
    def capture_flag(self, flag_number, title, answer, notes="", kql_used="", table_queried="", 
                     stage="", mitre="", correlation=None):
        """Capture a flag and update state"""
        
        flag_data = {
            "flag_number": flag_number,
            "title": title,
            "answer": answer,
            "stage": stage,
            "mitre": mitre,
            "captured_at": datetime.now().isoformat(),
            "notes": notes,
            "kql_used": kql_used,
            "table_queried": table_queried
        }
        
        if correlation:
            flag_data["correlation"] = correlation
        
        # Add to captured flags
        self.state["flags_captured"].append(flag_data)
        self.state["flags_completed"] = len(self.state["flags_captured"])
        self.state["current_flag"] = flag_number + 1
        
        # Update accumulated IOCs based on answer type
        self._accumulate_iocs(answer, flag_number, title)
        
        # Save state
        self.save_state()
        
        # Log event
        self.append_event("flag_captured", flag_data)
    
    def delete_last_flag(self):
        """
        Delete the most recently captured flag
        Returns: (success: bool, deleted_flag_number: int or None)
        """
        if not self.state["flags_captured"]:
            return False, None
        
        # Remove the last flag
        deleted_flag = self.state["flags_captured"].pop()
        deleted_flag_number = deleted_flag["flag_number"]
        
        # Update counters
        self.state["flags_completed"] = len(self.state["flags_captured"])
        self.state["current_flag"] = deleted_flag_number  # Go back to this flag
        
        # Log deletion event
        self.append_event("flag_deleted", {
            "flag_number": deleted_flag_number,
            "deleted_at": datetime.now().isoformat(),
            "reason": "User requested deletion"
        })
        
        # Save updated state
        self.save_state()
        
        # Regenerate report
        self.generate_report()
        
        return True, deleted_flag_number
    
    def _accumulate_iocs(self, answer, flag_number, title):
        """Intelligently accumulate IOCs based on answer"""
        
        title_lower = title.lower()
        
        # IP addresses
        if any(word in title_lower for word in ["ip", "address", "c2", "exfil"]):
            if answer not in self.state["accumulated_iocs"]["ips"]:
                self.state["accumulated_iocs"]["ips"].append(answer)
        
        # Accounts
        elif any(word in title_lower for word in ["account", "user", "username"]):
            if answer not in self.state["accumulated_iocs"]["accounts"]:
                self.state["accumulated_iocs"]["accounts"].append(answer)
        
        # Binaries
        elif any(word in title_lower for word in ["binary", "executable", "file", ".exe"]):
            if answer not in self.state["accumulated_iocs"]["binaries"]:
                self.state["accumulated_iocs"]["binaries"].append(answer)
        
        # Scheduled tasks
        elif "task" in title_lower or "scheduled" in title_lower:
            if answer not in self.state["accumulated_iocs"]["scheduled_tasks"]:
                self.state["accumulated_iocs"]["scheduled_tasks"].append(answer)
        
        # File paths
        elif "path" in title_lower or "folder" in title_lower or "exclusion" in title_lower:
            if answer not in self.state["accumulated_iocs"]["file_paths"]:
                self.state["accumulated_iocs"]["file_paths"].append(answer)
    
    def get_llm_context(self, current_flag_config=None, context_type="full"):
        """
        Format session for LLM consumption
        
        context_type:
        - "full": Complete context (for analysis)
        - "compact": Just IOCs and recent flags (for query building)
        """
        
        state = self.state
        
        if context_type == "compact":
            return self._format_compact_context(state, current_flag_config)
        else:
            return self._format_full_context(state, current_flag_config)
    
    def _format_full_context(self, state, current_flag_config):
        """Full markdown context for analysis"""
        
        md = "# INVESTIGATION SESSION CONTEXT\n\n"
        
        # Progress
        completed = state['flags_completed']
        total = state['total_flags']
        if total is not None and total > 0:
            progress_bar = "█" * completed + "░" * (total - completed)
            md += f"**Progress:** {completed}/{total} Flags [{progress_bar}]\n\n"
        else:
            # Dynamic mode - unknown total
            md += f"**Progress:** {completed} Flags Captured\n\n"
        
        # Previous flags (last 3 to save tokens)
        if state['flags_captured']:
            recent_flags = state['flags_captured'][-3:]
            md += "## Recently Captured Flags:\n\n"
            for flag in recent_flags:
                md += f"**Flag {flag['flag_number']}: {flag['title']}**\n"
                md += f"- Answer: `{flag['answer']}`\n"
                md += f"- Stage: {flag['stage']}\n"
                if flag.get('correlation'):
                    md += f"- Uses: {flag['correlation']}\n"
                md += "\n"
        
        # Accumulated IOCs
        md += "## Accumulated IOCs:\n\n"
        iocs = state['accumulated_iocs']
        ioc_found = False
        
        for ioc_type, values in iocs.items():
            if values:
                ioc_found = True
                md += f"- **{ioc_type.replace('_', ' ').title()}:** {', '.join(map(str, values))}\n"
        
        if not ioc_found:
            md += "*(No IOCs captured yet)*\n"
        
        md += "\n"
        
        # Current flag context
        if current_flag_config:
            md += f"## Current Hunt: Flag {current_flag_config.get('flag_number', '?')}\n\n"
            md += f"**Objective:** {current_flag_config.get('objective', 'N/A')}\n\n"
            
            # Auto-generate correlation hints
            hints = self._auto_correlate(state, current_flag_config)
            if hints:
                md += "**Correlation Hints:**\n"
                for hint in hints:
                    md += f"- {hint}\n"
                md += "\n"
        
        return md
    
    def _format_compact_context(self, state, current_flag_config):
        """Compact context for query building"""
        
        md = "# SESSION CONTEXT\n\n"
        
        # Just previous flags (compact)
        if state['flags_captured']:
            md += "**Previous Flags:**\n"
            for flag in state['flags_captured'][-2:]:  # Last 2 only
                md += f"- Flag {flag['flag_number']}: {flag['answer']}\n"
            md += "\n"
        
        # IOCs (one line)
        iocs = state['accumulated_iocs']
        ioc_line = []
        if iocs['ips']:
            ioc_line.append(f"IPs: {', '.join(iocs['ips'])}")
        if iocs['accounts']:
            ioc_line.append(f"Accounts: {', '.join(iocs['accounts'])}")
        if iocs['binaries']:
            ioc_line.append(f"Binaries: {', '.join(iocs['binaries'])}")
        
        if ioc_line:
            md += f"**IOCs:** {' | '.join(ioc_line)}\n\n"
        
        return md
    
    def _auto_correlate(self, state, current_flag_config):
        """Generate correlation hints"""
        
        hints = []
        
        # Check dependencies
        if current_flag_config.get('depends_on'):
            for dep_flag_num in current_flag_config['depends_on']:
                dep_flag = next((f for f in state['flags_captured'] 
                               if f['flag_number'] == dep_flag_num), None)
                if dep_flag:
                    hints.append(f"Use answer from Flag {dep_flag_num}: '{dep_flag['answer']}'")
        
        # Suggest filters from IOCs
        iocs = state['accumulated_iocs']
        if iocs.get('accounts') and 'account' in current_flag_config.get('objective', '').lower():
            hints.append(f"Filter by AccountName: {', '.join(iocs['accounts'])}")
        
        if iocs.get('ips') and 'ip' in current_flag_config.get('objective', '').lower():
            hints.append(f"Look for RemoteIP: {', '.join(iocs['ips'])}")
        
        return hints
    
    def generate_report(self):
        """Generate final markdown report"""
        
        state = self.state
        
        md = f"# 🎯 {state.get('project_name', state['scenario'])}\n\n"
        md += f"## Investigation Report\n\n"
        md += f"**Project:** {state.get('project_name', 'N/A')}\n"
        md += f"**Scenario:** {state['scenario'].replace('_', ' ').title()}\n"
        md += f"**Date:** {state['started_at'][:10]}\n"
        md += f"**Duration:** {self._calculate_duration()}\n"
        md += f"**Status:** {'✅ Complete' if state['status'] == 'completed' else '⚠️ Partial'}\n"
        
        # Handle dynamic mode (unknown total)
        if state['total_flags'] is not None:
            md += f"**Flags Completed:** {state['flags_completed']}/{state['total_flags']}\n\n"
        else:
            md += f"**Flags Completed:** {state['flags_completed']}\n\n"
        
        md += "---\n\n"
        
        # Each flag
        for flag in state['flags_captured']:
            md += f"## 🚩 Flag {flag['flag_number']}: {flag['title']}\n\n"
            
            if flag.get('stage'):
                md += f"**Stage:** {flag['stage']}\n"
            if flag.get('mitre'):
                md += f"**MITRE:** {flag['mitre']}\n"
            
            md += f"\n**Flag Answer:** `{flag['answer']}`\n\n"
            
            if flag.get('notes'):
                md += f"**Finding:**\n{flag['notes']}\n\n"
            
            if flag.get('kql_used'):
                md += f"**KQL Query Used:**\n```kql\n{flag['kql_used']}\n```\n\n"
            
            if flag.get('correlation'):
                md += f"**Correlation:** {flag['correlation']}\n\n"
            
            md += "---\n\n"
        
        # Summary
        md += "## 📊 Investigation Summary\n\n"
        
        md += "**Accumulated IOCs:**\n"
        for ioc_type, values in state['accumulated_iocs'].items():
            if values:
                md += f"- {ioc_type.replace('_', ' ').title()}: {', '.join(map(str, values))}\n"
        
        # Save report
        with open(self.report_file, "w", encoding="utf-8") as f:
            f.write(md)
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Investigation report generated: {self.report_file}{Fore.RESET}")
        
        return md
    
    def _calculate_duration(self):
        """Calculate session duration"""
        try:
            start = datetime.fromisoformat(self.state['started_at'])
            end = datetime.fromisoformat(self.state['last_updated'])
            duration = end - start
            
            hours = duration.seconds // 3600
            minutes = (duration.seconds % 3600) // 60
            
            if hours > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{minutes}m"
        except:
            return "N/A"

