"""
SOC Analyst Conversational Follow-up Mode
Allows users to discuss findings with the AI after analysis
Maintains SOC focus and session context
"""

import json
import tiktoken
from color_support import Fore, Style
import OLLAMA_CLIENT

class SocChatSession:
    def __init__(self, findings, log_data_summary, query_context, model_name):
        self.findings = findings
        self.log_data_summary = log_data_summary
        self.query_context = query_context
        self.model_name = model_name
        self.conversation_history = []
        
        # Safety limits
        self.MAX_TURNS = 15 if model_name == "qwen" else 5  # GPT-OSS has smaller context
        self.MAX_TOKENS = 100000 if model_name == "qwen" else 25000
        self.turn_count = 0
        
        # Build system context with findings
        self.system_context = self._build_system_context()
    
    def _build_system_context(self):
        """Build system prompt with findings context"""
        
        # Create findings summary
        findings_summary = f"CURRENT THREAT HUNTING SESSION:\n"
        findings_summary += f"Query: {self.query_context.get('rationale', 'N/A')}\n"
        findings_summary += f"Table: {self.query_context.get('table_name', 'N/A')}\n"
        findings_summary += f"Time Range: {self.query_context.get('time_range_hours', 'N/A')} hours\n"
        findings_summary += f"Total Findings: {len(self.findings)}\n\n"
        
        # Add each finding with actual data (IOCs, device names, etc.)
        findings_summary += "FINDINGS:\n"
        for i, finding in enumerate(self.findings[:10], 1):  # Include up to 10 findings
            findings_summary += f"\n[Finding {i}]\n"
            findings_summary += f"  Title: {finding.get('title', 'N/A')}\n"
            findings_summary += f"  Confidence: {finding.get('confidence', 'N/A')}\n"
            findings_summary += f"  MITRE: {finding.get('mitre', {}).get('technique', 'N/A')}\n"
            
            # Include IOCs (the actual data user needs!)
            iocs = finding.get('indicators_of_compromise', [])
            if iocs:
                findings_summary += f"  IOCs: {', '.join(str(ioc) for ioc in iocs[:5])}\n"  # First 5 IOCs
            
            # Include device names if present
            if finding.get('device_name'):
                findings_summary += f"  Device: {finding.get('device_name')}\n"
            
            # Include account names if present
            if finding.get('account_name'):
                findings_summary += f"  Account: {finding.get('account_name')}\n"
            
            # Include description (concise version)
            desc = finding.get('description', '')
            if desc and len(desc) < 200:
                findings_summary += f"  Description: {desc}\n"
        
        findings_summary += "\n(Answer questions using the data above)\n"
        
        # Directive system prompt with actual data
        system_prompt = f"""You are a SOC analyst AI. Answer questions using ONLY the data below.

{findings_summary}

RULES:
- Use the actual IOCs, device names, and account names from the findings above
- When asked for device names, list the specific devices shown in the data
- When asked for account names, list the specific accounts shown in the data
- Be direct and specific - don't say "see Finding X", just give the answer
- If data is not available, say "No device/account name found in findings"
- Stay focused on security and the findings above
"""
        
        return system_prompt
    
    def _estimate_tokens(self, messages):
        """Rough token estimate"""
        try:
            enc = tiktoken.get_encoding("cl100k_base")
            text = ""
            for m in messages:
                text += m.get("role", "") + " " + m.get("content", "") + "\n"
            return len(enc.encode(text))
        except:
            # Fallback: rough character-based estimate
            total_chars = sum(len(m.get("content", "")) for m in messages)
            return total_chars // 4  # ~4 chars per token
    
    def _truncate_history_if_needed(self):
        """Keep conversation within token budget"""
        # Keep system message + last N exchanges
        max_history = 8 if self.model_name == "qwen" else 3
        
        if len(self.conversation_history) > max_history:
            # Keep only recent history
            self.conversation_history = self.conversation_history[-max_history:]
            print(f"{Fore.YELLOW}📝 Truncated conversation history to last {max_history} exchanges{Fore.RESET}")
    
    def chat_loop(self):
        """Interactive chat about the findings"""
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}SOC ANALYST CONVERSATIONAL FOLLOW-UP")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.WHITE}Ask questions about the findings. Type 'exit' or 'done' to finish.")
        print(f"{Fore.WHITE}Model: {Fore.LIGHTGREEN_EX}{self.model_name}{Fore.WHITE}")
        print(f"{Fore.WHITE}Turn limit: {Fore.LIGHTYELLOW_EX}{self.MAX_TURNS}{Fore.WHITE}")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
        
        while self.turn_count < self.MAX_TURNS:
            # Get user input
            try:
                user_input = input(f"{Fore.LIGHTGREEN_EX}You: {Fore.RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Fore.YELLOW}Exiting chat mode...{Fore.RESET}")
                break
            
            # Exit commands
            if user_input.lower() in ['exit', 'quit', 'done', 'bye', 'q']:
                print(f"{Fore.LIGHTCYAN_EX}Ending conversation. Returning to main flow...{Fore.RESET}")
                break
            
            if not user_input:
                continue
            
            # Check if off-topic
            if self._is_offtopic(user_input):
                print(f"{Fore.YELLOW}Assistant: I can only discuss the current threat hunting findings. Please ask about the detected threats or cybersecurity topics related to this analysis.{Fore.RESET}\n")
                continue
            
            # Add user message to history
            self.conversation_history.append({
                "role": "user",
                "content": user_input
            })
            
            # Build messages for model
            messages = [
                {"role": "system", "content": self.system_context}
            ] + self.conversation_history
            
            # Check token budget
            estimated_tokens = self._estimate_tokens(messages)
            if estimated_tokens > self.MAX_TOKENS:
                print(f"{Fore.YELLOW}⚠️  Approaching token limit. Truncating history...{Fore.RESET}")
                self._truncate_history_if_needed()
                messages = [
                    {"role": "system", "content": self.system_context}
                ] + self.conversation_history
            
            # Get response from model
            try:
                print(f"{Fore.YELLOW}🤔 {self.model_name} is thinking... (streaming){Fore.RESET}")
                accum = ""
                try:
                    for line in OLLAMA_CLIENT.chat_stream(messages=messages, model_name=self.model_name, json_mode=False):
                        text = line if isinstance(line, str) else ""
                        accum += text
                        print(text, end="", flush=True)
                    print()
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Cancelled. Showing partial response.{Fore.RESET}")
                response = accum

                # Add to history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": response
                })
                
                # Display response (already streamed, but print newline separation)
                print(f"\n{Fore.LIGHTCYAN_EX}Assistant (complete):{Fore.RESET}\n")
                
                self.turn_count += 1
                
                # Warn when approaching limit
                if self.turn_count >= self.MAX_TURNS - 2:
                    print(f"{Fore.YELLOW}⚠️  {self.MAX_TURNS - self.turn_count} turns remaining{Fore.RESET}\n")
                
            except Exception as e:
                print(f"{Fore.RED}Error getting response: {e}{Fore.RESET}")
                print(f"{Fore.YELLOW}Try rephrasing your question or exit and restart.{Fore.RESET}\n")
                # Remove failed user message
                self.conversation_history.pop()
                continue
        
        # Session end
        if self.turn_count >= self.MAX_TURNS:
            print(f"\n{Fore.YELLOW}⚠️  Maximum turns ({self.MAX_TURNS}) reached. Ending conversation.{Fore.RESET}")
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}CONVERSATION SUMMARY")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.WHITE}Total turns: {self.turn_count}")
        print(f"{Fore.WHITE}Questions asked: {self.turn_count}")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
    
    def _is_offtopic(self, user_input):
        """Simple off-topic detection"""
        # Keywords that suggest off-topic
        offtopic_keywords = [
            'weather', 'recipe', 'joke', 'story', 'movie', 'music',
            'sports', 'politics', 'news', 'stock', 'finance',
            'write code', 'help me code', 'python script', 'program',
            'math problem', 'homework', 'essay', 'poem'
        ]
        
        user_lower = user_input.lower()
        
        # Check for off-topic keywords
        for keyword in offtopic_keywords:
            if keyword in user_lower:
                return True
        
        # Check if security-related keywords present (whitelist)
        security_keywords = [
            'finding', 'threat', 'attack', 'ioc', 'malware', 'suspicious',
            'compromise', 'breach', 'vulnerability', 'exploit', 'lateral',
            'credential', 'mitre', 'tactic', 'technique', 'investigate',
            'remediate', 'response', 'incident', 'risk', 'security'
        ]
        
        # If any security keyword present, assume on-topic
        for keyword in security_keywords:
            if keyword in user_lower:
                return False
        
        # If very short or question-like, assume on-topic (benefit of doubt)
        if len(user_input) < 50 or '?' in user_input:
            return False
        
        # Default: allow (benefit of doubt)
        return False


def start_chat_mode(findings, log_data_summary, query_context, model_name):
    """Start conversational follow-up about findings"""
    session = SocChatSession(findings, log_data_summary, query_context, model_name)
    session.chat_loop()

