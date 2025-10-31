"""
HYBRID_ENGINE.py - Dynamic Hybrid Model Engine
Combines Qwen (volume) + GPT-OSS (reasoning) for optimal threat detection

Features:
- Adapts to any investigation mode + severity level + query method
- Modular model selection and fusion strategies
- Easy model swapping and configuration
- Parallel processing for speed
- Intelligent result fusion
"""

import json
import time
import threading
import queue
from datetime import datetime
from pathlib import Path
from color_support import Fore, Style
import OLLAMA_CLIENT
import QWEN_ENHANCER
import GPT_OSS_ENHANCER
import LEARNING_ENGINE
import GUARDRAILS
import TIME_ESTIMATOR


class HybridEngine:
    """
    Dynamic Hybrid Model Engine
    - Adapts to any investigation mode + severity level + query method
    - Modular model selection and fusion strategies
    - Easy model swapping and configuration
    """
    
    def __init__(self, investigation_mode, severity_config, query_method, 
                 model_config=None, openai_client=None):
        self.investigation_mode = investigation_mode  # 'threat_hunt', 'anomaly', 'ctf'
        self.severity_config = severity_config
        self.query_method = query_method  # 'llm', 'structured', 'custom_kql'
        self.openai_client = openai_client
        
        # Dynamic model configuration based on context
        self.model_config = self._configure_models(model_config)
        
        # Initialize model adapters
        self.model_adapters = {
            'qwen': QwenModelAdapter(self.model_config['qwen']),
            'gpt_oss': GptOssModelAdapter(self.model_config['gpt_oss'])
        }
        
        # Initialize fusion engine
        self.fusion_engine = FusionEngine(self.model_config['fusion'])
        
        print(f"{Fore.LIGHTCYAN_EX}🔀 Hybrid Engine: {investigation_mode} + {severity_config['name']} + {query_method}{Fore.RESET}")
    
    def _configure_models(self, model_config):
        """Dynamically configure models based on investigation context"""
        
        # Base configurations
        base_config = {
            'qwen': {
                'model_name': 'qwen3:8b',
                'timeout': 180,
                'max_tokens': 128000,
                'temperature': 0.1,
                'role': 'volume_processor'
            },
            'gpt_oss': {
                'model_name': 'gpt-oss:20b', 
                'timeout': 240,
                'max_tokens': 32000,
                'temperature': 0.1,
                'role': 'reasoning_processor'
            },
            'fusion': {
                'strategy': 'adaptive',
                'confidence_threshold': self.severity_config['confidence_threshold'],
                'cross_validation': True
            }
        }
        
        # Adapt based on investigation mode
        if self.investigation_mode == 'threat_hunt':
            # Focus on precision and deep analysis
            base_config['gpt_oss']['temperature'] = 0.05  # More deterministic
            base_config['fusion']['strategy'] = 'precision_focused'
            
        elif self.investigation_mode == 'anomaly':
            # Focus on volume and pattern detection
            base_config['qwen']['max_tokens'] = 200000  # More context
            base_config['fusion']['strategy'] = 'volume_focused'
            
        elif self.investigation_mode == 'ctf':
            # Focus on speed and iterative analysis
            base_config['qwen']['timeout'] = 120  # Faster
            base_config['gpt_oss']['timeout'] = 180
            base_config['fusion']['strategy'] = 'speed_focused'
        
        # Adapt based on severity level
        if self.severity_config['name'] == 'CRITICAL':
            # Maximum sensitivity
            base_config['fusion']['confidence_threshold'] = 0
            base_config['fusion']['cross_validation'] = True
            base_config['qwen']['temperature'] = 0.2  # More creative for edge cases
            
        elif self.severity_config['name'] == 'RELAXED':
            # High confidence only
            base_config['fusion']['confidence_threshold'] = 2
            base_config['fusion']['cross_validation'] = False  # Faster
            base_config['gpt_oss']['temperature'] = 0.05  # Very deterministic
        
        # Adapt based on query method
        if self.query_method == 'custom_kql':
            # User wrote KQL, focus on analysis not query building
            base_config['fusion']['strategy'] = 'analysis_focused'
        elif self.query_method == 'structured':
            # Predictable input, optimize for speed
            base_config['qwen']['timeout'] = 90
            base_config['gpt_oss']['timeout'] = 120
        
        return base_config
    
    def analyze(self, messages, table_name=None, context=None):
        """
        Main analysis method - adapts to all combinations
        Automatically chunks large datasets based on actual model limits
        """
        # Check if chunked processing is needed based on actual model limits
        input_tokens = self._estimate_input_tokens(messages)
        
        # Get actual model limits
        qwen_limit = TIME_ESTIMATOR.get_model_context_limit('qwen3:8b')
        gpt_oss_limit = TIME_ESTIMATOR.get_model_context_limit('gpt-oss:20b')
        
        # Use the smaller limit (GPT-OSS) with safety buffer (80% to be safe)
        chunking_threshold = int(min(qwen_limit, gpt_oss_limit) * 0.8)
        
        if input_tokens > chunking_threshold:
            print(f"{Fore.LIGHTCYAN_EX}🔀 Large dataset detected ({input_tokens:,} tokens) - Using chunked processing{Fore.RESET}")
            print(f"{Fore.LIGHTCYAN_EX}   Model limits: Qwen {qwen_limit:,} | GPT-OSS {gpt_oss_limit:,} | Threshold: {chunking_threshold:,}{Fore.RESET}")
            return self.analyze_chunked(messages, table_name, context)
        
        print(f"\n{Fore.LIGHTYELLOW_EX}{'='*70}")
        print(f"{Fore.LIGHTYELLOW_EX}🔀 HYBRID ANALYSIS: {self.investigation_mode.upper()}{Fore.RESET}")
        print(f"{Fore.LIGHTYELLOW_EX}Severity: {self.severity_config['name']} | Method: {self.query_method.upper()}{Fore.RESET}")
        print(f"{Fore.LIGHTYELLOW_EX}{'='*70}{Fore.RESET}\n")
        
        # Step 1: Parallel processing with both models
        qwen_results = self.model_adapters['qwen'].process(messages, table_name, context)
        gpt_oss_results = self.model_adapters['gpt_oss'].process(messages, table_name, context)
        
        # Step 2: Intelligent fusion based on context
        fused_results = self.fusion_engine.fuse(
            qwen_results, gpt_oss_results, 
            investigation_mode=self.investigation_mode,
            severity_config=self.severity_config,
            query_method=self.query_method
        )
        
        # Step 3: Apply severity-based filtering
        final_results = self._apply_severity_filtering(fused_results)
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Hybrid analysis complete: {len(final_results)} findings{Fore.RESET}")
        return {"findings": final_results}
    
    def analyze_chunked(self, messages, table_name=None, context=None):
        """
        Chunked analysis for large datasets
        - Split data into manageable chunks
        - Process each chunk with hybrid model
        - Merge results intelligently
        """
        print(f"\n{Fore.LIGHTYELLOW_EX}{'='*70}")
        print(f"{Fore.LIGHTYELLOW_EX}🔀 CHUNKED HYBRID ANALYSIS: {self.investigation_mode.upper()}{Fore.RESET}")
        print(f"{Fore.LIGHTYELLOW_EX}Severity: {self.severity_config['name']} | Method: {self.query_method.upper()}{Fore.RESET}")
        print(f"{Fore.LIGHTYELLOW_EX}{'='*70}{Fore.RESET}\n")
        
        # Extract CSV data
        csv_data = self._extract_csv_from_messages(messages)
        
        if not csv_data:
            print(f"{Fore.YELLOW}No CSV data found for chunked processing{Fore.RESET}")
            return {"findings": []}
        
        # Calculate chunk size based on actual model limits (with safety buffer)
        qwen_limit = TIME_ESTIMATOR.get_model_context_limit('qwen3:8b')
        gpt_oss_limit = TIME_ESTIMATOR.get_model_context_limit('gpt-oss:20b')
        
        # Use 80% of the smaller limit for safety
        qwen_chunk_size = int(qwen_limit * 0.8)
        gpt_oss_chunk_size = int(gpt_oss_limit * 0.8)
        chunk_size = min(qwen_chunk_size, gpt_oss_chunk_size)
        
        print(f"{Fore.LIGHTBLACK_EX}Chunk size: {chunk_size:,} tokens (based on model limits: Qwen {qwen_limit:,}, GPT-OSS {gpt_oss_limit:,}){Fore.RESET}")
        
        # Split into chunks
        chunks = self._split_csv_into_chunks(csv_data, chunk_size)
        
        print(f"{Fore.LIGHTCYAN_EX}Processing {len(chunks)} chunks...{Fore.RESET}")
        
        all_findings = []
        
        for i, chunk in enumerate(chunks):
            print(f"\n{Fore.WHITE}Processing chunk {i+1}/{len(chunks)}...{Fore.RESET}")
            
            # Create chunk-specific messages
            chunk_messages = self._create_chunk_messages(messages, chunk)
            
            # Process chunk with hybrid model (recursive call without chunking check)
            chunk_results = self._analyze_single_chunk(chunk_messages, table_name, context)
            
            # Add chunk metadata
            for finding in chunk_results.get('findings', []):
                finding['chunk_id'] = i
                finding['chunk_total'] = len(chunks)
                finding['chunk_info'] = f"Chunk {i+1}/{len(chunks)}"
            
            all_findings.extend(chunk_results.get('findings', []))
            
            print(f"{Fore.LIGHTGREEN_EX}  ✓ Chunk {i+1} complete: {len(chunk_results.get('findings', []))} findings{Fore.RESET}")
        
        # Merge and deduplicate findings across chunks
        print(f"\n{Fore.LIGHTCYAN_EX}Merging results from {len(chunks)} chunks...{Fore.RESET}")
        merged_findings = self._merge_chunk_findings(all_findings)
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Chunked hybrid analysis complete: {len(merged_findings)} findings{Fore.RESET}")
        return {"findings": merged_findings}
    
    def _analyze_single_chunk(self, messages, table_name=None, context=None):
        """Analyze a single chunk without chunking check"""
        # Step 1: Parallel processing with both models
        qwen_results = self.model_adapters['qwen'].process(messages, table_name, context)
        gpt_oss_results = self.model_adapters['gpt_oss'].process(messages, table_name, context)
        
        # Step 2: Intelligent fusion based on context
        fused_results = self.fusion_engine.fuse(
            qwen_results, gpt_oss_results, 
            investigation_mode=self.investigation_mode,
            severity_config=self.severity_config,
            query_method=self.query_method
        )
        
        # Step 3: Apply severity-based filtering
        final_results = self._apply_severity_filtering(fused_results)
        
        return {"findings": final_results}
    
    def _estimate_input_tokens(self, messages):
        """Estimate token count for messages"""
        return TIME_ESTIMATOR.estimate_tokens(messages, "gpt-4")
    
    def _split_csv_into_chunks(self, csv_data, max_tokens):
        """Split CSV data into token-limited chunks"""
        lines = csv_data.split('\n')
        if len(lines) < 2:
            return [csv_data]
        
        header = lines[0]
        data_lines = lines[1:]
        
        chunks = []
        current_chunk = [header]
        current_tokens = self._estimate_tokens_for_text(header)
        
        for line in data_lines:
            if not line.strip():
                continue
                
            line_tokens = self._estimate_tokens_for_text(line)
            
            if current_tokens + line_tokens > max_tokens and len(current_chunk) > 1:
                # Save current chunk
                chunks.append('\n'.join(current_chunk))
                current_chunk = [header, line]
                current_tokens = self._estimate_tokens_for_text(header) + line_tokens
            else:
                current_chunk.append(line)
                current_tokens += line_tokens
        
        if len(current_chunk) > 1:  # More than just header
            chunks.append('\n'.join(current_chunk))
        
        return chunks
    
    def _estimate_tokens_for_text(self, text):
        """Rough token estimation for text"""
        return len(text) // 4  # Rough approximation
    
    def _create_chunk_messages(self, original_messages, chunk_data):
        """Create messages for a specific chunk"""
        chunk_messages = []
        
        for msg in original_messages:
            if msg.get("role") == "user" and "Log Data:" in msg.get("content", ""):
                # Replace with chunk data
                content = msg["content"].split("Log Data:")[0] + f"Log Data:\n{chunk_data}"
                chunk_messages.append({
                    "role": "user",
                    "content": content
                })
            else:
                chunk_messages.append(msg)
        
        return chunk_messages
    
    def _merge_chunk_findings(self, all_findings):
        """Merge findings from multiple chunks, handling cross-chunk patterns"""
        if not all_findings:
            return []
        
        # Group by finding type
        grouped = {}
        for finding in all_findings:
            key = self._get_finding_key(finding)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        
        merged = []
        for key, findings in grouped.items():
            if len(findings) == 1:
                merged.append(findings[0])
            else:
                # Merge cross-chunk findings
                merged_finding = self._merge_cross_chunk_findings(findings)
                merged.append(merged_finding)
        
        return merged
    
    def _merge_cross_chunk_findings(self, findings):
        """Merge findings that appear across multiple chunks"""
        if not findings:
            return None
        
        # Use the first finding as base
        merged = findings[0].copy()
        
        # Boost confidence for cross-chunk findings
        if merged.get('confidence', '').lower() in ['low', 'medium']:
            merged['confidence'] = 'High'
        elif merged.get('confidence', '').lower() == 'high':
            merged['confidence'] = 'Very High'
        
        # Add cross-chunk information
        chunk_ids = [f.get('chunk_id', '?') for f in findings]
        merged['cross_chunk'] = True
        merged['chunk_span'] = f"Found in chunks: {', '.join(map(str, sorted(set(chunk_ids))))}"
        merged['occurrence_count'] = len(findings)
        
        # Merge descriptions
        descriptions = [f.get('description', '') for f in findings if f.get('description')]
        if descriptions:
            unique_descriptions = list(set(descriptions))
            if len(unique_descriptions) > 1:
                merged['description'] = f"{unique_descriptions[0]} [Cross-chunk pattern: {len(unique_descriptions)} variations]"
        
        return merged
    
    def _get_finding_key(self, finding):
        """Generate a unique key for a finding"""
        ioc = finding.get('ioc', '')
        tactic = finding.get('tactic', '')
        desc = finding.get('description', '')[:100]
        key_parts = [str(ioc).lower(), str(tactic).lower(), desc.lower()]
        return "|".join(key_parts)
    
    def _apply_severity_filtering(self, findings):
        """Apply severity-based filtering to findings"""
        if not findings:
            return findings
        
        filtered = []
        for finding in findings:
            confidence = finding.get('confidence', 'Medium')
            confidence_levels = {'Low': 1, 'Medium': 2, 'High': 3, 'Very High': 4}
            
            finding_confidence = confidence_levels.get(confidence, 2)
            threshold = self.severity_config.get('confidence_threshold', 0)
            
            if finding_confidence >= threshold:
                filtered.append(finding)
        
        return filtered
    
    def swap_model_adapter(self, model_name, new_config):
        """Hot-swap a model adapter"""
        if model_name in self.model_adapters:
            self.model_adapters[model_name].update_config(new_config)
            print(f"{Fore.LIGHTGREEN_EX}✓ Swapped {model_name} adapter{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}Model {model_name} not found in adapters{Fore.RESET}")
    
    def add_model_adapter(self, model_name, config):
        """Add a new model adapter"""
        if model_name == 'qwen':
            self.model_adapters[model_name] = QwenModelAdapter(config)
        elif model_name == 'gpt_oss':
            self.model_adapters[model_name] = GptOssModelAdapter(config)
        else:
            # Generic adapter for new models
            self.model_adapters[model_name] = GenericModelAdapter(config)
        
        print(f"{Fore.LIGHTGREEN_EX}✓ Added {model_name} adapter{Fore.RESET}")
    
    def _extract_csv_from_messages(self, messages):
        """Extract CSV data from messages"""
        for message in messages:
            if isinstance(message, dict) and message.get("role") == "user":
                content = message.get("content", "")
                if "Log Data:" in content:
                    # Extract everything after "Log Data:"
                    csv_start = content.find("Log Data:") + len("Log Data:")
                    return content[csv_start:].strip()
                elif "Analyze these logs:" in content:
                    # Extract everything after "Analyze these logs:"
                    csv_start = content.find("Analyze these logs:") + len("Analyze these logs:")
                    return content[csv_start:].strip()
        return ""


class QwenModelAdapter:
    """Qwen model adapter - handles volume processing"""
    
    def __init__(self, config):
        self.config = config
        self.enhancer = QWEN_ENHANCER.QwenEnhancer(
            severity_multiplier=1.0,  # Will be set by severity
            openai_client=None,
            use_gpt_refinement=False
        )
    
    def process(self, messages, table_name, context):
        """Process with Qwen - optimized for volume"""
        print(f"{Fore.WHITE}  → Qwen: Processing high-volume data...{Fore.RESET}")
        
        try:
            # Use Qwen enhancer's rule-based patterns first
            csv_text = self._extract_csv_from_messages(messages)
            rule_findings, iocs = self.enhancer.apply_rule_based_patterns_to_csv(csv_text)
            
            # Enhance messages with rule context
            enhanced_messages = self._enhance_messages_with_rules(messages, rule_findings, iocs)
            
            # Get LLM analysis from Qwen
            print(f"    {Fore.WHITE}Getting Qwen analysis...{Fore.RESET}")
            llm_content = OLLAMA_CLIENT.chat(
                messages=enhanced_messages,
                model_name=self.config['model_name'],
                timeout=self.config['timeout']
            )
            
            try:
                llm_results = json.loads(llm_content)
                llm_findings = llm_results.get("findings", [])
            except json.JSONDecodeError:
                llm_findings = []
            
            # Combine rule + LLM findings
            combined = self._combine_findings(rule_findings, llm_findings)
            return combined
            
        except Exception as e:
            print(f"{Fore.YELLOW}Qwen processing error: {e}{Fore.RESET}")
            return []
    
    def update_config(self, new_config):
        """Update adapter configuration"""
        self.config.update(new_config)
    
    def _extract_csv_from_messages(self, messages):
        """Extract CSV text from messages"""
        for msg in messages:
            content = msg.get("content", "")
            if "Log Data:" in content:
                parts = content.split("Log Data:", 1)
                if len(parts) > 1:
                    return parts[1].strip()
        return ""
    
    def _enhance_messages_with_rules(self, messages, rule_findings, iocs):
        """Add rule-based context to messages"""
        enhanced = []
        rule_context = f"\n\nRule-based Pre-Analysis:\n- {len(rule_findings)} potential threats detected\n- {len(iocs)} IOCs identified"
        
        for msg in messages:
            if msg.get("role") == "user":
                enhanced_content = msg["content"] + rule_context
                enhanced.append({"role": "user", "content": enhanced_content})
            else:
                enhanced.append(msg)
        
        return enhanced
    
    def _combine_findings(self, rule_findings, llm_findings):
        """Combine rule-based and LLM findings"""
        combined = []
        seen = set()
        
        # Handle rule_findings - it might be a tuple (findings, iocs) or just findings
        if isinstance(rule_findings, tuple):
            rule_findings_list = rule_findings[0]  # Extract findings from tuple
        else:
            rule_findings_list = rule_findings
        
        for finding in rule_findings_list + llm_findings:
            key = self._get_finding_key(finding)
            if key not in seen:
                seen.add(key)
                combined.append(finding)
        
        return combined
    
    def _get_finding_key(self, finding):
        """Generate a unique key for a finding"""
        ioc = finding.get('ioc', '')
        tactic = finding.get('tactic', '')
        desc = finding.get('description', '')[:100]
        key_parts = [str(ioc).lower(), str(tactic).lower(), desc.lower()]
        return "|".join(key_parts)


class GptOssModelAdapter:
    """GPT-OSS model adapter - handles reasoning processing"""
    
    def __init__(self, config):
        self.config = config
        self.enhancer = GPT_OSS_ENHANCER.GptOssEnhancer(
            severity_multiplier=1.0,
            openai_client=None,
            use_gpt_refinement=False
        )
    
    def process(self, messages, table_name, context):
        """Process with GPT-OSS - optimized for reasoning"""
        print(f"{Fore.WHITE}  → GPT-OSS: Deep reasoning analysis...{Fore.RESET}")
        
        try:
            # Use GPT-OSS enhancer's rule-based patterns
            csv_text = self._extract_csv_from_messages(messages)
            rule_findings, iocs = self.enhancer.apply_rule_based_patterns_to_csv(csv_text)
            
            # Enhance messages for reasoning
            enhanced_messages = self._enhance_messages_for_reasoning(messages, rule_findings, iocs)
            
            # Get LLM analysis from GPT-OSS
            print(f"    {Fore.WHITE}Getting GPT-OSS analysis...{Fore.RESET}")
            llm_content = OLLAMA_CLIENT.chat(
                messages=enhanced_messages,
                model_name=self.config['model_name'],
                timeout=self.config['timeout']
            )
            
            try:
                llm_results = json.loads(llm_content)
                llm_findings = llm_results.get("findings", [])
            except json.JSONDecodeError:
                llm_findings = []
            
            # Combine rule + LLM findings
            combined = self._combine_findings(rule_findings, llm_findings)
            return combined
            
        except Exception as e:
            print(f"{Fore.YELLOW}GPT-OSS processing error: {e}{Fore.RESET}")
            return []
    
    def update_config(self, new_config):
        """Update adapter configuration"""
        self.config.update(new_config)
    
    def _extract_csv_from_messages(self, messages):
        """Extract CSV text from messages"""
        for msg in messages:
            content = msg.get("content", "")
            if "Log Data:" in content:
                parts = content.split("Log Data:", 1)
                if len(parts) > 1:
                    return parts[1].strip()
        return ""
    
    def _enhance_messages_for_reasoning(self, messages, rule_findings, iocs):
        """Enhance messages specifically for reasoning tasks"""
        enhanced = []
        reasoning_context = f"\n\nReasoning Context:\n- Analyze relationships between {len(rule_findings)} findings\n- Identify attack patterns and tactics\n- Connect IOCs to threat actors"
        
        for msg in messages:
            if msg.get("role") == "user":
                enhanced_content = msg["content"] + reasoning_context
                enhanced.append({"role": "user", "content": enhanced_content})
            else:
                enhanced.append(msg)
        
        return enhanced
    
    def _combine_findings(self, rule_findings, llm_findings):
        """Combine rule-based and LLM findings"""
        combined = []
        seen = set()
        
        # Handle rule_findings - it might be a tuple (findings, iocs) or just findings
        if isinstance(rule_findings, tuple):
            rule_findings_list = rule_findings[0]  # Extract findings from tuple
        else:
            rule_findings_list = rule_findings
        
        for finding in rule_findings_list + llm_findings:
            key = self._get_finding_key(finding)
            if key not in seen:
                seen.add(key)
                combined.append(finding)
        
        return combined
    
    def _get_finding_key(self, finding):
        """Generate a unique key for a finding"""
        ioc = finding.get('ioc', '')
        tactic = finding.get('tactic', '')
        desc = finding.get('description', '')[:100]
        key_parts = [str(ioc).lower(), str(tactic).lower(), desc.lower()]
        return "|".join(key_parts)


class GenericModelAdapter:
    """Generic model adapter for new models"""
    
    def __init__(self, config):
        self.config = config
    
    def process(self, messages, table_name, context):
        """Generic processing method"""
        print(f"{Fore.WHITE}  → {self.config.get('model_name', 'Unknown')}: Processing...{Fore.RESET}")
        # Implement generic processing logic here
        return []
    
    def update_config(self, new_config):
        """Update adapter configuration"""
        self.config.update(new_config)


class FusionEngine:
    """Intelligent fusion of model results based on context"""
    
    def __init__(self, config):
        self.config = config
        self.fusion_strategies = {
            'precision_focused': self._precision_fusion,
            'volume_focused': self._volume_fusion,
            'speed_focused': self._speed_fusion,
            'analysis_focused': self._analysis_focused_fusion,
            'adaptive': self._adaptive_fusion
        }
    
    def fuse(self, qwen_results, gpt_oss_results, investigation_mode, severity_config, query_method):
        """Fuse results using appropriate strategy"""
        strategy = self.config['strategy']
        
        print(f"{Fore.LIGHTCYAN_EX}Step 2: Fusion and cross-validation...{Fore.RESET}")
        
        if strategy in self.fusion_strategies:
            return self.fusion_strategies[strategy](
                qwen_results, gpt_oss_results, 
                investigation_mode, severity_config, query_method
            )
        else:
            return self._adaptive_fusion(qwen_results, gpt_oss_results, 
                                       investigation_mode, severity_config, query_method)
    
    def _precision_fusion(self, qwen_results, gpt_oss_results, investigation_mode, severity_config, query_method):
        """Fusion strategy for threat hunting - prioritize precision"""
        print(f"    {Fore.WHITE}Using precision-focused fusion (threat hunting){Fore.RESET}")
        
        # Prefer GPT-OSS for reasoning, use Qwen for validation
        fused = []
        
        # Create dictionaries for quick lookup
        qwen_dict = {self._get_finding_key(f): f for f in qwen_results}
        gpt_oss_dict = {self._get_finding_key(f): f for f in gpt_oss_results}
        
        # Find agreements (same finding from both models = high confidence)
        agreed_keys = set(qwen_dict.keys()) & set(gpt_oss_dict.keys())
        for key in agreed_keys:
            qwen_f = qwen_dict[key]
            gpt_oss_f = gpt_oss_dict[key]
            merged = self._merge_findings(qwen_f, gpt_oss_f, confidence_boost=True)
            fused.append(merged)
        
        # Add unique findings from both models
        all_keys = set(qwen_dict.keys()) | set(gpt_oss_dict.keys())
        unique_keys = all_keys - agreed_keys
        
        for key in unique_keys:
            if key in gpt_oss_dict:
                # Prefer GPT-OSS for reasoning
                finding = gpt_oss_dict[key]
                finding['confidence'] = finding.get('confidence', 'Medium')
                finding['source'] = 'gpt-oss'
                fused.append(finding)
            elif key in qwen_dict:
                # Add Qwen findings with validation note
                finding = qwen_dict[key]
                finding['confidence'] = finding.get('confidence', 'Low')
                finding['source'] = 'qwen'
                finding['note'] = 'Volume-based detection, needs validation'
                fused.append(finding)
        
        return fused
    
    def _volume_fusion(self, qwen_results, gpt_oss_results, investigation_mode, severity_config, query_method):
        """Fusion strategy for anomaly detection - prioritize volume"""
        print(f"    {Fore.WHITE}Using volume-focused fusion (anomaly detection){Fore.RESET}")
        
        # Prefer Qwen for volume, use GPT-OSS for pattern validation
        fused = []
        
        # Create dictionaries for quick lookup
        qwen_dict = {self._get_finding_key(f): f for f in qwen_results}
        gpt_oss_dict = {self._get_finding_key(f): f for f in gpt_oss_results}
        
        # Find agreements
        agreed_keys = set(qwen_dict.keys()) & set(gpt_oss_dict.keys())
        for key in agreed_keys:
            qwen_f = qwen_dict[key]
            gpt_oss_f = gpt_oss_dict[key]
            merged = self._merge_findings(qwen_f, gpt_oss_f, confidence_boost=True)
            fused.append(merged)
        
        # Add unique findings (prioritize Qwen for volume)
        all_keys = set(qwen_dict.keys()) | set(gpt_oss_dict.keys())
        unique_keys = all_keys - agreed_keys
        
        for key in unique_keys:
            if key in qwen_dict:
                finding = qwen_dict[key]
                finding['confidence'] = finding.get('confidence', 'Medium')
                finding['source'] = 'qwen'
                fused.append(finding)
            elif key in gpt_oss_dict:
                finding = gpt_oss_dict[key]
                finding['confidence'] = finding.get('confidence', 'Low')
                finding['source'] = 'gpt-oss'
                finding['note'] = 'Reasoning-based detection, needs volume validation'
                fused.append(finding)
        
        return fused
    
    def _speed_fusion(self, qwen_results, gpt_oss_results, investigation_mode, severity_config, query_method):
        """Fusion strategy for CTF mode - prioritize speed"""
        print(f"    {Fore.WHITE}Using speed-focused fusion (CTF mode){Fore.RESET}")
        
        # Quick fusion, minimal cross-validation
        fused = []
        
        # Combine all findings with basic deduplication
        all_findings = qwen_results + gpt_oss_results
        seen = set()
        
        for finding in all_findings:
            key = self._get_finding_key(finding)
            if key not in seen:
                seen.add(key)
                # Mark source for quick identification
                if not finding.get('source'):
                    finding['source'] = 'hybrid'
                fused.append(finding)
        
        return fused
    
    def _analysis_focused_fusion(self, qwen_results, gpt_oss_results, investigation_mode, severity_config, query_method):
        """Fusion strategy for custom KQL - focus on analysis"""
        print(f"    {Fore.WHITE}Using analysis-focused fusion (custom KQL){Fore.RESET}")
        
        # Focus on analysis quality, use both models equally
        return self._adaptive_fusion(qwen_results, gpt_oss_results, investigation_mode, severity_config, query_method)
    
    def _adaptive_fusion(self, qwen_results, gpt_oss_results, investigation_mode, severity_config, query_method):
        """Adaptive fusion based on context"""
        print(f"    {Fore.WHITE}Using adaptive fusion{Fore.RESET}")
        
        # Simple combination with conflict resolution
        fused = []
        
        # Create dictionaries for lookup
        qwen_dict = {self._get_finding_key(f): f for f in qwen_results}
        gpt_oss_dict = {self._get_finding_key(f): f for f in gpt_oss_results}
        
        # Process all findings
        all_keys = set(qwen_dict.keys()) | set(gpt_oss_dict.keys())
        
        for key in all_keys:
            if key in qwen_dict and key in gpt_oss_dict:
                # Both models found it - merge with confidence boost
                merged = self._merge_findings(qwen_dict[key], gpt_oss_dict[key], confidence_boost=True)
                fused.append(merged)
            elif key in qwen_dict:
                # Only Qwen found it
                finding = qwen_dict[key]
                finding['source'] = 'qwen'
                fused.append(finding)
            elif key in gpt_oss_dict:
                # Only GPT-OSS found it
                finding = gpt_oss_dict[key]
                finding['source'] = 'gpt-oss'
                fused.append(finding)
        
        return fused
    
    def _merge_findings(self, finding1, finding2, confidence_boost=False):
        """Merge two findings that agree"""
        merged = finding1.copy()
        
        # If both models agree, boost confidence
        if confidence_boost:
            if merged.get('confidence', '').lower() in ['low', 'medium']:
                merged['confidence'] = 'High'
            elif merged.get('confidence', '').lower() == 'high':
                merged['confidence'] = 'Very High'
        
        # Merge descriptions if different
        desc1 = merged.get('description', '')
        desc2 = finding2.get('description', '')
        if desc1 != desc2 and desc2:
            if len(desc2) > len(desc1):
                merged['description'] = desc2
            merged['description'] = f"{desc1} [Cross-validated by both models]"
        
        # Mark as cross-validated
        merged['validation'] = 'cross-validated'
        merged['sources'] = ['qwen', 'gpt-oss']
        
        return merged
    
    def _get_finding_key(self, finding):
        """Generate a unique key for a finding"""
        ioc = finding.get('ioc', '')
        tactic = finding.get('tactic', '')
        desc = finding.get('description', '')[:100]
        key_parts = [str(ioc).lower(), str(tactic).lower(), desc.lower()]
        return "|".join(key_parts)
