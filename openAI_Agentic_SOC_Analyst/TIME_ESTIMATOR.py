"""
TIME_ESTIMATOR.py - Universal Time Estimation System
Estimates inference time for all models (OpenAI, Ollama, Hybrid)
Includes chunked processing time estimates
"""

import tiktoken
from color_support import Fore


class TimeEstimator:
    """Universal time estimation for all models"""
    
    def __init__(self):
        # OpenAI model performance profiles
        self.openai_profiles = {
            'gpt-4.1-nano': {
                'base_time': 15,  # seconds
                'tokens_per_second': 50000,
                'api_overhead': 2,
                'max_tokens': 1047576
            },
            'gpt-4.1': {
                'base_time': 20,
                'tokens_per_second': 40000,
                'api_overhead': 3,
                'max_tokens': 1047576
            },
            'gpt-5-mini': {
                'base_time': 12,
                'tokens_per_second': 60000,
                'api_overhead': 2,
                'max_tokens': 272000
            },
            'gpt-5': {
                'base_time': 18,
                'tokens_per_second': 45000,
                'api_overhead': 3,
                'max_tokens': 272000
            },
            'gpt-4o-mini': {
                'base_time': 10,
                'tokens_per_second': 70000,
                'api_overhead': 1,
                'max_tokens': 128000
            }
        }
        
        # Ollama model performance profiles
        self.ollama_profiles = {
            'qwen3:8b': {
                'base_time': 5,
                'tokens_per_second': 2000,  # ~25s for 50K tokens
                'chunk_overhead': 2,
                'max_tokens': 128000
            },
            'gpt-oss:20b': {
                'base_time': 8,
                'tokens_per_second': 1000,  # ~45s for 25K tokens
                'chunk_overhead': 3,
                'max_tokens': 32000
            },
            'llama3:8b': {
                'base_time': 6,
                'tokens_per_second': 1800,
                'chunk_overhead': 2,
                'max_tokens': 128000
            }
        }
    
    def estimate_time(self, model_name, input_tokens, model_type=None):
        """Estimate processing time for any model"""
        
        if model_name in self.openai_profiles:
            return self._estimate_openai_time(model_name, input_tokens)
        elif model_name in self.ollama_profiles:
            return self._estimate_ollama_time(model_name, input_tokens)
        elif model_name == "local-mix":
            return self._estimate_hybrid_time(input_tokens)
        else:
            # Fallback estimation
            return self._estimate_fallback_time(input_tokens)
    
    def _estimate_openai_time(self, model_name, input_tokens):
        """Estimate OpenAI model processing time"""
        config = self.openai_profiles[model_name]
        
        # Calculate processing time
        processing_time = input_tokens / config['tokens_per_second']
        total_time = config['base_time'] + processing_time + config['api_overhead']
        
        # Add rate limit delays if approaching limits
        if input_tokens > config['max_tokens'] * 0.8:
            total_time += 10  # Additional delay for large requests
        
        return int(total_time)
    
    def _estimate_ollama_time(self, model_name, input_tokens):
        """Estimate Ollama model processing time"""
        config = self.ollama_profiles[model_name]
        
        # Check if chunking is needed
        if input_tokens > config['max_tokens']:
            chunks = self._calculate_chunks(input_tokens, config['max_tokens'])
            tokens_per_chunk = input_tokens / chunks
            chunk_time = tokens_per_chunk / config['tokens_per_second']
            total_time = config['base_time'] + (chunk_time * chunks) + (config['chunk_overhead'] * chunks)
        else:
            processing_time = input_tokens / config['tokens_per_second']
            total_time = config['base_time'] + processing_time
        
        return int(total_time)
    
    def _estimate_hybrid_time(self, input_tokens):
        """Estimate hybrid model processing time"""
        # Get individual model estimates
        qwen_time = self._estimate_ollama_time('qwen3:8b', input_tokens)
        gpt_oss_time = self._estimate_ollama_time('gpt-oss:20b', input_tokens)
        
        # Hybrid processes in parallel, so take the maximum
        parallel_time = max(qwen_time, gpt_oss_time)
        
        # Add fusion overhead
        fusion_overhead = 5  # seconds for result fusion
        
        # Add chunking overhead if needed
        if input_tokens > 100000:  # Chunking threshold
            chunks = self._calculate_chunks(input_tokens, 100000)
            chunk_overhead = chunks * 3  # 3 seconds per chunk for hybrid
            total_time = parallel_time + fusion_overhead + chunk_overhead
        else:
            total_time = parallel_time + fusion_overhead
        
        return int(total_time)
    
    def _calculate_chunks(self, input_tokens, max_tokens_per_chunk):
        """Calculate number of chunks needed"""
        if input_tokens <= max_tokens_per_chunk:
            return 1
        
        # Leave 20% buffer for safety
        safe_tokens = int(max_tokens_per_chunk * 0.8)
        chunks = (input_tokens + safe_tokens - 1) // safe_tokens  # Ceiling division
        return chunks
    
    def _estimate_fallback_time(self, input_tokens):
        """Fallback time estimation"""
        # Conservative estimate: 1 second per 1000 tokens
        return int(input_tokens / 1000)
    
    def format_time_display(self, estimated_time, input_tokens, model_name):
        """Format time display with additional info"""
        
        if estimated_time < 60:
            time_str = f"{estimated_time}s"
        else:
            minutes = estimated_time // 60
            seconds = estimated_time % 60
            if seconds == 0:
                time_str = f"{minutes}m"
            else:
                time_str = f"{minutes}m {seconds}s"
        
        # Add chunking info
        if model_name in self.ollama_profiles:
            max_tokens = self.ollama_profiles[model_name]['max_tokens']
            if input_tokens > max_tokens:
                chunks = self._calculate_chunks(input_tokens, max_tokens)
                time_str += f" ({chunks} chunks)"
        elif model_name == "local-mix" and input_tokens > 100000:
            chunks = self._calculate_chunks(input_tokens, 100000)
            time_str += f" ({chunks} chunks)"
        
        # Add parallel processing info for hybrid
        if model_name == "local-mix":
            time_str += " (parallel)"
        
        return time_str
    
    def get_model_context_limit(self, model_name):
        """Get context limit for a model"""
        if model_name in self.openai_profiles:
            return self.openai_profiles[model_name]['max_tokens']
        elif model_name in self.ollama_profiles:
            return self.ollama_profiles[model_name]['max_tokens']
        elif model_name == "local-mix":
            return 128000  # Qwen's limit
        else:
            return 32000  # Conservative fallback
    
    def estimate_tokens(self, messages, model_name="gpt-4"):
        """Estimate token count for messages"""
        try:
            encoding = tiktoken.encoding_for_model(model_name)
            total_tokens = 0
            
            for message in messages:
                if isinstance(message, dict):
                    content = message.get('content', '')
                else:
                    content = str(message)
                
                total_tokens += len(encoding.encode(content))
            
            return total_tokens
        except:
            # Fallback: rough estimate
            total_chars = sum(len(str(msg)) for msg in messages)
            return total_chars // 4  # Rough approximation


# Global instance
time_estimator = TimeEstimator()


def estimate_inference_time(model_name, input_tokens, model_type=None):
    """Convenience function for time estimation"""
    return time_estimator.estimate_time(model_name, input_tokens, model_type)


def estimate_time(model_name, input_tokens, model_type=None):
    """Convenience function for time estimation"""
    return time_estimator.estimate_time(model_name, input_tokens, model_type)


def format_time_display(estimated_time, input_tokens, model_name):
    """Convenience function for time formatting"""
    return time_estimator.format_time_display(estimated_time, input_tokens, model_name)


def get_model_context_limit(model_name):
    """Convenience function for context limits"""
    return time_estimator.get_model_context_limit(model_name)


def estimate_tokens(messages, model_name="gpt-4"):
    """Convenience function for token estimation"""
    return time_estimator.estimate_tokens(messages, model_name)
