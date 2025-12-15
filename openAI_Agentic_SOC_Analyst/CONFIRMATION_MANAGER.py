"""
CONFIRMATION_MANAGER.py - Pre-commit confirmation with time estimates
Shows analysis confirmation before starting processing
"""

from color_support import Fore, Style
import TIME_ESTIMATOR
import GUARDRAILS


def confirm_analysis_with_time_estimate(model_name, input_tokens, cost_info, investigation_mode="threat_hunt", severity_config=None):
    """
    Show confirmation with time estimate before starting analysis
    
    Args:
        model_name (str): Selected model name
        input_tokens (int): Estimated input tokens
        cost_info (dict): Cost information
        investigation_mode (str): Investigation mode
        severity_config (dict): Severity configuration
    
    Returns:
        bool: True if user confirms, False otherwise
    """
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📊 ANALYSIS CONFIRMATION")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}")
    
    # Basic info
    print(f"Model: {model_name}")
    print(f"Mode: {investigation_mode.replace('_', ' ').title()}")
    if severity_config:
        print(f"Severity: {severity_config.get('name', 'Unknown')}")
    
    # Input size
    if input_tokens:
        print(f"Input size: {input_tokens:,} tokens")
    else:
        print("Input size: Unknown")
    
    # Time estimate
    if input_tokens:
        estimated_time = TIME_ESTIMATOR.estimate_time(model_name, input_tokens)
        time_display = TIME_ESTIMATOR.format_time_display(estimated_time, input_tokens, model_name)
        print(f"Estimated time: {time_display}")
    else:
        print("Estimated time: Unknown")
    
    # Cost info - handle both string and numeric costs
    if cost_info:
        cost_value = cost_info.get('cost')
        if cost_value == 'Free' or cost_value == 'FREE':
            print(f"Cost: {Fore.LIGHTGREEN_EX}FREE{Fore.RESET}")
        elif isinstance(cost_value, (int, float)):
            # Show formatted cost estimate with appropriate precision
            if cost_value < 0.0001:
                print(f"Cost: {Fore.LIGHTGREEN_EX}${cost_value:.6f}{Fore.RESET}")
            elif cost_value < 0.01:
                print(f"Cost: {Fore.LIGHTGREEN_EX}${cost_value:.4f}{Fore.RESET}")
            elif cost_value < 1.0:
                print(f"Cost: {Fore.LIGHTYELLOW_EX}${cost_value:.4f}{Fore.RESET}")
            else:
                print(f"Cost: {Fore.LIGHTYELLOW_EX}${cost_value:.2f}{Fore.RESET}")
        else:
            # String cost (fallback)
            print(f"Cost: {cost_value}")
    
    # Processing details
    print(f"\n{Fore.LIGHTYELLOW_EX}Processing Details:{Fore.RESET}")
    
    if model_name == "local-mix":
        print(f"  • Hybrid processing (Qwen + GPT-OSS parallel)")
        if input_tokens and input_tokens > 100000:
            chunks = TIME_ESTIMATOR.time_estimator._calculate_chunks(input_tokens, 100000)
            print(f"  • Chunked processing ({chunks} chunks)")
        else:
            print(f"  • Single-pass processing")
    elif input_tokens and input_tokens > TIME_ESTIMATOR.get_model_context_limit(model_name):
        chunks = TIME_ESTIMATOR.time_estimator._calculate_chunks(input_tokens, TIME_ESTIMATOR.get_model_context_limit(model_name))
        print(f"  • Chunked processing ({chunks} chunks)")
    else:
        print(f"  • Single-pass processing")
    
    # Model type
    if model_name in ["qwen", "gpt-oss:20b", "local-mix"]:
        print(f"  • Local/Offline model (no API calls)")
    else:
        print(f"  • Cloud model (API calls required)")
    
    print(f"\n{Fore.YELLOW}Proceed with analysis? (y/n): {Fore.RESET}")
    
    while True:
        try:
            response = input().lower().strip()
            if response in ['y', 'yes', '']:
                return True
            elif response in ['n', 'no']:
                return False
            else:
                print(f"{Fore.RED}Please enter 'y' for yes or 'n' for no: {Fore.RESET}")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}Analysis cancelled.{Fore.RESET}")
            return False


def get_cost_info(model_name, input_tokens=None):
    """
    Get cost information for a model with accurate cost calculation for OpenAI models
    
    Args:
        model_name (str): Model name
        input_tokens (int, optional): Estimated input tokens for cost calculation
    
    Returns:
        dict: Cost information with actual cost estimate if input_tokens provided
    """
    
    # Check if it's a local/offline model
    if model_name in ["qwen", "gpt-oss:20b", "local-mix"]:
        return {"cost": "Free", "type": "Local/Offline"}
    
    # For OpenAI models, calculate actual cost if input_tokens provided
    if model_name in GUARDRAILS.ALLOWED_MODELS:
        model_info = GUARDRAILS.ALLOWED_MODELS[model_name]
        
        if input_tokens and input_tokens > 0:
            # Estimate output tokens based on task type
            # For security analysis tasks, output is typically 10-20% of input
            # Using 15% as a reasonable estimate for CTF/threat hunting analysis
            # This accounts for structured findings, explanations, and evidence summaries
            estimated_output_tokens = int(input_tokens * 0.15)
            
            # Ensure output doesn't exceed model's max_output_tokens
            max_output = model_info.get("max_output_tokens", 32768)
            if estimated_output_tokens > max_output:
                estimated_output_tokens = max_output
            
            # Calculate costs using pricing from GUARDRAILS.ALLOWED_MODELS
            input_cost_per_million = model_info["cost_per_million_input"]
            output_cost_per_million = model_info["cost_per_million_output"]
            
            input_cost = (input_tokens / 1_000_000.0) * input_cost_per_million
            output_cost = (estimated_output_tokens / 1_000_000.0) * output_cost_per_million
            total_cost = input_cost + output_cost
            
            return {
                "cost": total_cost,  # Numeric value for proper formatting
                "type": "Cloud/API",
                "input_cost": input_cost,
                "output_cost": output_cost,
                "estimated_output_tokens": estimated_output_tokens,
                "input_tokens": input_tokens
            }
        else:
            # No input tokens provided - return pricing info
            return {
                "cost": f"${model_info['cost_per_million_input']:.2f}/${model_info['cost_per_million_output']:.2f} per M tokens",
                "type": "Cloud/API"
            }
    
    # Fallback for unknown models
    return {"cost": "Variable", "type": "Cloud/API"}


def format_time_display(seconds):
    """
    Format time display in a user-friendly way
    
    Args:
        seconds (int): Time in seconds
    
    Returns:
        str: Formatted time string
    """
    
    if seconds < 60:
        return f"{seconds}s"
    else:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        if remaining_seconds == 0:
            return f"{minutes}m"
        else:
            return f"{minutes}m {remaining_seconds}s"
