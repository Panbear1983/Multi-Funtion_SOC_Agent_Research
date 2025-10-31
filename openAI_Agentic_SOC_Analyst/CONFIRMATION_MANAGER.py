"""
CONFIRMATION_MANAGER.py - Pre-commit confirmation with time estimates
Shows analysis confirmation before starting processing
"""

from color_support import Fore, Style
import TIME_ESTIMATOR


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
    
    # Cost info
    if cost_info:
        if cost_info.get('cost') == 'Free':
            print(f"Cost: {Fore.LIGHTGREEN_EX}FREE{Fore.RESET}")
        else:
            print(f"Cost: {cost_info.get('cost', 'Unknown')}")
    
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


def get_cost_info(model_name):
    """
    Get cost information for a model
    
    Args:
        model_name (str): Model name
    
    Returns:
        dict: Cost information
    """
    
    if model_name in ["qwen", "gpt-oss:20b", "local-mix"]:
        return {"cost": "Free", "type": "Local/Offline"}
    else:
        # For OpenAI models, we'd need to look up the actual cost
        # For now, return a placeholder
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
