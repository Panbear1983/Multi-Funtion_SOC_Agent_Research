"""
Learning Engine - Self-Learning Pattern Weight Adjustment
Analyzes user feedback to improve local model detection over time
"""

import json
import os
from datetime import datetime
from color_support import Fore

class LearningEngine:
    def __init__(self, weights_file="pattern_weights.json", feedback_file="_analysis_feedback.jsonl"):
        self.weights_file = weights_file
        self.feedback_file = feedback_file
        self.weights = self._load_weights()
        
        # Learning parameters
        self.LEARNING_RATE = 0.1  # 10% adjustment per session
        self.MIN_WEIGHT = 0.1  # Never disable patterns completely
        self.MAX_WEIGHT = 3.0  # Cap maximum boost
        self.MIN_SESSIONS = 3  # Minimum sessions before learning
    
    def _load_weights(self):
        """Load learned pattern weights or return defaults"""
        if not os.path.exists(self.weights_file):
            return {}
        
        try:
            with open(self.weights_file, 'r') as f:
                weights = json.load(f)
                print(f"{Fore.LIGHTCYAN_EX}📚 Loaded {len(weights)} learned pattern weights{Fore.RESET}")
                return weights
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not load weights: {e}{Fore.RESET}")
            return {}
    
    def _save_weights(self):
        """Save learned weights to disk"""
        try:
            with open(self.weights_file, 'w') as f:
                json.dump(self.weights, f, indent=2)
            print(f"{Fore.LIGHTGREEN_EX}💾 Saved learned weights to {self.weights_file}{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error saving weights: {e}{Fore.RESET}")
    
    def get_pattern_weight(self, pattern_category):
        """Get the learned weight for a pattern category"""
        return self.weights.get(pattern_category, 1.0)  # Default to 1.0
    
    def update_from_feedback(self):
        """Analyze recent feedback and update pattern weights"""
        if not os.path.exists(self.feedback_file):
            print(f"{Fore.YELLOW}No feedback history found. Skipping learning update.{Fore.RESET}")
            return
        
        # Load feedback
        feedback_records = []
        try:
            with open(self.feedback_file, 'r') as f:
                for line in f:
                    if line.strip():
                        feedback_records.append(json.loads(line))
        except Exception as e:
            print(f"{Fore.RED}Error loading feedback: {e}{Fore.RESET}")
            return
        
        if len(feedback_records) < self.MIN_SESSIONS:
            print(f"{Fore.YELLOW}Not enough sessions ({len(feedback_records)}) for learning. Need {self.MIN_SESSIONS} minimum.{Fore.RESET}")
            return
        
        print(f"{Fore.LIGHTCYAN_EX}🧠 Analyzing {len(feedback_records)} sessions for learning...{Fore.RESET}")
        
        # Analyze pattern performance
        pattern_stats = {}  # {pattern: {'good': count, 'bad': count}}
        
        for record in feedback_records:
            rating = record.get('user_rating', 0)
            findings = record.get('findings', [])
            
            for finding in findings:
                tags = finding.get('tags', [])
                
                for tag in tags:
                    if tag not in pattern_stats:
                        pattern_stats[tag] = {'good': 0, 'bad': 0, 'total': 0}
                    
                    pattern_stats[tag]['total'] += 1
                    
                    # Good rating (4-5) = pattern worked well
                    if rating >= 4:
                        pattern_stats[tag]['good'] += 1
                    # Bad rating (1-2) = pattern produced false positives
                    elif rating <= 2:
                        pattern_stats[tag]['bad'] += 1
        
        # Update weights based on performance
        updates_made = 0
        
        for pattern, stats in pattern_stats.items():
            if stats['total'] < 2:  # Need at least 2 occurrences
                continue
            
            # Calculate success rate
            success_rate = stats['good'] / stats['total'] if stats['total'] > 0 else 0.5
            
            current_weight = self.weights.get(pattern, 1.0)
            
            # Adjust weight based on success rate
            if success_rate > 0.7:  # 70%+ success → increase weight
                new_weight = current_weight * (1 + self.LEARNING_RATE)
                adjustment = "↑"
            elif success_rate < 0.3:  # 30%- success → decrease weight
                new_weight = current_weight * (1 - self.LEARNING_RATE)
                adjustment = "↓"
            else:
                new_weight = current_weight  # Neutral, no change
                adjustment = "→"
            
            # Apply bounds
            new_weight = max(self.MIN_WEIGHT, min(self.MAX_WEIGHT, new_weight))
            
            # Only update if changed significantly
            if abs(new_weight - current_weight) > 0.05:
                self.weights[pattern] = round(new_weight, 2)
                updates_made += 1
                print(f"{Fore.WHITE}  {adjustment} {pattern}: {current_weight:.2f} → {new_weight:.2f} (success: {success_rate:.0%})")
        
        if updates_made > 0:
            self._save_weights()
            print(f"{Fore.LIGHTGREEN_EX}✓ Updated {updates_made} pattern weights{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}No significant weight changes needed{Fore.RESET}")
    
    def get_learning_status(self):
        """Get summary of current learning state"""
        return {
            'total_patterns_learned': len(self.weights),
            'weights': self.weights,
            'avg_weight': sum(self.weights.values()) / len(self.weights) if self.weights else 1.0
        }
    
    def display_learning_status(self):
        """Display current learning state"""
        if not self.weights:
            print(f"{Fore.YELLOW}No learned weights yet. System using default weights (1.0){Fore.RESET}")
            return
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*60}")
        print(f"{Fore.LIGHTCYAN_EX}LEARNED PATTERN WEIGHTS (Local Models)")
        print(f"{Fore.LIGHTCYAN_EX}{'='*60}")
        
        # Sort by weight (highest first)
        sorted_weights = sorted(self.weights.items(), key=lambda x: x[1], reverse=True)
        
        for pattern, weight in sorted_weights:
            if weight > 1.5:
                color = Fore.LIGHTGREEN_EX
                label = "High confidence"
            elif weight < 0.5:
                color = Fore.LIGHTRED_EX
                label = "Low confidence (often FP)"
            else:
                color = Fore.WHITE
                label = "Normal"
            
            print(f"{color}{pattern:30} {weight:5.2f}x  {Fore.LIGHTBLACK_EX}({label}){Fore.RESET}")
        
        print(f"{Fore.LIGHTCYAN_EX}{'='*60}\n")
    
    def reset_learning(self):
        """Reset all learned weights (for testing or recalibration)"""
        self.weights = {}
        if os.path.exists(self.weights_file):
            os.remove(self.weights_file)
        print(f"{Fore.LIGHTGREEN_EX}✓ Learning reset. All weights back to 1.0{Fore.RESET}")


# Global learning engine instance
_learning_engine = None

def get_learning_engine():
    """Get or create global learning engine instance"""
    global _learning_engine
    if _learning_engine is None:
        _learning_engine = LearningEngine()
    return _learning_engine

