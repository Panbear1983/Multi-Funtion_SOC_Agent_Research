"""
Feedback Manager - Iterative Learning System for SOC Analysis
Collects user ratings and improves threat detection over time
"""
import json
import os
from datetime import datetime
from color_support import Fore, Style

class FeedbackManager:
    def __init__(self, feedback_file="_analysis_feedback.jsonl"):
        self.feedback_file = feedback_file
        self.current_session = {
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'user_rating': None,
            'user_comments': None
        }
    
    def record_finding(self, finding):
        """Record a finding for this session (excludes INVESTIGATIVE CONCLUSION)"""
        self.current_session['findings'].append(finding)
    
    def prompt_user_feedback(self):
        """Ask user to rate the analysis quality"""
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*60}")
        print(f"{Fore.LIGHTCYAN_EX}FEEDBACK REQUEST")
        print(f"{Fore.LIGHTCYAN_EX}{'='*60}")
        print(f"{Fore.WHITE}Rate this analysis call: 1-5 (1=Poor, 5=Excellent)")
        print(f"{Fore.YELLOW}Your rating helps improve future detections.{Fore.RESET}")
        
        # Get rating
        while True:
            try:
                rating_input = input(f"{Fore.LIGHTGREEN_EX}Rating (1-5): {Fore.RESET}").strip()
                if not rating_input:
                    print(f"{Fore.YELLOW}Skipping feedback...{Fore.RESET}")
                    return None
                rating = int(rating_input)
                if 1 <= rating <= 5:
                    break
                print(f"{Fore.RED}Please enter a number between 1 and 5.{Fore.RESET}")
            except ValueError:
                print(f"{Fore.RED}Invalid input. Enter a number 1-5 or press Enter to skip.{Fore.RESET}")
        
        self.current_session['user_rating'] = rating
        
        # Get comments
        print(f"{Fore.WHITE}Any comments? (press Enter to skip)")
        comments = input(f"{Fore.LIGHTGREEN_EX}Comments: {Fore.RESET}").strip()
        if comments:
            self.current_session['user_comments'] = comments
        
        # Save to file
        self._save_feedback()
        
        # Provide encouragement based on rating
        if rating >= 4:
            print(f"{Fore.LIGHTGREEN_EX}✓ Thanks! High-confidence patterns logged.{Fore.RESET}")
        elif rating == 3:
            print(f"{Fore.LIGHTYELLOW_EX}→ Noted. Will adjust detection sensitivity.{Fore.RESET}")
        else:
            print(f"{Fore.LIGHTRED_EX}! Low rating logged. Tuning detection rules...{Fore.RESET}")
        
        return rating
    
    def _save_feedback(self):
        """Append feedback to JSONL file"""
        with open(self.feedback_file, 'a', encoding='utf-8') as f:
            json_line = json.dumps(self.current_session, ensure_ascii=False)
            f.write(json_line + '\n')
        
        print(f"{Fore.LIGHTBLUE_EX}Feedback logged to {self.feedback_file}{Fore.RESET}\n")
    
    def load_previous_feedback(self, limit=20):
        """Load recent feedback to inform current analysis"""
        if not os.path.exists(self.feedback_file):
            return []
        
        feedback_records = []
        try:
            with open(self.feedback_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        feedback_records.append(json.loads(line))
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not load feedback history: {e}{Fore.RESET}")
            return []
        
        # Return most recent records
        return feedback_records[-limit:]
    
    def get_learning_summary(self):
        """Analyze past feedback to improve detection"""
        records = self.load_previous_feedback()
        
        if not records:
            return {
                'total_sessions': 0,
                'avg_rating': 0,
                'improvement_needed': []
            }
        
        # Calculate statistics
        ratings = [r['user_rating'] for r in records if r.get('user_rating')]
        avg_rating = sum(ratings) / len(ratings) if ratings else 0
        
        # Identify patterns in low-rated sessions
        low_rated = [r for r in records if r.get('user_rating', 0) < 3]
        improvement_areas = []
        
        for session in low_rated:
            if session.get('user_comments'):
                improvement_areas.append(session['user_comments'])
        
        return {
            'total_sessions': len(records),
            'avg_rating': round(avg_rating, 2),
            'recent_ratings': ratings[-5:],
            'improvement_needed': improvement_areas[-3:],  # Last 3 complaints
            'low_rated_count': len(low_rated)
        }
    
    def display_learning_summary(self):
        """Show performance trends to user"""
        summary = self.get_learning_summary()
        
        if summary['total_sessions'] == 0:
            print(f"{Fore.YELLOW}No previous feedback found. This is your first session.{Fore.RESET}")
            return
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*50}")
        print(f"{Fore.LIGHTCYAN_EX}LEARNING HISTORY")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*50}")
        print(f"{Fore.WHITE}Total Sessions: {summary['total_sessions']}")
        print(f"{Fore.WHITE}Average Rating: {summary['avg_rating']}/5.0")
        
        if summary['recent_ratings']:
            trend = "📈" if summary['recent_ratings'][-1] > summary['avg_rating'] else "📉"
            print(f"{Fore.WHITE}Recent Trend: {' → '.join(map(str, summary['recent_ratings']))} {trend}")
        
        if summary['improvement_needed']:
            print(f"\n{Fore.LIGHTYELLOW_EX}Learning from past feedback:")
            for note in summary['improvement_needed']:
                print(f"{Fore.WHITE}  • {note}")
        
        print(f"{Fore.LIGHTCYAN_EX}{'─'*50}\n")
    
    def should_escalate_to_human(self, confidence_level, avg_confidence_score):
        """Determine if human review needed based on confidence and past performance"""
        summary = self.get_learning_summary()
        
        # Convert confidence to score
        confidence_map = {'Low': 3, 'Medium': 5, 'High': 8}
        
        # If average rating is low (< 3), require human check more often
        if summary['avg_rating'] < 3 and summary['total_sessions'] > 5:
            threshold = 8
        else:
            threshold = 7
        
        if avg_confidence_score < threshold:
            return True, f"Confidence {avg_confidence_score}/10 below threshold {threshold}"
        
        return False, "Automated analysis sufficient"
    
    def get_tuning_recommendations(self):
        """Analyze feedback to suggest rule adjustments"""
        records = self.load_previous_feedback(limit=50)
        
        recommendations = []
        
        # Count pattern categories in low vs high rated sessions
        high_rated = [r for r in records if r.get('user_rating', 0) >= 4]
        low_rated = [r for r in records if r.get('user_rating', 0) <= 2]
        
        # Extract pattern categories from findings
        high_patterns = {}
        low_patterns = {}
        
        for session in high_rated:
            for finding in session.get('findings', []):
                for tag in finding.get('tags', []):
                    high_patterns[tag] = high_patterns.get(tag, 0) + 1
        
        for session in low_rated:
            for finding in session.get('findings', []):
                for tag in finding.get('tags', []):
                    low_patterns[tag] = low_patterns.get(tag, 0) + 1
        
        # Patterns that appear more in low-rated sessions should be deprioritized
        for pattern, count in low_patterns.items():
            if count > high_patterns.get(pattern, 0):
                recommendations.append(f"Reduce sensitivity for '{pattern}' (appears in low-rated sessions)")
        
        # Patterns that appear more in high-rated sessions should be prioritized
        for pattern, count in high_patterns.items():
            if count > low_patterns.get(pattern, 0) and count >= 3:
                recommendations.append(f"Increase priority for '{pattern}' (user finds valuable)")
        
        return recommendations[:5]  # Top 5 recommendations
