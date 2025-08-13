#!/usr/bin/env python3
"""
Refinement Quality Tracker

Tracks and reports on how multiple refinement iterations improve semgrep rule quality.
Provides detailed analytics on score improvements, error reduction, and pattern evolution.
"""

import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

@dataclass
class IterationMetrics:
    """Metrics for a single iteration."""
    iteration: int
    score: float
    tp_rate: float
    tn_rate: float
    syntax_valid: bool
    validation_errors: List[str]
    false_positives: int
    false_negatives: int
    pattern_complexity: int  # Number of patterns in rule
    message_quality: str  # "generic", "descriptive", "educational"
    processing_time: float  # seconds
    
@dataclass
class RuleRefinementHistory:
    """Complete refinement history for a single rule."""
    vuln_id: str
    iterations: List[IterationMetrics]
    final_score: float
    improvement: float  # final_score - initial_score
    converged: bool  # Did score stop improving?
    
    def get_score_trend(self) -> List[float]:
        """Get list of scores across iterations."""
        return [iter.score for iter in self.iterations]
    
    def get_best_iteration(self) -> int:
        """Get iteration number with highest score."""
        best_score = max(iter.score for iter in self.iterations)
        return next(i for i, iter in enumerate(self.iterations) if iter.score == best_score)

@dataclass  
class BatchRefinementReport:
    """Comprehensive report for batch refinement process."""
    timestamp: str
    total_rules: int
    refinement_histories: List[RuleRefinementHistory]
    summary_stats: Dict[str, Any]
    
    def save_report(self, output_path: Path):
        """Save comprehensive report to JSON."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)

class RefinementQualityTracker:
    """Tracks refinement quality across multiple iterations."""
    
    def __init__(self, output_dir: str = "./refinement_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.histories: Dict[str, RuleRefinementHistory] = {}
        
    def record_iteration(self, vuln_id: str, iteration: int, metrics: Dict[str, Any]):
        """Record metrics for a single iteration."""
        iteration_metrics = IterationMetrics(
            iteration=iteration,
            score=metrics.get('score', 0.0),
            tp_rate=metrics.get('tp_rate', 0.0),
            tn_rate=metrics.get('tn_rate', 0.0),
            syntax_valid=metrics.get('syntax_valid', False),
            validation_errors=metrics.get('validation_errors', []),
            false_positives=metrics.get('false_positives', 0),
            false_negatives=metrics.get('false_negatives', 0),
            pattern_complexity=metrics.get('pattern_complexity', 0),
            message_quality=metrics.get('message_quality', 'generic'),
            processing_time=metrics.get('processing_time', 0.0)
        )
        
        if vuln_id not in self.histories:
            self.histories[vuln_id] = RuleRefinementHistory(
                vuln_id=vuln_id,
                iterations=[],
                final_score=0.0,
                improvement=0.0,
                converged=False
            )
        
        self.histories[vuln_id].iterations.append(iteration_metrics)
        
    def finalize_rule(self, vuln_id: str):
        """Finalize metrics for a completed rule."""
        if vuln_id not in self.histories:
            return
            
        history = self.histories[vuln_id]
        if not history.iterations:
            return
            
        history.final_score = history.iterations[-1].score
        history.improvement = history.final_score - history.iterations[0].score
        
        # Check if converged (last 2 iterations have similar scores)
        if len(history.iterations) >= 2:
            last_two = history.iterations[-2:]
            score_diff = abs(last_two[1].score - last_two[0].score)
            history.converged = score_diff < 0.05  # Less than 5% change
    
    def generate_comprehensive_report(self) -> BatchRefinementReport:
        """Generate comprehensive refinement quality report."""
        
        # Calculate summary statistics
        all_improvements = [h.improvement for h in self.histories.values() if h.iterations]
        all_final_scores = [h.final_score for h in self.histories.values() if h.iterations]
        
        multi_iteration_rules = [h for h in self.histories.values() if len(h.iterations) > 1]
        syntax_improvements = sum(1 for h in multi_iteration_rules 
                                if not h.iterations[0].syntax_valid and h.iterations[-1].syntax_valid)
        
        summary_stats = {
            "total_rules_processed": len(self.histories),
            "multi_iteration_rules": len(multi_iteration_rules),
            "average_improvement": np.mean(all_improvements) if all_improvements else 0,
            "median_improvement": np.median(all_improvements) if all_improvements else 0,
            "max_improvement": max(all_improvements) if all_improvements else 0,
            "rules_with_positive_improvement": sum(1 for imp in all_improvements if imp > 0),
            "rules_with_negative_improvement": sum(1 for imp in all_improvements if imp < 0),
            "average_final_score": np.mean(all_final_scores) if all_final_scores else 0,
            "high_quality_rules": sum(1 for score in all_final_scores if score >= 0.8),
            "syntax_error_fixes": syntax_improvements,
            "convergence_rate": sum(1 for h in multi_iteration_rules if h.converged) / len(multi_iteration_rules) if multi_iteration_rules else 0,
            "iteration_distribution": self._get_iteration_distribution(),
            "improvement_by_iteration": self._get_improvement_by_iteration(),
            "processing_time_analysis": self._get_processing_time_analysis()
        }
        
        return BatchRefinementReport(
            timestamp=datetime.now().isoformat(),
            total_rules=len(self.histories),
            refinement_histories=list(self.histories.values()),
            summary_stats=summary_stats
        )
    
    def _get_iteration_distribution(self) -> Dict[str, int]:
        """Get distribution of number of iterations per rule."""
        distribution = {}
        for history in self.histories.values():
            iter_count = len(history.iterations)
            distribution[f"{iter_count}_iterations"] = distribution.get(f"{iter_count}_iterations", 0) + 1
        return distribution
    
    def _get_improvement_by_iteration(self) -> Dict[str, float]:
        """Get average improvement at each iteration number."""
        improvements = {}
        for history in self.histories.values():
            if len(history.iterations) < 2:
                continue
            base_score = history.iterations[0].score
            for i, iteration in enumerate(history.iterations[1:], 1):
                iteration_key = f"iteration_{i}"
                improvement = iteration.score - base_score
                if iteration_key not in improvements:
                    improvements[iteration_key] = []
                improvements[iteration_key].append(improvement)
        
        return {k: np.mean(v) for k, v in improvements.items()}
    
    def _get_processing_time_analysis(self) -> Dict[str, float]:
        """Analyze processing time by iteration."""
        times_by_iteration = {}
        for history in self.histories.values():
            for iteration in history.iterations:
                iter_key = f"iteration_{iteration.iteration}"
                if iter_key not in times_by_iteration:
                    times_by_iteration[iter_key] = []
                times_by_iteration[iter_key].append(iteration.processing_time)
        
        return {k: {"mean": np.mean(v), "median": np.median(v), "max": max(v)} 
                for k, v in times_by_iteration.items()}
    
    def create_quality_visualizations(self, report: BatchRefinementReport):
        """Create quality improvement visualizations."""
        output_dir = self.output_dir / "visualizations"
        output_dir.mkdir(exist_ok=True)
        
        # 1. Score improvement distribution
        plt.figure(figsize=(12, 8))
        improvements = [h.improvement for h in report.refinement_histories if h.iterations]
        plt.hist(improvements, bins=30, alpha=0.7, edgecolor='black')
        plt.axvline(x=0, color='red', linestyle='--', label='No improvement')
        plt.xlabel('Score Improvement')
        plt.ylabel('Number of Rules')
        plt.title('Distribution of Score Improvements Across All Rules')
        plt.legend()
        plt.savefig(output_dir / "score_improvement_distribution.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Iteration convergence patterns
        plt.figure(figsize=(15, 10))
        multi_iter_histories = [h for h in report.refinement_histories if len(h.iterations) > 1]
        
        for i, history in enumerate(multi_iter_histories[:20]):  # Show first 20 for clarity
            scores = history.get_score_trend()
            iterations = list(range(1, len(scores) + 1))
            plt.plot(iterations, scores, marker='o', alpha=0.6, linewidth=1)
        
        plt.xlabel('Iteration Number')
        plt.ylabel('Rule Quality Score')
        plt.title('Rule Quality Score Evolution Across Iterations (First 20 Rules)')
        plt.grid(True, alpha=0.3)
        plt.savefig(output_dir / "iteration_convergence_patterns.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Quality metrics by iteration
        plt.figure(figsize=(12, 8))
        improvement_by_iter = report.summary_stats["improvement_by_iteration"]
        iterations = [int(k.split('_')[1]) for k in improvement_by_iter.keys()]
        improvements = list(improvement_by_iter.values())
        
        plt.bar(iterations, improvements, alpha=0.7)
        plt.xlabel('Iteration Number')
        plt.ylabel('Average Score Improvement')
        plt.title('Average Score Improvement by Iteration Number')
        plt.grid(True, alpha=0.3)
        plt.savefig(output_dir / "improvement_by_iteration.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # 4. Processing time analysis
        plt.figure(figsize=(12, 8))
        time_analysis = report.summary_stats["processing_time_analysis"]
        iterations = [int(k.split('_')[1]) for k in time_analysis.keys()]
        mean_times = [time_analysis[k]["mean"] for k in time_analysis.keys()]
        
        plt.bar(iterations, mean_times, alpha=0.7)
        plt.xlabel('Iteration Number')
        plt.ylabel('Average Processing Time (seconds)')
        plt.title('Processing Time by Iteration Number')
        plt.grid(True, alpha=0.3)
        plt.savefig(output_dir / "processing_time_by_iteration.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Visualizations saved to: {output_dir}")
    
    def print_summary_report(self, report: BatchRefinementReport):
        """Print a human-readable summary report."""
        stats = report.summary_stats
        
        print("\n" + "="*60)
        print("📊 REFINEMENT QUALITY REPORT")
        print("="*60)
        print(f"Generated: {report.timestamp}")
        print(f"Total Rules Processed: {stats['total_rules_processed']}")
        print(f"Multi-iteration Rules: {stats['multi_iteration_rules']}")
        
        print("\n🎯 QUALITY IMPROVEMENTS:")
        print(f"  Average Improvement: {stats['average_improvement']:.3f}")
        print(f"  Median Improvement: {stats['median_improvement']:.3f}")
        print(f"  Maximum Improvement: {stats['max_improvement']:.3f}")
        print(f"  Rules Improved: {stats['rules_with_positive_improvement']}")
        print(f"  Rules Degraded: {stats['rules_with_negative_improvement']}")
        
        print("\n📈 FINAL QUALITY METRICS:")
        print(f"  Average Final Score: {stats['average_final_score']:.3f}")
        print(f"  High Quality Rules (≥0.8): {stats['high_quality_rules']}")
        print(f"  Syntax Errors Fixed: {stats['syntax_error_fixes']}")
        print(f"  Convergence Rate: {stats['convergence_rate']:.1%}")
        
        print("\n⏱️ PROCESSING EFFICIENCY:")
        for iteration, times in stats['processing_time_analysis'].items():
            print(f"  {iteration}: {times['mean']:.1f}s avg, {times['median']:.1f}s median")
        
        print("\n📊 ITERATION DISTRIBUTION:")
        for iter_count, rule_count in stats['iteration_distribution'].items():
            print(f"  {iter_count}: {rule_count} rules")
        
        print("\n🔄 IMPROVEMENT BY ITERATION:")
        for iteration, improvement in stats['improvement_by_iteration'].items():
            print(f"  {iteration}: +{improvement:.3f} average improvement")

def main():
    parser = argparse.ArgumentParser(description='Analyze refinement quality trends')
    parser.add_argument('--input', required=True, help='Directory with refinement history JSON files')
    parser.add_argument('--output', default='./refinement_reports', help='Output directory for reports')
    parser.add_argument('--create-visualizations', action='store_true', help='Create quality visualizations')
    
    args = parser.parse_args()
    
    tracker = RefinementQualityTracker(args.output)
    
    # Load existing refinement histories (would be populated during batch processing)
    input_path = Path(args.input)
    for history_file in input_path.glob("*_refinement_history.json"):
        with open(history_file, 'r', encoding='utf-8') as f:
            history_data = json.load(f)
            # Parse and add to tracker
            # Implementation depends on your data format
    
    # Generate comprehensive report
    report = tracker.generate_comprehensive_report()
    
    # Save report
    report_path = tracker.output_dir / f"refinement_quality_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report.save_report(report_path)
    
    # Print summary
    tracker.print_summary_report(report)
    
    # Create visualizations if requested
    if args.create_visualizations:
        tracker.create_quality_visualizations(report)
    
    print(f"\n📄 Full report saved to: {report_path}")

if __name__ == "__main__":
    main()