#!/usr/bin/env python3
"""
Refine Existing Rules

Re-runs refinement iterations on existing rules to improve quality.
Provides detailed before/after quality comparison.
"""

import argparse
import json
import time
from pathlib import Path
from integrated_batch_generator import generate_refined_rule
from refinement_quality_tracker import RefinementQualityTracker

def main():
    parser = argparse.ArgumentParser(description='Refine existing semgrep rules with additional iterations')
    parser.add_argument('--input', default='./out', help='Input directory with vulnerability data')
    parser.add_argument('--rules', default='./refined_batch_rules', help='Directory with existing rules')
    parser.add_argument('--output', default='./re_refined_rules', help='Output directory for improved rules')
    parser.add_argument('--model', default='gemma3:4b', help='Model to use')
    parser.add_argument('--max-iterations', type=int, default=3, help='Maximum refinement iterations')
    parser.add_argument('--min-score', type=float, default=0.7, help='Only refine rules below this score')
    parser.add_argument('--limit', type=int, help='Limit number of rules to refine')
    parser.add_argument('--create-visualizations', action='store_true', help='Create before/after visualizations')
    
    args = parser.parse_args()
    
    # Create output directory
    Path(args.output).mkdir(exist_ok=True)
    
    # Initialize quality tracker
    quality_tracker = RefinementQualityTracker("./re_refinement_reports")
    
    # Find existing rules to refine
    rules_dir = Path(args.rules)
    existing_rules = list(rules_dir.glob("GO-*.yml"))
    
    if args.limit:
        existing_rules = existing_rules[:args.limit]
    
    print(f"Found {len(existing_rules)} existing rules to potentially refine")
    
    refined_count = 0
    improved_count = 0
    total_improvement = 0
    
    for rule_file in existing_rules:
        vuln_id = rule_file.stem
        print(f"\nAnalyzing {vuln_id}...")
        
        # Check if we have vulnerability data
        vuln_dir = Path(args.input) / vuln_id
        if not vuln_dir.exists():
            print(f"  No vulnerability data found - skipping")
            continue
        
        # Read existing rule to get baseline score (simulate original generation)
        print(f"  Generating baseline score...")
        baseline_rule, baseline_score = generate_refined_rule(
            vuln_id, args.input, args.model, max_iterations=1, quality_tracker=quality_tracker
        )
        
        if baseline_score is None or baseline_score >= args.min_score:
            print(f"  Baseline score {baseline_score:.2f} meets threshold - skipping")
            continue
        
        print(f"  Baseline score: {baseline_score:.2f} - attempting refinement...")
        
        # Generate refined rule with more iterations
        start_time = time.time()
        refined_rule, refined_score = generate_refined_rule(
            vuln_id, args.input, args.model, max_iterations=args.max_iterations, quality_tracker=quality_tracker
        )
        refinement_time = time.time() - start_time
        
        if refined_rule and refined_score is not None:
            improvement = refined_score - baseline_score
            
            # Save refined rule if it's better
            if improvement > 0:
                output_file = Path(args.output) / f"{vuln_id}.yml"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(refined_rule)
                
                print(f"  IMPROVED: {baseline_score:.2f} → {refined_score:.2f} (+{improvement:.3f}) in {refinement_time:.1f}s")
                improved_count += 1
                total_improvement += improvement
            else:
                print(f"  NO IMPROVEMENT: {baseline_score:.2f} → {refined_score:.2f} ({improvement:.3f})")
            
            refined_count += 1
        else:
            print(f"  FAILED to generate refined rule")
    
    # Generate quality comparison report
    print(f"\n" + "="*60)
    print(f"📊 REFINEMENT RESULTS")
    print(f"="*60)
    print(f"Rules Analyzed: {len(existing_rules)}")
    print(f"Rules Refined: {refined_count}")
    print(f"Rules Improved: {improved_count}")
    if improved_count > 0:
        print(f"Average Improvement: +{total_improvement / improved_count:.3f}")
        print(f"Total Improvement: +{total_improvement:.3f}")
    
    # Generate comprehensive quality report
    report = quality_tracker.generate_comprehensive_report()
    quality_tracker.print_summary_report(report)
    
    # Save detailed report
    report_path = Path("./re_refinement_reports") / f"re_refinement_report_{refined_count}_rules.json"
    report.save_report(report_path)
    print(f"\nDetailed report saved to: {report_path}")
    
    # Create visualizations if requested
    if args.create_visualizations:
        quality_tracker.create_quality_visualizations(report)

if __name__ == "__main__":
    main()