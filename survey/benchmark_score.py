"""Score the SQL injection rule against the OWASP Benchmark answer key.

Usage: python3 survey/benchmark_score.py <scan-output.txt> <expectedresults.csv>

The benchmark marks every test case as a real vulnerability or a safe look-alike.
A test case counts as "flagged" if the scanner reported SQL_INJECTION_RISK in its file.
"""
import csv
import re
import sys

scan_path, key_path = sys.argv[1], sys.argv[2]

flagged = set()
for line in open(scan_path, encoding="utf-8", errors="replace"):
    if "[SQL_INJECTION_RISK]" in line:
        match = re.search(r"(BenchmarkTest\d+)\.java", line)
        if match:
            flagged.add(match.group(1))

tp = fp = fn = tn = 0
with open(key_path, newline="", encoding="utf-8") as f:
    for row in csv.reader(f):
        if not row or row[0].startswith("#") or len(row) < 3:
            continue
        name, category, real = row[0].strip(), row[1].strip(), row[2].strip().lower() == "true"
        if category != "sqli":
            continue
        hit = name in flagged
        if real and hit:
            tp += 1
        elif real:
            fn += 1
        elif hit:
            fp += 1
        else:
            tn += 1

total_real, total_safe = tp + fn, fp + tn
if total_real == 0 or total_safe == 0:
    print("No sqli test cases found in the answer key.")
    sys.exit(1)

tpr = tp / total_real
fpr = fp / total_safe
precision = tp / (tp + fp) if tp + fp else 0.0

print("### OWASP Benchmark: SQL injection rule")
print()
print("| Measure | Result |")
print("| :--- | ---: |")
print(f"| Real SQL injections in the benchmark | {total_real} |")
print(f"| Caught (true positives) | {tp} |")
print(f"| Missed (false negatives) | {fn} |")
print(f"| Safe look-alikes in the benchmark | {total_safe} |")
print(f"| Wrongly flagged (false positives) | {fp} |")
print(f"| Correctly left alone (true negatives) | {tn} |")
print(f"| Detection rate (TPR) | {tpr:.1%} |")
print(f"| False alarm rate (FPR) | {fpr:.1%} |")
print(f"| Precision | {precision:.1%} |")
print(f"| Benchmark score (TPR - FPR) | {tpr - fpr:+.1%} |")
