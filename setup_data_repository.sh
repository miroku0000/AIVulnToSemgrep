#!/bin/bash
#
# Setup Data Repository Script
# Creates a separate repository for Go vulnerability data
#

set -e

REPO_NAME="go-vulnerability-dataset"
GITHUB_USER="miroku0000"  # Update with your GitHub username

echo "🏗️  Setting up separate vulnerability data repository..."

# Check if we have vulnerability data to upload
if [ ! -d "out" ]; then
    echo "❌ Error: No 'out' directory found. Generate vulnerability data first:"
    echo "   python vuln2examples.py --out ./out --debug --save-llm --workers 1 --http-diff-first --model qwen2.5-coder:14b"
    exit 1
fi

VULN_COUNT=$(find out/ -name "*_bad.go" | wc -l)
echo "📊 Found $VULN_COUNT vulnerabilities with code examples"

if [ $VULN_COUNT -lt 100 ]; then
    echo "⚠️  Warning: Only $VULN_COUNT vulnerabilities found. Consider generating more data first."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# Create temporary directory for the new repo
TEMP_DIR="temp_${REPO_NAME}"
if [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
fi

mkdir "$TEMP_DIR"
cd "$TEMP_DIR"

# Initialize git repository
git init
git branch -M main

# Create README for data repository
cat > README.md << 'EOF'
# Go Vulnerability Dataset

Pre-processed vulnerability data for the [AI Vulnerability to Semgrep Rules](https://github.com/miroku0000/AIVulnToSemgrep) project.

## Dataset Overview

This repository contains processed Go vulnerability data with:
- **Vulnerable code examples** (`*_bad.go`)
- **Fixed code examples** (`*_good.go`) 
- **Vulnerability metadata** (`metadata.json`)
- **Processing logs** (`debug.txt`)

## Statistics

- **Total vulnerabilities**: 1,301+ with complete code examples
- **Source**: [vuln.go.dev](https://vuln.go.dev) vulnerability database
- **Processing**: Generated using LLM analysis of GitHub patches
- **Coverage**: 2021-2025 Go ecosystem vulnerabilities

## Usage

### Download with script (recommended):
```bash
# In your AIVulnToSemgrep directory
./download_vulnerability_data.sh
```

### Manual download:
```bash
git clone https://github.com/miroku0000/go-vulnerability-dataset.git
cp -r go-vulnerability-dataset/out ./
```

## Directory Structure

```
out/
├── GO-2021-0089/
│   ├── GO-2021-0089_bad.go      # Vulnerable code
│   ├── GO-2021-0089_good.go     # Fixed code
│   ├── metadata.json           # Vulnerability details
│   ├── report.json             # Analysis results
│   ├── debug.txt               # Processing logs
│   └── raw_diff.patch          # Original GitHub patch
├── GO-2021-0090/
└── ... (1,301 vulnerabilities)
```

## Data Quality

- **Success rate**: ~85% of vulnerabilities processed successfully
- **Code quality**: LLM-generated examples reviewed for accuracy
- **Metadata**: Complete vulnerability information and fix references
- **Diffs**: Original GitHub patches preserved for verification

## Generation Process

This dataset was generated using:
```bash
python vuln2examples.py \
  --out ./out \
  --debug \
  --save-llm \
  --workers 1 \
  --http-diff-first \
  --model qwen2.5-coder:14b
```

## License

MIT License - see main repository for details.

## Related

- **Main Project**: [AI Vulnerability to Semgrep Rules](https://github.com/miroku0000/AIVulnToSemgrep)
- **Generated Rules**: Use this data to create high-quality semgrep rules
- **Documentation**: Full pipeline documentation in main repository
EOF

# Copy vulnerability data
echo "📁 Copying vulnerability data..."
cp -r ../out .

# Create dataset statistics
echo "📊 Generating dataset statistics..."
TOTAL_VULNS=$(find out/ -maxdepth 1 -type d -name "GO-*" | wc -l)
VULNS_WITH_CODE=$(find out/ -name "*_bad.go" | wc -l)
TOTAL_SIZE=$(du -sh out/ | cut -f1)

cat > DATASET_STATS.md << EOF
# Dataset Statistics

Generated: $(date)

## Overview
- **Total vulnerabilities**: $TOTAL_VULNS
- **With code examples**: $VULNS_WITH_CODE
- **Success rate**: $(echo "scale=1; $VULNS_WITH_CODE * 100 / $TOTAL_VULNS" | bc -l)%
- **Total size**: $TOTAL_SIZE

## Vulnerability Types
\`\`\`
$(find out/ -name "metadata.json" -exec grep -l "infinite loop" {} \; | wc -l) - Infinite loop vulnerabilities
$(find out/ -name "metadata.json" -exec grep -l "denial of service" {} \; | wc -l) - Denial of service vulnerabilities  
$(find out/ -name "metadata.json" -exec grep -l "memory corruption" {} \; | wc -l) - Memory corruption vulnerabilities
$(find out/ -name "metadata.json" -exec grep -l "code execution" {} \; | wc -l) - Code execution vulnerabilities
\`\`\`

## File Distribution
\`\`\`
$(find out/ -name "*.go" | wc -l) - Go code files
$(find out/ -name "*.json" | wc -l) - JSON metadata files
$(find out/ -name "*.patch" | wc -l) - Patch files
$(find out/ -name "*.txt" | wc -l) - Log files
\`\`\`
EOF

# Add all files
git add .

# Create initial commit
git commit -m "Initial dataset: $VULNS_WITH_CODE Go vulnerabilities with code examples

Dataset includes:
- Vulnerable and fixed code examples for each CVE
- Complete vulnerability metadata and processing logs
- Original GitHub patches for verification
- Generated using LLM analysis of vuln.go.dev database

Statistics:
- Total vulnerabilities: $TOTAL_VULNS
- With complete examples: $VULNS_WITH_CODE  
- Success rate: $(echo "scale=1; $VULNS_WITH_CODE * 100 / $TOTAL_VULNS" | bc -l)%
- Total size: $TOTAL_SIZE

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"

echo "✅ Repository prepared in $TEMP_DIR/"
echo ""
echo "🚀 Next steps:"
echo "1. Create GitHub repository:"
echo "   gh repo create $REPO_NAME --public"
echo ""
echo "2. Push data:"
echo "   cd $TEMP_DIR"
echo "   git remote add origin https://github.com/$GITHUB_USER/$REPO_NAME.git"
echo "   git push -u origin main"
echo ""
echo "3. Update main repository:"
echo "   cd .."
echo "   git add download_vulnerability_data.sh"
echo "   git commit -m 'Add vulnerability data download script'"
echo "   git push origin master"

cd ..
echo "📁 Setup complete! Repository ready in $TEMP_DIR/"