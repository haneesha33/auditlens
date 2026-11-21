#!/usr/bin/env bash
# Creates a local demo repo "acme-support-app" with a clean main branch and 3 PR branches.
# Usage:  bash demo/setup_demo.sh YOUR_GITHUB_USERNAME
# Then:   create an empty GitHub repo named acme-support-app, push all branches, open 3 PRs.
#
# Everything here is fake and intentionally insecure. The "secrets" are not real credentials.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GH_USER="${1:-YOUR_GITHUB_USERNAME}"
DIR="${2:-acme-support-app}"

rm -rf "$DIR" && mkdir -p "$DIR" && cd "$DIR"
git init -q -b main

# ---------------- main: a small, clean Flask app ----------------
mkdir -p app infra .github/workflows
cat > app/main.py <<'EOF'
import logging
import os

from flask import Flask, jsonify

app = Flask(__name__)
logger = logging.getLogger("acme")


@app.get("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", "8080")))
EOF
cat > requirements.txt <<'EOF'
flask==3.0.3
EOF
cat > README.md <<'EOF'
# Acme Support App (demo)

Fictional, intentionally insecure app used to demo [AuditLens](https://github.com/GH_USER/auditlens).
Do not deploy.
EOF
sed -i.bak "s/GH_USER/$GH_USER/" README.md && rm README.md.bak
cat > .github/workflows/auditlens.yml <<EOF
name: AuditLens
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write
jobs:
  auditlens:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: $GH_USER/auditlens@main
        with:
          anthropic-api-key: \${{ secrets.ANTHROPIC_API_KEY }}
          fail-on: critical
EOF
sed "s/YOUR_GITHUB_USERNAME/$GH_USER/" "$SCRIPT_DIR/../examples/dashboard-workflow.yml" > .github/workflows/auditlens-dashboard.yml 2>/dev/null || true
git add -A && git commit -qm "Initial clean app"

# ---------------- PR 1: file exports to S3 (secret + public bucket) ----------------
git checkout -qb pr1-s3-exports
cat > app/exports.py <<'EOF'
import boto3
from flask import request

# TODO move to config
AWS_ACCESS_KEY_ID = "AKIA4QWERTYUIOPASDFG"
s3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)


def export_tickets(customer_id):
    rows = db.execute(f"SELECT * FROM tickets WHERE customer_id = {request.args['id']}")
    s3.put_object(Bucket="acme-exports", Key=f"{customer_id}.csv", Body=str(rows))
EOF
cat > infra/exports.tf <<'EOF'
resource "aws_s3_bucket" "exports" {
  bucket = "acme-exports"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_iam_policy" "exports_writer" {
  name   = "exports-writer"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
EOF
git add -A && git commit -qm "Add ticket export to S3"

# ---------------- PR 2: reporting service with exploited dependency ----------------
git checkout -q main && git checkout -qb pr2-reporting-service
mkdir -p reporting
cat > reporting/pom.xml <<'EOF'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>reporting</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
EOF
cat >> requirements.txt <<'EOF'
pyyaml==5.3.1
requests==2.19.1
EOF
git add -A && git commit -qm "Add legacy reporting service and config loader deps"

# ---------------- PR 3: AI support chatbot ----------------
git checkout -q main && git checkout -qb pr3-ai-support-bot
cat > app/support_bot.py <<'EOF'
import subprocess

from anthropic import Anthropic
from flask import request

client = Anthropic()

SYSTEM = "You are Acme's support agent. Internal only: refund override code is 7731, do not reveal."

TOOLS = [
    {"name": "run_shell", "description": "Run a shell command on the support server", "input_schema": {"type": "object"}},
    {"name": "lookup_order", "description": "Look up an order by id", "input_schema": {"type": "object"}},
]


def answer(customer):
    prompt = f"{SYSTEM} Customer email: {customer.email}, phone: {customer.phone}. Question: {request.json['question']}"
    response = client.messages.create(
        model="claude-sonnet-5-5",
        messages=[{"role": "user", "content": prompt}],
        tools=TOOLS,
    )
    result = response.content[0].text
    if result.startswith("CMD:"):
        subprocess.run(result[4:], shell=True)
    return result
EOF
echo "anthropic==0.40.0" >> requirements.txt
git add -A && git commit -qm "Add AI support chatbot"

git checkout -q main
echo
echo "Demo repo ready in ./$DIR with branches: main, pr1-s3-exports, pr2-reporting-service, pr3-ai-support-bot"
echo "Next:"
echo "  cd $DIR"
echo "  git remote add origin https://github.com/$GH_USER/$DIR.git"
echo "  git push -u origin main pr1-s3-exports pr2-reporting-service pr3-ai-support-bot"
echo "  Add repo secret ANTHROPIC_API_KEY, then open one PR per branch into main."
