# ============================================================
# IAM SETUP GUIDE — What your users need to do in AWS Console
# ============================================================
# 
# Your app calls GET /aws/setup/ to get the user's unique external_id.
# The user then creates this role in their own AWS account.
# ============================================================

# ── TRUST POLICY (paste into IAM role's Trust Relationships tab) ──
# Replace YOUR_APP_AWS_ACCOUNT_ID with your app's AWS account ID

TRUST_POLICY = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_APP_AWS_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "<USERS_UNIQUE_EXTERNAL_ID>"
        }
      }
    }
  ]
}
"""

# ── PERMISSIONS POLICY (attach to the role) ──
# Minimum permissions needed for cost analytics

PERMISSIONS_POLICY = """
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "ce:GetCostForecast",
        "ce:GetAnomalies",
        "ce:GetAnomalyMonitors",
        "ce:GetDimensionValues",
        "ce:GetTags",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
"""

# ── FULL CONNECTION FLOW ──
"""
Frontend Flow:
─────────────
1. User clicks "Connect AWS Account"

2. Frontend → GET /api/aws/setup/
   ← Gets external_id + step-by-step instructions

3. Show the user the instructions to create the IAM role in their AWS console.
   Display their unique external_id prominently.

4. User creates the role in their AWS console, copies the Role ARN.

5. User pastes Role ARN into your frontend form.

6. Frontend → POST /api/aws/connect/  { "role_arn": "arn:aws:iam::...", "account_alias": "Prod" }
   ← App verifies the role works immediately via STS
   ← Returns { "status": "connected", "account_id": "..." }

7. Frontend → POST /api/aws/accounts/<id>/sync/
   ← Pulls 30 days of cost data, caches it, detects anomalies

8. Frontend → GET /api/aws/accounts/<id>/dashboard/
   ← Returns all data needed for your AWSCostDashboard component

Ongoing:
────────
- Call /sync/ once per day (cron job or on page load if last_synced_at > 1hr ago)
- All dashboard reads hit the local DB (fast, no AWS API latency)
"""