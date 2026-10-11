#!/bin/bash
# =============================================================================
# IAM Identity Containment Script
# =============================================================================
# When an IAM user or role is suspected compromised, this script:
#   1. Auto-detects whether the target is an IAM user or role
#   2. Captures the current state (policies, keys, groups, trust)
#   3. Deactivates all access keys (users only)
#   4. Removes console access (users only)
#   5. Attaches an explicit deny-all inline policy
#   6. Revokes all active sessions (invalidates existing tokens)
#   7. Detaches from instance profiles (roles only)
#   8. Outputs a JSON containment report
#
# Usage: ./quarantine-iam-identity.sh <iam-user-or-role-name>
# =============================================================================

set -euo pipefail

# --- Input validation ---
if [ -z "${1:-}" ]; then
  echo "Usage: $0 <iam-user-or-role-name>"
  echo "  Accepts an IAM user name or role name."
  echo "  The script auto-detects which type it is."
  exit 1
fi

IDENTITY_NAME="$1"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
POLICY_NAME="Containment-DenyAll-$(date -u +%Y%m%d%H%M%S)"
IDENTITY_TYPE=""

echo "============================================"
echo "  IAM Identity Containment"
echo "============================================"
echo "[*] Target:     $IDENTITY_NAME"
echo "[*] Timestamp:  $TIMESTAMP"
echo "============================================"

# --- Step 1: Auto-detect identity type ---
echo ""
echo "[1/7] Detecting identity type..."

# Try user first
if aws iam get-user --user-name "$IDENTITY_NAME" &>/dev/null; then
  IDENTITY_TYPE="user"
  USER_ARN=$(aws iam get-user --user-name "$IDENTITY_NAME" --query 'User.Arn' --output text)
  echo "      Detected: IAM User"
  echo "      ARN: $USER_ARN"
elif aws iam get-role --role-name "$IDENTITY_NAME" &>/dev/null; then
  IDENTITY_TYPE="role"
  ROLE_ARN=$(aws iam get-role --role-name "$IDENTITY_NAME" --query 'Role.Arn' --output text)
  echo "      Detected: IAM Role"
  echo "      ARN: $ROLE_ARN"
else
  echo "[!] '$IDENTITY_NAME' is not a valid IAM user or role."
  exit 1
fi

# --- Step 2: Capture current state ---
echo ""
echo "[2/7] Capturing current state..."

if [ "$IDENTITY_TYPE" == "user" ]; then
  # List access keys
  ACCESS_KEYS=$(aws iam list-access-keys --user-name "$IDENTITY_NAME" \
    --query 'AccessKeyMetadata[*].[AccessKeyId,Status]' --output text)
  echo "      Access keys:"
  if [ -n "$ACCESS_KEYS" ]; then
    echo "$ACCESS_KEYS" | while read -r KEY_ID STATUS; do
      echo "        $KEY_ID ($STATUS)"
    done
  else
    echo "        (none)"
  fi

  # List attached policies
  ATTACHED_POLICIES=$(aws iam list-attached-user-policies --user-name "$IDENTITY_NAME" \
    --query 'AttachedPolicies[*].PolicyArn' --output text)
  echo "      Attached policies:"
  if [ -n "$ATTACHED_POLICIES" ] && [ "$ATTACHED_POLICIES" != "None" ]; then
    for POLICY in $ATTACHED_POLICIES; do
      echo "        $POLICY"
    done
  else
    echo "        (none)"
  fi

  # List inline policies
  INLINE_POLICIES=$(aws iam list-user-policies --user-name "$IDENTITY_NAME" \
    --query 'PolicyNames' --output text)
  echo "      Inline policies:"
  if [ -n "$INLINE_POLICIES" ] && [ "$INLINE_POLICIES" != "None" ]; then
    echo "        $INLINE_POLICIES"
  else
    echo "        (none)"
  fi

  # List group memberships
  GROUPS=$(aws iam list-groups-for-user --user-name "$IDENTITY_NAME" \
    --query 'Groups[*].GroupName' --output text)
  echo "      Groups:"
  if [ -n "$GROUPS" ] && [ "$GROUPS" != "None" ]; then
    echo "        $GROUPS"
  else
    echo "        (none)"
  fi

  # Check for login profile (console access)
  HAS_LOGIN_PROFILE="false"
  if aws iam get-login-profile --user-name "$IDENTITY_NAME" &>/dev/null; then
    HAS_LOGIN_PROFILE="true"
    echo "      Console access: ENABLED"
  else
    echo "      Console access: disabled"
  fi

  # Check MFA devices
  MFA_DEVICES=$(aws iam list-mfa-devices --user-name "$IDENTITY_NAME" \
    --query 'MFADevices[*].SerialNumber' --output text)
  echo "      MFA devices:"
  if [ -n "$MFA_DEVICES" ] && [ "$MFA_DEVICES" != "None" ]; then
    echo "        $MFA_DEVICES"
  else
    echo "        (none)"
  fi

else
  # Role: list attached policies
  ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name "$IDENTITY_NAME" \
    --query 'AttachedPolicies[*].PolicyArn' --output text)
  echo "      Attached policies:"
  if [ -n "$ATTACHED_POLICIES" ] && [ "$ATTACHED_POLICIES" != "None" ]; then
    for POLICY in $ATTACHED_POLICIES; do
      echo "        $POLICY"
    done
  else
    echo "        (none)"
  fi

  # List inline policies
  INLINE_POLICIES=$(aws iam list-role-policies --role-name "$IDENTITY_NAME" \
    --query 'PolicyNames' --output text)
  echo "      Inline policies:"
  if [ -n "$INLINE_POLICIES" ] && [ "$INLINE_POLICIES" != "None" ]; then
    echo "        $INLINE_POLICIES"
  else
    echo "        (none)"
  fi

  # Trust policy
  TRUST_POLICY=$(aws iam get-role --role-name "$IDENTITY_NAME" \
    --query 'Role.AssumeRolePolicyDocument' --output json)
  echo "      Trust policy: captured"

  # Instance profiles
  INSTANCE_PROFILES=$(aws iam list-instance-profiles-for-role --role-name "$IDENTITY_NAME" \
    --query 'InstanceProfiles[*].InstanceProfileName' --output text)
  echo "      Instance profiles:"
  if [ -n "$INSTANCE_PROFILES" ] && [ "$INSTANCE_PROFILES" != "None" ]; then
    echo "        $INSTANCE_PROFILES"
  else
    echo "        (none)"
  fi
fi

# --- Step 3: Deactivate access keys (users only) ---
echo ""
echo "[3/7] Deactivating access keys..."

DEACTIVATED_KEYS=""
if [ "$IDENTITY_TYPE" == "user" ]; then
  KEY_IDS=$(aws iam list-access-keys --user-name "$IDENTITY_NAME" \
    --query 'AccessKeyMetadata[*].AccessKeyId' --output text)

  if [ -n "$KEY_IDS" ] && [ "$KEY_IDS" != "None" ]; then
    for KEY_ID in $KEY_IDS; do
      aws iam update-access-key \
        --user-name "$IDENTITY_NAME" \
        --access-key-id "$KEY_ID" \
        --status Inactive
      echo "      Deactivated: $KEY_ID"
      DEACTIVATED_KEYS="${DEACTIVATED_KEYS}${KEY_ID} "
    done
  else
    echo "      No access keys to deactivate"
  fi
else
  echo "      Skipped (not applicable to roles)"
fi

# --- Step 4: Remove console access (users only) ---
echo ""
echo "[4/7] Removing console access..."

if [ "$IDENTITY_TYPE" == "user" ]; then
  if [ "$HAS_LOGIN_PROFILE" == "true" ]; then
    aws iam delete-login-profile --user-name "$IDENTITY_NAME"
    echo "      Login profile deleted (console access revoked)"
  else
    echo "      No login profile to remove"
  fi
else
  echo "      Skipped (not applicable to roles)"
fi

# --- Step 5: Attach deny-all inline policy ---
echo ""
echo "[5/7] Attaching deny-all inline policy..."

DENY_ALL_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ContainmentDenyAll",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }
  ]
}'

if [ "$IDENTITY_TYPE" == "user" ]; then
  aws iam put-user-policy \
    --user-name "$IDENTITY_NAME" \
    --policy-name "$POLICY_NAME" \
    --policy-document "$DENY_ALL_POLICY"
else
  aws iam put-role-policy \
    --role-name "$IDENTITY_NAME" \
    --policy-name "$POLICY_NAME" \
    --policy-document "$DENY_ALL_POLICY"
fi

echo "      Attached: $POLICY_NAME"
echo "      Effect: explicit Deny on all actions/resources"

# --- Step 6: Revoke active sessions ---
echo ""
echo "[6/7] Revoking all active sessions..."

# This policy denies all actions for tokens issued before right now.
# STS tokens already handed out become useless.
#
# Why this exists alongside deny-all: during un-containment, you remove
# the deny-all first but keep this policy so any pre-compromise STS
# tokens that are still valid remain blocked.
#
# Note: aws:TokenIssueTime only applies to temporary credentials (STS).
# For IAM users with long-term access keys, step 3 (key deactivation)
# is what blocks direct API access.
REVOKE_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RevokeOlderSessions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "TIMESTAMP_PLACEHOLDER"
        }
      }
    }
  ]
}'

# Replace placeholder with current timestamp
REVOKE_POLICY=$(echo "$REVOKE_POLICY" | sed "s/TIMESTAMP_PLACEHOLDER/$TIMESTAMP/")
REVOKE_POLICY_NAME="RevokeOlderSessions-$(date -u +%Y%m%d%H%M%S)"

if [ "$IDENTITY_TYPE" == "user" ]; then
  aws iam put-user-policy \
    --user-name "$IDENTITY_NAME" \
    --policy-name "$REVOKE_POLICY_NAME" \
    --policy-document "$REVOKE_POLICY"
else
  aws iam put-role-policy \
    --role-name "$IDENTITY_NAME" \
    --policy-name "$REVOKE_POLICY_NAME" \
    --policy-document "$REVOKE_POLICY"
fi

echo "      Attached: $REVOKE_POLICY_NAME"
echo "      All sessions issued before $TIMESTAMP are now denied"

# --- Step 7: Detach from instance profiles (roles only) ---
echo ""
echo "[7/7] Detaching from instance profiles..."

DETACHED_PROFILES=""
if [ "$IDENTITY_TYPE" == "role" ]; then
  PROFILE_NAMES=$(aws iam list-instance-profiles-for-role --role-name "$IDENTITY_NAME" \
    --query 'InstanceProfiles[*].InstanceProfileName' --output text)

  if [ -n "$PROFILE_NAMES" ] && [ "$PROFILE_NAMES" != "None" ]; then
    for PROFILE in $PROFILE_NAMES; do
      aws iam remove-role-from-instance-profile \
        --instance-profile-name "$PROFILE" \
        --role-name "$IDENTITY_NAME"
      echo "      Detached from: $PROFILE"
      DETACHED_PROFILES="${DETACHED_PROFILES}${PROFILE} "
    done
  else
    echo "      No instance profiles attached"
  fi
else
  echo "      Skipped (not applicable to users)"
fi

# --- Generate containment report ---
echo ""
echo "[*] Generating containment report..."

REPORT_FILE="containment-report-${IDENTITY_NAME}-$(date -u +%Y%m%d%H%M%S).json"

if [ "$IDENTITY_TYPE" == "user" ]; then
  cat > "$REPORT_FILE" <<REPORT
{
  "identity_name": "$IDENTITY_NAME",
  "identity_type": "user",
  "identity_arn": "$USER_ARN",
  "contained_at": "$TIMESTAMP",
  "actions_taken": {
    "access_keys_deactivated": "$(echo $DEACTIVATED_KEYS | xargs | tr ' ' ',')",
    "console_access_revoked": $HAS_LOGIN_PROFILE,
    "deny_all_policy": "$POLICY_NAME",
    "session_revocation_policy": "$REVOKE_POLICY_NAME",
    "groups_at_capture": "$(echo $GROUPS | xargs | tr ' ' ',')",
    "attached_policies_at_capture": "$(echo $ATTACHED_POLICIES | xargs | tr ' ' ',')"
  }
}
REPORT
else
  DETACHED_LIST=$(echo $DETACHED_PROFILES | xargs | tr ' ' ',')
  ATTACHED_LIST=$(echo $ATTACHED_POLICIES | xargs | tr ' ' ',')
  TRUST_ONELINE=$(echo "$TRUST_POLICY" | tr -d '\n')

  cat > "$REPORT_FILE" <<REPORT
{
  "identity_name": "$IDENTITY_NAME",
  "identity_type": "role",
  "identity_arn": "$ROLE_ARN",
  "contained_at": "$TIMESTAMP",
  "actions_taken": {
    "deny_all_policy": "$POLICY_NAME",
    "session_revocation_policy": "$REVOKE_POLICY_NAME",
    "instance_profiles_detached": "$DETACHED_LIST",
    "trust_policy_at_capture": $TRUST_ONELINE,
    "attached_policies_at_capture": "$ATTACHED_LIST"
  }
}
REPORT
fi

echo "      Report saved: $REPORT_FILE"

# --- Summary ---
echo ""
echo "============================================"
echo "  Containment Complete"
echo "============================================"
echo "  Identity:      $IDENTITY_NAME"
echo "  Type:          $IDENTITY_TYPE"
echo "  Status:        CONTAINED"
echo ""
if [ "$IDENTITY_TYPE" == "user" ]; then
echo "  Access Keys:   ALL DEACTIVATED"
echo "  Console:       REVOKED"
fi
echo "  Deny-All:      ATTACHED"
echo "  Sessions:      ALL REVOKED (pre-$TIMESTAMP)"
if [ "$IDENTITY_TYPE" == "role" ]; then
echo "  Profiles:      DETACHED"
fi
echo "  Report:        $REPORT_FILE"
echo ""
echo "  Next steps:"
echo "    1. Review CloudTrail for API calls made by this identity"
echo "    2. Check for any resources created/modified by the compromised identity"
echo "    3. Determine the attack vector (leaked keys, phishing, etc.)"
echo "    4. After investigation, remove containment policies:"
echo "       $POLICY_NAME"
echo "       $REVOKE_POLICY_NAME"
echo "============================================"
