#!/bin/bash
# =============================================================================
# EC2 Forensic Isolation Script
# =============================================================================
# When an EC2 instance is suspected compromised, this script:
#   1. Tags the instance as compromised (preserves evidence chain)
#   2. Snapshots all attached EBS volumes (evidence preservation)
#   3. Creates a forensic security group allowing only SSH from your IP
#   4. Swaps the instance's security groups to the forensic one (isolation)
#   5. Enables termination protection (prevent evidence destruction)
#
# Usage: ./isolate-instance.sh <instance-id> [--forensic-ip <your-ip>]
# =============================================================================

set -euo pipefail

# --- Input validation ---
if [ -z "${1:-}" ]; then
  echo "Usage: $0 <instance-id> [--forensic-ip <your-ip>]"
  echo "  instance-id    The EC2 instance to isolate (e.g., i-0abc123def456)"
  echo "  --forensic-ip  IP address allowed SSH access (default: your current public IP)"
  exit 1
fi

INSTANCE_ID="$1"
FORENSIC_IP=""
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Parse optional args
shift
while [[ $# -gt 0 ]]; do
  case $1 in
    --forensic-ip)
      FORENSIC_IP="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Auto-detect public IP if not provided
if [ -z "$FORENSIC_IP" ]; then
  FORENSIC_IP=$(curl -s https://checkip.amazonaws.com)
  echo "[*] Auto-detected forensic IP: $FORENSIC_IP"
fi

echo "============================================"
echo "  EC2 Forensic Isolation"
echo "============================================"
echo "[*] Instance:     $INSTANCE_ID"
echo "[*] Forensic IP:  $FORENSIC_IP"
echo "[*] Timestamp:    $TIMESTAMP"
echo "============================================"

# --- Step 1: Verify instance exists and get its VPC ---
echo ""
echo "[1/5] Verifying instance..."

INSTANCE_INFO=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].[VpcId,SubnetId,State.Name]' \
  --output text)

VPC_ID=$(echo "$INSTANCE_INFO" | awk '{print $1}')
SUBNET_ID=$(echo "$INSTANCE_INFO" | awk '{print $2}')
STATE=$(echo "$INSTANCE_INFO" | awk '{print $3}')

echo "      VPC:    $VPC_ID"
echo "      Subnet: $SUBNET_ID"
echo "      State:  $STATE"

if [ "$STATE" == "terminated" ]; then
  echo "[!] Instance is terminated. Nothing to isolate."
  exit 1
fi

# --- Step 2: Tag the instance ---
echo ""
echo "[2/5] Tagging instance as compromised..."

aws ec2 create-tags \
  --resources "$INSTANCE_ID" \
  --tags \
    Key=SecurityStatus,Value=Compromised \
    Key=IsolatedAt,Value="$TIMESTAMP" \
    Key=IsolatedBy,Value="forensic-isolation-script" \
    Key=ForensicIP,Value="$FORENSIC_IP"

echo "      Tagged with SecurityStatus=Compromised"

# --- Step 3: Snapshot all attached EBS volumes ---
echo ""
echo "[3/5] Snapshotting attached EBS volumes..."

VOLUME_IDS=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[*].Ebs.VolumeId' \
  --output text)

for VOL_ID in $VOLUME_IDS; do
  SNAP_ID=$(aws ec2 create-snapshot \
    --volume-id "$VOL_ID" \
    --description "Forensic snapshot - $INSTANCE_ID - $TIMESTAMP" \
    --tag-specifications "ResourceType=snapshot,Tags=[{Key=ForensicSource,Value=$INSTANCE_ID},{Key=CreatedAt,Value=$TIMESTAMP}]" \
    --query 'SnapshotId' \
    --output text)
  echo "      $VOL_ID -> $SNAP_ID"
done

# --- Step 4: Create forensic security group and swap ---
echo ""
echo "[4/5] Creating forensic security group and isolating..."

FORENSIC_SG_NAME="forensic-isolation-${INSTANCE_ID}"

# Check if forensic SG already exists
EXISTING_SG=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=$FORENSIC_SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' \
  --output text 2>/dev/null || echo "None")

if [ "$EXISTING_SG" != "None" ] && [ "$EXISTING_SG" != "null" ]; then
  FORENSIC_SG_ID="$EXISTING_SG"
  echo "      Using existing forensic SG: $FORENSIC_SG_ID"
else
  FORENSIC_SG_ID=$(aws ec2 create-security-group \
    --group-name "$FORENSIC_SG_NAME" \
    --description "Forensic isolation - SSH only from $FORENSIC_IP" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' \
    --output text)

  # Remove the default outbound "allow all" rule
  aws ec2 revoke-security-group-egress \
    --group-id "$FORENSIC_SG_ID" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

  # Allow inbound SSH only from forensic IP
  aws ec2 authorize-security-group-ingress \
    --group-id "$FORENSIC_SG_ID" \
    --protocol tcp \
    --port 22 \
    --cidr "${FORENSIC_IP}/32"

  echo "      Created forensic SG: $FORENSIC_SG_ID"
fi

# Record original security groups before swapping
ORIGINAL_SGS=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].SecurityGroups[*].GroupId' \
  --output text)

echo "      Original SGs: $ORIGINAL_SGS"

# Tag instance with original SGs for later restoration
aws ec2 create-tags \
  --resources "$INSTANCE_ID" \
  --tags Key=OriginalSecurityGroups,Value="$(echo $ORIGINAL_SGS | tr ' ' ',')"

# Swap to forensic SG
aws ec2 modify-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --groups "$FORENSIC_SG_ID"

echo "      Swapped to forensic SG (SSH from $FORENSIC_IP only, no egress)"

# --- Step 5: Enable termination protection ---
echo ""
echo "[5/5] Enabling termination protection..."

aws ec2 modify-instance-attribute \
  --instance-id "$INSTANCE_ID" \
  --disable-api-termination

echo "      Termination protection enabled"

# --- Summary ---
echo ""
echo "============================================"
echo "  Isolation Complete"
echo "============================================"
echo "  Instance:        $INSTANCE_ID"
echo "  Status:          ISOLATED"
echo "  Forensic SG:     $FORENSIC_SG_ID"
echo "  SSH Access:      $FORENSIC_IP -> port 22"
echo "  Egress:          BLOCKED"
echo "  EBS Snapshots:   Created for all volumes"
echo "  Termination:     Protected"
echo ""
echo "  Original SGs saved in tag: OriginalSecurityGroups"
echo ""
echo "  Next steps:"
echo "    1. SSH into the instance from $FORENSIC_IP"
echo "    2. Capture memory dump, process listings, network connections"
echo "    3. Review CloudTrail for API activity from this instance"
echo "    4. Analyze the EBS snapshots in a clean forensic environment"
echo "============================================"
