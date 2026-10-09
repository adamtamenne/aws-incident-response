# EC2 Forensic Isolation

## Overview

When an EC2 instance is suspected compromised, the first priority is to isolate it from the network while preserving evidence and maintaining forensic access. This script automates that initial response.

## What the Script Does

Given an instance ID, `isolate-instance.sh` performs five steps:

1. **Tags the instance** with `SecurityStatus=Compromised`, a timestamp, and the forensic analyst's IP. This establishes the evidence chain and makes the instance immediately identifiable.

2. **Snapshots all attached EBS volumes.** Snapshots are point-in-time copies. Even if the attacker is actively modifying the disk, you have a preserved copy from the moment of isolation.

3. **Creates a forensic security group** that allows only inbound SSH (port 22) from the forensic analyst's IP. All outbound traffic is blocked. This cuts off the attacker's command-and-control channel while letting the analyst connect.

4. **Swaps the instance's security groups** to the forensic one. The original security groups are saved in a tag (`OriginalSecurityGroups`) for later restoration. This is the actual network isolation step.

5. **Enables termination protection** so the instance can't be accidentally (or maliciously) deleted before forensic analysis is complete.

## Why Isolate, Not Terminate

Terminating a compromised instance destroys volatile evidence: memory, running processes, active network connections. Isolating it preserves that evidence while cutting off the attacker's access.

Blocking all egress is critical. A compromised instance with outbound access can still exfiltrate data, communicate with C2 servers, or pivot to other resources. The forensic security group has zero egress rules, meaning the instance can't initiate any outbound connection.

## Usage

```bash
# Auto-detect your public IP for SSH access
./isolate-instance.sh i-0abc123def456

# Specify the forensic workstation IP explicitly
./isolate-instance.sh i-0abc123def456 --forensic-ip 203.0.113.50
```

## Required IAM Permissions

- `ec2:DescribeInstances`
- `ec2:CreateTags`
- `ec2:CreateSnapshot`
- `ec2:CreateSecurityGroup`
- `ec2:DescribeSecurityGroups`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:RevokeSecurityGroupEgress`
- `ec2:ModifyInstanceAttribute`

## Post-Isolation Forensic Steps

1. SSH into the isolated instance
2. Capture a memory dump (`/proc/kcore` or use LiME)
3. List running processes, open files, and network connections
4. Export `/var/log/` contents
5. Review CloudTrail for API calls made by the instance's IAM role
6. Mount the EBS snapshots on a clean forensic instance for offline analysis

## Relevant Services

- **EC2** (instances, security groups, EBS snapshots)
- **IAM** (permissions for the forensic responder)
- **CloudTrail** (API activity audit trail)
- **VPC** (security group network isolation)
