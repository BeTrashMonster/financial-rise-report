#!/bin/bash
# Diagnose Cloud SQL connectivity from production VM

echo "========================================="
echo "CLOUD SQL CONNECTIVITY DIAGNOSTICS"
echo "========================================="
echo ""

echo "1. Checking VM network configuration..."
echo "-----------------------------------"
gcloud compute instances describe financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --format="get(networkInterfaces[0].network,networkInterfaces[0].subnetwork)"
echo ""

echo "2. Checking Cloud SQL instance details..."
echo "-----------------------------------"
gcloud sql instances describe financial-rise-production \
  --project=financial-rise-prod \
  --format="get(ipAddresses,settings.ipConfiguration)"
echo ""

echo "3. Testing connectivity from VM to Cloud SQL..."
echo "-----------------------------------"
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command="
    echo 'Pinging Cloud SQL private IP...'
    ping -c 3 34.134.76.171 || echo 'Ping failed'
    echo ''
    echo 'Testing port 5432 connectivity...'
    nc -zv 34.134.76.171 5432 -w 5 || echo 'Port 5432 not reachable'
    echo ''
    echo 'Checking VM network interfaces...'
    ip addr show
  "
echo ""

echo "4. Checking VPC peering status..."
echo "-----------------------------------"
gcloud services vpc-peerings list \
  --network=default \
  --project=financial-rise-prod
echo ""

echo "5. Checking firewall rules..."
echo "-----------------------------------"
gcloud compute firewall-rules list \
  --project=financial-rise-prod \
  --filter="name~cloudsql OR targetTags:allow-cloudsql OR sourceRanges:10.0.0.0/8"
echo ""

echo "========================================="
echo "DIAGNOSTICS COMPLETE"
echo "========================================="
echo ""
echo "Common fixes:"
echo "1. If VM is not on correct network: Recreate VM on 'default' VPC"
echo "2. If VPC peering missing: Run Cloud SQL private IP setup"
echo "3. If firewall blocking: Add rule to allow egress to 34.134.76.171:5432"
