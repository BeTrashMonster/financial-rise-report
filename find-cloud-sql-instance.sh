#!/bin/bash
# Find the actual Cloud SQL instance

echo "Listing all Cloud SQL instances in project..."
gcloud sql instances list --project=financial-rise-prod

echo ""
echo "Checking for instances with 'financial' in name..."
gcloud sql instances list --project=financial-rise-prod --filter="name:financial*"

echo ""
echo "Checking for instances with 'prod' in name..."
gcloud sql instances list --project=financial-rise-prod --filter="name:*prod*"

echo ""
echo "Showing all instances with IP addresses..."
gcloud sql instances list --project=financial-rise-prod --format="table(name,ipAddresses,settings.ipConfiguration.ipv4Enabled,settings.ipConfiguration.privateNetwork)"
