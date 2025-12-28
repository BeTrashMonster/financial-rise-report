# Google Cloud Platform Setup Instructions

## Step 1: Install Google Cloud SDK

### For Windows:

1. **Download the installer:**
   - Go to: https://cloud.google.com/sdk/docs/install
   - Download the Google Cloud CLI installer for Windows

2. **Run the installer:**
   - Execute the downloaded installer
   - Follow the installation wizard
   - Check "Run 'gcloud init'" at the end

3. **Restart your terminal** after installation

### Alternative: Using PowerShell

```powershell
# Download the installer
(New-Object Net.WebClient).DownloadFile("https://dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe", "$env:Temp\GoogleCloudSDKInstaller.exe")

# Run the installer
& $env:Temp\GoogleCloudSDKInstaller.exe
```

## Step 2: Authenticate to Google Cloud

After installation, run:

```bash
gcloud init
```

This will:
1. Open your browser for authentication
2. Ask you to select or create a GCP project
3. Set your default region/zone

## Step 3: Set Up Billing

**IMPORTANT:** You need a billing account to create resources.

1. Go to: https://console.cloud.google.com/billing
2. Create a billing account if you don't have one
3. Link your project to the billing account

## Step 4: Run the Automated Setup Script

Once gcloud is installed and authenticated, I'll create and run an automated script to:
- Create the GCP project
- Enable all required APIs
- Set up networking (VPC, firewall rules)
- Create Cloud SQL instances
- Set up Artifact Registry
- Create GCS buckets
- Reserve static IPs
- Create VMs with startup scripts
- Configure service accounts
- Set up Secret Manager

## Estimated Costs

**Monthly costs for running both environments:**
- Staging: ~$22/month (e2-medium preemptible + db-f1-micro)
- Production: ~$86/month (e2-standard-2 + db-g1-small HA)
- Shared services: ~$8/month (Artifact Registry, GCS, Logging)
- **Total: ~$116/month**

**Initial setup is FREE** - no resources will incur charges until VMs and databases are created and running.

## What to Do Now

1. Install Google Cloud SDK using the instructions above
2. Run `gcloud init` to authenticate and set up your account
3. Ensure billing is enabled on your account
4. Let me know when you're ready, and I'll create the automated setup script

## Quick Verification

After installing gcloud, verify it works:

```bash
gcloud --version
gcloud auth list
gcloud config list
```

You should see your authenticated account and project information.
