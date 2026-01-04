@echo off
echo =========================================
echo SECRET MANAGER VERIFICATION
echo =========================================
echo.

echo Checking version 3 contents (first 15 lines):
echo -----------------------------------------
gcloud secrets versions access 3 --secret=financial-rise-production-env --project=financial-rise-prod | findstr /N "^" | findstr "^[1-9]: ^1[0-5]:"
echo.

echo Checking LATEST version contents (first 15 lines):
echo -----------------------------------------
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod | findstr /N "^" | findstr "^[1-9]: ^1[0-5]:"
echo.

echo Checking JWT_REFRESH_SECRET line:
echo -----------------------------------------
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod | findstr "JWT_REFRESH_SECRET"
echo.

echo Starting staging VM:
echo -----------------------------------------
gcloud compute instances start financial-rise-staging-vm --zone=us-central1-a --project=financial-rise-prod
echo.

echo =========================================
echo VERIFICATION COMPLETE
echo =========================================
