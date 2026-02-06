import boto3
import os
import sys
from google.cloud import compute_v1
from azure.identity import InteractiveBrowserCredential
from azure.mgmt.storage import StorageManagementClient

# ================= ASCII HEADER =================
ascii_header = """
     _____ _                 _   _____      _     _____                                  
  / ____| |               | | |  __ \    (_)   / ____|                                 
 | |    | | ___  _   _  __| | | |__) |__  _   | (___   ___ __ _ _ __  _ __   ___ _ __  
 | |    | |/ _ \| | | |/ _` | |  ___/ _ \| |   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |____| | (_) | |_| | (_| | | |  | (_) | |   ____) | (_| (_| | | | | | | |  __/ |   
  \_____|_|\___/ \__,_|\__,_| |_|   \___/|_|  |_____/ \___\__,_|_| |_|_| |_|\___|_|   

    Cloud Infrastructure Misconfiguration & Risk Scanner
"""
print(ascii_header)

# ================= AWS SCAN =================
def scan_aws():
    print("Scanning AWS for misconfigurations...")

    region = os.environ.get("AWS_DEFAULT_REGION")
    if not region:
        raise RuntimeError("AWS_DEFAULT_REGION is not set")

    s3_client = boto3.client("s3", region_name=region)
    ec2_client = boto3.client("ec2", region_name=region)

    found_issues = []

    # ---- S3 Public ACL Check ----
    try:
        response = s3_client.list_buckets()
        for bucket in response["Buckets"]:
            acl = s3_client.get_bucket_acl(Bucket=bucket["Name"])
            for grant in acl["Grants"]:
                if "AllUsers" in grant["Grantee"].get("URI", ""):
                    found_issues.append(
                        f"S3 bucket '{bucket['Name']}' allows public access (ACL)"
                    )
    except Exception as e:
        found_issues.append(f"S3 check failed: {e}")

    # ---- Security Group Open Access ----1
    try:
        response = ec2_client.describe_security_groups()
        for sg in response["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                for ip in perm.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        found_issues.append(
                            f"Security Group '{sg['GroupName']}' allows 0.0.0.0/0"
                        )
    except Exception as e:
        found_issues.append(f"EC2 SG check failed: {e}")

    return found_issues

# ================= GCP SCAN =================
def scan_gcp():
    print("Scanning GCP for misconfigurations...")
    found_issues = []

    project_id = os.environ.get("GCP_PROJECT_ID")
    if not project_id:
        raise RuntimeError("GCP_PROJECT_ID environment variable not set")

    client = compute_v1.InstancesClient()
    request = client.aggregated_list(project=project_id)

    for zone, response in request:
        if response.instances:
            for instance in response.instances:
                for nic in instance.network_interfaces:
                    if nic.access_configs:
                        found_issues.append(
                            f"GCP instance '{instance.name}' has a public IP"
                        )

    return found_issues

# ================= AZURE SCAN =================
def scan_azure():
    print("Scanning Azure for misconfigurations...")
    found_issues = []

    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise RuntimeError("AZURE_SUBSCRIPTION_ID not set")

    credential = InteractiveBrowserCredential()
    storage_client = StorageManagementClient(credential, subscription_id)

    for account in storage_client.storage_accounts.list():
        props = storage_client.storage_accounts.get_properties(
            account.id.split("/")[4],
            account.name
        )
        if props.allow_blob_public_access:
            found_issues.append(
                f"Azure Storage Account '{account.name}' allows public blob access"
            )

    return found_issues

# ================= PROVIDER CHOICE =================
def choose_cloud_provider():
    print("\nChoose cloud provider:")
    print("1. AWS")
    print("2. Google Cloud")
    print("3. Azure")
    print("4. Exit")

    choice = input("> ")

    if choice == "1":
        return scan_aws, "AWS"
    elif choice == "2":
        return scan_gcp, "GCP"
    elif choice == "3":
        return scan_azure, "Azure"
    elif choice == "4":
        sys.exit()
    else:
        print("Invalid choice")
        return choose_cloud_provider()

# ================= CREDENTIAL SETUP =================
def configure_credentials(provider):
    if provider == "AWS":
        print("\nAWS Credential Setup")
        print("1. aws configure")
        print("2. Manual entry")
        choice = input("> ")

        if choice == "1":
            os.system("aws configure")
        elif choice == "2":
            os.environ["AWS_ACCESS_KEY_ID"] = input("Access Key ID: ")
            os.environ["AWS_SECRET_ACCESS_KEY"] = input("Secret Access Key: ")
            region = input("Region (e.g. ap-southeast-2): ")

            if region[-1].isalpha():
                print("❌ Availability Zone entered. Use region only.")
                sys.exit(1)

            os.environ["AWS_DEFAULT_REGION"] = region
        else:
            sys.exit("Invalid choice")

    elif provider == "GCP":
        print("\nGCP uses GOOGLE_APPLICATION_CREDENTIALS")
        print("Set GCP_PROJECT_ID env variable")

    elif provider == "Azure":
        print("\nAzure login required")
        os.system("az login")

# ================= RUN =================
def run_scan():
    scan_function, provider = choose_cloud_provider()
    configure_credentials(provider)

    print(f"\nScanning {provider}...\n")
    issues = scan_function()

    if issues:
        print(f"*** Issues Found in {provider} ***")
        for issue in issues:
            print(f"[!] {issue}")
    else:
        print("No misconfigurations found.")

if __name__ == "__main__":
    run_scan()
