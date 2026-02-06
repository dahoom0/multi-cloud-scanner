# multi-cloud-scanner
This is a solid tool! A project like this needs a `README.md` that highlights its multi-cloud capabilities and clearly explains the environment variables required for each provider.

Here is a professionally formatted `README.md` file you can copy and paste directly into your project.

---

 Multi-Cloud Scanner 🛡️☁️

A Python-based security utility designed to identify common infrastructure misconfigurations and risks across AWS, Google Cloud (GCP), and Microsoft Azure.

text
      _____ _                 _   _____      _     _____                                
  / ____| |               | | |  __ \    (_)   / ____|                                
 | |    | | ___  _   _  __| | | |__) |__  _   | (___   ___ __ _ _ __  _ __   ___ _ __  
 | |    | |/ _ \| | | |/ _` | |  ___/ _ \| |   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |____| | (_) | |_| | (_| | | |  | (_) | |   ____) | (_| (_| | | | | | | |  __/ |    
  \_____|_|\___/ \__,_|\__,_|_| |_|   \___/|_|  |_____/ \___\__,_|_| |_|_| |_|\___|_|  

    Cloud Infrastructure Misconfiguration & Risk Scanner


 🚀 Features

This scanner checks for high-risk security gaps including:

AWS: Publicly accessible S3 Buckets (ACLs) and Security Groups with open `0.0.0.0/0` ingress.
 GCP: Compute Engine instances exposed via Public IP addresses.
 Azure: Storage Accounts allowing public blob access.

---

🛠️ Installation

1. Clone the repository:
bash
git clone https://github.com/dahoom0/multi-cloud-scanner.git
cd multi-cloud-scanner




2. Create a virtual environment (Recommended):
bash
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate




3. Install dependencies:
bash
pip install boto3 google-cloud-compute azure-identity azure-mgmt-storage





---

 ⚙️ Configuration & Usage

The scanner relies on environment variables and local CLI configurations to authenticate with cloud providers.

Environment Variables Required

| Provider | Variable | Description |
| 
| AWS      | `AWS_DEFAULT_REGION` | The region to scan (e.g., `us-east-1`) |
| GCP      | `GCP_PROJECT_ID` | Your Google Cloud Project ID |
| Azure    | `AZURE_SUBSCRIPTION_ID` | Your Azure Subscription ID |

Running the Scanner

Execute the script and follow the interactive prompts to choose your provider:

bash
----
python main.py



-----------------------------------------------------------------------------------------------

🔐 Security Best Practices

Warning: Never hardcode your cloud credentials inside the source code.

1. Use a `.env` file for local testing and add it to your `.gitignore`.
2. Use IAM roles or Service Accounts with **Read-Only** permissions to run these scans.
3. If using the interactive AWS setup, your credentials will be stored in `~/.aws/credentials`.

----------------------------------------------------------------------------------------------



🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

-------------------------------------------------------------------------------------------------

thanks




