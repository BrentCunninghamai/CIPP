# Deploying this CIPP fork to Azure Static Web Apps

This walks through deploying **this fork** (`BrentCunninghamai/CIPP`) as a self-hosted CIPP
instance using the ARM template in [`deployment/`](deployment/). The template creates everything
in one deployment:

| Resource | Purpose |
| --- | --- |
| Static Web App | Hosts this frontend, built from this repo's `main` branch |
| Function App (PowerShell) | The CIPP-API backend, installed from the official release feed (`cipp-api/latest.zip`) — no API fork needed |
| Storage account | State for the function app |
| Key Vault | Holds the Secure Application Model (SAM) secrets |

## 1. Create a GitHub personal access token

Azure needs it once, to connect the Static Web App to this repo and commit a deployment workflow.

1. GitHub → Settings → Developer settings → **Personal access tokens (classic)** → Generate new token.
2. Scopes: **`repo`** and **`workflow`**. Expiration: 30 days is fine (only used at deploy time).
3. Copy the token.

## 2. Deploy the template

Click to open the template pre-loaded in the Azure portal (sign in with the account that owns your
Azure subscription):

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FBrentCunninghamai%2FCIPP%2Fmain%2Fdeployment%2FAzureDeploymentTemplate.json)

Fill in:

- **Resource group**: create a new one, e.g. `CIPP`.
- **Base Name**: `CIPP` (prefixes all resource names).
- **Github Repository**: `https://github.com/BrentCunninghamai/CIPP`
- **Github Token**: the PAT from step 1.

Then **Review + create** → **Create**. If you need the frontend and API in a specific region, use
[`AzureDeploymentTemplate_regionoptions.json`](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FBrentCunninghamai%2FCIPP%2Fmain%2Fdeployment%2FAzureDeploymentTemplate_regionoptions.json) instead.

## 3. Wait for the first frontend build

Connecting the Static Web App makes Azure commit a workflow file to this repo
(`.github/workflows/azure-static-web-apps-<generated-name>.yml`) with its own deployment-token
secret, then run it. Watch the **Actions** tab — the first build takes ~10–15 minutes. The portal
URL (shown on the Static Web App overview blade) serves the app once it's green.

## 4. Invite yourself as admin

CIPP uses the Static Web App's built-in authentication:

1. Azure portal → your Static Web App → **Role management** → **Invite**.
2. Authentication provider: **Microsoft Entra ID**. Email: your M365 partner-tenant account.
3. Role: `admin` (use `superadmin` in addition if you need the super-admin settings pages).
4. Open the generated invite link while logged in as that user.

## 5. First-run SAM setup wizard

Browse to the Static Web App URL and sign in. CIPP will start the **SAM (Secure Application
Model) wizard**:

1. Choose **Create new application registrations** (first-time setup).
2. When prompted to authenticate, use a **Global Administrator in your partner tenant** that is a
   member of the **AdminAgents** group in Partner Center. This is what links CIPP to your partner
   relationship so customer tenants appear.
3. Complete the wizard; secrets are stored in the Key Vault created by the template.

After the wizard, your GDAP customer tenants show up under **Tenant Administration** and the
portal is fully functional.

## Notes

- The two `azure-static-web-apps-*.yml` workflows inherited from the upstream repo were removed —
  they referenced upstream's deployment tokens and could never succeed here. Azure adds a working
  one for your own instance during step 2.
- Running cost is small: the function app runs on a consumption plan; the Static Web App free tier
  is sufficient.
- To update CIPP later: sync this fork with upstream (`Sync fork` on GitHub) — the push to `main`
  triggers a rebuild and redeploy automatically. The API updates from the official feed.
