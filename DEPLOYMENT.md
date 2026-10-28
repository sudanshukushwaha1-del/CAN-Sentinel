# Hosting and deployment

CAN-Sentinel runs as a Python/Streamlit application in a managed server container. The original Python app, detector package, and user workflow are preserved. Nginx sits in front of Streamlit to expose the required root route manifest, forward ordinary HTTP and Streamlit WebSocket traffic, and serve the unauthenticated readiness endpoint.

The project declares a managed container entrypoint in `Dockerfile` and health path `/_stcore/health`. The image installs dependencies from `requirements.txt`, starts Streamlit on its private internal listener, then makes Nginx listen on the platform-provided `PORT` (default 3000). The root endpoint serves the dashboard; `/manus-routes.json` serves the declared route set. The public website is [CAN-Sentinel](https://cansentinel-knbjqxgy.manus.space). Hosting is on demand, so an idle app can cold-start.

## Public app and data handling

The website is public and has no account/login gate. Synthetic scenarios are the recommended way to try the demo. When a CSV is selected, its contents are uploaded to the hosted application for processing. The interface warns users not to submit confidential, personal, or unauthorized vehicle captures. The app adds no durable capture storage, database, CAN adapter, or transmission path. Container memory and local files are temporary; the alert JSONL is a user download, not persistent server storage.

A permanent website URL does not necessarily mean an always-warm process. Depending on hosting policy, an idle app can sleep and take longer to respond to the next visit. No keep-alive traffic is configured.

## Local production-style proxy (Linux)

```bash
sudo apt-get update
sudo apt-get install -y nginx gettext-base
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PORT=3000 bash start.sh
```

Open `http://localhost:3000`. `/_stcore/health` returns `ok`; `/manus-routes.json` returns the website route declaration. `start.sh` starts Streamlit on the internal port `8502`, waits for readiness, and runs Nginx on `PORT`. It uses a temporary standalone Nginx config and writable temporary directories, so the local process does not require root after package installation.

For a simpler dashboard-only local run, use `streamlit run app.py`. This skips the proxy and does not expose the root `/manus-routes.json` route.

## Container operation

`Dockerfile` uses Python 3.12 slim, installs Nginx and `gettext-base`, installs the runtime requirements, and copies only the files needed to serve the dashboard and route manifest. The production listener honors the managed `PORT`. Nginx forwards WebSocket upgrades for Streamlit and sets a bounded upload body size; Streamlit's upload limit is 200 MB. The container has no database and does not persist uploaded captures.
