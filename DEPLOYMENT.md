# Deploy CAN-Sentinel for a persistent public demo

## Links in the README

The README's **Try the live app** badge points to a task-cloud preview. It is online now, but it is temporary and can stop when the preview environment expires. The **Download project ZIP** button points to GitHub's public archive for the `development` branch; it works for anyone while the repository remains public.

## Publish your own persistent Streamlit app

The repository can be deployed through Streamlit Community Cloud. This creates a cloud app under the account that authorizes the deployment; it is separate from the temporary Manus preview.

1. Sign in to Streamlit Community Cloud with the GitHub account that can access `sudanshukushwaha1-del/CAN-Sentinel`.
2. Create a new app and select the repository `sudanshukushwaha1-del/CAN-Sentinel`.
3. Choose branch `development` and main file path `app.py`.
4. Deploy. The app installs Python dependencies from `requirements.txt`; no secret values are required for the demo.
5. Open the deployed app's settings/sharing controls and select the access mode you want. If you want anyone to try it, make it public, then copy the stable app URL.
6. Once you have that stable URL, replace the temporary preview URL in the README's **Try the live app** badge with your persistent app URL.

## Local alternative

```bash
python -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

The Streamlit app only analyzes synthetic or uploaded offline CSV data. It does not connect to a vehicle or transmit CAN frames. Do not upload captures unless you are authorized to share them with the chosen hosting provider; avoid including sensitive data in public demos.
