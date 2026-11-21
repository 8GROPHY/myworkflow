import os
import sys
import json
import base64
import requests
import uvicorn
import subprocess
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from nacl import encoding, public # NEW: Required for GitHub Secret Encryption

# ==========================================
# ⚙️  ENVIRONMENT CONFIGURATION
# ==========================================
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_USER = os.getenv("GITHUB_USER")
WORKFLOW_FILE = os.getenv("WORKFLOW_FILE", "workflow.yml")
FLEET_FILE = "fleet.json"

# Master secrets to inject into new nodes
TS_AUTHKEY = os.getenv("TS_AUTHKEY")
BACKUP_PAT = os.getenv("BACKUP_PAT")
ENC_PASS = os.getenv("ENC_PASS")

if not GITHUB_TOKEN or not GITHUB_USER:
    print("❌ ERROR: You must set GITHUB_TOKEN and GITHUB_USER environment variables.")
    sys.exit(1)

GH_HEADERS = {
    "Accept": "application/vnd.github.v3+json",
    "Authorization": f"token {GITHUB_TOKEN}"
}

app = FastAPI(title="Ephemeral Fleet C2")

# ==========================================
# 💾 STATE MANAGEMENT
# ==========================================
def load_fleet():
    if os.path.exists(FLEET_FILE):
        with open(FLEET_FILE, "r") as f:
            return json.load(f)
    return {}

def save_fleet(fleet_data):
    with open(FLEET_FILE, "w") as f:
        json.dump(fleet_data, f, indent=4)

# ==========================================
# 🔐 GITHUB SECRET ENCRYPTION
# ==========================================
def encrypt_secret(public_key: str, secret_value: str) -> str:
    """Encrypt a secret using GitHub's required Libsodium (NaCl) algorithm."""
    public_key_bytes = base64.b64decode(public_key)
    sealed_box = public.SealedBox(public.PublicKey(public_key_bytes))
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")
def inject_github_secret(repo: str, secret_name: str, secret_value: str):
    """Fetches the repo's public key, encrypts the secret, and uploads it."""
    # 1. Get Repo Public Key
    key_url = f"https://api.github.com/repos/{GITHUB_USER}/{repo}/actions/secrets/public-key"
    res = requests.get(key_url, headers=GH_HEADERS)
    if res.status_code != 200:
        print(f"❌ Failed to get public key for {repo}: {res.text}")
        return

    key_id = res.json()["key_id"]
    pub_key = res.json()["key"]

    # 2. Encrypt and Push
    enc_value = encrypt_secret(pub_key, secret_value)
    put_url = f"https://api.github.com/repos/{GITHUB_USER}/{repo}/actions/secrets/{secret_name}"
    put_res = requests.put(put_url, headers=GH_HEADERS, json={"encrypted_value": enc_value, "key_id": key_id})

    if put_res.status_code in [201, 204]:
        print(f"🔒 Successfully injected secret: {secret_name}")
    else:
        print(f"❌ Failed to inject {secret_name}: {put_res.text}")
# ==========================================
# 📦 API MODELS
# ==========================================
class NodeInfo(BaseModel):
    name: str
    public_repo: str
    worker_id: str
    icon: str
    cloud_init: str = ""
    auto_provision: bool = False

class ExecRequest(BaseModel):
    command: str

# ==========================================
# 🚀 FLEET CRUD & PROVISIONING
# ==========================================
@app.get("/api/nodes")
def get_nodes():
    fleet = load_fleet()
    return fleet

@app.post("/api/nodes")
def add_node(node: NodeInfo):
    fleet = load_fleet()

    if node.auto_provision:
        repo_url = "https://api.github.com/user/repos"

        # 1. Create Public Repo
        pub_payload = {"name": node.public_repo, "private": False, "description": f"Ephemeral C2 Node: {node.name}"}
        pub_res = requests.post(repo_url, headers=GH_HEADERS, json=pub_payload)
        if pub_res.status_code == 422:
            print(f"⚠ Public repo '{node.public_repo}' already exists.")
        elif pub_res.status_code != 201:
            raise HTTPException(status_code=400, detail=f"Public repo creation failed: {pub_res.text}")

        # 2. Inject Workflow File
        try:
            with open(WORKFLOW_FILE, "rb") as f:
                workflow_content = base64.b64encode(f.read()).decode("utf-8")
            put_url = f"https://api.github.com/repos/{GITHUB_USER}/{node.public_repo}/contents/.github/workflows/{WORKFLOW_FILE}"
            put_payload = {"message": "C2 Automated: Initialize Node Workflow", "content": workflow_content}
            requests.put(put_url, headers=GH_HEADERS, json=put_payload)
        except FileNotFoundError:
            print(f"⚠️ Local template {WORKFLOW_FILE} not found! Skipping workflow injection.")

        # 3. Create Private Backup Repo
        backup_repo_name = f"{node.public_repo}-backup"
        priv_payload = {"name": backup_repo_name, "private": True, "description": f"Automated encrypted state backup"}
        requests.post(repo_url, headers=GH_HEADERS, json=priv_payload)

        # 4. Inject Secrets (The New Magic Step)
        if TS_AUTHKEY and BACKUP_PAT and ENC_PASS:
            print(f"Injecting secrets into {node.public_repo}...")
            inject_github_secret(node.public_repo, "TAILSCALE_AUTHKEY", TS_AUTHKEY)
            inject_github_secret(node.public_repo, "BACKUP_PAT", BACKUP_PAT)
            inject_github_secret(node.public_repo, "ENCRYPTION_PASS", ENC_PASS)
            inject_github_secret(node.public_repo, "BACKUP_REPO", backup_repo_name)
        else:
            print("⚠️ Secrets missing from C2 environment. Skipping secret injection.")

    # Generate new ID and save
    new_id = str(max([int(k) for k in fleet.keys()] + [0]) + 1)
    save_data = node.dict()
    save_data.pop("auto_provision", None)
    fleet[new_id] = save_data
    save_fleet(fleet)

    return {"status": "success", "message": f"Added node {node.name}. Automation complete."}

@app.put("/api/nodes/{node_id}")
def edit_node(node_id: str, node: NodeInfo):
    fleet = load_fleet()
    if node_id not in fleet:
        raise HTTPException(status_code=404, detail="Node not found")
    save_data = node.dict()
    save_data.pop("auto_provision", None)
    fleet[node_id] = save_data
    save_fleet(fleet)
    return {"status": "success", "message": f"Updated node {node.name}"}

@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: str):
    fleet = load_fleet()
    if node_id in fleet:
        del fleet[node_id]
        save_fleet(fleet)
        return {"status": "success", "message": "Node removed."}
    raise HTTPException(status_code=404, detail="Node not found")

# ==========================================
# ⚡ ACTION ENDPOINTS
# ==========================================
@app.post("/api/spawn/{node_id}")
def spawn_node(node_id: str):
    fleet = load_fleet()
    config = fleet.get(node_id)
    url = f"https://api.github.com/repos/{GITHUB_USER}/{config['public_repo']}/actions/workflows/{WORKFLOW_FILE}/dispatches"
    res = requests.post(url, headers=GH_HEADERS, json={"ref": "main", "inputs": {"worker_id": config["worker_id"]}})
    if res.status_code == 204:
        return {"status": "success", "message": f"✅ {config['worker_id']} is booting up! Wait ~45 seconds."}
    return {"status": "error", "message": f"❌ Boot Error: {res.text}"}

@app.post("/api/stop/{node_id}")
def stop_node(node_id: str):
    fleet = load_fleet()
    config = fleet.get(node_id)
    repo = config['public_repo']
    runs_url = f"https://api.github.com/repos/{GITHUB_USER}/{repo}/actions/workflows/{WORKFLOW_FILE}/runs?status=in_progress"
    runs_res = requests.get(runs_url, headers=GH_HEADERS).json()

    if not runs_res.get("workflow_runs"):
        return {"status": "error", "message": f"⚠️ No active runs found for {config['worker_id']}"}

    run_id = runs_res["workflow_runs"][0]["id"]
    requests.post(f"https://api.github.com/repos/{GITHUB_USER}/{repo}/actions/runs/{run_id}/cancel", headers=GH_HEADERS)
    return {"status": "success", "message": f"🛑 Kill signal sent to {config['worker_id']}. Commencing safe backup..."}

# ==========================================
# 💻 RCE & CLOUD INIT INJECTION
# ==========================================
@app.post("/api/exec/{node_id}")
def exec_command(node_id: str, req: ExecRequest):
    fleet = load_fleet()
    def run_cmd(worker_id, command):
        # NOTE: Added UserKnownHostsFile=/dev/null to fix fingerprint mismatches
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{worker_id}@{worker_id}", command]
        try:
            res = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
            output = res.stdout if res.stdout else res.stderr
            return f"--- [{worker_id}] ---\n{output.strip()}"
        except Exception as e:
            return f"--- [{worker_id}] ---\n❌ Connection Error: {str(e)}"

    if node_id == "all":
        results = [run_cmd(config['worker_id'], req.command) for config in fleet.values()]
        return {"status": "success", "message": "\n\n".join(results)}
    else:
        config = fleet.get(node_id)
        return {"status": "success", "message": run_cmd(config['worker_id'], req.command)}

@app.post("/api/init/{node_id}")
def push_init(node_id: str):
    fleet = load_fleet()
    config = fleet.get(node_id)
    if not config:
        raise HTTPException(status_code=404, detail="Invalid node")

    script = config.get("cloud_init", "")
    worker = config["worker_id"]

    if not script.strip():
        return {"status": "error", "message": f"❌ No cloud_init script defined in dashboard for {worker}."}

    b64_script = base64.b64encode(script.encode("utf-8")).decode("utf-8")
    injection_cmd = f"echo '{b64_script}' | base64 -d > ~/.cloud_init && chmod +x ~/.cloud_init && nohup bash ~/.cloud_init > /tmp/cloud_init_manual.log 2>&1 &"

    # NOTE: Added UserKnownHostsFile=/dev/null here as well
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{worker}@{worker}", injection_cmd]

    try:
        subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)
        return {"status": "success", "message": f"⚙️ Script injected into {worker} and executing in the background!"}
    except Exception as e:
        return {"status": "error", "message": f"❌ Failed to connect to {worker}: {str(e)}"}

# ==========================================
# 🖥️  FRONTEND UI
# ==========================================
@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    return r"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cloud Fleet C2</title>
        <!-- Using a highly reliable static CSS CDN that privacy filters ignore -->
        <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-900 text-gray-200 font-sans p-6 min-h-screen">
        <div class="max-w-7xl mx-auto">
            <header class="mb-8 flex justify-between items-center">
                <div>
                    <h1 class="text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-green-400">☁ Ephemeral Fleet C2</h1>
                    <p class="text-gray-400 mt-2">Central Command & Orchestration</p>
                </div>
                <button onclick="openForm()" class="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-4 rounded-lg shadow-lg">
                    + Add New Node
                </button>
            </header>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <!-- Left Column (Fleet & Terminal) -->
                <div class="lg:col-span-2 flex flex-col space-y-6">
                    <div class="bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-700">
                        <h2 class="text-2xl font-semibold mb-4 text-white">🚀 Fleet Roster</h2>
                        <div id="node-list" class="space-y-4"></div>
                    </div>

                    <!-- Remote Command Execution Shell -->
                    <div class="bg-gray-800 p-6 rounded-xl shadow-lg border border-purple-500">
                        <h2 class="text-xl font-semibold mb-4 text-purple-400">💻 Fleet RCE Terminal</h2>
                        <div class="flex space-x-2 mb-3">
                            <select id="cmd-target" class="w-1/3 bg-gray-900 border border-gray-600 rounded p-2 text-white outline-none focus:border-purple-500">
                                <option value="all">🌐 Broadcast (All Nodes)</option>
                            </select>
                            <input type="text" id="cmd-input" placeholder="Enter bash command (e.g., uptime, ls -la)..." class="w-2/3 bg-gray-900 border border-gray-600 rounded p-2 text-white font-mono outline-none focus:border-purple-500">
                            <button onclick="executeCommand()" class="bg-purple-600 hover:bg-purple-500 text-white font-bold py-2 px-4 rounded">Run</button>
                        </div>
                    </div>
                </div>

                <!-- Right Column (Form & Logs) -->
                <div class="flex flex-col space-y-6">
                    <!-- Hidden Form -->
                    <div id="node-form-card" class="hidden bg-gray-800 p-6 rounded-xl shadow-lg border border-green-500">
                        <h2 id="form-title" class="text-xl font-semibold mb-4 text-white">Add Node</h2>
                        <input type="hidden" id="node-id">
                        <input type="text" id="node-name" placeholder="Node Name" class="w-full bg-gray-900 border border-gray-600 rounded p-2 mb-3 text-white">
                        <input type="text" id="node-repo" placeholder="Public Repo Name" class="w-full bg-gray-900 border border-gray-600 rounded p-2 mb-3 text-white">
                        <input type="text" id="node-worker" placeholder="Worker ID (Tailscale)" class="w-full bg-gray-900 border border-gray-600 rounded p-2 mb-3 text-white">
                        <input type="text" id="node-icon" placeholder="Icon (e.g. 🛡️)" class="w-full bg-gray-900 border border-gray-600 rounded p-2 mb-3 text-white">

                        <label class="block text-sm text-gray-400 mb-1">cloud_init bash script:</label>
                        <textarea id="node-init-script" rows="5" placeholder="#!/bin/bash\nexec > /tmp/cloud_init.log 2>&1\n\n# Fix permissions\nsudo chown -R $USER:$USER /home/$USER\nsudo apt-get update\nsudo apt-get install -y kitty-terminfo" class="w-full bg-gray-900 border border-gray-600 rounded p-2 mb-3 text-white font-mono text-xs"></textarea>

                        <div class="mb-4">
                            <label class="flex items-center text-gray-300 text-sm">
                                <input type="checkbox" id="node-provision" class="mr-2">
                                Auto-Provision on GitHub
                            </label>
                        </div>
                        <div class="flex space-x-2">
                            <button onclick="saveNode()" class="flex-1 bg-green-600 hover:bg-green-500 text-white font-bold py-2 rounded">Save</button>
                            <button onclick="closeForm()" class="flex-1 bg-gray-600 hover:bg-gray-500 text-white font-bold py-2 rounded">Cancel</button>
                        </div>
                    </div>

                    <!-- Console Logs -->
                    <div class="bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-700 flex-1">
                        <div class="flex justify-between items-center mb-2">
                            <h3 class="text-lg font-semibold text-white">Terminal Output</h3>
                            <button onclick="clearLogs()" class="text-xs text-gray-400 hover:text-white">Clear</button>
                        </div>
                        <!-- Swapped the JIT height class for an inline style that works globally -->
                        <div id="console-log" style="height: 400px;" class="bg-black border border-gray-700 rounded-lg p-4 font-mono text-sm overflow-y-auto text-green-400 whitespace-pre-wrap">> C2 Initialized...\n</div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            function logToConsole(msg) {
                const con = document.getElementById('console-log');
                con.innerHTML += `> [${new Date().toLocaleTimeString()}] ${msg}\n`;
                con.scrollTop = con.scrollHeight;
            }
            function clearLogs() { document.getElementById('console-log').innerHTML = ''; }

            let fleetData = {};

            async function loadNodes() {
                try {
                    logToConsole("Syncing fleet data...");
                    const res = await fetch('/api/nodes', { cache: 'no-store' });
                    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

                    fleetData = await res.json();

                    const container = document.getElementById('node-list');
                    const targetDropdown = document.getElementById('cmd-target');

                    container.innerHTML = '';
                    targetDropdown.innerHTML = '<option value="all">🌐 Broadcast (All Nodes)</option>';

                    const nodeCount = Object.keys(fleetData).length;
                    if (nodeCount === 0) {
                        container.innerHTML = '<p class="text-gray-500 p-4">No nodes found in fleet.json. Click "+ Add New Node" to begin.</p>';
                        return;
                    }

                    for (const [id, n] of Object.entries(fleetData)) {
                        container.innerHTML += `
                        <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between bg-gray-900 border border-gray-700 rounded-lg p-4 gap-4">
                            <div class="flex items-center space-x-4">
                                <span class="text-3xl">${n.icon}</span>
                                <div>
                                    <h3 class="font-bold text-lg text-white">${n.name}</h3>
                                    <p class="text-sm text-gray-400">Host: ${n.worker_id} | Repo: ${n.public_repo}</p>
                                </div>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                <button onclick="actionNode('${id}', 'spawn')" class="bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded shadow" title="Start Machine">▶ Boot</button>
                                <button onclick="actionNode('${id}', 'stop')" class="bg-red-600 hover:bg-red-500 text-white px-3 py-1 rounded shadow" title="Backup & Terminate">🛑 Stop</button>
                                <button onclick="actionNode('${id}', 'init')" class="bg-yellow-600 hover:bg-yellow-500 text-white px-3 py-1 rounded shadow" title="Push cloud_init Script">⚙️ Push Init</button>
                                <button onclick="editForm('${id}')" class="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded shadow">✏️</button>
                                <button onclick="deleteNode('${id}')" class="bg-gray-700 hover:bg-red-600 text-white px-3 py-1 rounded shadow">🗑️</button>
                            </div>
                        </div>`;
                        targetDropdown.innerHTML += `<option value="${id}">${n.icon} ${n.name}</option>`;
                    }
                    logToConsole(`✅ Successfully loaded ${nodeCount} nodes.`);
                } catch (err) {
                    logToConsole(`❌ UI Error: Failed to load nodes. ${err.message}`);
                }
            }

            async function executeCommand() {
                const target = document.getElementById('cmd-target').value;
                const cmd = document.getElementById('cmd-input').value;
                if(!cmd) return;
                logToConsole(`Executing: '${cmd}'...`);
                document.getElementById('cmd-input').value = '';
                try {
                    const res = await fetch(`/api/exec/${target}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ command: cmd })
                    });
                    const data = await res.json();
                    logToConsole(data.message);
                } catch(e) { logToConsole(`❌ Network error.`); }
            }

            document.getElementById('cmd-input').addEventListener('keypress', function (e) {
                if (e.key === 'Enter') executeCommand();
            });

            async function actionNode(id, action) {
                logToConsole(`Sending ${action} signal...`);
                try {
                    const res = await fetch(`/api/${action}/${id}`, { method: 'POST' });
                    const data = await res.json();
                    logToConsole(data.message);
                } catch(e) { logToConsole(`❌ Network error.`); }
            }

            async function deleteNode(id) {
                if(!confirm("Delete node from dashboard? (GitHub repos remain untouched)")) return;
                await fetch(`/api/nodes/${id}`, { method: 'DELETE' });
                loadNodes();
            }

            function openForm() {
                document.getElementById('form-title').innerText = "Add Node";
                document.getElementById('node-id').value = "";
                document.getElementById('node-name').value = "";
                document.getElementById('node-repo').value = "";
                document.getElementById('node-worker').value = "";
                document.getElementById('node-icon').value = "🚀";
                document.getElementById('node-init-script').value = "#!/bin/bash\nexec > /tmp/cloud_init.log 2>&1\n\n# Fix permissions\nsudo chown -R $USER:$USER /home/$USER\n\n# Your commands here\nsudo apt-get update\n";
                document.getElementById('node-provision').checked = false;
                document.getElementById('node-form-card').classList.remove('hidden');
            }

            function editForm(id) {
                const n = fleetData[id];
                document.getElementById('form-title').innerText = "Edit Node";
                document.getElementById('node-id').value = id;
                document.getElementById('node-name').value = n.name;
                document.getElementById('node-repo').value = n.public_repo;
                document.getElementById('node-worker').value = n.worker_id;
                document.getElementById('node-icon').value = n.icon;
                document.getElementById('node-init-script').value = n.cloud_init || "";
                document.getElementById('node-provision').checked = false;
                document.getElementById('node-form-card').classList.remove('hidden');
            }

            function closeForm() { document.getElementById('node-form-card').classList.add('hidden'); }

            async function saveNode() {
                const id = document.getElementById('node-id').value;
                const node = {
                    name: document.getElementById('node-name').value,
                    public_repo: document.getElementById('node-repo').value,
                    worker_id: document.getElementById('node-worker').value,
                    icon: document.getElementById('node-icon').value,
                    cloud_init: document.getElementById('node-init-script').value,
                    auto_provision: document.getElementById('node-provision').checked
                };

                logToConsole(`Saving metadata...`);
                const url = id ? `/api/nodes/${id}` : '/api/nodes';
                try {
                    const res = await fetch(url, {
                        method: id ? 'PUT' : 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(node)
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail);
                    logToConsole(`✅ ${data.message}`);
                    closeForm();
                    loadNodes();
                } catch (error) { logToConsole(`❌ Error: ${error.message}`); }
            }
            window.onload = loadNodes;
        </script>
    </body>
    </html>
    """
# ==========================================
# 🔒 NETWORK BINDING (TAILSCALE ONLY)
# ==========================================
def get_tailscale_ip():
    try:
        res = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception as e:
        print(f"⚠️ Could not detect Tailscale IP: {e}")
        return "127.0.0.1"

if __name__ == "__main__":
    ts_ip = get_tailscale_ip()
    print(f"🔒 Starting Secure C2 Server bound to Tailscale Interface: http://{ts_ip}:8000")
    uvicorn.run(app, host=ts_ip, port=8000)
