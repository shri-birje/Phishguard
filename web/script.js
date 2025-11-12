async function checkPhishing() {
    const urlInput = document.getElementById('urlInput').value;
    const resultBox = document.getElementById('result');

    if (!urlInput) {
        resultBox.textContent = "⚠️ Please enter a valid URL.";
        return;
    }

    resultBox.textContent = "🔍 Analyzing...";

    try {
        // ✅ Use the correct backend API endpoint:
        const API_BASE = "https://phish-guard-3uvw.onrender.com";

        const response = await fetch(`${API_BASE}/api/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });
        console.log("Sending request to:", `${API_BASE}/api/check`);

        if (!response.ok) {
            throw new Error(`Server responded with ${response.status}`);
        }

        const result = await response.json();

        if (result.risk_level === "High" || result.prediction === "phishing") {
            resultBox.style.background = "rgba(255, 0, 0, 0.4)";
            resultBox.textContent = `🚨 Warning! The URL "${urlInput}" is likely a phishing domain.`;
        } else {
            resultBox.style.background = "rgba(0, 255, 0, 0.3)";
            resultBox.textContent = `✅ Safe! The URL "${urlInput}" appears legitimate.`;
        }

    } catch (error) {
        resultBox.style.background = "rgba(255, 165, 0, 0.3)";
        resultBox.textContent = "❌ Error: Unable to connect to the backend.";
        console.error("Connection error:", error);
    }
}
const API_BASE = "https://phish-guard-3uvw.onrender.com";

async function checkPhishing() {
    const urlInput = document.getElementById('urlInput').value;
    const resultBox = document.getElementById('result');
    const blockBtn = document.getElementById('blockBtn');

    if (!urlInput) {
        resultBox.textContent = "⚠️ Please enter a valid URL.";
        return;
    }

    resultBox.textContent = "🔍 Analyzing...";
    blockBtn.style.display = "none";

    try {
        const response = await fetch(`${API_BASE}/api/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        const result = await response.json();
        if (result.prediction === "phishing" || result.risk_level === "High") {
            resultBox.style.background = "rgba(255, 0, 0, 0.4)";
            resultBox.textContent = `🚨 Warning! "${urlInput}" is likely a phishing domain.`;
            blockBtn.style.display = "block";
        } else {
            resultBox.style.background = "rgba(0, 255, 0, 0.3)";
            resultBox.textContent = `✅ Safe! "${urlInput}" appears legitimate.`;
        }
    } catch (err) {
        resultBox.textContent = "❌ Error connecting to backend.";
    }
}

function blockUrl() {
    const url = document.getElementById('urlInput').value;
    fetch(`${API_BASE}/api/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, reason: "User manual block" })
    });
    alert(`🚫 URL "${url}" has been blocked.`);
}
