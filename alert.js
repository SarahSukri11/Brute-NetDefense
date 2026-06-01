async function updateAlertsPage() {
    const response = await fetch("/api/alerts");
    const alerts = await response.json();

    let critical = 0;
    let high = 0;
    let low = 0;

    alerts.forEach(alert => {
        const severity = (alert.severity || "HIGH").toUpperCase();

        if (severity === "CRITICAL") critical++;
        else if (severity === "HIGH") high++;
        else if (severity === "LOW") low++;
    });

    document.getElementById("criticalCount").innerText = critical;
    document.getElementById("highCount").innerText = high;
    document.getElementById("lowCount").innerText = low;
    document.getElementById("totalCount").innerText = alerts.length;

    const list = document.getElementById("alertsList");
    list.innerHTML = "";

    if (alerts.length === 0) {
        list.innerHTML = `<p class="empty-alert">No alerts available yet</p>`;
        return;
    }

    alerts.slice(-10).reverse().forEach(alert => {
        const severity = (alert.severity || "HIGH").toUpperCase();
        const ip = alert.src_ip || alert.ip || alert.source_ip || "Unknown";
        const encodedIp = encodeURIComponent(ip);
        const time = alert.time || alert.timestamp || "Unknown";
        const attack = alert.attack || "Brute Force Attack";

        list.innerHTML += `
            <div class="alert-item ${severity.toLowerCase()}">
                <div>
                    <span class="severity-badge ${severity.toLowerCase()}">${severity}</span>

                    <h3>${attack}</h3>

                    <p>
                        Detected suspicious activity from 
                        <strong>${ip}</strong>
                    </p>

                    <small>Time: ${time}</small>
                </div>

                <div class="response-actions">
                    <button type="button" class="respond-btn" onclick="blockIP('${encodedIp}', '${ip}')">
                        Block IP
                    </button>

                    <button type="button" class="unblock-btn" onclick="unblockIP('${encodedIp}', '${ip}')">
                        Unblock IP
                    </button>
                </div>
            </div>
        `;
    });
}

async function blockIP(encodedIp, ip) {
    try {
        const response = await fetch(`/respond/${encodedIp}`);
        if (response.ok) {
            alert(`IP ${ip} has been blocked successfully.`);
            updateAlertsPage();
        } else {
            alert("Failed to block IP.");
        }
    } catch (error) {
        alert("Failed to block IP.");
    }
}

async function unblockIP(encodedIp, ip) {
    try {
        const response = await fetch(`/unblock/${encodedIp}`);
        if (response.ok) {
            alert(`IP ${ip} has been unblocked successfully.`);
            updateAlertsPage();
        } else {
            alert("Failed to unblock IP.");
        }
    } catch (error) {
        alert("Failed to unblock IP.");
    }
}

document.addEventListener("DOMContentLoaded", function () {
    updateAlertsPage();
    setInterval(updateAlertsPage, 2000);
});