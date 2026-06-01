let trafficChart;

function createTrafficChart() {
    const ctx = document.getElementById("trafficAnalysisChart");

    trafficChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "Normal Traffic",
                    data: [],
                    borderColor: "#22c55e",
                    backgroundColor: "rgba(34, 197, 94, 0.15)",
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3
                },
                {
                    label: "Brute Force",
                    data: [],
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239, 68, 68, 0.15)",
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: {
                    position: "top"
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: "Time"
                    },
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                },
                y: {
                    beginAtZero: true,
                    min: 0,
                    ticks: {
                        stepSize: 10,
                        precision: 0
                    },
                    title: {
                        display: true,
                        text: "Traffic Count"
                    }
                }
            }
        }
    });
}

async function updateTrafficPage() {
    const response = await fetch("/api/traffic");
    const data = await response.json();

    const totalBox = document.getElementById("trafficTotal");
    const attacksBox = document.getElementById("trafficAttacks");
    const failedBox = document.getElementById("trafficFailed");

    if (totalBox) totalBox.innerText = data.length;

    const attacks = data.filter(item => {
        const status = (item.status || "").toLowerCase();
        return status.includes("brute") || status.includes("attack");
    }).length;

    const failed = data.reduce((sum, item) => {
        return sum + Number(item.failed_attempt || 0);
    }, 0);

    if (attacksBox) attacksBox.innerText = attacks;
    if (failedBox) failedBox.innerText = failed;

    const latest = data.slice(-30);

    trafficChart.data.labels = latest.map(item => {
        const time = item.time || item.timestamp || "";
        return time.toString().split(" ")[1] || time;
    });

    trafficChart.data.datasets[0].data = latest.map(item => {
        const status = (item.status || "Normal").toLowerCase();

        if (status === "normal") {
            return Math.floor(Math.random() * 40) + 10;
        }

        return 0;
    });

    trafficChart.data.datasets[1].data = latest.map(item => {
        const status = (item.status || "Normal").toLowerCase();

        if (status.includes("brute") || status.includes("attack")) {
            return Math.floor(Math.random() * 8) + 2;
        }

        return 0;
    });

    trafficChart.update();

    const tbody = document.getElementById("trafficTableBody");
    tbody.innerHTML = "";

    if (data.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-row">No traffic data yet</td>
            </tr>
        `;
        return;
    }

    data.slice(-20).reverse().forEach(item => {
        const time = item.time || item.timestamp || "Unknown";
        const srcIp = item.src_ip || item.source_ip || "Unknown";
        const dstIp = item.dst_ip || item.destination_ip || "Unknown";
        const dstPort = item.dst_port || item.destination_port || "Unknown";
        const protocol = item.protocol || "Unknown";
        const failedAttempt = item.failed_attempt || 0;
        const status = item.status || "Normal";

        tbody.innerHTML += `
            <tr>
                <td>${time}</td>
                <td>${srcIp}</td>
                <td>${dstIp}</td>
                <td>${dstPort}</td>
                <td>${protocol}</td>
                <td>${failedAttempt}</td>
                <td>
                    <span class="badge ${status.toLowerCase().replace(/\s+/g, '-')}">
                        ${status}
                    </span>
                </td>
            </tr>
        `;
    });
}

createTrafficChart();
updateTrafficPage();
setInterval(updateTrafficPage, 2000);