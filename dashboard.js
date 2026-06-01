let dashboardChart;

function createDashboardChart() {
    const ctx = document.getElementById("trafficChart");

    dashboardChart = new Chart(ctx, {
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
                    tension: 0.4
                },
                {
                    label: "Brute Force Attack",
                    data: [],
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239, 68, 68, 0.15)",
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    title: {
                        display: true,
                        text: "Time"
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: "Detection Status"
                    },
                    min: 0,
                    max: 1,
                    ticks: {
                        stepSize: 1,
                        callback: function(value) {
                            if (value === 0) return "Normal";
                            if (value === 1) return "Detected";
                            return value;
                        }
                    }
                }
            }
        }
    });
}

async function updateDashboard() {
    try {
        if (!monitoringActive) {
            return;
        }

        const response = await fetch("/api/dashboard_traffic");
        const data = await response.json();

        document.getElementById("totalTraffic").innerText = data.length;

        const attacks = data.filter(item => {
            const status = (item.status || "").toLowerCase();
            return status.includes("brute") || status.includes("attack");
        }).length;

        const failed = data.reduce((sum, item) => {
            return sum + Number(item.failed_attempt || 0);
        }, 0);

        document.getElementById("detectedAttacks").innerText = attacks;
        document.getElementById("failedAttempts").innerText = failed;

        const latest = data.slice(-15);

        dashboardChart.data.labels = latest.map(item => {
            const time = item.time || item.timestamp || "";
            return time.toString().split(" ")[1] || time;
        });

        dashboardChart.data.datasets[0].data = latest.map(item => {
            const status = (item.status || "Normal").toLowerCase();
            return status.includes("normal") ? 1 : 0;
        });

        dashboardChart.data.datasets[1].data = latest.map(item => {
            const status = (item.status || "").toLowerCase();
            return status.includes("brute") || status.includes("attack") ? 1 : 0;
        });

        dashboardChart.update();

    } catch (error) {
        console.log("Dashboard update error:", error);
    }
}

document.addEventListener("DOMContentLoaded", function () {
    createDashboardChart();
    updateDashboard();
    setInterval(updateDashboard, 2000);
});