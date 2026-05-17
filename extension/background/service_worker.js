// service_worker.js
// Listens for scan results FROM the popup and sets the badge color
// We do NOT auto-scan every tab — that would spam the backend

// Listen for messages from popup.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SCAN_RESULT") {
        const { tabId, riskLevel } = message;

        const colors = {
            LOW: "#1D9E75",
            MEDIUM: "#E8A838",
            HIGH: "#E06B2E",
            CRITICAL: "#E24B4A",
        };

        const badgeText = {
            LOW: "✓",
            MEDIUM: "!",
            HIGH: "!!",
            CRITICAL: "?",
        };

        // Set badge color and text on the extension icon
        chrome.action.setBadgeText({ text: badgeText[riskLevel] || "?", tabId });
        chrome.action.setBadgeBackgroundColor({ color: colors[riskLevel] || "#555", tabId });

        // Show desktop notification for high risk
        if (riskLevel === "HIGH" || riskLevel === "CRITICAL") {
            chrome.notifications.create({
                type: "basic",
                iconUrl: "../icons/icon48.png",
                title: `⚠️ PhishGuard — ${riskLevel} RISK DETECTED`,
                message: message.explanation || "This site may be a phishing attempt.",
                priority: 2,
            });
        }
    }
});

// Clear badge when user navigates to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === "loading") {
        chrome.action.setBadgeText({ text: "", tabId });
    }
});
