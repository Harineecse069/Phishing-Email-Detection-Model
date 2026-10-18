const emailForm = document.getElementById("emailForm");
const subjectInput = document.getElementById("subject");
const contentInput = document.getElementById("emailContent");

const resultSection = document.getElementById("resultSection");
const resultBadge = document.getElementById("resultBadge");
const riskScore = document.getElementById("riskScore");
const findingsList = document.getElementById("findings");
const historyBody = document.getElementById("historyBody");

let total = 0;
let phishingTotal = 0;
let safeTotal = 0;

const history = [];

// Analyze the email using simple rules.
function analyzeEmail(subject, content) {
    const text = subject + " " + content;
    const lowerText = text.toLowerCase();

    let score = 0;
    const findings = [];

    const suspiciousPhrases = [
        "verify your account",
        "account suspended",
        "urgent action",
        "click here immediately",
        "confirm your password",
        "update your payment",
        "you have won",
        "claim your prize",
        "send your password",
        "login immediately"
    ];

    for (const phrase of suspiciousPhrases) {
        if (lowerText.includes(phrase)) {
            score += 15;
            findings.push(
                "Suspicious phrase detected: \"" + phrase + "\"."
            );
        }
    }

    // Extract URLs from the email.
    const urlPattern = /https?:\/\/[^\s<>"']+/gi;
    const urls = content.match(urlPattern) || [];

    if (urls.length > 0) {
        findings.push(urls.length + " URL(s) found in the email.");

        for (const item of urls) {
            try {
                const url = new URL(item);
                const hostname = url.hostname.toLowerCase();

                if (url.protocol !== "https:") {
                    score += 15;
                    findings.push(
                        "A link uses HTTP rather than HTTPS: " + item
                    );
                }

                if (hostname.startsWith("xn--") ||
                    hostname.split(".").some(part =>
                        part.startsWith("xn--")
                    )) {
                    score += 20;
                    findings.push(
                        "A link contains an internationalized hostname."
                    );
                }

                if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
                    score += 20;
                    findings.push(
                        "A link uses an IP address instead of a domain name."
                    );
                }

                if (url.username || url.password) {
                    score += 25;
                    findings.push(
                        "A link contains an unusual username or password field."
                    );
                }

            } catch {
                score += 10;
                findings.push("A URL could not be parsed.");
            }
        }
    }

    const urgencyWords = [
        "urgent",
        "immediately",
        "suspended",
        "limited time",
        "act now"
    ];

    if (urgencyWords.some(word => lowerText.includes(word))) {
        score += 10;
        findings.push("Urgency-related language detected.");
    }

    const passwordWords = [
        "password",
        "bank details",
        "credit card",
        "otp",
        "one-time password"
    ];

    if (passwordWords.some(word => lowerText.includes(word))) {
        score += 15;
        findings.push("The email mentions sensitive information.");
    }

    score = Math.min(score, 100);

    // This threshold is only a demonstration rule.
    const classification = score >= 30 ? "Phishing" : "Safe";

    if (findings.length === 0) {
        findings.push(
            "No indicators covered by these simple rules were detected."
        );
    }

    return {
        score,
        classification,
        findings
    };
}

function displayResult(result) {
    resultSection.hidden = false;

    resultBadge.textContent = result.classification;
    resultBadge.className =
        result.classification === "Phishing" ? "phishing" : "safe";

    riskScore.textContent =
        "Rule-based risk score: " + result.score + "/100";

    findingsList.replaceChildren();

    for (const finding of result.findings) {
        const li = document.createElement("li");
        li.textContent = finding;
        findingsList.appendChild(li);
    }
}

function updateDashboard() {
    document.getElementById("totalEmails").textContent = total;
    document.getElementById("phishingCount").textContent = phishingTotal;
    document.getElementById("safeCount").textContent = safeTotal;
}

function displayHistory() {
    historyBody.replaceChildren();

    for (const item of history.slice().reverse()) {
        const row = document.createElement("tr");

        const subjectCell = document.createElement("td");
        const classificationCell = document.createElement("td");
        const scoreCell = document.createElement("td");

        subjectCell.textContent = item.subject;
        classificationCell.textContent = item.classification;
        scoreCell.textContent = item.score + "/100";

        row.append(subjectCell, classificationCell, scoreCell);
        historyBody.appendChild(row);
    }
}

emailForm.addEventListener("submit", function (event) {
    event.preventDefault();

    const subject = subjectInput.value.trim();
    const content = contentInput.value.trim();

    if (!subject || !content) {
        alert("Please enter both the subject and email content.");
        return;
    }

    const result = analyzeEmail(subject, content);

    displayResult(result);

    total++;

    if (result.classification === "Phishing") {
        phishingTotal++;
    } else {
        safeTotal++;
    }

    history.push({
        subject,
        classification: result.classification,
        score: result.score
    });

    updateDashboard();
    displayHistory();
});

document.getElementById("clearButton").addEventListener("click", function () {
    emailForm.reset();
    resultSection.hidden = true;
});

// A small, built-in demonstration dataset.
// Labels are illustrative and are not a validated benchmark.
const demoDataset = [
    {
        subject: "Urgent account suspended",
        content: "Verify your account immediately. Confirm your password.",
        actual: "Phishing"
    },
    {
        subject: "You have won a prize",
        content: "Claim your prize now. Click here immediately.",
        actual: "Phishing"
    },
    {
        subject: "Payment update required",
        content: "Update your payment and login immediately.",
        actual: "Phishing"
    },
    {
        subject: "Meeting schedule",
        content: "Hello, our meeting is scheduled for Monday at 10 AM.",
        actual: "Safe"
    },
    {
        subject: "Project report",
        content: "Please review the project report before tomorrow.",
        actual: "Safe"
    },
    {
        subject: "Class notes",
        content: "I have shared the notes from today's lecture.",
        actual: "Safe"
    }
];

document.getElementById("evaluateButton").addEventListener(
    "click",
    function () {
        let tp = 0;
        let tn = 0;
        let fp = 0;
        let fn = 0;

        for (const email of demoDataset) {
            const prediction = analyzeEmail(
                email.subject,
                email.content
            ).classification;

            if (email.actual === "Phishing" &&
                prediction === "Phishing") {
                tp++;
            } else if (email.actual === "Safe" &&
                       prediction === "Safe") {
                tn++;
            } else if (email.actual === "Safe" &&
                       prediction === "Phishing") {
                fp++;
            } else {
                fn++;
            }
        }

        const accuracy =
            ((tp + tn) / demoDataset.length) * 100;

        const precision =
            tp + fp === 0 ? 0 : (tp / (tp + fp)) * 100;

        const recall =
            tp + fn === 0 ? 0 : (tp / (tp + fn)) * 100;

        document.getElementById("accuracy").textContent =
            accuracy.toFixed(1) + "%";

        document.getElementById("precision").textContent =
            precision.toFixed(1) + "%";

        document.getElementById("recall").textContent =
            recall.toFixed(1) + "%";

        document.getElementById("tp").textContent = tp;
        document.getElementById("fn").textContent = fn;
        document.getElementById("fp").textContent = fp;
        document.getElementById("tn").textContent = tn;

        document.getElementById("evaluationResults").hidden = false;
    }
);

