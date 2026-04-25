const express = require("express");
const axios = require("axios");
const multer = require("multer");
const cors = require("cors");
const FormData = require("form-data");
require("dotenv").config();

const app = express();
const API_KEY = process.env.VT_API_KEY;
const PORT = process.env.PORT || 3000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_SCANS_PER_WINDOW = Number(process.env.MAX_SCANS_PER_MINUTE || 5);
const MAX_FILE_SIZE_BYTES = Number(process.env.MAX_FILE_SIZE_MB || 10) * 1024 * 1024;
const upload = multer({
    limits: {
        fileSize: MAX_FILE_SIZE_BYTES
    }
});
const ipScanHistory = new Map();

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

if (!API_KEY) {
    console.error("Thieu VT_API_KEY trong file .env");
    process.exit(1);
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function getClientIp(req) {
    const forwardedFor = req.headers["x-forwarded-for"];

    if (typeof forwardedFor === "string" && forwardedFor.trim()) {
        return forwardedFor.split(",")[0].trim();
    }

    return req.ip || req.socket?.remoteAddress || "unknown";
}

function cleanupIpHistory(now) {
    for (const [ip, timestamps] of ipScanHistory.entries()) {
        const validTimestamps = timestamps.filter(
            (timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS
        );

        if (validTimestamps.length === 0) {
            ipScanHistory.delete(ip);
            continue;
        }

        ipScanHistory.set(ip, validTimestamps);
    }
}

function enforceScanRateLimit(req, res, next) {
    const now = Date.now();
    const ip = getClientIp(req);

    cleanupIpHistory(now);

    const recentScans = (ipScanHistory.get(ip) || []).filter(
        (timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS
    );

    if (recentScans.length >= MAX_SCANS_PER_WINDOW) {
        return res.status(429).json({
            error: `Moi IP chi duoc scan toi da ${MAX_SCANS_PER_WINDOW} lan moi phut. Vui long thu lai sau.`
        });
    }

    recentScans.push(now);
    ipScanHistory.set(ip, recentScans);
    return next();
}

function handleUpload(req, res, next) {
    upload.single("file")(req, res, (error) => {
        if (!error) {
            return next();
        }

        if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `File vuot qua gioi han ${Math.floor(MAX_FILE_SIZE_BYTES / (1024 * 1024))}MB.`
            });
        }

        return res.status(400).json({
            error: error.message || "Khong the tai file len."
        });
    });
}

async function waitForAnalysis(analysisId, options = {}) {
    const {
        maxRetries = 20,
        delayMs = 3000,
        timeoutMessage = "Virus Checker phan tich qua lau, vui long thu lai."
    } = options;

    for (let attempt = 0; attempt < maxRetries; attempt += 1) {
        const result = await axios.get(
            `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
            { headers: { "x-apikey": API_KEY } }
        );

        if (result.data?.data?.attributes?.status === "completed") {
            return result.data;
        }

        await sleep(delayMs);
    }

    const timeoutError = new Error(timeoutMessage);
    timeoutError.analysisId = analysisId;
    timeoutError.code = "ANALYSIS_TIMEOUT";
    throw timeoutError;
}

app.post("/scan-url", enforceScanRateLimit, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: "Thieu URL" });
        }

        const response = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            new URLSearchParams({ url }),
            {
                headers: {
                    "x-apikey": API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }
        );

        const analysisId = response.data.data.id;
        const result = await waitForAnalysis(analysisId, {
            maxRetries: 20,
            delayMs: 2500,
            timeoutMessage: "URL dang duoc phan tich lau hon du kien. Vui long thu lai sau."
        });

        return res.json(result);
    } catch (error) {
        console.error("URL ERROR:", error.response?.data || error.message);

        if (error.code === "ANALYSIS_TIMEOUT") {
            return res.status(202).json({
                error: error.message,
                analysisId: error.analysisId,
                pending: true
            });
        }

        return res
            .status(error.response?.status || 500)
            .json(error.response?.data || { error: error.message || "Scan URL fail" });
    }
});

app.post("/scan-file", enforceScanRateLimit, handleUpload, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "Chua chon file" });
        }

        const form = new FormData();
        form.append("file", req.file.buffer, req.file.originalname);

        const response = await axios.post(
            "https://www.virustotal.com/api/v3/files",
            form,
            {
                headers: {
                    ...form.getHeaders(),
                    "x-apikey": API_KEY
                },
                maxBodyLength: Infinity
            }
        );

        const analysisId = response.data.data.id;
        const result = await waitForAnalysis(analysisId, {
            maxRetries: 40,
            delayMs: 3000,
            timeoutMessage: "File dang duoc phan tich. Virus Checker can them thoi gian, vui long doi them roi thu lai."
        });

        return res.json(result);
    } catch (error) {
        console.error("FILE ERROR:", error.response?.data || error.message);

        if (error.code === "ANALYSIS_TIMEOUT") {
            return res.status(202).json({
                error: error.message,
                analysisId: error.analysisId,
                pending: true
            });
        }

        return res
            .status(error.response?.status || 500)
            .json(error.response?.data || { error: error.message || "Scan file fail" });
    }
});

app.listen(PORT, () => {
    console.log(`Server chay tai http://localhost:${PORT}`);
});
