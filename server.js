const express = require("express");
const multer = require("multer");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();

// Důležité: Přidáme 'form-data' pro vytvoření multipart/form-data požadavků
const FormData = require('form-data'); // <-- NOVINKA

const app = express();
const upload = multer();
app.use(cors());
app.use(express.static("public"));

const VT_API_KEY = process.env.VT_API_KEY;

if (!VT_API_KEY) {
  console.error("💥 VT_API_KEY environment variable is not set!");
}

app.post("/api/scan", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  console.log(`Received file: ${req.file.originalname}, size: ${req.file.size} bytes`);

  if (!VT_API_KEY) {
    return res.status(500).json({ error: "VirusTotal API key is not configured on the server." });
  }

  try {
    // Krok 1: Nahrání souboru na VirusTotal
    console.log("Uploading file to VirusTotal...");

    // Vytvoříme nový FormData objekt pro odeslání souboru na VirusTotal
    const form = new FormData(); // <-- NOVINKA
    // Přidáme soubor k FormData s názvem pole "file"
    form.append('file', req.file.buffer, { filename: req.file.originalname }); // <-- NOVINKA

    const uploadResponse = await axios.post(
      "https://www.virustotal.com/api/v3/files",
      form, // <-- ZMĚNA: posíláme FormData objekt
      {
        headers: {
          ...form.getHeaders(), // <-- ZMĚNA: Důležité pro nastavení 'Content-Type: multipart/form-data' s boundary
          "x-apikey": VT_API_KEY,
          // 'Content-Type' už není 'application/octet-stream', ale 'multipart/form-data' s boundary,
          // které zajistí `form.getHeaders()`
        },
      }
    );

    const analysisId = uploadResponse.data.data.id;
    console.log(`File uploaded. Analysis ID: ${analysisId}`);

    // Krok 2: Čekání na výsledky analýzy
    console.log("Waiting for analysis results (6 seconds timeout)...");
    setTimeout(async () => {
      try {
        const resultResponse = await axios.get(
          `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          {
            headers: { "x-apikey": VT_API_KEY },
          }
        );
        console.log("Analysis results received.");
        res.json(resultResponse.data);
      } catch (err) {
        console.error("Error fetching analysis results from VirusTotal:", err.response?.data || err.message);
        res.status(500).json({ error: "Failed to retrieve scan results from VirusTotal." });
      }
    }, 6000);

  } catch (err) {
    console.error("Error during file upload to VirusTotal or initial API call:", err.response?.data || err.message);
    if (err.response && err.response.data && err.response.data.error && err.response.data.error.message) {
      res.status(err.response.status || 500).json({ error: `VirusTotal API error: ${err.response.data.error.message}` });
    } else {
      res.status(500).json({ error: "Scan failed due to an unexpected server error." });
    }
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Skibidi Antivirus API running on ${port}`));