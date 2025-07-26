const express = require("express");
const multer = require("multer");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();

const app = express();
const upload = multer();
app.use(cors());
app.use(express.static("public"));

const VT_API_KEY = process.env.VT_API_KEY;

app.post("/api/scan", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  try {
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/files",
      req.file.buffer,
      {
        headers: {
          "x-apikey": VT_API_KEY,
          "Content-Type": "application/octet-stream",
        },
      }
    );

    const analysisUrl = response.data.data.id;

    // čekání na výsledky
    setTimeout(async () => {
      const result = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisUrl}`,
        {
          headers: { "x-apikey": VT_API_KEY },
        }
      );

      res.json(result.data);
    }, 6000); // trochu počkáme na zpracování

  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: "Scan failed" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Skibidi Antivirus API running on ${port}`));
