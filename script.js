document.getElementById("scan-btn").addEventListener("click", async () => {
  const file = document.getElementById("file").files[0];
  const status = document.getElementById("status");
  const results = document.getElementById("results");

  if (!file) {
    status.textContent = "❌ bro u forgot the file 💀";
    return;
  }

  status.textContent = "🔍 Skibidi scanning... hold tight giga chad 🧠";
  results.textContent = "";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();
    if (data.error) {
      status.textContent = "💥 API go boom: " + data.error;
      return;
    }

    const malicious = data.data.attributes.stats.malicious;
    const harmless = data.data.attributes.stats.harmless;

    if (malicious > 0) {
      results.innerHTML = `☠️ ${malicious} antiviruses say: THIS FILE SUS 💀`;
    } else {
      results.innerHTML = `🧼 giga clean: ${harmless} antiviruses say YES 🔥`;
    }

    status.textContent = "✅ Skibidi scan complete";

  } catch (err) {
    console.error(err);
    status.textContent = "💥 scan go kaboom 💀";
  }
});
