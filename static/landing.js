document.getElementById("uploadButton").onclick = () => {
  document.getElementById("fileInput").click();
};

document.getElementById("fileInput").onchange = async function () {
  const file = this.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  const status = document.getElementById("status");
  status.textContent = "Uploading and analyzing...";
  status.style.color = "#fff";

  try {
    const res = await fetch("/api/compare", {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      const error = await res.json();
      status.textContent = `Error: ${error.error || "Upload failed"}`;
      status.style.color = "#ff4444";
      return;
    }

    const data = await res.json();

    const uploadedFile = data.uploaded_file;
    const sha256 = uploadedFile.sha256;
    const existsInDb = uploadedFile.exists_in_database;

    status.textContent = "Analysis complete! Redirecting...";

    if (existsInDb) {
      // File exists in database - redirect to its SHA256 page
      console.log(`File found in database: ${sha256}`);
      setTimeout(() => {
        window.location.href = `/visualize/${sha256}`;
      }, 500);
    } else {
      // New file - store results and redirect to /visualize/new
      console.log(`New file uploaded: ${sha256}`);
      sessionStorage.setItem("comparisonResults", JSON.stringify(data));
      setTimeout(() => {
        window.location.href = `/visualize/new`;
      }, 500);
    }
  } catch (error) {
    status.textContent = `Error: ${error.message}`;
    status.style.color = "#ff4444";
    console.error("Upload error:", error);
  }
};
