document.getElementById("uploadButton").onclick = () => {
  document.getElementById("fileInput").click();
};

document.getElementById("fileInput").onchange = async function () {
  const file = this.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);
  // Always save new files to database
  formData.append("save_to_db", "true");

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
    const savedToDb = uploadedFile.saved_to_database;

    if (savedToDb) {
      status.textContent = "File saved to database! Redirecting...";
      console.log(`New file saved to database: ${sha256}`);
    } else if (existsInDb) {
      status.textContent = "File already in database! Redirecting...";
      console.log(`File already exists in database: ${sha256}`);
    } else {
      status.textContent = "Analysis complete! Redirecting...";
    }

    // Always redirect to the SHA256 page now (since file is in DB)
    setTimeout(() => {
      window.location.href = `/visualize/${sha256}`;
    }, 500);
  } catch (error) {
    status.textContent = `Error: ${error.message}`;
    status.style.color = "#ff4444";
    console.error("Upload error:", error);
  }
};
