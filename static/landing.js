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

    status.textContent = "Analysis complete! Redirecting...";

    // Store the comparison results in sessionStorage
    sessionStorage.setItem("comparisonResults", JSON.stringify(data));

    // Redirect to visualize page with special 'new' identifier
    setTimeout(() => {
      window.location.href = `/visualize/new`;
    }, 500);
  } catch (error) {
    status.textContent = `Error: ${error.message}`;
    status.style.color = "#ff4444";
    console.error("Upload error:", error);
  }
};
