document.getElementById("uploadButton").onclick = () => {
    document.getElementById("fileInput").click();
};

document.getElementById("fileInput").onchange = async function () {
    const file = this.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    const status = document.getElementById("status");
    status.textContent = "Uploading...";

    const res = await fetch("/upload", {
        method: "POST",
        body: formData
    });

    const data = await res.json();

    status.textContent = "Processing...";

    // Redirige a la página de visualización
    window.location.href = `/visualize/${data.id}`;
};

