let chart1 = null;

/* ------------ FETCH DATA ------------- */

async function fetchData() {
  // Check if this is a new upload result
  if (fileId === "new") {
    const storedResults = sessionStorage.getItem("comparisonResults");

    if (!storedResults) {
      throw new Error(
        "No comparison results found. Please upload a file first."
      );
    }

    // Clear the stored results after retrieving them
    sessionStorage.removeItem("comparisonResults");

    // Transform comparison results into the format expected by renderMetadata
    const results = JSON.parse(storedResults);
    return transformComparisonResults(results);
  }

  // Otherwise, fetch from API (existing file in database)
  const res = await fetch(`/api/file/${fileId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch file data: ${res.status}`);
  }
  return await res.json();
}

function transformComparisonResults(compareData) {
  /**
   * Transform /api/compare response into format expected by visualize page
   *
   * Input: { uploaded_file: {...}, tlsh: {...}, ssdeep: {...} }
   * Output: { name, size, file_type, hashes: {...}, similar: [...] }
   */

  const uploadedFile = compareData.uploaded_file;
  const tlshMatches = compareData.tlsh?.top_10_matches || [];
  const ssdeepMatches = compareData.ssdeep?.top_10_matches || [];

  // Merge matches from both algorithms, creating a combined similar array
  const similarMap = new Map();

  // Add TLSH matches
  tlshMatches.forEach((match) => {
    similarMap.set(match.sha256, {
      sha256: match.sha256,
      name: match.name,
      family: match.family,
      file_type: match.file_type,
      tags: match.tags || [],
      tlsh_score: Math.max(0, 100 - match.distance), // Convert distance to similarity score
      ssdeep_score: 0,
    });
  });

  // Add/update with ssdeep matches
  ssdeepMatches.forEach((match) => {
    if (similarMap.has(match.sha256)) {
      similarMap.get(match.sha256).ssdeep_score = match.similarity;
    } else {
      similarMap.set(match.sha256, {
        sha256: match.sha256,
        name: match.name,
        family: match.family,
        file_type: match.file_type,
        tags: match.tags || [],
        tlsh_score: 0,
        ssdeep_score: match.similarity,
      });
    }
  });

  return {
    name: uploadedFile.filename,
    size: `${uploadedFile.content_size_bytes} bytes`,
    file_type: uploadedFile.file_type,
    upload_date: new Date().toISOString(),
    desc: "Newly uploaded file (not in database)",
    hashes: {
      sha256: "N/A (not stored)",
      md5: "N/A",
      tlsh: uploadedFile.hashes.tlsh || "N/A",
      ssdeep: uploadedFile.hashes.ssdeep || "N/A",
    },
    similar: Array.from(similarMap.values()),
  };
}

/* ------------ METADATA RENDER ---------- */

function renderMetadata(meta) {
  const gridHashes = document.getElementById("metadataHashes");
  const gridMain = document.getElementById("metadataMain");

  const hashFields = {
    SHA256: meta.hashes.sha256,
    MD5: meta.hashes.md5,
    TLSH: meta.hashes.tlsh,
    ssdeep: meta.hashes.ssdeep,
  };

  const mainFields = {
    Name: Array.isArray(meta.name) ? meta.name.join(", ") : meta.name,
    Size: meta.size,
    Type: meta.file_type,
    "Upload Date": meta.upload_date || meta.last_upload_date || "N/A",
    Description: meta.desc || "No description",
  };

  // Create grid row with tooltip
  const createGridRow = (key, value) => {
    const isHash = key in hashFields;
    const needsTooltip = isHash && value && value.length > 20;

    const dataAttr = needsTooltip ? `data-full="${value}"` : "";
    const valueDiv = `<div class="value-container" ${dataAttr}>${
      value || "N/A"
    }</div>`;

    return `<div><strong>${key}</strong></div>${valueDiv}`;
  };

  // Render Hashes
  gridHashes.innerHTML = Object.entries(hashFields)
    .map(([key, value]) => createGridRow(key, value))
    .join("");

  // Render Main Metadata
  gridMain.innerHTML = Object.entries(mainFields)
    .map(([key, value]) => createGridRow(key, value))
    .join("");
}

/* ------------ CHART RENDERING ----------- */
function drawChart(canvasId, labels, values, label, color) {
  const ctx = document.getElementById(canvasId);
  const neonColor = color || "rgb(0, 239, 255)"; // #0ef

  return new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: label,
          data: values,
          backgroundColor: neonColor,
          borderColor: neonColor,
          borderWidth: 1,
          hoverBackgroundColor: "rgba(0, 239, 255, 0.7)",
          hoverBorderColor: neonColor,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      scales: {
        x: {
          beginAtZero: true,
          max: 100, // Escala de 0 a 100 para porcentajes de similitud
          grid: { color: "rgba(0, 239, 255, 0.1)" },
          ticks: { color: neonColor },
        },
        y: {
          grid: { display: false },
          ticks: { color: neonColor },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(0, 0, 0, 0.8)",
          titleColor: neonColor,
          bodyColor: "#fff",
          borderColor: neonColor,
          borderWidth: 1,
        },
      },
    },
  });
}

/* ------------ MAIN INIT ---------------- */

async function init() {
  const data = await fetchData();
  const metadata = data;

  renderMetadata(metadata);

  const allSimilar = metadata.similar || [];
  const tlshColor = "rgb(0, 239, 255)"; // Blue Neon
  const ssdeepColor = "rgb(255, 105, 180)"; // Pink Neon

  function updateChart(method) {
    let metricKey = method === "tlsh" ? "tlsh_score" : "ssdeep_score";
    let color = method === "tlsh" ? tlshColor : ssdeepColor;
    let label = method === "tlsh" ? "TLSH Similarity" : "ssdeep Similarity";

    // sort by score of chosen sim hash
    const rankedSimilar = [...allSimilar].sort(
      (a, b) => (b[metricKey] || 0) - (a[metricKey] || 0)
    );

    // 2. Extraer los datos ordenados
    const labels = rankedSimilar.map((x) =>
      Array.isArray(x.name) ? x.name[0] : x.name
    );
    const values = rankedSimilar.map((x) => x[metricKey] || 0);

    // Limpiar gráficos
    if (chart1) chart1.destroy();

    // Renderizar el gráfico principal
    chart1 = drawChart("similarityChart", labels, values, label, color);
  }

  // Initialize with TLSH ranking
  if (allSimilar.length > 0) {
    updateChart("tlsh");
  } else {
    console.warn("No similar files found in metadata");
  }

  document.getElementById("simMethod").addEventListener("change", (e) => {
    const method = e.target.value;
    if (method === "tlsh" || method === "ssdeep") {
      updateChart(method);
    }
  });
}

init();
