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
  const data = await res.json();

  // Transform database response to include similar files
  return transformDatabaseResponse(data);
}

function transformDatabaseResponse(dbData) {
  /**
   * Transform database file response to include similar array
   * The backend now calculates similarities on-the-fly and returns
   * similar files with tlsh_score and ssdeep_score already calculated
   */

  console.log("Database response data:", dbData);
  console.log("Similar files from backend:", dbData.similar);

  // The response already includes the similar array calculated by backend
  // Make sure the similar array is properly formatted
  const similar = (dbData.similar || []).map((s) => {
    console.log("Similar file entry:", s);
    return {
      sha256: s.sha256,
      name: s.name,
      family: s.family || "Unknown",
      file_type: s.file_type || "Unknown",
      tags: s.tags || [],
      // Backend already provides these scores
      tlsh_score: s.tlsh_score || 0,
      ssdeep_score: s.ssdeep_score || 0,
    };
  });

  console.log("Transformed similar files:", similar);

  return {
    name: dbData.name,
    size: dbData.size,
    file_type: dbData.file_type,
    upload_date: dbData.last_upload_date || dbData.first_upload_date,
    desc: dbData.desc || "File from database",
    hashes: {
      sha256: dbData.hashes?.sha256 || dbData.sha256 || fileId,
      md5: dbData.hashes?.md5 || "N/A",
      tlsh: dbData.hashes?.tlsh || "N/A",
      ssdeep: dbData.hashes?.ssdeep || "N/A",
    },
    // Use the transformed similar array
    similar: similar,
  };
}

function transformComparisonResults(compareData) {
  /**
   * Transform /api/compare response into format expected by visualize page
   *
   * Input: { uploaded_file: {...}, tlsh: {...}, ssdeep: {...} }
   * Output: { name, size, file_type, hashes: {...}, similar: [...] }
   */

  console.log("=== RAW COMPARISON DATA ===");
  console.log(JSON.stringify(compareData, null, 2));

  const uploadedFile = compareData.uploaded_file;
  const tlshMatches = compareData.tlsh?.top_10_matches || [];
  const ssdeepMatches = compareData.ssdeep?.top_10_matches || [];

  console.log("=== TLSH MATCHES ===");
  console.log("Number of TLSH matches:", tlshMatches.length);
  console.log("TLSH matches:", JSON.stringify(tlshMatches, null, 2));

  console.log("=== SSDEEP MATCHES ===");
  console.log("Number of ssdeep matches:", ssdeepMatches.length);
  console.log("ssdeep matches:", JSON.stringify(ssdeepMatches, null, 2));

  // Merge matches from both algorithms, creating a combined similar array
  const similarMap = new Map();

  // Add TLSH matches
  tlshMatches.forEach((match) => {
    const distance = match.distance;
    const tlshScore = Math.max(0, 100 - distance);

    console.log(
      `Processing TLSH match: ${JSON.stringify(
        match.name
      )} - distance: ${distance}, calculated score: ${tlshScore}`
    );

    similarMap.set(match.sha256, {
      sha256: match.sha256,
      name: match.name,
      family: match.family || "Unknown",
      file_type: match.file_type || "Unknown",
      tags: match.tags || [],
      tlsh_score: tlshScore,
      ssdeep_score: 0,
    });
  });

  // Add/update with ssdeep matches
  ssdeepMatches.forEach((match) => {
    console.log(
      `Processing ssdeep match: ${JSON.stringify(match.name)} - similarity: ${
        match.similarity
      }`
    );

    if (similarMap.has(match.sha256)) {
      similarMap.get(match.sha256).ssdeep_score = match.similarity || 0;
    } else {
      similarMap.set(match.sha256, {
        sha256: match.sha256,
        name: match.name,
        family: match.family || "Unknown",
        file_type: match.file_type || "Unknown",
        tags: match.tags || [],
        tlsh_score: 0,
        ssdeep_score: match.similarity || 0,
      });
    }
  });

  const similarArray = Array.from(similarMap.values());
  console.log("=== FINAL SIMILAR ARRAY ===");
  console.log(JSON.stringify(similarArray, null, 2));

  return {
    name: uploadedFile.filename,
    size: `${uploadedFile.content_size_bytes} bytes`,
    file_type: uploadedFile.file_type,
    upload_date: new Date().toISOString(),
    desc: "Newly uploaded file (not in database)",
    hashes: {
      sha256: uploadedFile.hashes.sha256 || uploadedFile.sha256 || "N/A",
      md5: uploadedFile.hashes.md5 || "N/A",
      tlsh: uploadedFile.hashes.tlsh || "N/A",
      ssdeep: uploadedFile.hashes.ssdeep || "N/A",
    },
    similar: similarArray,
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
    Size: typeof meta.size === "number" ? `${meta.size} bytes` : meta.size,
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
  const neonColor = color || "rgb(0, 239, 255)";

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
          max: 100,
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
  try {
    const data = await fetchData();
    const metadata = data;

    renderMetadata(metadata);

    const allSimilar = metadata.similar || [];
    console.log("All similar files for charting:", allSimilar);

    const tlshColor = "rgb(0, 239, 255)"; // Blue Neon
    const ssdeepColor = "rgb(255, 105, 180)"; // Pink Neon

    function updateChart(method) {
      let metricKey = method === "tlsh" ? "tlsh_score" : "ssdeep_score";
      let color = method === "tlsh" ? tlshColor : ssdeepColor;
      let label = method === "tlsh" ? "TLSH Similarity" : "ssdeep Similarity";

      console.log(`Updating chart for ${method}`);
      console.log(`Checking ${allSimilar.length} similar files`);

      // Filter to only show non-zero scores, then sort and take top 5
      const rankedSimilar = allSimilar
        .filter((x) => {
          const score = x[metricKey] || 0;
          console.log(
            `File: ${
              Array.isArray(x.name) ? x.name[0] : x.name
            }, ${metricKey}: ${score}`
          );
          return score > 0; // Only show files with similarity > 0
        })
        .sort((a, b) => (b[metricKey] || 0) - (a[metricKey] || 0))
        .slice(0, 5); // Top 5 only

      console.log(`After filtering and sorting: ${rankedSimilar.length} files`);

      if (rankedSimilar.length === 0) {
        // No similar files found
        if (chart1) chart1.destroy();
        document.querySelector(
          ".chart-container"
        ).innerHTML = `<div style="color: #ff4444; text-align: center; padding: 50px;">
            No similar files found using ${method.toUpperCase()}
          </div>`;
        return;
      }

      // Extract the sorted data - display names as-is, no special labeling
      const labels = rankedSimilar.map((x) =>
        Array.isArray(x.name) ? x.name[0] : x.name
      );
      const values = rankedSimilar.map((x) => x[metricKey] || 0);

      console.log("Chart labels:", labels);
      console.log("Chart values:", values);

      // Clear previous chart
      if (chart1) chart1.destroy();

      // Restore canvas if it was replaced with error message
      const container = document.querySelector(".chart-container");
      if (!container.querySelector("#similarityChart")) {
        container.innerHTML = '<canvas id="similarityChart"></canvas>';
      }

      // Render the main chart
      chart1 = drawChart("similarityChart", labels, values, label, color);
    }

    // Initialize with TLSH ranking
    if (allSimilar.length > 0) {
      updateChart("tlsh");
    } else {
      console.warn("No similar files found in metadata");
      document.querySelector(".chart-container").innerHTML =
        '<div style="color: #ff4444; text-align: center; padding: 50px;">No similar files found in database</div>';
    }

    document.getElementById("simMethod").addEventListener("change", (e) => {
      const method = e.target.value;
      if (method === "tlsh" || method === "ssdeep") {
        updateChart(method);
      }
    });
  } catch (error) {
    console.error("Error initializing visualization:", error);
    document.body.innerHTML += `<div style="color: #ff4444; text-align: center; margin-top: 50px;">
      <h2>Error loading file data</h2>
      <p>${error.message}</p>
      <a href="/" style="color: #0ef;">← Back to home</a>
    </div>`;
  }
}

init();
