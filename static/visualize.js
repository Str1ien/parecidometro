let chart1 = null;

/* ------------ FETCH DATA ------------- */

async function fetchData() {
  const res = await fetch(`/api/file/${fileId}`);
  return await res.json();
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
    Name: meta.name.join(", "),
    Size: meta.size,
    Type: meta.file_type,
    "Upload Date": meta.upload_date,
    Description: meta.desc || "No description",
  };

  // Función para generar la fila de la rejilla con tooltip opcional
  const createGridRow = (key, value) => {
    const isHash = key in hashFields;
    const needsTooltip = isHash && value.length > 20;

    const dataAttr = needsTooltip ? `data-full="${value}"` : "";
    const valueDiv = `<div class="value-container" ${dataAttr}>${value}</div>`;

    return `<div><strong>${key}</strong></div>${valueDiv}`;
  };

  // 2. Renderizar Hashes con Tooltip
  gridHashes.innerHTML = Object.entries(hashFields)
    .map(([key, value]) => createGridRow(key, value))
    .join("");

  // 3. Renderizar Metadata Principal
  gridMain.innerHTML = Object.entries(mainFields)
    .map(([key, value]) => createGridRow(key, value))
    .join("");
}

/* ------------ CHART RENDERING ----------- */
function drawChart(canvasId, labels, values, label, color) {
  const ctx = document.getElementById(canvasId);

  // Ajustes de color para el tema neon
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
      maintainAspectRatio: false, // Permitir que la gráfica use el 100% de la altura de su contenedor
      indexAxis: "y", // Convertir en barra horizontal para mejor lectura de nombres de archivos
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
  const metaKey = Object.keys(data)[0];
  const metadata = data[metaKey];

  renderMetadata(metadata);

  const allSimilar = metadata.similar || [];
  const tlshColor = "rgb(0, 239, 255)"; // Blue Neon
  const ssdeepColor = "rgb(255, 105, 180)"; // Pink Neon

  function updateChart(method) {
    let metricKey = method === "tlsh" ? "tlsh_score" : "ssdeep_score";
    let color = method === "tlsh" ? tlshColor : ssdeepColor;
    let label = method === "tlsh" ? "TLSH Similarity" : "ssdeep Similarity";

    // sort by score of chosen sim hash
    const rankedSimilar = allSimilar.sort(
      (a, b) => (b[metricKey] || 0) - (a[metricKey] || 0)
    );

    // 2. Extraer los datos ordenados
    const labels = rankedSimilar.map((x) => x.name);
    const values = rankedSimilar.map((x) => x[metricKey] || 0);

    // Limpiar gráficos
    if (chart1) chart1.destroy();

    // Renderizar el gráfico principal
    chart1 = drawChart("similarityChart", labels, values, label, color);
  }

  /* Inicializar con el ranking por TLSH */
  updateChart("tlsh");

  document.getElementById("simMethod").addEventListener("change", (e) => {
    const method = e.target.value;
    if (method === "tlsh" || method === "ssdeep") {
      updateChart(method);
    }
  });
}

init();
