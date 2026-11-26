/* Racing the Scanner: presentation logic.
   Reveal.js runs the deck; Chart.js draws the figures. Every charted number is read
   from window.RTS (assets/results.js, generated from the repo by
   tools/extract_data.py), so nothing on a chart is typed in by hand. */
(function () {
  "use strict";

  const R = window.RTS;
  const printing = /print-pdf/i.test(window.location.search);
  const css = getComputedStyle(document.documentElement);
  const v = (name) => css.getPropertyValue(name).trim();
  const COL = {
    ink: v("--ink"), navy: v("--navy"), blue: v("--blue"), blueLight: v("--blue-light"),
    orange: v("--orange"), orangeLight: v("--orange-light"), gray: v("--gray"),
    grayLight: v("--gray-light"), muted: v("--muted"), line: v("--line"),
  };

  // ---------- data helpers ----------
  const P = R.policies;
  const ML = Object.keys(P).filter((p) => P[p].group.startsWith("ml"));
  const RES = Object.keys(P).filter((p) => ["reservation", "invariant"].includes(P[p].group));
  const NAMES = {
    baseline: "Stock EEVDF", invariant: "Invariant", sched_fifo: "SCHED_FIFO", sched_deadline: "SCHED_DEADLINE",
    cgroup_weight: "cpu.weight", cgroup_cpumax: "cpu.max (20% cap)", iforest: "Isolation Forest", ocsvm: "One-class SVM",
    lof: "LOF", elliptic: "Robust covariance", knn: "k-NN distance", hbos: "HBOS", gmm: "Gaussian mixture",
    rf: "Random forest", histgb: "Gradient boosting", logreg: "Logistic regression", svm_rbf: "RBF-SVM",
    mlp: "MLP", knn_clf: "k-NN vote", naive_bayes: "Naive Bayes",
  };
  const by = (key) => (a, b) => P[a][key] - P[b][key];
  const groupColor = (p) => (ML.includes(p) ? COL.orange : RES.includes(p) ? COL.blue : COL.gray);

  // ---------- chart defaults ----------
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  Chart.defaults.font.size = 15;
  Chart.defaults.color = COL.muted;
  Chart.defaults.borderColor = COL.line;
  Chart.defaults.devicePixelRatio = Math.max(2, window.devicePixelRatio || 1);
  Chart.defaults.plugins.tooltip.enabled = false;
  Chart.defaults.plugins.legend.display = false;
  Chart.defaults.animation.duration = 900;
  Chart.defaults.animation.easing = "easeOutCubic";

  // Dashed reference lines (the 8-tick window, chance, the 1/8 share): options.plugins.refLines.lines
  const refLines = {
    id: "refLines",
    afterDatasetsDraw(chart, _args, opts) {
      const { ctx, chartArea: a } = chart;
      (opts.lines || []).forEach((l) => {
        const p = chart.scales[l.axis].getPixelForValue(l.value);
        ctx.save();
        ctx.strokeStyle = l.color || COL.ink;
        ctx.lineWidth = 2;
        ctx.setLineDash([7, 5]);
        ctx.beginPath();
        if (l.axis === "x") { ctx.moveTo(p, a.top); ctx.lineTo(p, a.bottom); } else { ctx.moveTo(a.left, p); ctx.lineTo(a.right, p); }
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = l.color || COL.ink;
        ctx.font = "600 14px Inter, sans-serif";
        if (l.axis === "x") { ctx.textAlign = "left"; ctx.textBaseline = "top"; ctx.fillText(l.label, p + 7, a.top + 2); }
        else { ctx.textAlign = "right"; ctx.textBaseline = "bottom"; ctx.fillText(l.label, a.right, p - 6); }
        ctx.restore();
      });
    },
  };

  // Value labels at the end of each bar. Formats are named (not functions) so Chart.js
  // does not treat them as scriptable options: options.plugins.barLabels = {format, datasets?}
  const r1 = (x) => (Math.round(x * 10 + 1e-6) / 10).toFixed(1); // half up: 4.85 -> 4.9, as in the report
  const FORMATS = {
    pct1: (x) => `${r1(x)}%`,
    x1: (x) => `${r1(x)}×`,
    dec2: (x) => x.toFixed(2),
    num1: (x) => String(Number(x.toFixed(1))),
    int: (x) => String(Math.round(x)),
    ms: (x) => (x < 10 ? x.toFixed(1) : Math.round(x).toLocaleString("en-US")),
    sps: (x) => (x < 10 ? x.toFixed(2).replace(/0$/, "") : x.toFixed(1)),
  };
  const barLabels = {
    id: "barLabels",
    afterDatasetsDraw(chart, _args, opts) {
      if (!opts.format) return;
      const fmt = FORMATS[opts.format];
      const { ctx } = chart;
      const horizontal = chart.options.indexAxis === "y";
      chart.data.datasets.forEach((ds, i) => {
        if (ds.type === "line" || (opts.datasets && !opts.datasets.includes(i))) return;
        chart.getDatasetMeta(i).data.forEach((bar, j) => {
          const val = ds.data[j];
          if (val == null) return;
          ctx.save();
          ctx.fillStyle = COL.ink;
          ctx.font = `500 ${opts.size || 14}px Inter, sans-serif`;
          if (horizontal) { ctx.textAlign = "left"; ctx.textBaseline = "middle"; ctx.fillText(fmt(val), bar.x + 6, bar.y); }
          else { ctx.textAlign = "center"; ctx.textBaseline = "bottom"; ctx.fillText(fmt(val), bar.x, bar.y - 5); }
          ctx.restore();
        });
      });
    },
  };
  // A bracket and a label beside a run of bars in a horizontal bar chart, so the
  // takeaway sits on the figure: options.plugins.groupLabels.groups = [{from, to, text, sub, color}]
  const groupLabels = {
    id: "groupLabels",
    afterDatasetsDraw(chart, _args, opts) {
      const bars = chart.getDatasetMeta(0).data;
      const { ctx, chartArea: a } = chart;
      (opts.groups || []).forEach((g) => {
        const top = bars[g.from].y - bars[g.from].height / 2;
        const bot = bars[g.to].y + bars[g.to].height / 2;
        const x = a.right + 16;
        const mid = (top + bot) / 2;
        ctx.save();
        ctx.strokeStyle = g.color;
        ctx.lineWidth = 2.5;
        ctx.beginPath(); ctx.moveTo(x - 7, top); ctx.lineTo(x, top); ctx.lineTo(x, bot); ctx.lineTo(x - 7, bot); ctx.stroke();
        ctx.textAlign = "left"; ctx.textBaseline = "middle";
        ctx.fillStyle = g.color;
        ctx.font = "700 21px 'Source Serif 4', serif";
        ctx.fillText(g.text, x + 11, g.sub ? mid - 10 : mid);
        if (g.sub) { ctx.fillStyle = COL.muted; ctx.font = "500 13px Inter, sans-serif"; ctx.fillText(g.sub, x + 11, mid + 12); }
        ctx.restore();
      });
    },
  };
  Chart.register(refLines, barLabels, groupLabels);

  // Diagonal hatching for the real-kernel bars (solid = simulation), as in the report's G3
  function hatch(color) {
    const c = document.createElement("canvas");
    c.width = c.height = 10;
    const x = c.getContext("2d");
    x.fillStyle = "#ffffff"; x.fillRect(0, 0, 10, 10);
    x.strokeStyle = color; x.lineWidth = 2.2;
    x.beginPath();
    x.moveTo(-2, 12); x.lineTo(12, -2); x.moveTo(-2, 2); x.lineTo(2, -2); x.moveTo(8, 12); x.lineTo(12, 8);
    x.stroke();
    return x.createPattern(c, "repeat");
  }

  const axisTitle = (text) => ({ display: true, text, color: COL.muted, font: { size: 14 } });
  const noGrid = { display: false };

  // ---------- the figures ----------
  const builders = {
    // Framework: the scanner's share under the coupled attack vs the 1/8 it needs
    theory() {
      const s = R.shares;
      return {
        type: "bar",
        data: {
          labels: ["No attack", "Stock EEVDF", "ML, fooled by the mimic", "ML, catches a naive hog", "Reservation (cpu.weight)"],
          datasets: [{
            data: [s.no_attack, s.eevdf, s.ml_fooled, s.ml_detected, s.reservation].map((x) => x * 100),
            backgroundColor: [COL.grayLight, COL.gray, COL.orange, COL.orangeLight, COL.blue],
            borderRadius: 3, barPercentage: 0.72,
          }],
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          layout: { padding: { right: 50, top: 22 } },
          scales: {
            x: { min: 0, max: 25, ticks: { callback: (t) => `${t}%`, stepSize: 5 }, title: axisTitle("Scanner's share of the CPU, coupled attack") },
            y: { grid: noGrid, ticks: { color: COL.ink, font: { size: 16 } } },
          },
          plugins: {
            refLines: { lines: [{ axis: "x", value: 12.5, label: "needed: 1/8", color: COL.navy }] },
            barLabels: { format: "pct1", size: 15 },
          },
        },
      };
    },

    // G1: per-scan catch rate vs exposure (dwell per 100 ms), scan every 37 ms
    g1() {
      const dw = ["1", "5", "10", "25"];
      return {
        type: "bar",
        data: {
          labels: dw.map((d) => `${d} ms`),
          datasets: [
            { label: "V2 (mprotect)", data: dw.map((d) => R.g1.v2[d].rate * 100), backgroundColor: COL.blue, borderRadius: 3, order: 2 },
            { label: "V3 (userfaultfd)", data: dw.map((d) => R.g1.v3[d].rate * 100), backgroundColor: COL.navy, borderRadius: 3, order: 2 },
            { type: "line", label: "Time a page is exposed", data: dw.map(Number), borderColor: COL.ink, borderDash: [7, 5], borderWidth: 2, pointRadius: 4, pointBackgroundColor: COL.ink, order: 1 },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          scales: {
            y: { min: 0, max: 30, ticks: { callback: (t) => `${t}%`, stepSize: 10 }, title: axisTitle("Scans that catch it") },
            x: { grid: noGrid, ticks: { color: COL.ink }, title: axisTitle("Exposure (dwell) per 100 ms") },
          },
          plugins: { legend: { display: true, position: "top", align: "start", labels: { boxWidth: 14, boxHeight: 14, color: COL.ink } } },
        },
      };
    },

    // G3 (simulation): p95 latency / no-attack p95, mimicry attacker
    g3() {
      const conds = ["hiding", "starvation", "coupled"];
      const pol = [["baseline", "Stock EEVDF", COL.gray], ["iforest", "Isolation Forest", COL.orange], ["rf", "Random forest", COL.orangeLight], ["cgroup_weight", "cpu.weight", COL.blue]];
      return {
        type: "bar",
        data: {
          labels: ["Hiding", "Starvation", "Coupled"],
          datasets: pol.map(([k, name, color]) => ({ label: name, data: conds.map((c) => R.g3_sim[k][c]), backgroundColor: color, borderRadius: 3 })),
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          scales: {
            y: { min: 0, max: 8, ticks: { stepSize: 2, callback: (t) => `${t}×` }, title: axisTitle("Scanner p95 latency ÷ no attack") },
            x: { grid: noGrid, ticks: { color: COL.ink, font: { size: 16 } } },
          },
          plugins: {
            legend: { display: true, position: "top", align: "start", labels: { boxWidth: 14, boxHeight: 14, color: COL.ink } },
            barLabels: { format: "x1", size: 13 },
          },
        },
      };
    },

    // G4: p95 per policy under coupled mimicry vs the 8-tick window
    g4() {
      const order = [...[...RES].sort(by("p95_latency")), ...[...ML].sort(by("p95_latency")), "baseline"];
      return {
        type: "bar",
        data: {
          labels: order.map((p) => NAMES[p]),
          datasets: [{ data: order.map((p) => P[p].p95_latency), backgroundColor: order.map(groupColor), borderRadius: 2, barPercentage: 0.78, categoryPercentage: 0.9 }],
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          layout: { padding: { right: 170, top: 20 } },
          scales: {
            x: { min: 0, max: 40, ticks: { stepSize: 8 }, title: axisTitle("Scanner p95 latency (ticks)") },
            y: { grid: noGrid, ticks: { color: COL.ink, font: { size: 13 }, autoSkip: false } },
          },
          plugins: {
            refLines: { lines: [{ axis: "x", value: 8, label: "8-tick window", color: COL.navy }] },
            barLabels: { format: "num1", size: 12 },
            groupLabels: { groups: [
              { from: 0, to: RES.length - 1, text: "0% miss", sub: "5 reservations", color: COL.blue },
              { from: RES.length, to: RES.length + ML.length - 1, text: "100% miss", sub: "all 14 ML policies", color: COL.orange },
              { from: RES.length + ML.length, to: RES.length + ML.length, text: "100% miss", sub: "stock EEVDF", color: COL.gray },
            ] },
          },
        },
      };
    },

    // Why: each detector's ROC-AUC against the benign apps (0.5 = chance)
    auc() {
      const order = [...ML].sort(by("roc_auc_benign"));
      const below = order.filter((p) => P[p].roc_auc_benign <= 0.5).length;
      return {
        type: "bar",
        data: {
          labels: order.map((p) => NAMES[p]),
          datasets: [{ data: order.map((p) => P[p].roc_auc_benign), backgroundColor: order.map((p) => (P[p].roc_auc_benign <= 0.5 ? COL.orange : COL.gray)), borderRadius: 2, barPercentage: 0.78 }],
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          layout: { padding: { right: 185, top: 20 } },
          scales: {
            x: { min: 0, max: 1, ticks: { stepSize: 0.25, callback: (t) => t.toFixed(2) }, title: axisTitle("ROC-AUC vs benign apps") },
            y: { grid: noGrid, ticks: { color: COL.ink, font: { size: 14 }, autoSkip: false } },
          },
          plugins: {
            refLines: { lines: [{ axis: "x", value: 0.5, label: "chance", color: COL.navy }] },
            barLabels: { format: "dec2", size: 13 },
            groupLabels: { groups: [
              { from: 0, to: below - 1, text: `${below} of ${order.length}`, sub: "at or below chance", color: COL.orange },
              { from: below, to: order.length - 1, text: `${order.length - below} of ${order.length}`, sub: "above, never demote it", color: COL.gray },
            ] },
          },
        },
      };
    },

    // G6a: policy compute per 600-tick run (log scale)
    g6a() {
      // sorted within each group, so the group brackets below always cover exactly one group
      const order = [...[...RES].sort(by("overhead_ms")), ...[...ML].sort(by("overhead_ms"))];
      const ovRes = RES.map((p) => P[p].overhead_ms), ovML = ML.map((p) => P[p].overhead_ms);
      return {
        type: "bar",
        data: {
          labels: order.map((p) => NAMES[p]),
          datasets: [{ data: order.map((p) => P[p].overhead_ms), backgroundColor: order.map(groupColor), borderRadius: 2, barPercentage: 0.78, categoryPercentage: 0.9 }],
        },
        options: {
          indexAxis: "y", responsive: true, maintainAspectRatio: false,
          layout: { padding: { right: 170 } },
          scales: {
            x: { type: "logarithmic", min: 1, max: 10000, title: axisTitle("Policy compute per run (ms, log scale)"),
              ticks: { autoSkip: false, maxRotation: 0, callback: (t) => ([1, 10, 100, 1000].includes(t) ? t.toLocaleString("en-US") : "") } },
            y: { grid: noGrid, ticks: { color: COL.ink, font: { size: 13 }, autoSkip: false } },
          },
          plugins: {
            barLabels: { format: "ms", size: 12 },
            groupLabels: { groups: [
              { from: 0, to: RES.length - 1, text: `${FORMATS.ms(Math.min(...ovRes))}–${FORMATS.ms(Math.max(...ovRes))} ms`, sub: "5 reservations", color: COL.blue },
              { from: RES.length, to: order.length - 1, text: `${FORMATS.ms(Math.min(...ovML))}–${FORMATS.ms(Math.max(...ovML))} ms`, sub: "14 ML policies", color: COL.orange },
            ] },
          },
        },
      };
    },

    // Real kernel (G3): scanner slowdown vs no attack. Solid = simulation (p95 ratio, mimicry);
    // hatched = real kernel (scan period ratio, i.e. no-attack scans/s over attacked scans/s)
    kernel() {
      const conds = ["hiding", "starvation", "coupled"];
      const real = (p) => conds.map((c) => R.live[p].none.scans_per_s / R.live[p][c].scans_per_s);
      const sim = (p) => conds.map((c) => R.g3_sim[p][c]);
      return {
        type: "bar",
        data: {
          labels: ["Hiding", "Starvation", "Coupled"],
          datasets: [
            { label: "EEVDF, simulation", data: sim("baseline"), backgroundColor: COL.gray, borderRadius: 3 },
            { label: "EEVDF, real kernel", data: real("eevdf"), backgroundColor: hatch(COL.gray), borderColor: COL.gray, borderWidth: 2, borderRadius: 3 },
            { label: "cpu.weight, simulation", data: sim("cgroup_weight"), backgroundColor: COL.blue, borderRadius: 3 },
            { label: "cpu.weight, real kernel", data: real("cgroup_weight"), backgroundColor: hatch(COL.blue), borderColor: COL.blue, borderWidth: 2, borderRadius: 3 },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          layout: { padding: { top: 24 } },
          scales: {
            y: { min: 0, max: 10, ticks: { stepSize: 2, callback: (t) => `${t}×` }, title: axisTitle("Scanner slowdown vs no attack") },
            x: { grid: noGrid, ticks: { color: COL.ink, font: { size: 16 } } },
          },
          plugins: { barLabels: { format: "x1", size: 14 } },
        },
      };
    },

    // G5: hiders caught and false alarms per detector (5 batches pooled)
    g5() {
      const det = [["default_sigs", "Default rules (27)"], ["custom", "Custom rule"], ["ai", "LLM triage"]];
      return {
        type: "bar",
        data: {
          labels: det.map((d) => d[1]),
          datasets: [
            { label: "Hiders caught (of 15)", data: det.map(([k]) => R.g5[k].caught), backgroundColor: COL.blue, borderRadius: 3 },
            { label: "False alarms (of 30 benign)", data: det.map(([k]) => R.g5[k].false_alarms), backgroundColor: COL.orange, borderRadius: 3 },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          layout: { padding: { top: 24 } },
          scales: {
            y: { min: 0, max: 15, ticks: { stepSize: 5 }, title: axisTitle("Processes") },
            x: { grid: noGrid, ticks: { color: COL.ink, font: { size: 16 } } },
          },
          plugins: { barLabels: { format: "int", size: 15 } },
        },
      };
    },
  };

  // ---------- build each chart the first time its slide is shown (so it animates in) ----------
  const built = new WeakMap();
  function buildCharts(scope) {
    scope.querySelectorAll("canvas[data-chart]").forEach((cv) => {
      if (built.has(cv)) return;
      const make = builders[cv.dataset.chart];
      if (!make) { console.error("no chart builder for", cv.dataset.chart); return; }
      const cfg = make();
      if (printing) cfg.options.animation = false;
      built.set(cv, new Chart(cv, cfg));
    });
  }

  // The roadmap lives in a breadcrumb along the top of each content slide
  const CRUMBS = ["Problem", "Hiding", "Simulation", "Real kernel", "Detection", "Conclusions"];
  document.querySelectorAll(".slides section[data-crumb]").forEach((sec) => {
    const nav = document.createElement("div");
    nav.className = "crumbs";
    nav.setAttribute("aria-hidden", "true");
    nav.innerHTML = CRUMBS.map((c) => `<span${c === sec.dataset.crumb ? ' class="on"' : ""}>${c}</span>`).join("")
      + (sec.dataset.testbed ? `<em class="testbed">${sec.dataset.testbed}</em>` : "");
    sec.prepend(nav);
  });

  Reveal.initialize({
    width: 1280,
    height: 720,
    margin: 0.04,
    center: false,
    hash: true,
    controls: true,
    controlsTutorial: false,
    progress: true,
    slideNumber: "c/t",
    navigationMode: "linear", // arrows and space walk every fragment, then every slide
    transition: "fade",
    transitionSpeed: "default",
    backgroundTransition: "fade",
    pdfSeparateFragments: false,
    plugins: [RevealNotes],
  }).then(async () => {
    await document.fonts.ready; // chart text uses Inter: draw after it loads
    if (printing) document.querySelectorAll(".slides section").forEach(buildCharts);
    else buildCharts(Reveal.getCurrentSlide());
    window.__deckReady = true;
  });
  Reveal.on("slidechanged", (e) => buildCharts(e.currentSlide));
})();
