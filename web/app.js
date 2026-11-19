"use strict";

const $ = (selector) => document.querySelector(selector);
const form = $("#trace-form");
const block = $("#block");
const key = $("#key");
const output = $("#output");
const tablePicker = $("#table-picker");
const pad = (n) => String(n).padStart(2, "0");
const stages = ["IP", ...Array.from({length: 16}, (_, i) => pad(i + 1)), "FP"];
const tabs = [...document.querySelectorAll('[role="tab"]')];

let trace = null;
let tables = {};
let step = 0;
let binary = false;
let timer = null;
let version = 0;
let tableGroup = null;

const layouts = {
  IP: {
    nodes: [[280, 42, 220], [280, 123, 220], [148, 231, 150, "teal"], [412, 231, 150, "blue"]],
    wires: [["M280 62 V103"], ["M280 143 V179 H148 V211", "teal"], ["M280 179 H412 V211", "blue"]],
  },
  round: {
    nodes: [[125, 38, 154, "teal"], [407, 38, 154, "blue"], [245, 113, 137, "gold"],
      [407, 113, 154, "blue"], [125, 231, 154, "teal"], [407, 231, 154, "blue"]],
    wires: [["M125 58 V151", "teal"], ["M407 58 V93", "blue"], ["M407 73 H534 V231 H484", "blue"],
      ["M313.5 113 H330", "gold"], ["M407 133 V169 H143", "teal"], ["M125 187 V211", "teal"]],
  },
  FP: {
    nodes: [[145, 34, 152, "blue"], [415, 34, 152, "teal"], [280, 105, 200],
      [280, 175, 220], [280, 243, 220, "teal"]],
    wires: [["M145 54 V105 H180", "blue"], ["M415 54 V105 H380", "teal"],
      ["M280 125 V155"], ["M280 195 V223", "teal"]],
  },
};

function element(tag, text, className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
}

function svg(tag, attributes, text) {
  const item = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attributes)) item.setAttribute(name, value);
  if (text !== undefined) item.textContent = text;
  return item;
}

function draw(stage) {
  const signals = $("#signals");
  signals.replaceChildren();
  $("#flow-caption").textContent = stage ? stage.title : "Alur data DES";
  if (!stage) {
    signals.append(svg("text", {x: 280, y: 140, "text-anchor": "middle", class: "diagram-empty"}, "Klik Jalankan untuk melihat alur data."));
    return;
  }
  const layout = layouts[stage.label] ?? layouts.round;
  for (const [d, lane = ""] of layout.wires) signals.append(svg("path", {d, class: `wire ${lane}`}));
  layout.nodes.forEach(([x, y, width, lane = ""], i) => {
    const [label, value] = stage.flow[i];
    const node = svg("g", {class: lane});
    node.append(
      svg("rect", {x: x - width / 2, y: y - 20, width, height: 40, rx: 4, class: "node-box"}),
      svg("rect", {x: x - width / 2, y: y - 16, width: 3, height: 32, rx: 1, class: "node-mark"}),
      svg("text", {x, y: y - 3, "text-anchor": "middle", class: "node-label"}, label),
      svg("text", {x, y: y + 13, "text-anchor": "middle", class: "node-value"}, value),
    );
    signals.append(node);
  });
  if (layout === layouts.round) {
    signals.append(svg("circle", {cx: 125, cy: 169, r: 18, class: "xor"}),
      svg("text", {x: 125, y: 173, "text-anchor": "middle", class: "node-label teal"}, "XOR"));
  }
}

const stageButtons = stages.map((label, i) => {
  const button = element("button", label);
  button.type = "button";
  button.setAttribute("aria-label", label === "IP" ? "Permutasi awal (IP)" : label === "FP" ? "Permutasi akhir (FP)" : `Putaran ${label}`);
  button.addEventListener("click", () => goTo(i));
  $("#timeline").append(button);
  return button;
});

const activeStage = () => trace?.steps[step];
const bitString = (value) => value.match(/.{8}/g).join(" ");

function renderValues() {
  const list = $("#value-list");
  const rows = activeStage()?.values ?? [];
  list.replaceChildren(...rows.map(({label, bits, hex, binary: value}) => {
    const row = element("div", undefined, label.startsWith("Kunci putaran") ? "value-row key" : "value-row");
    const term = element("dt", label);
    term.append(element("small", `${bits} bit`));
    row.append(term, element("dd", binary ? bitString(value) : hex));
    return row;
  }));
  $("#format").textContent = binary ? "Tampilkan heks" : "Tampilkan biner";
  $("#format").setAttribute("aria-pressed", String(binary));
}

const tableLabel = (name, title) => name === "Shifts" ? title : `${name} | ${title}`;

function renderTable() {
  const stage = activeStage();
  const group = stage?.label === "FP" ? "FP" : !stage || stage.label === "IP" ? "IP" : "E";
  if (tableGroup !== group && Object.hasOwn(tables, group)) {
    tableGroup = group;
    tablePicker.value = group;
  }
  const name = tablePicker.value;
  const table = tables[name];
  const container = $("#table-content");
  $("#copy-table").disabled = !table;
  tablePicker.disabled = !table;
  if (!table) {
    container.replaceChildren(element("p", "Klik Jalankan untuk melihat tabel acuan DES."));
    return;
  }
  container.replaceChildren(element("h4", tableLabel(name, table.title)), element("p", table.intro),
    element("pre", table.grid), element("h4", "Contoh perhitungan"),
    element("pre", stage?.examples[name] ?? "Klik Jalankan untuk melihat contoh perhitungan."));
}

function render() {
  const stage = activeStage();
  stageButtons.forEach((button, i) => {
    button.disabled = !stage;
    button.dataset.visited = String(!!stage && i < step);
    if (stage && i === step) button.setAttribute("aria-current", "step");
    else button.removeAttribute("aria-current");
  });
  $("#step-count").textContent = stage ? `TAHAP ${pad(step + 1)} / ${stages.length}` : "BELUM DIJALANKAN";
  $("#phase").textContent = !stage ? "DES" : stage.label === "IP" ? "MASUKAN / IP" :
    stage.label === "FP" ? "KELUARAN / FP" : `PUTARAN ${stage.label}`;
  $("#stage-title").textContent = stage?.title ?? "Belum ada hasil";
  $("#stage-note").textContent = stage?.note ?? "";
  $("#previous").disabled = !stage || step === 0;
  $("#next").disabled = !stage || step === stages.length - 1;
  for (const id of ["play", "copy-step", "format"]) $("#" + id).disabled = !stage;
  $("#copy-result").disabled = $("#reverse").disabled = !trace?.output;
  output.value = trace?.output ?? "";
  $("#copy-feedback").textContent = "";
  draw(stage);
  const walkthrough = $("#walkthrough");
  const lesson = stage?.walkthrough ?? [["Panduan DES", "Klik Muat contoh untuk menelusuri enkripsi dengan pesan dan kunci bawaan."]];
  walkthrough.replaceChildren(...lesson.map(([heading, text]) => {
    const section = element("section", undefined, "lesson");
    section.append(element("h4", heading), element("p", text));
    return section;
  }));
  renderValues();
  renderTable();
  for (const pane of document.querySelectorAll(".detail-pane")) pane.scrollTop = 0;
}

const mode = () => form.elements.mode.value;

function labels() {
  const decrypt = mode() === "decrypt";
  $("#block-label").textContent = decrypt ? "Teks sandi (Base64)" : "Teks asli (UTF-8)";
  $("#output-label").textContent = decrypt ? "Teks asli (UTF-8)" : "Teks sandi (Base64)";
}

function status(message, error = false) {
  $("#status").textContent = message;
  $("#status").dataset.error = String(error);
}

function invalidate(message) {
  version++;
  pause();
  trace = null;
  step = 0;
  labels();
  block.removeAttribute("aria-invalid");
  key.removeAttribute("aria-invalid");
  status(message ?? (mode() === "decrypt" ? "Tempel teks sandi Base64 dan masukkan kunci enkripsinya." :
    "Masukkan 1 hingga 8 byte UTF-8. Jika kurang dari 8 byte, aplikasi menambahkan byte nol di akhir."));
  render();
}

async function runTrace(example = false) {
  invalidate(example ? "Memuat contoh..." : "Menjalankan DES...");
  const requestVersion = version;
  try {
    const response = example ? await fetch("/api/example") : await fetch("/api/trace", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({mode: mode(), block: block.value, key: key.value}),
    });
    const data = await response.json();
    if (version !== requestVersion) return;
    if (!response.ok) {
      status(data.error ?? "DES tidak dapat dijalankan.", true);
      const field = {block, key}[data.field];
      if (field) {
        field.setAttribute("aria-invalid", "true");
        field.focus();
      }
      return;
    }
    if (example) {
      form.elements.mode.value = "encrypt";
      block.value = data.block;
      key.value = data.key;
      labels();
    }
    if (!Object.keys(tables).length) {
      tables = data.tables;
      tablePicker.replaceChildren(...Object.entries(tables).map(([name, {title}]) => {
        const option = element("option", tableLabel(name, title));
        option.value = name;
        return option;
      }));
    }
    trace = data;
    status(data.status, !data.output);
    render();
  } catch {
    if (version === requestVersion) status("Hasil tidak bisa dimuat. Pastikan server Python berjalan.", true);
  }
}

function pause() {
  if (timer !== null) clearInterval(timer);
  timer = null;
  $("#play").textContent = "Putar";
}

function goTo(index) {
  if (!trace || index < 0 || index >= stages.length) return;
  pause();
  step = index;
  render();
}

function play() {
  if (timer !== null) {
    pause();
    return;
  }
  if (step === stages.length - 1) goTo(0);
  $("#play").textContent = "Jeda";
  timer = setInterval(() => {
    step++;
    render();
    if (step === stages.length - 1) pause();
  }, 850);
}

async function copy(text, description) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    $("#copy-feedback").textContent = `${description} disalin.`;
  } catch {
    const dialog = $("#copy-dialog");
    const manual = $("#manual-copy");
    manual.value = text;
    dialog.showModal();
    manual.focus();
    manual.select();
  }
}

function selectTab(tab) {
  for (const item of tabs) {
    item.setAttribute("aria-selected", String(item === tab));
    item.tabIndex = item === tab ? 0 : -1;
    document.getElementById(item.getAttribute("aria-controls")).hidden = item !== tab;
  }
}

tabs.forEach((tab, i) => {
  tab.addEventListener("click", () => selectTab(tab));
  tab.addEventListener("keydown", (event) => {
    const choices = {ArrowLeft: (i + tabs.length - 1) % tabs.length, ArrowRight: (i + 1) % tabs.length,
      Home: 0, End: tabs.length - 1};
    if (!Object.hasOwn(choices, event.key)) return;
    event.preventDefault();
    const next = tabs[choices[event.key]];
    selectTab(next);
    next.focus();
  });
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  runTrace();
});
form.addEventListener("input", (event) => {
  if (["block", "key", "mode"].includes(event.target.id || event.target.name)) invalidate();
});
$("#example").addEventListener("click", () => runTrace(true));
$("#reverse").addEventListener("click", () => {
  block.value = trace.output;
  form.elements.mode.value = mode() === "decrypt" ? "encrypt" : "decrypt";
  runTrace();
});
$("#previous").addEventListener("click", () => goTo(step - 1));
$("#next").addEventListener("click", () => goTo(step + 1));
$("#play").addEventListener("click", play);
$("#format").addEventListener("click", () => {
  binary = !binary;
  renderValues();
});
tablePicker.addEventListener("change", renderTable);
$("#copy-result").addEventListener("click", () => copy(trace.output, "Hasil"));
$("#copy-table").addEventListener("click", () => copy(
  [...$("#table-content").children].map((item) => item.textContent).join("\n\n"), "Tabel"));
$("#copy-step").addEventListener("click", () => {
  const stage = activeStage();
  const report = [stage.title, stage.note, "\nPanduan", ...stage.walkthrough.map((item) => item.join("\n")),
    "\nDiagram (heks)", ...stage.flow.map((item) => item.join(": ")), `\nNilai (${binary ? "biner" : "heks"})`,
    ...stage.values.map((row) => `${row.label} (${row.bits} bit): ${binary ? bitString(row.binary) : row.hex}`)];
  copy(report.join("\n"), "Tahap");
});

runTrace(true);
