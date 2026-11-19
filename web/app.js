"use strict";

const $ = (selector) => document.querySelector(selector);
const form = $("#trace-form");
const block = $("#block");
const key = $("#key");
const output = $("#output");
const tablePicker = $("#table-picker");
const speed = $("#speed");
const speedSlider = $("#speed-slider");
const pad = (n) => String(n).padStart(2, "0");
const stages = ["IP", ...Array.from({length: 16}, (_, i) => pad(i + 1)), "FP"];
const chain = $("#operation-chain");
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

let trace = null;
let tables = {};
let operations = [];
let operationIndex = 0;
let renderedStage = null;
let binary = false;
let version = 0;
let lastTable = null;
let activeButton = null;
let frameId = null;
let lastFrame = null;
let elapsed = 0;
let playbackRate = 1;
let sequence = false;
let paintFrame = null;

function element(tag, text, className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
}

function showValue(value) {
  if (Object.hasOwn(value, "text")) return JSON.stringify(value.text);
  if (!value.binary) return "0 byte";
  return BigInt(`0b${value.binary}`).toString(16).toUpperCase().padStart(value.binary.length / 4, "0");
}

function buildDiagram(groups) {
  operations = [];
  activeButton = null;
  chain.replaceChildren();
  chain.parentElement.scrollTop = 0;
  $("#empty-chain").hidden = groups.length > 0;
  for (const group of groups) {
    const section = element("li", undefined, "operation-section");
    const list = element("ol", undefined, "operation-list");
    section.append(element("h4", group.title), list);
    for (const operation of group.operations) {
      const index = operations.length;
      const node = element("li", undefined, "operation-node");
      const button = element("button", undefined, "node-button");
      button.type = "button";
      const result = operation.outputs.map((value) => `${value.label}: ${showValue(value)}`).join(" / ");
      button.append(element("span", pad(index + 1), "node-index"), element("span", operation.title),
        element("code", result, "node-result"));
      button.addEventListener("click", () => goTo(index));
      node.append(button);
      list.append(node);
      operations.push({...operation, group: group.title, stage: group.stage, button});
    }
    chain.append(section);
  }
}

function drawOperation(operation) {
  const view = $("#operation-view");
  const note = $("#operation-annotation");
  const progress = $("#operation-progress");
  view.replaceChildren();
  note.textContent = "";
  progress.value = 0;
  progress.hidden = !operation;
  if (!operation) return null;

  const inputText = [];
  const bitRows = (values, groupSize, isOutput = false) => {
    return values.map((value) => {
      const row = element("div", undefined, "operand");
      const hasBits = !!value.binary;
      const content = element("code", undefined, hasBits ? "bits" : "text-value");
      const cells = [];
      if (hasBits) {
        content.setAttribute("aria-label", value.binary.split("").join(" "));
        for (let offset = 0; offset < value.binary.length; offset += groupSize) {
          const group = element("span", undefined, "bit-group");
          for (const bit of value.binary.slice(offset, offset + groupSize)) {
            const cell = element("span", bit, "bit");
            cells.push(cell);
            group.append(cell);
          }
          content.append(group);
        }
      } else if (isOutput && value.text !== undefined) {
        for (const char of showValue(value)) {
          const cell = element("span", char);
          cells.push(cell);
          content.append(cell);
        }
      } else {
        content.textContent = showValue(value);
        if (!isOutput) inputText.push(content);
      }
      row.append(element("div", value.label, "operand-label"), content);
      view.append(row);
      return cells;
    });
  };

  const kind = operation.kind;
  const inputRows = bitRows(operation.inputs, kind === "sboxes" ? 6 : operation.inputs.some((value) => value.binary?.length === 28) ? 4 : 8);
  const input = inputRows.flat();
  const connector = element("div", kind === "xor" ? "XOR" : "\u2193", "operation-arrow");
  connector.setAttribute("aria-hidden", "true");
  view.append(connector);
  const lookupRows = (operation.lookups ?? []).map(({input, row, column, output}, i) =>
    element("div", `S${i + 1}: ${input} \u2192 [${row}, ${column}] \u2192 ${output}`, "lookup"));
  if (lookupRows.length) {
    const grid = element("div", undefined, "lookup-grid");
    grid.append(...lookupRows);
    view.append(grid);
  }
  const result = bitRows(operation.outputs, kind === "sboxes" || operation.outputs.some((value) => value.binary?.length === 28) ? 4 : 8, true).flat();
  const frames = kind === "sboxes" ? lookupRows.length : Math.max(result.length, 1);
  let last = -2;

  return (fraction) => {
    progress.value = fraction;
    const i = fraction >= 1 ? frames : Math.floor(Math.max(0, fraction) * frames);
    if (i === last) return;
    last = i;
    const finished = i === frames;
    const outputIndex = kind === "sboxes" ? i * 4 : i;
    let highlighted = [];
    let caption = "";
    if (!finished && kind === "mapping" && operation.positions.length) {
      const source = operation.positions[i];
      highlighted = source ? [input[source - 1]] : [];
      caption = source ? `Bit masukan ke-${source} \u2192 bit keluaran ke-${i + 1}` : `Isi bit keluaran ke-${i + 1} dengan 0`;
    } else if (!finished && kind === "xor") {
      highlighted = inputRows.map((row) => row[i]);
      caption = `Bit ${i + 1}: ${highlighted[0].textContent} XOR ${highlighted[1].textContent} = ${result[i].textContent}`;
    } else if (!finished && kind === "sboxes") {
      highlighted = input.slice(i * 6, i * 6 + 6);
      const lookup = operation.lookups[i];
      caption = `S${i + 1}: baris ${lookup.row}, kolom ${lookup.column} (heks)`;
    } else if (!finished && kind === "conversion") {
      highlighted = input;
      caption = `Masukan \u2192 ${operation.outputs[0].label}`;
    }
    for (const node of inputText) node.classList.toggle("is-source", !finished);
    for (const cell of input) cell.classList.toggle("is-source", highlighted.includes(cell));
    result.forEach((cell, n) => {
      cell.classList.toggle("is-waiting", !finished && n >= outputIndex + (kind === "sboxes" ? 4 : 1));
      cell.classList.toggle("is-destination", !finished && n >= outputIndex && n < outputIndex + (kind === "sboxes" ? 4 : 1));
    });
    lookupRows.forEach((node, n) => {
      node.classList.toggle("is-source", !finished && n === i);
      node.classList.toggle("is-waiting", !finished && n > i);
    });
    note.textContent = caption;
  };
}

const stageButtons = stages.map((label, i) => {
  const button = element("button", label);
  button.type = "button";
  button.setAttribute("aria-label", label === "IP" ? "Permutasi awal (IP)" : label === "FP" ? "Permutasi akhir (FP)" : `Putaran ${label}`);
  button.addEventListener("click", () => goTo(operations.findIndex((operation) => operation.stage === i)));
  $("#timeline").append(button);
  return button;
});

const activeOperation = () => operations[operationIndex];
const activeStage = () => trace?.steps[activeOperation()?.stage];
const bitString = (value) => value.match(/.{1,8}/g)?.join(" ") ?? "";

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
  const operation = activeOperation();
  const name = tablePicker.value;
  const table = tables[name];
  const container = $("#table-content");
  $("#copy-table").disabled = !table;
  tablePicker.disabled = !table;
  if (!table) {
    container.replaceChildren(element("p", "Klik Jalankan untuk melihat tabel acuan DES."));
    return;
  }
  const stage = operation?.reference_stage ? trace.steps[operation.reference_stage] : activeStage();
  container.replaceChildren(element("h4", tableLabel(name, table.title)), element("p", table.intro),
    element("pre", table.grid), element("h4", "Contoh perhitungan"),
    element("pre", stage?.examples[name] ?? "Klik Jalankan untuk melihat contoh perhitungan."));
}

function render() {
  const operation = activeOperation();
  const stage = activeStage();
  stageButtons.forEach((button, i) => {
    button.disabled = !operation;
    button.dataset.visited = String(!!operation && i < operation.stage);
    if (operation && i === operation.stage) button.setAttribute("aria-current", "step");
    else button.removeAttribute("aria-current");
  });
  $("#step-count").textContent = operation ? `OPERASI ${pad(operationIndex + 1)} / ${operations.length}` : "BELUM DIJALANKAN";
  $("#phase").textContent = operation?.group ?? "DES";
  $("#operation-title").textContent = operation?.title ?? "Belum ada operasi";
  $("#previous").disabled = !operation || operationIndex === 0;
  $("#next").disabled = !operation || operationIndex === operations.length - 1;
  for (const id of ["play", "replay", "speed", "speed-slider", "copy-step", "format"]) $("#" + id).disabled = !operation;
  $("#copy-result").disabled = $("#reverse").disabled = !trace?.output;
  output.value = trace?.output ?? "";
  $("#copy-feedback").textContent = "";

  activeButton?.removeAttribute("aria-current");
  activeButton = operation?.button;
  if (activeButton) {
    activeButton.setAttribute("aria-current", "step");
    const viewport = chain.parentElement;
    const bounds = viewport.getBoundingClientRect();
    const node = activeButton.getBoundingClientRect();
    if (node.top < bounds.top + 8) viewport.scrollTop += node.top - bounds.top - 8;
    else if (node.bottom > bounds.bottom - 8) viewport.scrollTop += node.bottom - bounds.bottom + 8;
  }

  paintFrame = drawOperation(operation);
  if (stage !== renderedStage) {
    renderedStage = stage;
    $("#stage-title").textContent = stage?.title ?? "Belum ada hasil";
    $("#stage-note").textContent = stage?.note ?? "";
    const lesson = stage?.walkthrough ?? [["Mulai dengan contoh", "Klik Muat contoh untuk memakai pesan dan kunci bawaan."]];
    $("#walkthrough").replaceChildren(...lesson.map(([heading, text]) => {
      const section = element("section", undefined, "lesson");
      section.append(element("h5", heading), element("p", text));
      return section;
    }));
    renderValues();
  }
  if (operation?.table && operation.table !== lastTable) tablePicker.value = operation.table;
  lastTable = operation?.table;
  renderTable();
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
  operationIndex = 0;
  elapsed = 0;
  buildDiagram([]);
  labels();
  block.removeAttribute("aria-invalid");
  key.removeAttribute("aria-invalid");
  status(message ?? (mode() === "decrypt" ? "Tempel teks sandi Base64 dan masukkan kunci enkripsinya." :
    "Masukkan 1 hingga 8 byte UTF-8. Aplikasi menambahkan byte nol hingga blok berisi 8 byte."));
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
    tablePicker.value = "IP";
    buildDiagram(data.groups);
    status(data.status, !data.output);
    render();
    paintFrame?.(1);
  } catch {
    if (version === requestVersion) status("Hasil tidak bisa dimuat. Pastikan server Python berjalan.", true);
  }
}

function pause() {
  if (frameId !== null) cancelAnimationFrame(frameId);
  frameId = null;
  lastFrame = null;
  $("#play").textContent = "Putar semua";
}

function goTo(index) {
  if (index < 0 || index >= operations.length) return;
  pause();
  operationIndex = index;
  render();
  elapsed = 0;
  animate(false);
}

function tick(timestamp) {
  const operation = activeOperation();
  const duration = operation.kind === "sboxes" ? 2050 : 1350;
  if (lastFrame !== null) elapsed += ((timestamp - lastFrame) / duration) * playbackRate;
  lastFrame = timestamp;
  paintFrame(reducedMotion.matches ? 1 : Math.min(1, elapsed));
  if (elapsed >= (sequence ? 1.15 : 1)) {
    if (!sequence || operationIndex === operations.length - 1) {
      pause();
      return;
    }
    elapsed = 0;
    operationIndex++;
    render();
    paintFrame(reducedMotion.matches ? 1 : 0);
  }
  frameId = requestAnimationFrame(tick);
}

function animate(all) {
  sequence = all;
  lastFrame = null;
  paintFrame(reducedMotion.matches ? 1 : Math.min(1, elapsed));
  if (reducedMotion.matches && !all) {
    elapsed = 1;
    return;
  }
  $("#play").textContent = "Jeda";
  frameId = requestAnimationFrame(tick);
}

function play() {
  if (frameId !== null) {
    pause();
    return;
  }
  if (operationIndex === operations.length - 1 && elapsed >= 1) {
    operationIndex = 0;
    render();
  }
  if (elapsed >= 1) elapsed = 0;
  animate(true);
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
$("#previous").addEventListener("click", () => goTo(operationIndex - 1));
$("#next").addEventListener("click", () => goTo(operationIndex + 1));
$("#play").addEventListener("click", play);
$("#replay").addEventListener("click", () => goTo(operationIndex));
speedSlider.addEventListener("input", () => {
  playbackRate = Number((10 ** Number(speedSlider.value)).toPrecision(3));
  speed.value = String(playbackRate).replace(".", ",");
  speed.removeAttribute("aria-invalid");
  speedSlider.setAttribute("aria-valuetext", `${speed.value} kali`);
});
speed.addEventListener("input", () => {
  const value = speed.value.trim().replace(",", ".");
  const rate = Number(value);
  if (!/^\+?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(value) || !Number.isFinite(rate) || rate <= 0) {
    speed.setAttribute("aria-invalid", "true");
    return;
  }
  playbackRate = rate;
  speed.removeAttribute("aria-invalid");
  speedSlider.value = Math.log10(rate);
  speedSlider.setAttribute("aria-valuetext", `${String(rate).replace(".", ",")} kali`);
});
speed.addEventListener("blur", () => {
  speed.value = String(playbackRate).replace(".", ",");
  speed.removeAttribute("aria-invalid");
});
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
  const operation = activeOperation();
  const report = [stage.title, stage.note, "\nPanduan", ...stage.walkthrough.map((item) => item.join("\n")),
    `\nOperasi: ${operation.title}`, ...[...operation.inputs, ...operation.outputs].map((item) =>
      `${item.label}: ${binary && item.binary ? bitString(item.binary) : showValue(item)}`),
    "\nDiagram (heks)", ...stage.flow.map((item) => item.join(": ")), `\nNilai (${binary ? "biner" : "heks"})`,
    ...stage.values.map((row) => `${row.label} (${row.bits} bit): ${binary ? bitString(row.binary) : row.hex}`)];
  copy(report.join("\n"), "Tahap");
});

runTrace(true);
