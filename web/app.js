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
const feistel = $("#feistel-diagram");
const roundToggle = $("#diagram-rounds");
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
let diagramHighlights = new Map();
let highlightedNodes = new Map();
let updateScheduleLabel = null;

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
  drawFeistel();
}

function drawFeistel() {
  const flow = $("#feistel-flow");
  flow.replaceChildren();
  diagramHighlights = new Map();
  highlightedNodes = new Map();
  updateScheduleLabel = null;
  const ready = operations.length > 0;
  feistel.toggleAttribute("hidden", !ready);
  $("#empty-diagram").hidden = ready;
  $("#diagram-legend").hidden = !ready;
  roundToggle.disabled = !ready;
  feistel.parentElement.scrollTop = 0;
  if (!ready) return;

  const full = roundToggle.getAttribute("aria-pressed") === "true";
  const left = 116, right = 284, center = 200, boxHeight = 38, pitch = 112;
  const atStage = (stage) => operations.filter((item) => item.stage === stage);
  const lastStage = stages.length - 1;
  const ip = operations.find((item) => item.table === "IP");
  const fp = operations.find((item) => item.table === "FP");
  const split = operations[operations.indexOf(ip) + 1];
  const swap = atStage(lastStage)[0];
  const preparation = operations.slice(0, operations.indexOf(ip));
  const schedule = operations.slice(operations.indexOf(split) + 1, operations.findIndex((item) => item.stage === 1));
  const conversion = atStage(lastStage).slice(2);
  const states = new Map();

  function svg(tag, attributes, text, parent = flow) {
    const node = document.createElementNS(feistel.namespaceURI, tag);
    for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
    if (text !== undefined) node.textContent = text;
    parent.append(node);
    return node;
  }

  const label = (x, y, text, cls, parent) => svg("text", {x, y, class: cls}, text, parent);
  const wire = (d, arrow = true, dashed = false) => svg("path", {d, class: `feistel-wire${dashed ? " feistel-dash" : ""}`,
    ...(arrow ? {"marker-end": "url(#feistel-arrow)"} : {})});
  const subscript = (value) => value.replace(/\d/g, (digit) => "\u2080\u2081\u2082\u2083\u2084\u2085\u2086\u2087\u2088\u2089"[digit]);

  function mark(node, role, ...items) {
    for (const operation of items) {
      if (!diagramHighlights.has(operation)) diagramHighlights.set(operation, new Map());
      diagramHighlights.get(operation).set(node, role);
    }
  }

  function target(title, activate) {
    const node = svg("g", {role: "button", tabindex: 0, "aria-label": title, class: "feistel-target"});
    svg("title", {}, title, node);
    node.addEventListener("click", activate);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        activate();
      }
    });
    return node;
  }

  function operationNode(operation, title) {
    return target(title, () => goTo(operations.indexOf(operation)));
  }

  function box(x, y, title, value, operation, width = 154) {
    const node = operationNode(operation, value ? `${title}: ${value}` : title);
    svg("rect", {x: x - width / 2, y, width, height: value ? boxHeight : 24, rx: value ? 1 : 12, class: "feistel-shape"}, undefined, node);
    label(x, y + (value ? 15 : 16), title, "feistel-label", node);
    if (value) label(x, y + 30, value, "feistel-value", node);
    return node;
  }

  function gate(x, y, symbol, operation, title) {
    const node = operationNode(operation, title);
    svg("circle", {cx: x, cy: y, r: 15, class: "feistel-hit"}, undefined, node);
    svg("circle", {cx: x, cy: y, r: 9, class: "feistel-shape"}, undefined, node);
    label(x, y + 4, symbol, "feistel-label", node);
    return node;
  }

  function stateBox(x, y, title, operation, value = operation.outputs[0]) {
    const node = box(x, y, title, showValue(value), operation);
    states.set(value.label, node);
    mark(node, "result", operation);
  }

  // Round arrows leave the R junction and XOR gate; the crossing has no junction.
  function round(n, y) {
    const ops = atStage(n);
    const expand = ops.find((item) => item.table === "E");
    const substitute = ops.find((item) => item.kind === "sboxes");
    const permute = ops.find((item) => item.table === "P");
    const [keyXor, leftXor] = ops.filter((item) => item.kind === "xor");
    const copyRight = ops.at(-1);
    const keyValue = keyXor.inputs[1];
    const k = subscript(String(Number(keyValue.label.slice(1))));
    const i = subscript(String(n - 1)), j = subscript(String(n));
    const gateY = y + 72, next = y + pitch;
    const final = n === lastStage - 1;

    mark(wire(`M${left} ${y + boxHeight}V${gateY - 9}`), "signal", leftXor);
    mark(wire(`M${right} ${y + boxHeight}V${gateY}`, false), "signal", expand, copyRight);
    mark(wire(`M${right} ${gateY}H${center + 9}`), "signal", expand);
    mark(wire(`M${center - 9} ${gateY}H${left + 9}`), "signal", permute, leftXor);
    mark(wire(`M371 ${y + 51}H${center}V${gateY - 9}`), "signal", keyXor);
    for (const [from, to, start, operation] of [[left, final ? left : right, gateY + 9, leftXor],
      [right, final ? right : left, gateY, copyRight]]) {
      mark(wire(`M${from} ${start}V${y + 86}L${to} ${next - 7}V${next}`), "signal", operation);
    }
    svg("circle", {cx: right, cy: gateY, r: 2.7, class: "feistel-junction"});
    label(8, y + 70, `#${pad(n)}`, "feistel-round-number");

    const keyNode = operationNode(keyXor, `${keyValue.label}: ${showValue(keyValue)}`);
    svg("rect", {x: 371, y: y + 40, width: 37, height: 22, rx: 3, class: "feistel-shape feistel-key"}, undefined, keyNode);
    label(389.5, y + 55, `K${k}`, "feistel-label", keyNode);
    mark(keyNode, "input", keyXor);
    mark(keyNode, "result", ...schedule.filter((item) => item.reference_stage === n && item.table === "PC-2"));
    mark(gate(left, gateY, "\u2295", leftXor, leftXor.title), "operation", leftXor);
    const functionGate = gate(center, gateY, "f", expand, `Fungsi Feistel putaran ${n}`);
    mark(functionGate, "operation", expand, keyXor, substitute, permute);
    mark(functionGate, "input", leftXor);
    mark(states.get(expand.inputs[0].label), "input", expand, copyRight);
    mark(states.get(leftXor.inputs[0].label), "input", leftXor);

    const l = [`L${j} = R${i}`, copyRight];
    const r = [`R${j} = L${i} \u2295 f(R${i}, K${k})`, leftXor];
    stateBox(left, next, ...(final ? r : l));
    stateBox(right, next, ...(final ? l : r));
    return next;
  }

  const inputBlock = box(center, 12, "Blok masukan", showValue(ip.inputs[0]), operations[0], 174);
  mark(inputBlock, "operation", ...preparation);
  mark(inputBlock, "input", ip);
  mark(wire(`M${center} 50V64`), "signal", ip);
  const ipBox = box(center, 64, "Permutasi awal (IP)", null, ip, 186);
  mark(ipBox, "operation", ip);
  mark(ipBox, "input", split);
  let y = 190;
  mark(wire(`M${center} 88V106H${left}V${y}`), "signal", split);
  mark(wire(`M${center} 106H${right}V${y}`), "signal", split);
  const fork = operationNode(split, split.title);
  svg("circle", {cx: center, cy: 106, r: 10, class: "feistel-hit"}, undefined, fork);
  svg("circle", {cx: center, cy: 106, r: 3.4, class: "feistel-shape"}, undefined, fork);
  mark(fork, "operation", split);
  const keyX = 352, keyWidth = 104;
  label(keyX, 14, "Jadwal kunci", "feistel-label");
  const steps = [
    ["UTF-8", [schedule[0]]],
    ["PC-1", [schedule[1]]],
    ["Bagi C dan D", [schedule[2]]],
    ["Rotasi C/D", schedule.filter((item) => item.table === "Shifts")],
    ["PC-2", schedule.filter((item) => item.table === "PC-2")],
  ];
  const scheduleNodes = steps.map(([title, items], i) => {
    const top = 21 + i * 29;
    const node = box(keyX, top, title, null, items[0], keyWidth);
    mark(node, "operation", ...items);
    if (i > 0) mark(wire(`M${keyX} ${top - 5}V${top}`), "signal", ...(i === 3 ? items.slice(0, 1) : items));
    return node;
  });
  mark(scheduleNodes[0], "input", ...steps[1][1]);
  mark(scheduleNodes[1], "input", ...steps[2][1]);
  mark(scheduleNodes[2], "input", steps[3][1][0]);
  mark(scheduleNodes[3], "input", ...steps[4][1]);
  const subkeyLabel = label(keyX, 178, "", "feistel-value feistel-schedule-key");
  updateScheduleLabel = (operation) => {
    const name = operation?.outputs[0].label;
    const isRotation = operation?.table === "Shifts";
    const isSelection = operation?.table === "PC-2";
    subkeyLabel.textContent = isRotation ? `Siapkan K${name.slice(1)}` : isSelection ? `Hasil: ${name}` : "";
    subkeyLabel.classList.toggle("feistel-schedule-result", isSelection);
  };

  stateBox(left, y, "L\u2080", split, split.outputs[0]);
  stateBox(right, y, "R\u2080", split, split.outputs[1]);
  if (full) {
    for (let n = 1; n < lastStage; n++) y = round(n, y);
  } else {
    y = round(2, round(1, y));
    for (const x of [left, right]) wire(`M${x} ${y + boxHeight}V${y + 100}`, true, true);
    const omitted = target("Tampilkan putaran 03 sampai 15", () => setExpanded(true));
    mark(omitted, "operation", ...operations.filter((item) => item.stage >= 3 && item.stage <= 15));
    svg("rect", {x: 137, y: y + 55, width: 126, height: 24, rx: 12, class: "feistel-shape"}, undefined, omitted);
    label(center, y + 71, "Putaran 03\u201315", "feistel-label", omitted);
    y += 100;
    const round15 = atStage(15);
    const copyRight = round15.at(-1);
    const leftXor = round15.filter((item) => item.kind === "xor").at(-1);
    stateBox(left, y, "L\u2081\u2085", copyRight);
    stateBox(right, y, "R\u2081\u2085", leftXor);
    y = round(16, y);
  }

  const joinY = y + 55;
  mark(wire(`M${left} ${y + boxHeight}V${joinY}H${center}`, false), "signal", swap);
  mark(wire(`M${right} ${y + boxHeight}V${joinY}H${center}`, false), "signal", swap);
  mark(wire(`M${center} ${joinY}V${y + 72}`), "signal", fp);
  for (const value of swap.inputs) mark(states.get(value.label), "input", swap);
  const junction = operationNode(swap, swap.title);
  svg("circle", {cx: center, cy: joinY, r: 10, class: "feistel-hit"}, undefined, junction);
  svg("circle", {cx: center, cy: joinY, r: 3.4, class: "feistel-shape"}, undefined, junction);
  mark(junction, "operation", swap);
  mark(junction, "input", fp);
  mark(box(center, y + 72, "Permutasi akhir (FP)", null, fp, 186), "operation", fp);
  mark(wire(`M${center} ${y + 96}V${y + 112}`), "signal", fp);
  const result = box(center, y + 112, "Blok keluaran", showValue(fp.outputs[0]), operations.at(-1), 174);
  mark(result, "result", fp);
  mark(result, "operation", ...conversion);
  feistel.setAttribute("viewBox", `0 0 416 ${y + 162}`);
}

function setExpanded(full) {
  roundToggle.setAttribute("aria-pressed", String(full));
  drawFeistel();
  syncFeistel();
  roundToggle.focus({preventScroll: true});
}

function syncFeistel() {
  const operation = activeOperation();
  $("#diagram-operation").textContent = operation?.title ?? "";
  updateScheduleLabel?.(operation);
  const next = diagramHighlights.get(operation) ?? new Map();
  for (const node of highlightedNodes.keys()) {
    node.removeAttribute("data-highlight");
    node.removeAttribute("aria-current");
  }
  let primary;
  for (const [node, role] of next) {
    node.setAttribute("data-highlight", role);
    if (role === "operation" || (!primary && role === "result")) primary = node;
  }
  highlightedNodes = next;
  if (primary) {
    primary.setAttribute("aria-current", "step");
    keepVisible(feistel.parentElement, primary);
  }
}

function keepVisible(viewport, item) {
  const bounds = viewport.getBoundingClientRect();
  const node = item.getBoundingClientRect();
  if (node.top < bounds.top + 8) viewport.scrollTop += node.top - bounds.top - 8;
  else if (node.bottom > bounds.bottom - 8) viewport.scrollTop += node.bottom - bounds.bottom + 8;
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
  button.addEventListener("click", () => goTo(operations.findIndex((operation) =>
    i === 0 || i === stages.length - 1 ? operation.table === label : operation.stage === i)));
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
    if ($("#operation-browser").open) keepVisible(chain.parentElement, activeButton);
  }
  if (operation?.stage >= 3 && operation.stage <= 15 && roundToggle.getAttribute("aria-pressed") === "false") {
    roundToggle.setAttribute("aria-pressed", "true");
    drawFeistel();
  }
  syncFeistel();

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
roundToggle.addEventListener("click", () => setExpanded(roundToggle.getAttribute("aria-pressed") !== "true"));
$("#operation-browser").addEventListener("toggle", () => {
  if ($("#operation-browser").open && activeButton) keepVisible(chain.parentElement, activeButton);
});
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
