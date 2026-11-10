// app.js implements the embedded read-only Flow Audit interface.
const state = {
  cursor: "",
  cursorStack: [],
  currentQuery: "",
  selectedFlowID: "",
};

const elements = {
  form: document.querySelector("#search-form"),
  start: document.querySelector("#start"),
  end: document.querySelector("#end"),
  protocol: document.querySelector("#protocol"),
  ip: document.querySelector("#ip"),
  dport: document.querySelector("#dport"),
  open: document.querySelector("#open"),
  rows: document.querySelector("#flow-rows"),
  detail: document.querySelector("#detail"),
  status: document.querySelector("#runtime-status"),
  count: document.querySelector("#summary-count"),
  openCount: document.querySelector("#summary-open"),
  originalBytes: document.querySelector("#summary-original-bytes"),
  replyBytes: document.querySelector("#summary-reply-bytes"),
  nextPage: document.querySelector("#next-page"),
  exportJSONL: document.querySelector("#export-jsonl"),
  exportCSV: document.querySelector("#export-csv"),
};

// Format a Date for an HTML datetime-local input.
function localDateTime(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("-") + "T" + [
    pad(date.getHours()),
    pad(date.getMinutes()),
  ].join(":");
}

// Convert a datetime-local value to the API's UTC timestamp format.
function toRFC3339(value) {
  if (!value) {
    return "";
  }
  return new Date(value).toISOString();
}

// Build API filters from the current search form.
function buildQuery(cursor = "") {
  const params = new URLSearchParams();
  if (elements.start.value) params.set("start", toRFC3339(elements.start.value));
  if (elements.end.value) params.set("end", toRFC3339(elements.end.value));
  if (elements.protocol.value) params.set("protocol", elements.protocol.value);
  if (elements.ip.value.trim()) {
    params.set("ip", elements.ip.value.trim());
  }
  if (elements.dport.value) params.set("dst_port", elements.dport.value);
  if (elements.open.value) params.set("open", elements.open.value);
  if (cursor) params.set("cursor", cursor);
  return params;
}

// Fetch JSON and surface the API's structured error message.
async function requestJSON(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const payload = await response.json();
      message = payload.error?.message || message;
    } catch {
      // Keep the status-based error message when the response is not JSON.
    }
    throw new Error(message);
  }
  return response.json();
}

// Refresh the collector and storage health indicator.
async function refreshStatus() {
  try {
    const payload = await requestJSON("/api/v1/status");
    const runtime = payload.runtime;
    const ready = runtime.source_state === "healthy" && runtime.store_state === "healthy";
    elements.status.textContent = ready ? "采集中" : "状态异常";
    elements.status.className = `status ${ready ? "ready" : "degraded"}`;
  } catch (error) {
    elements.status.textContent = "状态读取失败";
    elements.status.className = "status degraded";
  }
}

// Render a byte count using a compact binary unit.
function formatBytes(value) {
  const number = Number(value || 0);
  if (number < 1024) return `${number} B`;
  if (number < 1024 ** 2) return `${(number / 1024).toFixed(1)} KiB`;
  if (number < 1024 ** 3) return `${(number / 1024 ** 2).toFixed(1)} MiB`;
  return `${(number / 1024 ** 3).toFixed(1)} GiB`;
}

// Render one normalized network tuple for display.
function tupleText(tuple) {
  if (!tuple?.source_ip || tuple.source_ip === "invalid IP") {
    return "—";
  }
  const host = tuple.source_ip.includes(":") ? `[${tuple.source_ip}]` : tuple.source_ip;
  return `${host}:${tuple.source_port} → ${tuple.destination_ip}:${tuple.destination_port}`;
}

// Append a text cell to a table row.
function appendCell(row, text) {
  const cell = document.createElement("td");
  cell.textContent = text;
  row.appendChild(cell);
  return cell;
}

// Render a Flow page and its aggregate summary.
function renderFlows(page) {
  elements.count.textContent = String(page.summary.count);
  elements.openCount.textContent = String(page.summary.open_count);
  elements.originalBytes.textContent = formatBytes(page.summary.original_bytes);
  elements.replyBytes.textContent = formatBytes(page.summary.reply_bytes);
  elements.rows.replaceChildren();

  if (!page.items.length) {
    const row = document.createElement("tr");
    const cell = appendCell(row, "暂无数据");
    cell.className = "empty";
    cell.colSpan = 8;
    elements.rows.appendChild(row);
    return;
  }

  for (const item of page.items) {
    const row = document.createElement("tr");
    row.dataset.flowId = item.flow_id;
    if (item.flow_id === state.selectedFlowID) {
      row.classList.add("selected");
    }
    appendCell(row, new Date(item.last_seen_at).toLocaleString());
    appendCell(row, item.direction);
    appendCell(row, item.protocol.toUpperCase());
    appendCell(row, tupleText(item.original));
    appendCell(row, String(item.original.destination_port));
    appendCell(row, item.state || "—");
    appendCell(row, formatBytes(item.counters.original.bytes));
    appendCell(row, formatBytes(item.counters.reply.bytes));
    row.addEventListener("click", () => showFlow(item.flow_id));
    elements.rows.appendChild(row);
  }
}

// Load one Flow page with the active filters.
async function loadFlows(cursor = "") {
  try {
    const params = buildQuery(cursor);
    state.currentQuery = params.toString();
    const page = await requestJSON(`/api/v1/flows?${state.currentQuery}`);
    renderFlows(page);
    state.cursor = page.next_cursor || "";
    elements.nextPage.classList.toggle("hidden", !state.cursor);
  } catch (error) {
    renderError(error);
  }
}

// Load and render a Flow snapshot plus its lifecycle events.
async function showFlow(flowID) {
  state.selectedFlowID = flowID;
  document.querySelectorAll("#flow-rows tr").forEach((row) => {
    row.classList.toggle("selected", row.dataset.flowId === flowID);
  });

  elements.detail.replaceChildren();
  const title = document.createElement("h2");
  title.textContent = "连接详情";
  elements.detail.appendChild(title);

  try {
    const [item, events] = await Promise.all([
      requestJSON(`/api/v1/flows/${encodeURIComponent(flowID)}`),
      requestJSON(`/api/v1/flows/${encodeURIComponent(flowID)}/events`),
    ]);

    elements.detail.appendChild(detailBlock("连接", {
      "Flow ID": item.flow_id,
      "协议": item.protocol.toUpperCase(),
      "方向": item.direction,
      "状态": item.state || "—",
      "首次观测": new Date(item.first_seen_at).toLocaleString(),
      "最后观测": new Date(item.last_seen_at).toLocaleString(),
      "是否关闭": item.open ? "否" : "是",
      "已回复": item.replied ? "是" : "否",
      "记录完整": item.complete ? "是" : "否",
    }));

    elements.detail.appendChild(detailBlock("Tuple", {
      "原方向": tupleText(item.original),
      "回复方向": tupleText(item.reply),
      "NAT": item.nat?.detected ? "已检测到" : "未检测到",
    }));

    elements.detail.appendChild(detailBlock("流量", {
      "原方向包数": String(item.counters.original.packets),
      "原方向字节": formatBytes(item.counters.original.bytes),
      "回复包数": String(item.counters.reply.packets),
      "回复字节": formatBytes(item.counters.reply.bytes),
      "计数可用": item.counters.available ? "是" : "否",
    }));

    const timeline = document.createElement("div");
    timeline.className = "detail-block";
    const heading = document.createElement("h3");
    heading.textContent = "事件时间线";
    timeline.appendChild(heading);
    const list = document.createElement("ul");
    list.className = "timeline";
    for (const event of events.items) {
      const entry = document.createElement("li");
      const label = document.createElement("strong");
      label.textContent = event.event_type.toUpperCase();
      const time = document.createElement("small");
      time.textContent = new Date(event.observed_at).toLocaleString();
      entry.append(label, time);
      list.appendChild(entry);
    }
    timeline.appendChild(list);
    elements.detail.appendChild(timeline);
  } catch (error) {
    const message = document.createElement("p");
    message.className = "error";
    message.textContent = error.message;
    elements.detail.appendChild(message);
  }
}

// Create one key-value block in the Flow detail panel.
function detailBlock(title, values) {
  const block = document.createElement("div");
  block.className = "detail-block";
  const heading = document.createElement("h3");
  heading.textContent = title;
  block.appendChild(heading);
  const grid = document.createElement("div");
  grid.className = "kv";
  for (const [key, value] of Object.entries(values)) {
    const label = document.createElement("span");
    label.textContent = key;
    const content = document.createElement("span");
    content.textContent = value;
    grid.append(label, content);
  }
  block.appendChild(grid);
  return block;
}

// Replace the result table with a user-visible error.
function renderError(error) {
  elements.rows.replaceChildren();
  const row = document.createElement("tr");
  const cell = appendCell(row, error.message);
  cell.className = "empty error";
  cell.colSpan = 8;
  elements.rows.appendChild(row);
}

// Download the current filtered result in the requested format.
function exportData(format) {
  const params = buildQuery("");
  params.set("format", format);
  window.location.href = `/api/v1/export?${params.toString()}`;
}

elements.start.value = localDateTime(new Date(Date.now() - 60 * 60 * 1000));
elements.end.value = localDateTime(new Date());

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  state.cursorStack = [];
  loadFlows();
});

elements.nextPage.addEventListener("click", () => {
  if (!state.cursor) return;
  state.cursorStack.push(state.cursor);
  loadFlows(state.cursor);
});

elements.exportJSONL.addEventListener("click", () => exportData("jsonl"));
elements.exportCSV.addEventListener("click", () => exportData("csv"));

refreshStatus();
setInterval(refreshStatus, 15000);
loadFlows();
