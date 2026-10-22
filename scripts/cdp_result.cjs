// Polls a headless browser tab over the DevTools protocol until #result leaves RUNNING.
// usage: node cdp_result.cjs <debug-port> <page-url> <timeout-seconds>
const [port, pageUrl, timeout] = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function target() {
  for (let i = 0; i < 100; i++) {
    try {
      const made = await fetch(`http://127.0.0.1:${port}/json/new?${pageUrl}`, { method: "PUT" });
      return (await made.json()).webSocketDebuggerUrl;
    } catch {
      await sleep(200);
    }
  }
  throw new Error("browser debugging port never opened");
}

async function main() {
  const socket = new WebSocket(await target());
  await new Promise((resolve) => (socket.onopen = resolve));
  const pending = new Map();
  let id = 0;
  socket.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    pending.get(message.id)?.(message.result);
  };
  const send = (method, params) => new Promise((resolve) => {
    pending.set(++id, resolve);
    socket.send(JSON.stringify({ id, method, params }));
  });
  const deadline = Date.now() + Number(timeout) * 1000;
  while (Date.now() < deadline) {
    const out = await send("Runtime.evaluate", { expression: 'document.getElementById("result")?.textContent' });
    const value = out?.result?.value;
    if (value && value !== "RUNNING") return value;
    await sleep(500);
  }
  return "FAIL timed out";
}

main().then((value) => { console.log(value); process.exit(value.startsWith("PASS") ? 0 : 1); });
