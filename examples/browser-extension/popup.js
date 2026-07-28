const modeSel = document.getElementById("mode");
const result = document.getElementById("result");

chrome.storage.local.get(["mode"]).then((c) => {
  modeSel.value = c.mode || "warn";
});

modeSel.addEventListener("change", () =>
  chrome.storage.local.set({ mode: modeSel.value })
);

document.getElementById("opts").addEventListener("click", () =>
  chrome.runtime.openOptionsPage()
);

document.getElementById("test").addEventListener("click", () => {
  result.textContent = "Testing…";
  result.className = "";
  chrome.runtime.sendMessage({ type: "shield-test" }, (r) => {
    if (!r) { result.textContent = "No response."; result.className = "bad"; return; }
    const id = r.identity || {};
    const idLine =
      "\nas: " + (id.userId || "(no policy userId)") + "\ndevice: " + (id.deviceId || "(none)");
    if (r.error) {
      // r.block tells us what actually happened, rather than assuming.
      result.textContent = "✗ " + r.error +
        (r.block ? "\n(prompt would be BLOCKED — fail closed)"
                 : "\n(prompt would send UNSCREENED — fail open)") + idLine;
      result.className = "bad";
    } else {
      result.textContent =
        "✓ Reached Shield. mode=" + r.mode +
        (r.reason ? "\nguards: " + r.reason : "\nverdict: pass") + idLine;
      result.className = "ok";
    }
  });
});
