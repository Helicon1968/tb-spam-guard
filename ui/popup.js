/** SpamGuard - ツールバーのポップアップ */

import { ACTIONS, loadSettings, saveSettings } from "../src/config.js";
import { readLog } from "../src/log.js";

const $ = (id) => document.getElementById(id);

const ACTION_LABELS = {
  [ACTIONS.LOG_ONLY]: "ログのみ",
  [ACTIONS.TAG_ONLY]: "タグ付与",
  [ACTIONS.MARK_JUNK]: "タグ＋迷惑マーク",
  [ACTIONS.MARK_AND_MOVE]: "タグ＋迷惑マーク＋移動"
};

function verdictClass(v) {
  return v === "spam" ? "v-spam" : v === "suspect" ? "v-suspect" : "v-ham";
}

async function render() {
  const settings = await loadSettings();
  const log = await readLog();

  const today = new Date().toISOString().slice(0, 10);
  const todayLog = log.filter((r) => String(r.loggedAt).startsWith(today));
  const todaySpam = todayLog.filter((r) => r.verdict === "spam").length;

  $("status").textContent =
    (settings.enabled ? "稼働中" : "停止中") +
    " / 動作: " + (ACTION_LABELS[settings.action] || settings.action) +
    " / Jev: " + (settings.jevEnabled && settings.jevApiKey ? "有効" : "無効") +
    " / しきい値: " + settings.spamThreshold +
    " / 本日 " + todayLog.length + "件中 迷惑 " + todaySpam + "件";

  $("toggle").textContent = settings.enabled ? "一時停止" : "再開";

  const tbody = $("recent").querySelector("tbody");
  tbody.replaceChildren();
  for (const r of log.slice(0, 20)) {
    const tr = document.createElement("tr");
    const v = document.createElement("td");
    v.textContent = r.verdict;
    v.className = verdictClass(r.verdict);
    const s = document.createElement("td");
    s.textContent = String(r.score);
    const t = document.createElement("td");
    t.textContent = r.subject || "(件名なし)";
    t.title = (r.author || "") + "\n" + (r.applied || "");
    tr.append(v, s, t);
    tbody.appendChild(tr);
  }
}

$("openOptions").addEventListener("click", () => {
  browser.runtime.openOptionsPage();
  window.close();
});

$("toggle").addEventListener("click", async () => {
  const settings = await loadSettings();
  await saveSettings({ enabled: !settings.enabled });
  await render();
});

render();
