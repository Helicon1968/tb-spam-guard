/** SpamGuard - 設定画面 */

import { DEFAULT_SETTINGS, FREEMAIL_DOMAINS, loadSettings, saveSettings } from "../src/config.js";
import { askJev } from "../src/jev.js";
import { clearLog, readLog, toCsv } from "../src/log.js";

const $ = (id) => document.getElementById(id);

/** 入力欄と設定キーの対応。type は値の取り出し方を決める */
const FIELDS = [
  ["enabled", "check"],
  ["action", "text"],
  ["spamThreshold", "int"],
  ["grayLow", "int"],
  ["grayHigh", "int"],
  ["jevEnabled", "check"],
  ["jevApiKey", "text"],
  ["jevEndpoint", "text"],
  ["jevModel", "text"],
  ["jevBodyLimit", "int"],
  ["weightLocal", "float"],
  ["weightJev", "float"],
  ["allowDomains", "lines"],
  ["allowAddresses", "lines"],
  ["blockDomains", "lines"],
  ["blockAddresses", "lines"]
];

function setValue(id, type, value) {
  const el = $(id);
  if (type === "check") el.checked = Boolean(value);
  else if (type === "lines") el.value = (value || []).join("\n");
  else el.value = value === null || value === undefined ? "" : value;
}

function getValue(id, type) {
  const el = $(id);
  if (type === "check") return el.checked;
  if (type === "int") return Number.parseInt(el.value, 10);
  if (type === "float") return Number.parseFloat(el.value);
  if (type === "lines") {
    return el.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  }
  return el.value.trim();
}

async function render(settings) {
  for (const [id, type] of FIELDS) setValue(id, type, settings[id]);
}

/** 入力値の妥当性を確認する。問題があればメッセージを返す */
function validate(patch) {
  if (!Number.isFinite(patch.spamThreshold) || patch.spamThreshold < 0 || patch.spamThreshold > 100) {
    return "迷惑メール判定のしきい値は0〜100で指定してください。";
  }
  if (patch.grayLow >= patch.grayHigh) {
    return "グレーゾーンは 下限 < 上限 となるように指定してください。";
  }
  if (patch.spamThreshold < patch.grayLow) {
    return "迷惑メール判定のしきい値はグレーゾーン下限以上にしてください。";
  }
  if (!(patch.weightLocal >= 0) || !(patch.weightJev >= 0) || patch.weightLocal + patch.weightJev <= 0) {
    return "重みは0以上で、合計が0より大きくなるように指定してください。";
  }
  if (patch.jevEnabled && !patch.jevApiKey) {
    return "Jevを有効にする場合はAPIキーを入力してください。";
  }
  return null;
}

$("save").addEventListener("click", async () => {
  const patch = {};
  for (const [id, type] of FIELDS) patch[id] = getValue(id, type);
  const error = validate(patch);
  if (error) {
    $("saveResult").textContent = "保存していません: " + error;
    return;
  }
  await saveSettings(patch);
  $("saveResult").textContent = "保存しました（" + new Date().toLocaleTimeString() + "）";
});

$("reset").addEventListener("click", async () => {
  await browser.storage.local.set({ settings: {} });
  await render(DEFAULT_SETTINGS);
  $("saveResult").textContent = "既定値に戻しました";
});

$("testJev").addEventListener("click", async () => {
  $("testResult").textContent = "問い合わせ中...";
  const settings = await loadSettings();
  const probe = {
    ...settings,
    jevApiKey: getValue("jevApiKey", "text") || settings.jevApiKey,
    jevEndpoint: getValue("jevEndpoint", "text") || settings.jevEndpoint,
    jevModel: getValue("jevModel", "text") || settings.jevModel,
    jevMaxRetries: 0
  };
  try {
    const res = await askJev(
      {
        from_display_name: "国税庁",
        from_address: "notice@ad4ch8896b.example-random.com",
        from_domain: "example-random.com",
        subject: "【国税庁】メッセージボックスのご確認",
        body_excerpt: "お客様の未納の税金がございます。本日中に下記よりご確認ください。",
        link_domains: ["example-random.com"],
        delivery_path_hosts: ["softbank126001.bbtec.net"]
      },
      probe
    );
    const impersonation = res?.answers?.sender_impersonation?.noul;
    const pretext = res?.answers?.phishing_pretext?.choice;
    $("testResult").textContent =
      "成功 (model=" + (res.model || "?") +
      " / なりすまし確率=" + impersonation +
      " / 口実=" + (pretext || "?") + ")";
  } catch (e) {
    $("testResult").textContent = "失敗: " + (e && e.message ? e.message : e);
  }
});

// --- ログ表示 ---------------------------------------------------------------

function verdictClass(v) {
  return v === "spam" ? "v-spam" : v === "suspect" ? "v-suspect" : "v-ham";
}

function reasonText(record) {
  const parts = (record.ruleHits || []).map((h) => h.label + "(" + h.weight + ")");
  if (record.jev) {
    const d = record.jev.detail;
    parts.push(
      "Jev: なりすまし" + d.sender_impersonation.toFixed(2) +
      " / 情報詐取" + d.credential_phishing.toFixed(2) +
      " / 口実" + d.phishing_pretext.toFixed(2) +
      (record.jev.pretext ? "(" + record.jev.pretext + ")" : "") +
      " / 通常の商業メール" + d.ordinary_business_mail.toFixed(2)
    );
  }
  if (record.error) parts.push("エラー: " + record.error);
  return parts.join("、") || "-";
}

async function renderLog() {
  const log = await readLog();
  const tbody = $("logTable").querySelector("tbody");
  tbody.replaceChildren();
  for (const r of log) {
    const tr = document.createElement("tr");
    const cells = [
      new Date(r.loggedAt).toLocaleString(),
      r.verdict,
      String(r.score) + (r.localScore !== undefined ? " (L" + r.localScore + (r.jevScore !== null && r.jevScore !== undefined ? "/J" + r.jevScore : "") + ")" : ""),
      r.path,
      r.author,
      r.subject,
      reasonText(r),
      r.applied
    ];
    cells.forEach((text, i) => {
      const td = document.createElement("td");
      td.textContent = text === null || text === undefined ? "" : String(text);
      if (i === 1) td.className = verdictClass(r.verdict);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }
  const counts = log.reduce((acc, r) => {
    acc[r.verdict] = (acc[r.verdict] || 0) + 1;
    return acc;
  }, {});
  const jevCalls = log.filter((r) => r.jevScore !== null && r.jevScore !== undefined).length;
  $("logSummary").textContent =
    log.length + "件 / 迷惑" + (counts.spam || 0) +
    " 疑い" + (counts.suspect || 0) +
    " 正常" + (counts.ham || 0) +
    " / Jev呼び出し" + jevCalls + "件";
}

$("refreshLog").addEventListener("click", renderLog);

$("clearLog").addEventListener("click", async () => {
  await clearLog();
  await renderLog();
});

$("exportCsv").addEventListener("click", async () => {
  const log = await readLog();
  const blob = new Blob([toCsv(log)], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "spamguard-log-" + new Date().toISOString().slice(0, 10) + ".csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
});

(async () => {
  await render(await loadSettings());
  await renderLog();
})();

// --- 設定のバックアップ -------------------------------------------------------
// アドオンをアンインストールすると storage.local ごと消えるため、
// 更新前に書き出せるようにしておく（APIキーの再入力を避ける）。

$("exportSettings").addEventListener("click", async () => {
  const settings = await loadSettings();
  const blob = new Blob([JSON.stringify(settings, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "spamguard-settings-" + new Date().toISOString().slice(0, 10) + ".json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  $("backupResult").textContent = "書き出しました（APIキーを含みます）";
});

$("importSettings").addEventListener("click", () => $("importFile").click());

$("importFile").addEventListener("change", async (event) => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("設定ファイルの形式が不正です");
    }
    // 既定値に存在するキーだけを取り込む（未知のキーは無視する）
    const patch = {};
    for (const key of Object.keys(DEFAULT_SETTINGS)) {
      if (key in parsed) patch[key] = parsed[key];
    }
    const merged = await saveSettings(patch);
    await render(merged);
    $("backupResult").textContent =
      Object.keys(patch).length + " 項目を読み込みました";
  } catch (e) {
    $("backupResult").textContent = "読み込めません: " + (e && e.message ? e.message : e);
  } finally {
    event.target.value = "";
  }
});

// --- 拒否リストの候補 ---------------------------------------------------------
// 自動登録はしない。実データでは迷惑判定された差出人の98.6%が1回きりのアドレスで、
// 自動登録しても防げるのは3.9%にとどまる一方、誤検知が永続化する副作用が大きい。
// （拒否リストはルール判定より前に効くため、一度入ると根拠がログに残らなくなる）
// そこで「繰り返し出ている差出人」だけを候補として出し、追加はユーザーが判断する。

/** 候補から外す差出人か（フリーメール・自ドメイン・登録済み） */
function isExcludedSuggestion(domain, address, settings) {
  const lower = String(domain || "").toLowerCase();
  if (FREEMAIL_DOMAINS.includes(lower)) return true;
  if ((settings.selfDomains || []).some((d) => String(d).toLowerCase() === lower)) return true;
  if ((settings.blockDomains || []).some((d) => String(d).toLowerCase() === lower)) return true;
  if ((settings.blockAddresses || []).some((a) => String(a).toLowerCase() === address)) return true;
  if ((settings.allowDomains || []).some((d) => String(d).toLowerCase() === lower)) return true;
  if ((settings.allowAddresses || []).some((a) => String(a).toLowerCase() === address)) return true;
  return false;
}

/** "表示名 <addr>" からアドレス部分だけ取り出す */
function addressOf(author) {
  const m = String(author || "").match(/<([^>]+)>/);
  return (m ? m[1] : String(author || "")).trim().toLowerCase();
}

async function renderSuggestions() {
  const min = Math.max(2, Number.parseInt($("suggestMin").value, 10) || 2);
  const settings = await loadSettings();
  const log = await readLog();
  const spam = log.filter((r) => r.verdict === "spam");

  const byDomain = new Map();
  const byAddress = new Map();
  for (const r of spam) {
    const address = addressOf(r.author);
    const domain = String(r.fromDomain || "").toLowerCase();
    if (!domain || isExcludedSuggestion(domain, address, settings)) continue;
    const dom = byDomain.get(domain) || { n: 0, subject: "" };
    dom.n++; dom.subject = dom.subject || r.subject;
    byDomain.set(domain, dom);
    if (address) {
      const adr = byAddress.get(address) || { n: 0, subject: "" };
      adr.n++; adr.subject = adr.subject || r.subject;
      byAddress.set(address, adr);
    }
  }

  const rows = [
    ...[...byDomain.entries()].map(([v, d]) => ({ kind: "ドメイン", key: "blockDomains", value: v, ...d })),
    ...[...byAddress.entries()].map(([v, d]) => ({ kind: "アドレス", key: "blockAddresses", value: v, ...d }))
  ].filter((r) => r.n >= min).sort((a, b) => b.n - a.n);

  const tbody = $("suggestTable").querySelector("tbody");
  tbody.replaceChildren();
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const text of [String(row.n), row.kind, row.value, String(row.subject || "").slice(0, 40)]) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.appendChild(td);
    }
    const action = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "拒否に追加";
    button.addEventListener("click", async () => {
      const current = await loadSettings();
      const list = [...(current[row.key] || []), row.value];
      await saveSettings({ [row.key]: list });
      await render(await loadSettings());
      await renderSuggestions();
      $("suggestResult").textContent = "拒否リストに追加しました: " + row.value;
    });
    action.appendChild(button);
    tr.appendChild(action);
    tbody.appendChild(tr);
  }
  $("suggestResult").textContent = rows.length
    ? rows.length + " 件の候補（迷惑判定 " + spam.length + " 件から）"
    : "候補なし（迷惑判定 " + spam.length + " 件）";
}

$("refreshSuggest").addEventListener("click", renderSuggestions);
renderSuggestions();
