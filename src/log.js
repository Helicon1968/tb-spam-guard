/**
 * SpamGuard - 判定ログ
 *
 * storage.local にリングバッファとして保持する。
 * 閾値調整と誤検出の確認はこのログを見て行うため、
 * 判定根拠（ヒットしたルール、Jevの各回答）まで残す。
 */

const KEY = "log";

/** ログを新しい順で取得する */
export async function readLog() {
  const stored = await browser.storage.local.get(KEY);
  return Array.isArray(stored[KEY]) ? stored[KEY] : [];
}

/** 1件追記する（上限を超えた古い分は捨てる） */
export async function appendLog(record, limit) {
  const log = await readLog();
  log.unshift({ ...record, loggedAt: new Date().toISOString() });
  if (log.length > limit) log.length = limit;
  await browser.storage.local.set({ [KEY]: log });
  return log.length;
}

/** ログを空にする */
export async function clearLog() {
  await browser.storage.local.remove(KEY);
}

/** CSV文字列に変換する（Excelで開く前提でBOM付き） */
export function toCsv(log) {
  // applied（実際に行った操作）と source（判定の契機）は切り分けに必須なので必ず出す。
  // 設定画面の表には出ていたのにCSVから抜けており、
  // 「タグが付かない」原因を調べられない状態になっていた。
  const columns = [
    "loggedAt", "date", "verdict", "score", "localScore", "jevScore", "path",
    "author", "fromDomain", "subject", "brands", "ruleHits", "applied", "source", "error"
  ];
  const escape = (v) => {
    const s = v === null || v === undefined ? "" : String(v);
    return '"' + s.replace(/"/g, '""').replace(/\r?\n/g, " ") + '"';
  };
  const rows = log.map((r) => columns.map((c) => {
    if (c === "brands") return escape((r.brands || []).join("/"));
    if (c === "ruleHits") return escape((r.ruleHits || []).map((h) => h.id).join("/"));
    return escape(r[c]);
  }).join(","));
  return "﻿" + columns.join(",") + "\r\n" + rows.join("\r\n") + "\r\n";
}
