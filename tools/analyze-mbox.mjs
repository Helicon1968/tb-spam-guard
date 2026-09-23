/**
 * SpamGuard - 実データでの判定精度チェック（チューニング用）
 *
 * 実行例:
 *   node tools/analyze-mbox.mjs --spam "<プロファイル>/Mail/<アカウント>/Junk" \
 *                               --ham  "<プロファイル>/Mail/<アカウント>/Inbox" \
 *                               --limit 400
 *
 * 出力:
 *   - 点数分布と、現在のしきい値での見逃し／誤検出の件数
 *   - どのルールがどれだけ効いているか
 *   - 見逃した迷惑メールの差出人ドメイン・件名（配点見直しの材料）
 */

import { readMbox } from "./mbox.mjs";
import { extractFeatures } from "../src/extract.js";
import { scoreByRules, markSelfDomainSpoof, RULES } from "../src/rules.js";
import { DEFAULT_SETTINGS } from "../src/config.js";

function parseArgs(argv) {
  const args = { spam: [], ham: [], limit: 400, selfDomains: [], show: 25 };
  for (let i = 2; i < argv.length; i++) {
    const key = argv[i].replace(/^--/, "");
    const value = argv[i + 1];
    if (key === "spam" || key === "ham") { args[key].push(value); i++; }
    else if (key === "self-domain") { args.selfDomains.push(String(value).toLowerCase()); i++; }
    else if (key === "limit" || key === "show") { args[key] = Number(value); i++; }
  }
  return args;
}

const args = parseArgs(process.argv);
const S = DEFAULT_SETTINGS;

/** 1フォルダ分を採点する */
function scoreFolder(path, limit) {
  const rows = [];
  for (const { part } of readMbox(path, limit)) {
    let f;
    try {
      f = extractFeatures(part);
    } catch (e) {
      continue;
    }
    const { score, hits } = scoreByRules(markSelfDomainSpoof(f, { selfDomains: args.selfDomains }));
    rows.push({ score, hits, f, path });
  }
  return rows;
}

function histogram(rows) {
  const buckets = new Array(11).fill(0);
  for (const r of rows) buckets[Math.min(10, Math.floor(r.score / 10))]++;
  const max = Math.max(1, ...buckets);
  return buckets.map((n, i) => {
    const label = String(i * 10).padStart(3) + "-" + String(i * 10 + 9).padEnd(3);
    return "  " + label + " " + "#".repeat(Math.round((n / max) * 40)).padEnd(40) + " " + n;
  }).join("\n");
}

function ruleStats(rows) {
  const counts = new Map();
  for (const r of rows) for (const h of r.hits) counts.set(h.id, (counts.get(h.id) || 0) + 1);
  return RULES
    .map((rule) => ({ id: rule.id, label: rule.label, weight: rule.weight, n: counts.get(rule.id) || 0 }))
    .sort((a, b) => b.n - a.n);
}

function pct(n, total) {
  return total ? (100 * n / total).toFixed(1) + "%" : "-";
}

const spam = args.spam.flatMap((p) => scoreFolder(p, args.limit));
const ham = args.ham.flatMap((p) => scoreFolder(p, args.limit));

console.log("=".repeat(72));
console.log("検体数: 迷惑 " + spam.length + " 通 / 正常 " + ham.length + " 通");
console.log("しきい値: spam>=" + S.spamThreshold + " / グレーゾーン " + S.grayLow + "-" + S.grayHigh);
console.log("=".repeat(72));

console.log("\n【迷惑メールの点数分布】");
console.log(histogram(spam));
console.log("\n【正常メールの点数分布】");
console.log(histogram(ham));

const missed = spam.filter((r) => r.score < S.grayLow);
const grayS = spam.filter((r) => r.score >= S.grayLow && r.score < S.grayHigh);
const caught = spam.filter((r) => r.score >= S.spamThreshold);
const fp = ham.filter((r) => r.score >= S.spamThreshold);
const grayH = ham.filter((r) => r.score >= S.grayLow && r.score < S.grayHigh);

console.log("\n【現状の成績（ローカルルールのみ）】");
console.log("  迷惑を即座に検出  : " + caught.length + " / " + spam.length + " (" + pct(caught.length, spam.length) + ")");
console.log("  迷惑がグレーゾーン: " + grayS.length + " / " + spam.length + " (" + pct(grayS.length, spam.length) + ")  ← Jevで拾える");
console.log("  迷惑を completely 見逃し: " + missed.length + " / " + spam.length + " (" + pct(missed.length, spam.length) + ")  ← Jevにも回らない");
console.log("  正常の誤検出      : " + fp.length + " / " + ham.length + " (" + pct(fp.length, ham.length) + ")");
console.log("  正常がグレーゾーン: " + grayH.length + " / " + ham.length + " (" + pct(grayH.length, ham.length) + ")  ← Jev呼び出しコスト");

console.log("\n【ルールの発火率（迷惑 " + spam.length + " 通中 / 正常 " + ham.length + " 通中）】");
const rsSpam = new Map(ruleStats(spam).map((r) => [r.id, r.n]));
const rsHam = new Map(ruleStats(ham).map((r) => [r.id, r.n]));
for (const rule of RULES) {
  const a = rsSpam.get(rule.id) || 0;
  const b = rsHam.get(rule.id) || 0;
  console.log(
    "  " + String(rule.weight).padStart(4) + "  " +
    rule.id.padEnd(22) + " 迷惑 " + String(a).padStart(4) + " (" + pct(a, spam.length).padStart(6) + ")" +
    "   正常 " + String(b).padStart(4) + " (" + pct(b, ham.length).padStart(6) + ")"
  );
}

console.log("\n【見逃した迷惑メール（点数 < " + S.grayLow + "）上位 " + args.show + " 件】");
for (const r of missed.slice(0, args.show)) {
  console.log(
    "  " + String(r.score).padStart(3) + "  " +
    (r.f.fromDomain || "-").padEnd(28) + "  " +
    String(r.f.subject || "(件名なし)").slice(0, 44)
  );
}

console.log("\n【見逃した迷惑メールの差出人ドメイン頻度 上位30】");
const domainCount = new Map();
for (const r of missed) domainCount.set(r.f.fromDomain, (domainCount.get(r.f.fromDomain) || 0) + 1);
for (const [d, n] of [...domainCount.entries()].sort((a, b) => b[1] - a[1]).slice(0, 30)) {
  console.log("  " + String(n).padStart(4) + "  " + d);
}

console.log("\n【誤検出した正常メール（点数 >= " + S.spamThreshold + "）】");
for (const r of fp.slice(0, args.show)) {
  console.log(
    "  " + String(r.score).padStart(3) + "  " +
    (r.f.fromDomain || "-").padEnd(28) + "  " +
    r.hits.filter((h) => h.weight > 0).map((h) => h.id).join(",")
  );
}
