/**
 * SpamGuard - Jev質問セットの新旧比較（チューニング用）
 *
 * eval-jev.mjs の結果ファイルを2つ読み、同じメールに対する回答を突き合わせる。
 * 質問文を作り直したときに「本当に良くなったか」を確認するためのもの。
 *
 * 実行:
 *   node tools/compare-eval.mjs
 *   node tools/compare-eval.mjs --old tools/eval-jev-result.v1-questions.json \
 *                               --new tools/eval-jev-result.json
 *
 * 比較の軸:
 *   - 詐称型／正規メールそれぞれの、しきい値超えの数
 *   - 各問いの「詐称型の平均 − 正規の平均」（＝判別力）
 *   - メール単位で見た改善／悪化の内訳
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_SETTINGS } from "../src/config.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const S = DEFAULT_SETTINGS;

function parseArgs(argv) {
  const args = {
    old: join(ROOT, "tools", "eval-jev-result.v1-questions.json"),
    new: join(ROOT, "tools", "eval-jev-result.json")
  };
  for (let i = 2; i < argv.length; i++) {
    const key = argv[i].replace(/^--/, "");
    if (key === "old" || key === "new") { args[key] = argv[i + 1]; i++; }
  }
  return args;
}

const args = parseArgs(process.argv);

for (const [name, path] of [["旧", args.old], ["新", args.new]]) {
  if (!existsSync(path)) {
    console.error(name + "の結果ファイルが見つかりません: " + path);
    console.error("先に node tools/eval-jev.mjs --sample 40 を実行してください。");
    process.exit(1);
  }
}

/** key ("label:messageId:score") から messageId を取り出す */
function messageIdOf(key) {
  const first = key.indexOf(":");
  const last = key.lastIndexOf(":");
  return key.slice(first + 1, last);
}

function load(path) {
  const rows = Object.values(JSON.parse(readFileSync(path, "utf8")).byKey || {});
  const byMid = new Map();
  for (const r of rows) {
    if (typeof r.jevScore !== "number") continue;
    byMid.set(messageIdOf(r.key), r);
  }
  return byMid;
}

const oldRows = load(args.old);
const newRows = load(args.new);

const pairs = [];
for (const [mid, n] of newRows) {
  const o = oldRows.get(mid);
  if (o) pairs.push({ mid, old: o, now: n });
}

console.log("=".repeat(74));
console.log("突き合わせ: 旧 " + oldRows.size + " 件 / 新 " + newRows.size + " 件 → 共通 " + pairs.length + " 件");
console.log("しきい値 " + S.spamThreshold + " 点で比較");
console.log("=".repeat(74));

const P = pairs.filter((p) => p.now.label === "phish");
const H = pairs.filter((p) => p.now.label === "ham");
const pct = (n, d) => (d ? (100 * n / d).toFixed(1) + "%" : "-");

function over(rows, pick) {
  return rows.filter((p) => pick(p).finalScore >= S.spamThreshold).length;
}

console.log("\n【しきい値超えの数】");
console.log("  詐称型 n=" + P.length +
  " : 旧 " + over(P, (p) => p.old) + " (" + pct(over(P, (p) => p.old), P.length) + ")" +
  "  →  新 " + over(P, (p) => p.now) + " (" + pct(over(P, (p) => p.now), P.length) + ")");
console.log("  正規   n=" + H.length +
  " : 旧 " + over(H, (p) => p.old) + " (" + pct(over(H, (p) => p.old), H.length) + ")" +
  "  →  新 " + over(H, (p) => p.now) + " (" + pct(over(H, (p) => p.now), H.length) + ")");

const avg = (rows, f) => (rows.length ? rows.reduce((a, r) => a + f(r), 0) / rows.length : 0);

console.log("\n【Jev単独スコアの平均】");
console.log("  詐称型: 旧 " + avg(P, (p) => p.old.jevScore).toFixed(1) +
  " → 新 " + avg(P, (p) => p.now.jevScore).toFixed(1));
console.log("  正規  : 旧 " + avg(H, (p) => p.old.jevScore).toFixed(1) +
  " → 新 " + avg(H, (p) => p.now.jevScore).toFixed(1));
const sepOld = avg(P, (p) => p.old.jevScore) - avg(H, (p) => p.old.jevScore);
const sepNew = avg(P, (p) => p.now.jevScore) - avg(H, (p) => p.now.jevScore);
console.log("  分離幅: 旧 " + sepOld.toFixed(1) + " → 新 " + sepNew.toFixed(1) +
  "  (" + (sepNew >= sepOld ? "+" : "") + (sepNew - sepOld).toFixed(1) + ")");

/** 各問いの判別力（詐称型の平均 − 正規の平均） */
function separation(rows, hamRows, key, pick) {
  const get = (p) => {
    const d = pick(p).detail || {};
    return typeof d[key] === "number" ? d[key] : null;
  };
  const p = rows.map(get).filter((v) => v !== null);
  const h = hamRows.map(get).filter((v) => v !== null);
  if (!p.length || !h.length) return null;
  const pa = p.reduce((a, b) => a + b, 0) / p.length;
  const ha = h.reduce((a, b) => a + b, 0) / h.length;
  return { phish: pa, ham: ha, sep: pa - ha };
}

console.log("\n【各問いの判別力（詐称型の平均 − 正規の平均。大きいほど効いている）】");
const allKeys = new Set();
for (const p of pairs) {
  for (const k of Object.keys(p.old.detail || {})) allKeys.add("旧:" + k);
  for (const k of Object.keys(p.now.detail || {})) allKeys.add("新:" + k);
}
for (const tag of ["旧", "新"]) {
  console.log("  [" + tag + "]");
  const pick = tag === "旧" ? ((p) => p.old) : ((p) => p.now);
  for (const full of [...allKeys].filter((k) => k.startsWith(tag + ":"))) {
    const key = full.slice(2);
    const s = separation(P, H, key, pick);
    if (!s) continue;
    console.log("    " + key.padEnd(24) +
      " 詐称 " + s.phish.toFixed(2) +
      " / 正規 " + s.ham.toFixed(2) +
      " / 差 " + (s.sep >= 0 ? "+" : "") + s.sep.toFixed(2));
  }
}

console.log("\n【メール単位の増減】");
const improvedP = P.filter((p) => p.old.finalScore < S.spamThreshold && p.now.finalScore >= S.spamThreshold);
const lostP = P.filter((p) => p.old.finalScore >= S.spamThreshold && p.now.finalScore < S.spamThreshold);
const worseH = H.filter((p) => p.old.finalScore < S.spamThreshold && p.now.finalScore >= S.spamThreshold);
const fixedH = H.filter((p) => p.old.finalScore >= S.spamThreshold && p.now.finalScore < S.spamThreshold);

console.log("  詐称型で新たに拾えた : " + improvedP.length + " 通");
for (const p of improvedP) console.log("    " + p.old.finalScore + "→" + p.now.finalScore + "  " + p.now.fromDomain + "  " + String(p.now.subject).slice(0, 34));
console.log("  詐称型で拾えなくなった: " + lostP.length + " 通");
for (const p of lostP) console.log("    " + p.old.finalScore + "→" + p.now.finalScore + "  " + p.now.fromDomain + "  " + String(p.now.subject).slice(0, 34));
console.log("  正規で新たに誤検出   : " + worseH.length + " 通");
for (const p of worseH) console.log("    " + p.old.finalScore + "→" + p.now.finalScore + "  " + p.now.fromDomain + "  " + String(p.now.subject).slice(0, 34));
console.log("  正規で誤検出が消えた : " + fixedH.length + " 通");
for (const p of fixedH) console.log("    " + p.old.finalScore + "→" + p.now.finalScore + "  " + p.now.fromDomain + "  " + String(p.now.subject).slice(0, 34));

console.log("\n【総評】");
const netP = improvedP.length - lostP.length;
const netH = worseH.length - fixedH.length;
console.log("  しきい値をまたいだ本数  詐称型 " + (netP >= 0 ? "+" : "") + netP +
  " 通 / 正規 " + (netH > 0 ? "+" + netH + " 通（悪化）" : netH === 0 ? "変化なし" : netH + " 通（改善）"));
console.log("  Jevスコアの分離幅        " + sepOld.toFixed(1) + " → " + sepNew.toFixed(1) +
  " (" + (sepNew >= sepOld ? "+" : "") + (sepNew - sepOld).toFixed(1) + ")");

/**
 * 判定は分離幅を主、しきい値の本数を従とする。
 *
 * しきい値をまたいだ本数だけで良し悪しを決めると、検体数が数十のときは
 * 境界付近の1〜2通の動きに結論が振り回される。一方、分離幅（詐称型の平均 −
 * 正規の平均）は全検体の情報を使うため安定しており、しかも分離さえ広がって
 * いれば、しきい値や重みの調整で本数はあとから取り戻せる。
 */
const sepDelta = sepNew - sepOld;
const noiseLevel = Math.max(1, Math.round(P.length * 0.05));
if (sepDelta > 5 && netH <= 0) {
  console.log("  → 新しい質問セットのほうが良い。分離幅が " + sepDelta.toFixed(1) + " 広がっている。");
  if (netP < 0) {
    console.log("     しきい値をまたいだ本数は " + netP + " 通だが、分離が広がっているので");
    console.log("     重み（scoreFromJev）としきい値の調整で取り戻せる。検体数 " + P.length +
      " ではこの程度の増減は誤差（目安 ±" + noiseLevel + " 通）。");
  }
} else if (sepDelta < -5) {
  console.log("  → 旧セットのほうが良い。分離幅が " + Math.abs(sepDelta).toFixed(1) + " 狭まっている。差し戻しを検討する。");
} else if (netH > 0) {
  console.log("  → 正規メールの誤検出が増えている。分離幅にかかわらず採用すべきでない。");
} else {
  console.log("  → 有意な差なし。検体を増やすか、別の観点で比較する。");
}
