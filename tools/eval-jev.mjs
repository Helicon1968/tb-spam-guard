/**
 * SpamGuard - Jev（TypeSafe System One）の効果測定（チューニング用・拡張本体には含めない）
 *
 * ローカルルールでグレーゾーンに落ちた実メールをJevへ投げ、
 *  - 詐称型フィッシングをしきい値の上へ押し上げられるか（＝拾えるようになるか）
 *  - 正規メールをしきい値の上へ押し上げてしまわないか（＝誤検出を生まないか）
 * を測る。
 *
 * ■ APIキーの扱い
 *   キーはこのスクリプトに書かない。次のいずれかから読む。
 *     1) 環境変数 TYPESAFE_API_KEY
 *     2) --key-file で指定したファイルの1行目
 *        （既定: %LOCALAPPDATA%\SpamGuard\typesafe-key.txt。
 *          Dropbox配下に秘密情報を置かないよう、あえてプロジェクト外にしている）
 *   どちらもファイル／環境に置いたままにでき、コマンドラインや画面に出ない。
 *
 * ■ 使い方
 *   # 1) まず送信内容を確認する（ネットワークへは一切出ない）
 *   node tools/eval-jev.mjs --dry-run --sample 60
 *
 *   # 2) 実際に測定する
 *   node tools/eval-jev.mjs --sample 60
 *
 *   # 3) 途中で止めても、--resume で続きから（既に取得済みの回答は再利用する）
 *   node tools/eval-jev.mjs --sample 60 --resume
 *
 * ■ 主なオプション
 *   --sample N     迷惑側・正常側それぞれの検体数（既定 40）
 *   --dry-run      送信せず、送信予定の内容とおおよその規模だけ出す
 *   --show N       ドライラン時に中身を表示する検体数（既定 2）
 *   --concurrency N 同時リクエスト数（既定 3）
 *   --out PATH     結果の保存先（既定 tools/eval-jev-result.json）
 *   --spam-band L-H 迷惑側の検体を抽出する点数帯（既定はグレーゾーン）
 *   --ham-band L-H  正規側の検体を抽出する点数帯（既定はグレーゾーン）
 *                  正規側はグレーゾーンに入る数が少なく統計的に弱いため、
 *                  帯を広げて「もしグレーゾーンに入ったらJevは押し上げるか」を測れる。
 *   --self-domain D 自分のアカウントのドメイン（複数指定可）。
 *                  拡張本体は accounts.list() から自動取得するが、mboxを直読みする
 *                  このツールでは分からないため、明示しないと selfDomainSpoof(+30) が
 *                  効かず、自ドメイン詐称メールの点数が実際より低く出る。
 *                  例: --self-domain example.jp --self-domain example.co.jp
 *   --spam PATH / --ham PATH  検体のmbox（複数指定可）。省略時は環境変数
 *                  SPAMGUARD_SPAM_MBOX / SPAMGUARD_HAM_MBOX（";" 区切り）を使う。
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { readMbox } from "./mbox.mjs";
import { extractFeatures } from "../src/extract.js";
import { scoreByRules, markSelfDomainSpoof } from "../src/rules.js";
import { DEFAULT_SETTINGS } from "../src/config.js";
import { askJev, buildState, scoreFromJev, QUESTIONS } from "../src/jev.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// --- 引数 -------------------------------------------------------------------

function parseArgs(argv) {
  const args = {
    sample: 40, dryRun: false, show: 2, concurrency: 3, resume: false,
    out: join(ROOT, "tools", "eval-jev-result.json"),
    keyFile: join(process.env.LOCALAPPDATA || process.env.HOME || ".", "SpamGuard", "typesafe-key.txt"),
    spam: [], ham: [], limit: 400, selfDomains: [],
    // 検体を抽出する点数帯。既定はグレーゾーンそのもの。
    // grayLow を下げる価値を測るときや、正規側の検体数を増やすときに広げる。
    spamBand: null, hamBand: null
  };
  for (let i = 2; i < argv.length; i++) {
    const key = argv[i].replace(/^--/, "");
    const value = argv[i + 1];
    if (key === "dry-run") args.dryRun = true;
    else if (key === "resume") args.resume = true;
    else if (key === "spam" || key === "ham") { args[key].push(value); i++; }
    else if (key === "self-domain") { args.selfDomains.push(String(value).toLowerCase()); i++; }
    else if (key === "spam-band" || key === "ham-band") {
      const m = String(value).match(/^(\d+)-(\d+)$/);
      if (m) args[key === "spam-band" ? "spamBand" : "hamBand"] = [Number(m[1]), Number(m[2])];
      i++;
    }
    else if (key === "out") { args.out = value; i++; }
    else if (key === "key-file") { args.keyFile = value; i++; }
    else if (key === "sample" || key === "show" || key === "concurrency" || key === "limit") {
      args[key === "dry-run" ? "dryRun" : key] = Number(value); i++;
    }
  }
  return args;
}

const args = parseArgs(process.argv);
const S = DEFAULT_SETTINGS;

/**
 * 検体フォルダ（mbox）。--spam / --ham が無ければ環境変数から読む。
 * 個人のプロファイルパスをソースに書かないため、既定値は持たない。
 *   SPAMGUARD_SPAM_MBOX / SPAMGUARD_HAM_MBOX（複数は ";" 区切り）
 */
const fromEnv = (name) => String(process.env[name] || "").split(";").map((s) => s.trim()).filter(Boolean);
if (!args.spam.length) args.spam = fromEnv("SPAMGUARD_SPAM_MBOX");
if (!args.ham.length) args.ham = fromEnv("SPAMGUARD_HAM_MBOX");
if (!args.spam.length || !args.ham.length) {
  console.error("検体フォルダが未指定です。--spam / --ham を指定するか、" +
    "環境変数 SPAMGUARD_SPAM_MBOX / SPAMGUARD_HAM_MBOX を設定してください。");
  process.exit(1);
}

/** APIキーを環境変数かファイルから読む。画面にもログにも出さない */
function readApiKey() {
  if (process.env.TYPESAFE_API_KEY) return process.env.TYPESAFE_API_KEY.trim();
  if (existsSync(args.keyFile)) {
    const first = readFileSync(args.keyFile, "utf8").split(/\r?\n/)[0].trim();
    if (first) return first;
  }
  return "";
}

// --- 検体の用意 --------------------------------------------------------------

function load(files) {
  const rows = [];
  for (const f of files) {
    if (!existsSync(f)) continue;
    for (const { part } of readMbox(f, args.limit)) {
      try {
        const feat = extractFeatures(part);
        rows.push({ feat, ...scoreByRules(markSelfDomainSpoof(feat, { selfDomains: args.selfDomains })) });
      } catch (e) { /* 壊れた検体は飛ばす */ }
    }
  }
  return rows;
}

const authPass = (r) => r.feat.auth.spf === "pass" || r.feat.auth.dkim === "pass";
const inGray = (r) => r.score >= S.grayLow && r.score < S.grayHigh;
/** 指定された点数帯（未指定ならグレーゾーン）に入るか */
const inBand = (r, band) => band ? (r.score >= band[0] && r.score <= band[1]) : inGray(r);

/**
 * ブランド辞書に一致し認証も通る＝正規送信元と確認できるもの。
 * これだけでは不十分で、辞書に載っていない組織のメルマガを取りこぼす。
 */
const provenLegit = (r) => r.feat.brandMatched && authPass(r);

/**
 * 迷惑フォルダの中身は「詐称型フィッシング」と「詐称ではない不要メルマガ」の
 * 混合物なので、Jevの効果測定にはラベルの選別が要る。
 * 不要メルマガを詐称型として数えると、Jevが正しく「詐称ではない」と答えたときに
 * 取りこぼしとして集計されてしまい、測定そのものが無意味になる。
 *
 * ここでは「受信トレイにも同じアドレスから認証付きで届いている送信者」を
 * 正規送信者とみなして除外する。同じ差出人から届くメールを
 * ユーザーが選別して迷惑フォルダへ入れている＝詐称ではない、という判断。
 */
function buildLegitSenderSet(inboxRows) {
  const addresses = new Set();
  const domains = new Map();
  for (const r of inboxRows) {
    if (!authPass(r)) continue;
    if (r.feat.from.address) addresses.add(r.feat.from.address);
    const d = r.feat.fromDomain;
    if (d) domains.set(d, (domains.get(d) || 0) + 1);
  }
  return { addresses, domains };
}

/** 点数の帯ごとに均等に抜き出す（低い帯だけに偏らないように） */
function stratify(rows, n) {
  const bands = new Map();
  for (const r of rows) {
    const b = Math.floor(r.score / 10);
    if (!bands.has(b)) bands.set(b, []);
    bands.get(b).push(r);
  }
  const keys = [...bands.keys()].sort((a, b) => a - b);
  const out = [];
  let i = 0;
  while (out.length < n && keys.length) {
    const k = keys[i % keys.length];
    const list = bands.get(k);
    if (list.length) out.push(list.shift());
    else { keys.splice(i % keys.length, 1); continue; }
    i++;
  }
  return out;
}

const junk = load(args.spam);
const inbox = load(args.ham);

const legitSenders = buildLegitSenderSet(inbox);

/**
 * 詐称型とみなす条件。
 *  - 正規送信元と確認できるものを除く
 *  - 受信トレイにも同じアドレスから認証付きで届く送信者を除く
 *  - 認証が通り、かつ受信トレイに同ドメインから3通以上届いている送信者を除く
 *    （辞書に載っていない取引先・メルマガの取りこぼし対策）
 */
function looksPhishing(r) {
  if (provenLegit(r)) return false;
  if (legitSenders.addresses.has(r.feat.from.address)) return false;
  if (authPass(r) && (legitSenders.domains.get(r.feat.fromDomain) || 0) >= 3) return false;
  return true;
}

// 迷惑側: グレーゾーンに落ちた「詐称型」＝ Jevに拾ってほしいもの
const phishPool = junk.filter((r) => looksPhishing(r) && inBand(r, args.spamBand));
const phishGray = stratify(phishPool, args.sample);
// 正常側: グレーゾーンに落ちた「認証が通るメール」＝ Jevに上げられては困るもの
const hamPool = inbox.filter((r) => authPass(r) && inBand(r, args.hamBand));
const hamGray = stratify(hamPool, args.sample);

const cases = [
  ...phishGray.map((r) => ({ label: "phish", row: r })),
  ...hamGray.map((r) => ({ label: "ham", row: r }))
];

console.log("=".repeat(74));
const bandLabel = (band, fallback) => band ? (band[0] + "-" + band[1]) : fallback;
console.log("抽出帯: 迷惑側 " + bandLabel(args.spamBand, S.grayLow + "-" + (S.grayHigh - 1)) +
  " / 正規側 " + bandLabel(args.hamBand, S.grayLow + "-" + (S.grayHigh - 1)));
console.log("  迷惑フォルダの詐称型     : " + phishPool.length + " 通中 " + phishGray.length + " 通を抽出");
console.log("  受信トレイの認証passメール: " + hamPool.length + " 通中 " + hamGray.length + " 通を抽出");
console.log("  （正規送信者と判定して除外: 受信トレイの認証付き差出人 " +
  legitSenders.addresses.size + " アドレス）");
console.log("=".repeat(74));

// ラベルの妥当性は測定の前提なので、抽出結果は必ず目視できるようにする
console.log("\n【詐称型として抽出した検体（ラベル確認用）】");
for (const r of phishGray) {
  console.log("  " + String(r.score).padStart(3) + "pt  " +
    (r.feat.fromDomain || "-").padEnd(24) +
    String(r.feat.from.display || "").slice(0, 14).padEnd(15) +
    String(r.feat.subject || "").slice(0, 38));
}

// --- ドライラン --------------------------------------------------------------

const settings = { ...S, jevApiKey: "dummy", jevMaxRetries: 1 };

if (args.dryRun) {
  let totalChars = 0;
  for (const c of cases) {
    totalChars += JSON.stringify(buildState(c.row.feat, S.jevBodyLimit)).length;
  }
  const questionChars = JSON.stringify(QUESTIONS).length;

  console.log("\n【送信されるもの】1通につき以下を TypeSafe (" + S.jevEndpoint + ") へPOSTします。");
  console.log("  state   : 差出人表示名／アドレス／ドメイン、Reply-To、Return-Path、");
  console.log("            Message-IDドメイン、配信停止ドメイン、Feedback-ID、");
  console.log("            配信経路ホスト(最大12)、件名、本文の先頭" + S.jevBodyLimit + "文字、リンク先ドメイン(最大20)");
  console.log("  questions: 固定の6問（" + Object.keys(QUESTIONS).join(", ") + "）");
  console.log("  ※ 添付ファイル、宛先(To/Cc)、本文の" + S.jevBodyLimit + "文字目以降は送信しません。");

  console.log("\n【規模】");
  console.log("  検体数          : " + cases.length + " 通（迷惑 " + phishGray.length + " / 正常 " + hamGray.length + "）");
  console.log("  stateの合計文字数: " + totalChars.toLocaleString() + " 文字");
  console.log("  質問文(毎回同一): " + questionChars.toLocaleString() + " 文字 × " + cases.length + " 通");
  const lo = Math.round((totalChars + questionChars * cases.length) / 3);
  const hi = Math.round((totalChars + questionChars * cases.length) / 1.5);
  console.log("  入力トークン概算 : 約 " + lo.toLocaleString() + " 〜 " + hi.toLocaleString() + " トークン");
  console.log("  （日本語は1文字≒1トークンになりやすいため上振れ側を見ておくのが安全）");

  console.log("\n【送信内容のサンプル " + args.show + " 件】");
  for (const c of cases.slice(0, args.show)) {
    const state = buildState(c.row.feat, S.jevBodyLimit);
    console.log("\n--- [" + c.label + "] ローカル " + c.row.score + "点 ---");
    console.log(JSON.stringify(state, null, 2).slice(0, 1400));
  }
  console.log("\nドライランのため、ネットワークへは一切送信していません。");
  process.exit(0);
}

// --- 実測 --------------------------------------------------------------------

const apiKey = readApiKey();
if (!apiKey) {
  console.error("\nAPIキーが見つかりません。次のいずれかを用意してください。");
  console.error("  1) 環境変数 TYPESAFE_API_KEY に設定する");
  console.error("  2) " + args.keyFile + " の1行目にキーだけを書く");
  console.error("\nキーは https://console.typesafe.ai/keys で発行できます。");
  process.exit(1);
}

/** 既存の結果を読み込む（--resume 用） */
let cached = {};
if (args.resume && existsSync(args.out)) {
  try {
    cached = JSON.parse(readFileSync(args.out, "utf8")).byKey || {};
    console.log("既存の結果 " + Object.keys(cached).length + " 件を再利用します。");
  } catch (e) { cached = {}; }
}

const caseKey = (c) => c.label + ":" + c.row.feat.messageId + ":" + c.row.score;

const live = { ...settings, jevApiKey: apiKey, jevMaxRetries: 3 };
const results = [];
let done = 0;
let usageIn = 0;
let usageOut = 0;
let errors = 0;

async function runOne(c) {
  const key = caseKey(c);
  if (cached[key]) {
    results.push({ ...cached[key], cachedHit: true });
    done++;
    return;
  }
  try {
    const response = await askJev(buildState(c.row.feat, S.jevBodyLimit), live);
    const jev = scoreFromJev(response);
    const wl = S.weightLocal;
    const wj = S.weightJev;
    const final = Math.round((wl * c.row.score + wj * jev.score) / (wl + wj));
    if (jev.usage) {
      usageIn += jev.usage.input_tokens || 0;
      usageOut += jev.usage.output_tokens || 0;
    }
    const rec = {
      key,
      label: c.label,
      localScore: c.row.score,
      jevScore: jev.score,
      finalScore: final,
      detail: jev.detail,
      pretext: jev.pretext,
      fromDomain: c.row.feat.fromDomain,
      subject: String(c.row.feat.subject || "").slice(0, 50),
      usage: jev.usage
    };
    results.push(rec);
  } catch (e) {
    errors++;
    results.push({ key, label: c.label, localScore: c.row.score, error: String(e.message || e) });
  }
  done++;
  if (done % 10 === 0) process.stdout.write("  " + done + "/" + cases.length + " 完了\n");
}

/** 同時実行数を制限して順に流す */
async function runAll() {
  const queue = [...cases];
  const workers = [];
  for (let i = 0; i < Math.max(1, args.concurrency); i++) {
    workers.push((async () => {
      while (queue.length) await runOne(queue.shift());
    })());
  }
  await Promise.all(workers);
}

console.log("\nJevへ問い合わせます（同時 " + args.concurrency + " 件）...");
const started = Date.now();
await runAll();
const elapsed = ((Date.now() - started) / 1000).toFixed(1);

// --- 集計 --------------------------------------------------------------------

const ok = results.filter((r) => !r.error);
const phish = ok.filter((r) => r.label === "phish");
const ham = ok.filter((r) => r.label === "ham");

function band(rows, get) {
  const over = rows.filter((r) => get(r) >= S.spamThreshold).length;
  return over + "/" + rows.length + " (" + (rows.length ? (100 * over / rows.length).toFixed(1) : "0") + "%)";
}

console.log("\n" + "=".repeat(74));
console.log("結果（" + elapsed + "秒 / エラー " + errors + "件）");
console.log("=".repeat(74));
console.log("\n【しきい値 " + S.spamThreshold + " 点を超えた数】");
console.log("  詐称型（拾えると嬉しい）  ローカルのみ " + band(phish, (r) => r.localScore) +
  "  →  Jev併用 " + band(phish, (r) => r.finalScore));
console.log("  正規メール（上げたくない）ローカルのみ " + band(ham, (r) => r.localScore) +
  "  →  Jev併用 " + band(ham, (r) => r.finalScore));

const avg = (rows, f) => (rows.length ? (rows.reduce((a, r) => a + f(r), 0) / rows.length).toFixed(1) : "-");
console.log("\n【平均点】");
console.log("  詐称型    : ローカル " + avg(phish, (r) => r.localScore) +
  " / Jev " + avg(phish, (r) => r.jevScore) + " / 合成 " + avg(phish, (r) => r.finalScore));
console.log("  正規メール: ローカル " + avg(ham, (r) => r.localScore) +
  " / Jev " + avg(ham, (r) => r.jevScore) + " / 合成 " + avg(ham, (r) => r.finalScore));

console.log("\n【Jevの各問いの平均（0-1）】");
for (const q of Object.keys(QUESTIONS)) {
  console.log("  " + q.padEnd(26) +
    " 詐称型 " + avg(phish, (r) => r.detail[q]).padStart(5) +
    "   正規 " + avg(ham, (r) => r.detail[q]).padStart(5));
}

console.log("\n【判定された口実（phishing_pretext）の分布】");
{
  const tally = (rows) => {
    const m = new Map();
    for (const r of rows) m.set(r.pretext || "(なし)", (m.get(r.pretext || "(なし)") || 0) + 1);
    return [...m.entries()].sort((x, y) => y[1] - x[1]).map(([k, n]) => k + " " + n).join(" / ");
  };
  console.log("  詐称型: " + tally(phish));
  console.log("  正規  : " + tally(ham));
}

console.log("\n【トークン使用量】入力 " + usageIn.toLocaleString() +
  " / 出力 " + usageOut.toLocaleString() +
  "（実測 " + ok.filter((r) => !r.cachedHit).length + " 通分）");
if (ok.length) {
  console.log("  1通あたり入力 約 " + Math.round(usageIn / Math.max(1, ok.filter((r) => !r.cachedHit).length)) + " トークン");
}

console.log("\n【ローカル点数の帯ごとの内訳（Jev併用でしきい値を超えた数）】");
console.log("  帯        詐称型              正規メール");
for (const lo of [25, 35, 45, 55, 65]) {
  const hi = lo + 10;
  const p = phish.filter((r) => r.localScore >= lo && r.localScore < hi);
  const h = ham.filter((r) => r.localScore >= lo && r.localScore < hi);
  const pOver = p.filter((r) => r.finalScore >= S.spamThreshold).length;
  const hOver = h.filter((r) => r.finalScore >= S.spamThreshold).length;
  console.log("  " + (lo + "-" + (hi - 1)).padEnd(10) +
    (pOver + " / " + p.length + " 通").padEnd(20) +
    hOver + " / " + h.length + " 通");
}

console.log("\n【Jevが正規メールを押し上げてしまった例】");
const pushed = ham.filter((r) => r.localScore < S.spamThreshold && r.finalScore >= S.spamThreshold);
if (!pushed.length) console.log("  なし");
for (const r of pushed.slice(0, 10)) {
  console.log("  " + r.localScore + "→" + r.finalScore + "  " + r.fromDomain + "  " + r.subject);
}

console.log("\n【Jevが新たに拾えた詐称型の例】");
const rescued = phish.filter((r) => r.localScore < S.spamThreshold && r.finalScore >= S.spamThreshold);
for (const r of rescued.slice(0, 10)) {
  console.log("  " + r.localScore + "→" + r.finalScore + "  " + r.fromDomain + "  " + r.subject);
}

const byKey = {};
for (const r of ok) byKey[r.key] = r;
writeFileSync(args.out, JSON.stringify({ generatedAt: new Date().toISOString(), byKey }, null, 2), "utf8");
console.log("\n結果を保存しました: " + args.out);
console.log("（--resume を付けて再実行すると、この結果を再利用して差分だけ問い合わせます）");
