/**
 * SpamGuard - 個別の .eml を採点して内訳を出す（チューニング用）
 *
 * 「このメールが引っかからない」という報告を受けたとき、
 * どのルールが立ってどのルールが立たなかったのかを1通単位で確認する。
 *
 * 実行:
 *   node tools/score-eml.mjs "C:/path/to/mail.eml" [...]
 *   node tools/score-eml.mjs --self-domain example.jp "C:/path/to/mail.eml"
 *   node tools/score-eml.mjs --verbose "C:/path/to/mail.eml"   特徴量も全部出す
 */

import { readFileSync, existsSync } from "node:fs";
import { parseMessage } from "./mbox.mjs";
import { extractFeatures } from "../src/extract.js";
import { scoreByRules, markSelfDomainSpoof, RULES } from "../src/rules.js";
import { DEFAULT_SETTINGS as S } from "../src/config.js";

const args = { files: [], selfDomains: [], verbose: false };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a === "--self-domain") { args.selfDomains.push(String(process.argv[++i]).toLowerCase()); }
  else if (a === "--verbose") { args.verbose = true; }
  else args.files.push(a);
}

if (!args.files.length) {
  console.error("採点する .eml を指定してください。");
  process.exit(1);
}

for (const path of args.files) {
  if (!existsSync(path)) {
    console.error("見つかりません: " + path);
    continue;
  }
  const part = parseMessage(readFileSync(path));
  const feat = markSelfDomainSpoof(extractFeatures(part), { selfDomains: args.selfDomains });
  const { score, hits } = scoreByRules(feat);

  const verdict = score >= S.spamThreshold ? "迷惑"
    : score >= S.grayLow ? "疑い（Jevへ送られる）" : "正常";

  console.log("=".repeat(76));
  console.log(path.split(/[\\/]/).pop());
  console.log("=".repeat(76));
  console.log("  差出人表示名 : " + (feat.from.display || "(なし)"));
  console.log("  差出人アドレス: " + (feat.from.address || "(なし)"));
  console.log("  登録可能ドメイン: " + (feat.fromDomain || "(なし)"));
  console.log("  件名         : " + (feat.subject || "(なし)"));
  console.log("  認証         : spf=" + (feat.auth.spf || "-") +
    " dkim=" + (feat.auth.dkim || "-") + " dmarc=" + (feat.auth.dmarc || "-"));
  console.log("  リンク先     : " + (feat.linkDomains.join(", ") || "(なし)"));
  console.log("  詐称候補     : " + (feat.brands.join(", ") || "なし") +
    (feat.brandInDisplay ? "（表示名に出現）" : feat.brands.length ? "（件名のみ）" : ""));
  console.log("");
  console.log("  ローカル点数: " + score + " → " + verdict +
    "  （しきい値 " + S.spamThreshold + " / グレー " + S.grayLow + "-" + S.grayHigh + "）");
  console.log("");

  console.log("  【立ったルール】");
  if (!hits.length) console.log("    なし");
  for (const h of hits) {
    console.log("    " + (h.weight > 0 ? "+" : "") + String(h.weight).padStart(3) + "  " + h.label);
  }

  const fired = new Set(hits.map((h) => h.id));
  const missed = RULES.filter((r) => r.weight > 0 && !fired.has(r.id));
  console.log("\n  【立たなかった加点ルール】（なぜ点が伸びないかの手がかり）");
  console.log("    " + missed.map((r) => r.id).join(", "));

  if (args.verbose) {
    console.log("\n  【特徴量】");
    const skip = new Set(["bodyText", "bodyHtml", "links"]);
    for (const [k, v] of Object.entries(feat)) {
      if (skip.has(k)) continue;
      const s = typeof v === "object" ? JSON.stringify(v) : String(v);
      console.log("    " + k.padEnd(26) + " " + s.slice(0, 110));
    }
    console.log("\n  【本文冒頭】");
    console.log("    " + String(feat.bodyText).slice(0, 400).replace(/\n/g, "\n    "));
  }
  console.log("");
}
