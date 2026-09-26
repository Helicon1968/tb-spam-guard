/**
 * SpamGuard - メッセージから判定用の特徴量を抽出する
 *
 * messages.getFull() の MessagePart ツリーだけを入力とし、
 * ルール判定にもJevへ渡すstateにも使える中立的な形にまとめる。
 */

import {
  ABUSED_TLDS, BRANDS, COMMON_SENDER_LABELS, CONSUMER_ISP_DOMAINS, FREEMAIL_DOMAINS,
  RESIDENTIAL_HOST_PATTERNS, URGENCY_PATTERNS
} from "./config.js";

/** 実効的なTLDが2ラベルになる代表的なサフィックス（簡易PSL） */
const MULTI_LEVEL_SUFFIXES = new Set([
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "co.kr", "com.cn", "com.au", "com.br",
  "com.tw", "co.nz", "co.in", "com.hk", "co.th", "com.sg", "com.mx"
]);

/** ホスト名から登録可能ドメイン（例: sub.a.co.jp -> a.co.jp）を求める */
export function registrableDomain(host) {
  if (!host) return "";
  const parts = String(host).toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_LEVEL_SUFFIXES.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

/** ドメインが指定ドメイン（またはそのサブドメイン）に属するか */
export function isUnderDomain(host, domain) {
  if (!host || !domain) return false;
  const h = String(host).toLowerCase();
  const d = String(domain).toLowerCase();
  return h === d || h.endsWith("." + d);
}

/** "表示名 <addr@example.com>" 形式を分解する */
export function parseAddress(value) {
  if (!value) return { display: "", address: "", host: "" };
  const raw = String(value).trim();
  const angle = raw.match(/<([^>]+)>/);
  let address = angle ? angle[1].trim() : raw;
  let display = angle ? raw.slice(0, angle.index).trim() : "";
  display = display.replace(/^"(.*)"$/s, "$1").trim();
  if (!angle && /\s/.test(raw) && raw.includes("@")) {
    // 表示名とアドレスが山括弧なしで並んでいるケース
    const token = raw.split(/\s+/).find((t) => t.includes("@"));
    if (token) {
      address = token.replace(/^[<(]|[>)]$/g, "");
      display = raw.replace(token, "").trim();
    }
  }
  const at = address.lastIndexOf("@");
  const host = at >= 0 ? address.slice(at + 1).toLowerCase().replace(/[>\s]/g, "") : "";
  return { display, address: address.toLowerCase(), host };
}

/** getFull のヘッダオブジェクトから最初の値を取り出す（キーは小文字） */
function header(part, name) {
  const v = part && part.headers ? part.headers[name] : null;
  return Array.isArray(v) && v.length ? String(v[0]) : "";
}

/** 同上。複数値をすべて返す */
function headerAll(part, name) {
  const v = part && part.headers ? part.headers[name] : null;
  return Array.isArray(v) ? v.map(String) : [];
}

/** MessagePart ツリーを走査して text/plain と text/html を集める */
function collectBodies(part, acc = { plain: [], html: [] }) {
  if (!part) return acc;
  const ct = (part.contentType || "").toLowerCase();
  if (part.body) {
    if (ct.startsWith("text/plain")) acc.plain.push(part.body);
    else if (ct.startsWith("text/html")) acc.html.push(part.body);
  }
  for (const child of part.parts || []) collectBodies(child, acc);
  return acc;
}

/** HTMLからタグを除いて素のテキストにする */
export function htmlToText(html) {
  return String(html)
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&amp;/gi, "&")
    .replace(/[ \t\u00A0]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** HTML中のリンク先URLを集める */
function extractLinks(html, plain) {
  const urls = new Set();
  for (const m of String(html).matchAll(/href\s*=\s*["']([^"']+)["']/gi)) urls.add(m[1]);
  for (const m of String(plain).matchAll(/https?:\/\/[^\s<>"')]+/gi)) urls.add(m[0]);
  const hosts = [];
  const kept = [];
  for (const u of urls) {
    if (!/^https?:/i.test(u)) continue;
    kept.push(u);
    try {
      hosts.push(new URL(u).hostname.toLowerCase());
    } catch (e) { /* 不正URLは無視 */ }
  }
  return { urls: kept, hosts: [...new Set(hosts)] };
}

/**
 * 不可視要素の中にランダム文字列が仕込まれているか。
 * 正規のマーケティングメールもプリヘッダを隠すため、
 * 「隠されている」だけでなく「中身がランダムらしい」ことを条件にする。
 */
function hasHiddenRandomText(html) {
  const source = String(html);
  const lower = source.toLowerCase();
  // 非表示スタイルを持つ開始タグだけを直接探す。
  // 入れ子を素直にたどると <html> の閉じタグまで一気に飛んでしまい、
  // 内側の非表示要素を取りこぼすため、開始タグ起点で走査する。
  const openTag = /<([a-z]+)\b([^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|max-height\s*:\s*0)[^>]*)>/gi;
  for (const m of source.matchAll(openTag)) {
    const tag = m[1].toLowerCase();
    const start = m.index + m[0].length;
    const close = lower.indexOf("</" + tag, start);
    const end = close === -1 ? Math.min(start + 4000, source.length) : close;
    const text = htmlToText(source.slice(start, end)).replace(/\s+/g, "");
    if (/[A-Za-z0-9]{16,}/.test(text)) return true;
  }
  return false;
}

/** ホスト名のラベルが自動生成らしいか（英字と数字が混在する長いラベル） */
export function looksRandomHost(host) {
  if (!host) return false;
  const labels = host.toLowerCase().split(".");
  for (const label of labels.slice(0, -1)) {
    if (/^(?=.*[a-z])(?=.*\d)[a-z0-9]{8,}$/.test(label)) return true;
  }
  return false;
}

/**
 * 英字だけの文字列が「発音できない＝自動生成らしい」かを判定する。
 * 実データの迷惑メールには fshmjx.com / hmxdag.com / shlvchen.com のような
 * 数字を含まないランダム文字列ドメインが多く、looksRandomHost では拾えない。
 * 母音率の低さと子音の連続で機械的に判定する。
 */
export function looksUnpronounceable(label) {
  if (!/^[a-z]{5,20}$/.test(label)) return false;
  const vowels = (label.match(/[aeiouy]/g) || []).length;
  if (vowels / label.length < 0.28) return true;
  return /[bcdfghjklmnpqrstvwxz]{4,}/.test(label);
}

/**
 * ホスト名のいずれかのラベルが自動生成らしいか。
 *
 * looksUnpronounceable は登録可能ドメインの先頭ラベルしか見ていなかったため、
 * `info@jgdyyt.yunshang-china.com` のように**サブドメイン側がランダム**な
 * パターンを取りこぼしていた（実運用ログで見逃しの主要因）。
 */
export function hasRandomLabel(host) {
  const labels = String(host || "").toLowerCase().split(".");
  // 末尾のTLDは除いて調べる
  for (const label of labels.slice(0, -1)) {
    if (looksUnpronounceable(label)) return true;
  }
  return false;
}

/**
 * 母音(aeiou)を1つも含まない英字ラベルがあるか。
 * `jgdyyt` `rwvnra` `sgbjcw` `phpxk` のような機械生成の文字列に強く、
 * `starbucks` `jsports` のような実在の社名には当たらない。
 */
export function hasVowellessLabel(host) {
  const labels = String(host || "").toLowerCase().split(".");
  for (const label of labels.slice(0, -1)) {
    if (/^[a-z]{4,20}$/.test(label) && !/[aeiou]/.test(label)) return true;
  }
  return false;
}

/** 双方向テキスト制御文字（表示を偽装するために使われる） */
const BIDI_CONTROL = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/;
/** 文字の間に挟んで単語照合を妨害するゼロ幅文字 */
const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/;

/**
 * 不可視の制御文字を取り除く。
 * 攻撃者はまさにキーワード照合を妨害する目的でこれらを挿入してくるので
 * （実データでは「お知らせ」「確認待」の語の途中へゼロ幅文字が仕込まれていた）、
 * ブランド名や煽り文句の照合は必ず除去後の文字列に対して行う。
 */
export function stripInvisible(text) {
  return String(text || "").replace(/[\u202A-\u202E\u2066-\u2069\u200B-\u200F\u2060\uFEFF\u061C\u00AD]/g, "");
}

/**
 * 受信サーバが付けたスパム判定ヘッダを読む。
 *
 * heteml の場合 SpamAssassin 系の `X-Spam-Status: Yes, score=...` が付く。
 * 「No」は付かず、スパムと判定したときだけ現れる。
 * 実データでは迷惑フォルダの76%に付いており、こちらで再発明する必要のない
 * 強い証拠になっている（サーバ側は「拒否」していないだけでタグは付けている）。
 *
 * 先頭の1件だけを見るのは、最後に通過した＝最も信頼できるサーバが付けたものだから。
 * 攻撃者が偽の「Yes」を挿入しても自分が不利になるだけなので、
 * Yes を加点材料にする方向でのみ使う（No を減点材料にはしない）。
 */
export function parseUpstreamSpamFlag(full, header) {
  const status = header(full, "x-spam-status");
  const flag = header(full, "x-spam-flag");
  const level = header(full, "x-spam-level");
  const flagged =
    /^\s*yes/i.test(status) ||
    /^\s*yes/i.test(flag) ||
    /^\*{5,}/.test(level);
  const m = status.match(/score=([-\d.]+)/i);
  return { flagged, score: m ? Number(m[1]) : null, raw: status || flag || level || "" };
}

/**
 * RFC2047 のエンコード語を展開する（Thunderbirdの復号が失敗したときの保険）。
 *
 * messages.getFull() は既定でヘッダを復号して返すが、エンコード語の途中で
 * 行が折り返されている不正なヘッダでは復号に失敗し、`=?iso-2022-jp?B?...?=`
 * が生のまま渡ってくることがある（実運用ログで Amazon 詐称メールが該当し、
 * 件名が生文字列のままだったためブランド判定が一切効かなかった）。
 * 復号できなければ元の文字列をそのまま返す。
 */
export function decodeEncodedWords(value) {
  const text = String(value || "");
  if (!text.includes("=?")) return text;
  return text
    // 折り返しで割れたエンコード語をつなぎ直す
    .replace(/\?=[\s\r\n\t]+=\?/g, "?==?")
    .replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (whole, charset, enc, payload) => {
      try {
        let bytes;
        if (enc.toUpperCase() === "B") {
          const binary = atob(payload.replace(/[^A-Za-z0-9+/=]/g, ""));
          bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
        } else {
          const decoded = payload
            .replace(/_/g, " ")
            .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
          bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0) & 0xff);
        }
        return new TextDecoder(charset.toLowerCase(), { fatal: false }).decode(bytes);
      } catch (e) {
        return whole;
      }
    });
}

/** Authentication-Results から spf / dkim / dmarc の結果を取り出す */
export function parseAuthResults(value) {
  const v = String(value || "").toLowerCase();
  const pick = (name) => {
    const m = v.match(new RegExp(name + "\\s*=\\s*([a-z]+)"));
    return m ? m[1] : "";
  };
  return { spf: pick("spf"), dkim: pick("dkim"), dmarc: pick("dmarc") };
}

/** 表示名・件名から詐称されている可能性のあるブランドを特定する */
export function detectBrands(text) {
  const t = String(text || "").toLowerCase();
  const hits = [];
  for (const brand of BRANDS) {
    if (brand.keywords.some((k) => matchKeyword(t, k.toLowerCase()))) hits.push(brand);
  }
  return hits;
}

/**
 * キーワード照合。
 * ASCIIだけのキーワードは前後が英数字でないことを条件にする。
 * 単純な部分一致にすると "au" が "Paul" や "audible" に、
 * "line" が ".online" に当たって正規メールを詐称と誤判定する。
 * （実データで見つかった誤検出の大半がこれだった）
 * 日本語のキーワードは語境界が存在しないのでそのまま部分一致で照合する。
 */
export function matchKeyword(text, keyword) {
  if (!keyword) return false;
  if (!/^[\x20-\x7e]+$/.test(keyword)) return text.includes(keyword);
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp("(^|[^a-z0-9])" + escaped + "($|[^a-z0-9])").test(text);
}

/** Received ヘッダからホスト名を取り出す */
function receivedHosts(values) {
  const hosts = [];
  for (const line of values) {
    for (const m of String(line).matchAll(/(?:from|by)\s+([A-Za-z0-9._-]+\.[A-Za-z]{2,})/g)) {
      hosts.push(m[1].toLowerCase());
    }
  }
  return [...new Set(hosts)];
}

/**
 * Received ヘッダの括弧内にある逆引き名を取り出す。
 * `from [172.30.157.21] (c-69-180-237-15.hsd1.ga.comcast.net [69.180.237.15])` のように、
 * 送信元が HELO を IP で名乗ると receivedHosts() では拾えず、実際の回線が見えないため。
 */
function receivedRdnsHosts(values) {
  const hosts = [];
  for (const line of values) {
    for (const m of String(line).matchAll(/\(\s*([A-Za-z0-9._-]+\.[A-Za-z]{2,})\s*(?:\[[0-9A-Fa-f.:]+\])?\s*\)/g)) {
      hosts.push(m[1].toLowerCase());
    }
  }
  return [...new Set(hosts)];
}

/**
 * 送信ホストの先頭ラベルが、Return-Path のローカル部にもそのまま使われているか。
 *
 * 使い捨てドメインのスパマーは `info@kjehuf.cn-dqsb.com`（Return-Path は
 * `kjehuf@kjehuf.cn-dqsb.com`）のように、1通ごとに生成したラベルを
 * サブドメインとバウンス先の両方に流用する。ラベル自体は `kjehuf` `swhups` のように
 * 母音を含むことが多く、発音可否の判定（looksUnpronounceable）では拾えない。
 * `mail@mail.adobe.com` のような一般語は COMMON_SENDER_LABELS で除外する。
 */
function senderLabelEcho(fromHost, fromDomain, returnPathAddress) {
  const host = String(fromHost || "");
  if (!fromDomain || !host.endsWith("." + fromDomain)) return false;
  const label = host.slice(0, -(fromDomain.length + 1)).split(".")[0];
  if (!/^[a-z]{4,12}$/.test(label) || COMMON_SENDER_LABELS.includes(label)) return false;
  const rpLocal = String(returnPathAddress || "").split("@")[0].toLowerCase();
  return rpLocal === label;
}

/**
 * メッセージ1通分の特徴量を作る。
 * @param {object} full messages.getFull() の戻り値
 * @param {object} meta messages.get() の戻り値（subject/author のフォールバック用）
 */
export function extractFeatures(full, meta = {}) {
  // Thunderbird側の復号が失敗している場合に備え、エンコード語が残っていれば展開する
  const fromRaw = decodeEncodedWords(header(full, "from") || meta.author || "");
  const from = parseAddress(fromRaw);
  const subject = decodeEncodedWords(header(full, "subject") || meta.subject || "");

  const replyTo = parseAddress(header(full, "reply-to"));
  const returnPath = parseAddress(header(full, "return-path"));
  const messageId = header(full, "message-id");
  const messageIdHost = (messageId.match(/@([^>\s]+)>?/) || ["", ""])[1].toLowerCase();

  const listUnsub = header(full, "list-unsubscribe");
  const listUnsubHosts = [];
  for (const m of listUnsub.matchAll(/https?:\/\/([^/\s>]+)/gi)) listUnsubHosts.push(m[1].toLowerCase());
  for (const m of listUnsub.matchAll(/mailto:[^@\s>]+@([^\s>,]+)/gi)) listUnsubHosts.push(m[1].toLowerCase());

  const feedbackId = header(full, "feedback-id");
  const received = headerAll(full, "received");
  const hops = receivedHosts(received);
  const rdnsHosts = receivedRdnsHosts(received);

  const bodies = collectBodies(full);
  const html = bodies.html.join("\n");
  const plain = bodies.plain.join("\n");
  const bodyText = plain.trim() ? plain : htmlToText(html);
  const links = extractLinks(html, plain);

  const fromDomain = registrableDomain(from.host);
  const cleanSubject = stripInvisible(subject);
  const cleanDisplay = stripInvisible(from.display);
  // 表示名に組織名がある＝その組織を名乗っている。
  // 件名にしかない場合は「言及しているだけ」の可能性が高く、証拠としては弱い。
  // 実データでは、食べログの「Vポイント付与のお知らせ」（三井住友のVポイントに言及）や
  // 映画ニュースの本文中のNetflix言及が、件名側の一致だけで誤検出になっていた。
  const brandsInDisplay = detectBrands(cleanDisplay);
  const brands = detectBrands(cleanDisplay + " " + cleanSubject);
  const brandDomains = brands.flatMap((b) => b.domains);
  const brandMatched = brands.length > 0 && brandDomains.some((d) => isUnderDomain(from.host, d));
  const brandInDisplay = brandsInDisplay.length > 0;

  const linkDomains = [...new Set(links.hosts.map(registrableDomain))];
  // 送信ドメインとも詐称対象の正規ドメインとも違う「第三のドメイン」
  const foreignLinkDomains = linkDomains.filter(
    (d) => d && d !== fromDomain && !brandDomains.some((bd) => isUnderDomain(d, bd))
  );
  // 名乗っている組織の正規ドメイン以外へ誘導しているリンク。
  // 送信ドメインと同じでも、組織を詐称している以上は証拠になる。
  const brandForeignLinkDomains = brands.length === 0 ? [] : linkDomains.filter(
    (d) => d && !brandDomains.some((bd) => isUnderDomain(d, bd))
  );

  const cleanBody = stripInvisible(bodyText);
  const urgencyHits = URGENCY_PATTERNS.filter(
    (p) => cleanSubject.includes(p) || cleanBody.includes(p)
  );

  const display = String(from.display || "");
  const localPart = from.address.split("@")[0] || "";
  const fromLabel = fromDomain.split(".")[0] || "";
  const tld = fromDomain.split(".").pop() || "";
  const auth = parseAuthResults(header(full, "authentication-results"));
  const upstreamSpam = parseUpstreamSpamFlag(full, header);

  return {
    subject,
    from,
    fromDomain,
    replyTo,
    returnPath,
    messageId,
    messageIdHost,
    messageIdDomain: registrableDomain(messageIdHost),
    listUnsubHosts,
    listUnsubDomains: [...new Set(listUnsubHosts.map(registrableDomain))],
    feedbackId,
    receivedCount: received.length,
    hops,
    consumerIspHops: [
      ...hops.filter((h) => CONSUMER_ISP_DOMAINS.some((d) => isUnderDomain(h, d))),
      ...rdnsHosts.filter((h) => RESIDENTIAL_HOST_PATTERNS.some((re) => re.test(h)))
    ],
    bodyText,
    bodyHtml: html,
    hasHtml: Boolean(html.trim()),
    links: links.urls,
    linkDomains,
    foreignLinkDomains,
    brandForeignLinkDomains,
    hiddenRandomText: hasHiddenRandomText(html),
    randomFromHost: looksRandomHost(from.host),
    brands: brands.map((b) => b.name),
    brandDomains,
    brandMatched,
    brandInDisplay,
    brandsInDisplay: brandsInDisplay.map((b) => b.name),
    brandMismatch: brands.length > 0 && !brandMatched,
    urgencyHits,
    authResults: header(full, "authentication-results"),
    auth,

    // --- 実データ（実際の迷惑メールフォルダ）の分析で追加した特徴量 ---
    /** 件名や表示名に双方向制御文字を仕込んで表示を偽装している */
    bidiObfuscation: BIDI_CONTROL.test(subject) || BIDI_CONTROL.test(display),
    /** 件名の文字の間にゼロ幅文字を挟んで語句照合を妨害している */
    zeroWidthObfuscation: ZERO_WIDTH.test(subject),
    /** 表示名がメールアドレスそのもの（正規の企業配信ではまず無い） */
    displayNameIsAddress: /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(display.trim()),
    /**
     * 表示名がメールアドレスで、しかも実際の差出人アドレスと違う。
     * 実運用ログで見つかった宣伝メールは
     * `"ojtdvgm@exweb.ne.jp" <xnycaxg@exweb.ne.jp>` のように
     * **例外なく**表示名と実アドレスが食い違っていた。
     * 正規のメールがこの形になることはまず無い。
     */
    displayNameIsOtherAddress:
      /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(display.trim()) &&
      display.trim().toLowerCase() !== from.address,
    /**
     * Fromのローカル部が自動生成らしい。
     * 英字のみの羅列（looksUnpronounceable）に加え、
     * `xx9efvig` のような英数字混在も拾う。
     */
    randomLocalPart: looksUnpronounceable(localPart) ||
      /^(?=.*[a-z])(?=.*\d)[a-z0-9]{7,}$/.test(localPart),
    /**
     * 送信ドメインのラベルが自動生成らしい英字の羅列。
     * サブドメイン側だけがランダムなパターン（info@jgdyyt.example.com）も拾うため、
     * 登録可能ドメインの先頭ラベルだけでなくホスト全体のラベルを見る。
     */
    unpronounceableDomain: looksUnpronounceable(fromLabel) || hasRandomLabel(from.host),
    /** ホスト名に母音を含まないラベルがある（機械生成の強い証拠） */
    vowellessDomain: hasVowellessLabel(from.host),
    /** 送信ホストの先頭ラベルが Return-Path のローカル部に流用されている（使い捨てドメインの型） */
    senderLabelEcho: senderLabelEcho(from.host, fromDomain, returnPath.address),
    /**
     * 件名だけで組織に言及し、本文のリンクがすべて「送信ドメインでも組織の正規ドメインでもない」
     * 第三者を指している。e-Tax を件名に入れて無関係なドメインへ誘導する型。
     * `pia.co.jp` → `pia.jp` のように先頭ラベルが同じ兄弟ドメインは第三者と見なさない。
     */
    mentionThirdPartyLinks: brands.length > 0 && !brandMatched && brandsInDisplay.length === 0 &&
      linkDomains.length > 0 &&
      linkDomains.every((d) => foreignLinkDomains.includes(d) &&
        d.split(".")[0] !== fromDomain.split(".")[0]),
    /** 受信サーバ（heteml等）が既にスパムと判定している */
    upstreamSpam,
    /** 濫用されやすいTLD */
    abusedTld: ABUSED_TLDS.includes(tld) ? tld : "",
    /** 差出人が無料メール・携帯キャリアのドメイン */
    freemailSender: FREEMAIL_DOMAINS.includes(fromDomain),
    /** 本文または件名に日本語が含まれるか */
    hasJapanese: /[ぁ-んァ-ヶ一-龠]/.test(subject + bodyText.slice(0, 500))
  };
}
