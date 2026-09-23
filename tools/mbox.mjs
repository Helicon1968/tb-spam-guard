/**
 * SpamGuard - mbox 読み取りと MIME 展開（チューニング用・拡張本体には含めない）
 *
 * Thunderbird のローカルフォルダ（mbox）を読み、
 * messages.getFull() と同じ形のオブジェクトに変換する。
 * これにより、Thunderbirdを起動せずに実データで判定ロジックを検証できる。
 *
 *   { contentType, headers: { "小文字キー": [値, ...] }, parts: [ ... ] }
 *   本文を持つリーフには decode 済みの body が入る
 */

import { readFileSync, openSync, readSync, closeSync, statSync } from "node:fs";

/** 巨大な Inbox を丸ごと読まずに済むよう、末尾だけを読む */
function readTail(path, tailBytes) {
  const size = statSync(path).size;
  if (!tailBytes || size <= tailBytes) return readFileSync(path);
  const buf = Buffer.alloc(tailBytes);
  const fd = openSync(path, "r");
  try {
    readSync(fd, buf, 0, tailBytes, size - tailBytes);
  } finally {
    closeSync(fd);
  }
  return buf;
}

/** RFC2047 の =?charset?B|Q?text?= を展開する */
export function decodeRfc2047(value) {
  if (!value || !value.includes("=?")) return value;
  return value
    // 連続するエンコード語の間の空白は削除する決まり
    .replace(/(\?=)\s+(=\?)/g, "$1$2")
    .replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (whole, charset, enc, text) => {
      try {
        let bytes;
        if (enc.toUpperCase() === "B") {
          bytes = Buffer.from(text, "base64");
        } else {
          bytes = Buffer.from(
            text.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_, h) =>
              String.fromCharCode(parseInt(h, 16))
            ),
            "latin1"
          );
        }
        return decodeBytes(bytes, charset);
      } catch (e) {
        return whole;
      }
    });
}

/** 文字コードを指定してバイト列を文字列にする */
export function decodeBytes(buf, charset) {
  const cs = String(charset || "utf-8").toLowerCase().replace(/["']/g, "").trim();
  const alias = {
    "iso-2022-jp": "iso-2022-jp",
    "shift_jis": "shift_jis",
    "shift-jis": "shift_jis",
    "sjis": "shift_jis",
    "x-sjis": "shift_jis",
    "windows-31j": "shift_jis",
    "cp932": "shift_jis",
    "euc-jp": "euc-jp",
    "x-euc-jp": "euc-jp",
    "us-ascii": "utf-8",
    "ansi_x3.4-1968": "utf-8",
    "unknown-8bit": "utf-8",
    "gb2312": "gbk",
    "ks_c_5601-1987": "euc-kr"
  };
  try {
    return new TextDecoder(alias[cs] || cs, { fatal: false }).decode(buf);
  } catch (e) {
    return buf.toString("utf8");
  }
}

/** quoted-printable を展開してバイト列に戻す */
function decodeQuotedPrintable(text) {
  const joined = text.replace(/=\r?\n/g, "");
  const out = [];
  for (let i = 0; i < joined.length; i++) {
    if (joined[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(joined.slice(i + 1, i + 3))) {
      out.push(parseInt(joined.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      out.push(joined.charCodeAt(i) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** ヘッダ部を解析する。折り返し行を連結し、RFC2047を展開する */
function parseHeaders(raw) {
  const headers = {};
  const order = [];
  const lines = raw.split(/\r?\n/);
  let current = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && current) {
      current.value += " " + line.trim();
      continue;
    }
    const m = line.match(/^([!-9;-~]+):[ \t]?(.*)$/);
    if (!m) continue;
    current = { name: m[1].toLowerCase(), value: m[2] };
    order.push(current);
  }
  for (const h of order) {
    const decoded = decodeRfc2047(h.value);
    (headers[h.name] = headers[h.name] || []).push(decoded);
  }
  return headers;
}

/** Content-Type から media type とパラメータを取り出す */
function parseContentType(value) {
  const raw = String(value || "text/plain");
  const type = raw.split(";")[0].trim().toLowerCase();
  const params = {};
  for (const m of raw.matchAll(/;\s*([\w-]+)\s*=\s*("([^"]*)"|[^;\s]+)/g)) {
    params[m[1].toLowerCase()] = m[3] !== undefined ? m[3] : m[2];
  }
  return { type, params };
}

/** multipart の本文を boundary で分割する */
function splitMultipart(body, boundary) {
  const marker = "--" + boundary;
  const text = body.toString("latin1");
  const chunks = [];
  let index = text.indexOf(marker);
  if (index === -1) return chunks;
  index += marker.length;
  while (index < text.length) {
    if (text.startsWith("--", index)) break; // 終端マーカー
    const nl = text.indexOf("\n", index);
    if (nl === -1) break;
    const start = nl + 1;
    const next = text.indexOf(marker, start);
    const end = next === -1 ? text.length : next;
    chunks.push(Buffer.from(text.slice(start, end).replace(/\r?\n$/, ""), "latin1"));
    if (next === -1) break;
    index = next + marker.length;
  }
  return chunks;
}

/** ヘッダと本文のバイト列から MessagePart 相当を作る */
function buildPart(headers, bodyBuf) {
  const ct = parseContentType(headers["content-type"] ? headers["content-type"][0] : "text/plain");
  const part = { contentType: ct.type, headers, parts: [] };

  if (ct.type.startsWith("multipart/") && ct.params.boundary) {
    for (const chunk of splitMultipart(bodyBuf, ct.params.boundary)) {
      const sep = findHeaderEnd(chunk);
      const subHeaders = parseHeaders(chunk.slice(0, sep.headerEnd).toString("latin1"));
      part.parts.push(buildPart(subHeaders, chunk.slice(sep.bodyStart)));
    }
    return part;
  }

  if (ct.type.startsWith("text/")) {
    const cte = String(headers["content-transfer-encoding"] ? headers["content-transfer-encoding"][0] : "")
      .toLowerCase().trim();
    let bytes = bodyBuf;
    if (cte === "base64") {
      bytes = Buffer.from(bodyBuf.toString("latin1").replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
    } else if (cte === "quoted-printable") {
      bytes = decodeQuotedPrintable(bodyBuf.toString("latin1"));
    }
    part.body = decodeBytes(bytes, ct.params.charset || "utf-8");
  }
  return part;
}

/** ヘッダ部の終端位置（空行）を探す */
function findHeaderEnd(buf) {
  const text = buf.toString("latin1");
  let i = text.indexOf("\r\n\r\n");
  if (i !== -1) return { headerEnd: i, bodyStart: i + 4 };
  i = text.indexOf("\n\n");
  if (i !== -1) return { headerEnd: i, bodyStart: i + 2 };
  return { headerEnd: buf.length, bodyStart: buf.length };
}

/** 1通分のバイト列を getFull 相当に変換する */
export function parseMessage(buf) {
  const sep = findHeaderEnd(buf);
  const headers = parseHeaders(buf.slice(0, sep.headerEnd).toString("latin1"));
  return buildPart(headers, buf.slice(sep.bodyStart));
}

/**
 * mbox ファイルを読み、新しい順に最大 limit 通を返す。
 * @returns {Array<{index:number, part:object}>}
 */
export function readMbox(path, limit = Infinity, tailBytes = 80 * 1024 * 1024) {
  const buf = readTail(path, tailBytes);
  const text = buf.toString("latin1");
  // "From " で始まる行が1通の境界
  const starts = [];
  if (text.startsWith("From ")) starts.push(0);
  for (const m of text.matchAll(/\n(From )/g)) starts.push(m.index + 1);
  // 末尾読みで先頭が途中から始まっている場合、最初の1通は不完全なので捨てる
  if (starts.length > 1 && !text.startsWith("From ")) starts.shift();

  const take = starts.length > limit ? starts.slice(starts.length - limit) : starts;
  const offset = starts.length - take.length;
  const out = [];
  for (let i = 0; i < take.length; i++) {
    const from = take[i];
    const to = i + 1 < take.length ? take[i + 1] : text.length;
    // 先頭の "From - <date>" 行を落とし、mboxrd のクォート解除を行う
    const nl = text.indexOf("\n", from);
    const raw = text.slice(nl + 1, to).replace(/\n>(>*From )/g, "\n$1");
    out.push({ index: offset + i, part: parseMessage(Buffer.from(raw, "latin1")) });
  }
  return out;
}
