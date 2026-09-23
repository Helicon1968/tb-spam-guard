/**
 * SpamGuard - XPI（ZIP）を作る
 *
 * 実行: node tools/build.mjs  （プロジェクトルートから）
 * 出力: dist/tb-spam-guard-<version>.xpi
 *
 * 外部ツールに依存しないよう、Node標準のzlibだけでZIPを組み立てる。
 * ZIP内のパス区切りは必ず "/" にする（"\" だとThunderbirdが読めない）。
 */

import { readFileSync, readdirSync, statSync, mkdirSync, writeFileSync } from "node:fs";
import { deflateRawSync, crc32 } from "node:zlib";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * XPIに含めるもの（許可リスト方式）。
 * 除外リスト方式だと、直下に置いた作業メモや測定記録まで同梱してしまうため。
 */
const INCLUDE_DIRS = new Set(["src", "ui", "icons"]);
const INCLUDE_FILES = new Set(["manifest.json", "background.js", "LICENSE"]);

function collect(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = relative(ROOT, full).split("\\").join("/");
    if (statSync(full).isDirectory()) {
      if (!INCLUDE_DIRS.has(rel.split("/")[0])) continue;
      collect(full, out);
    } else {
      if (!rel.includes("/") && !INCLUDE_FILES.has(rel)) continue;
      out.push({ rel, full });
    }
  }
  return out;
}

/** DOSの日時形式（ZIPのローカルヘッダ用） */
function dosDateTime(d) {
  const time = ((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xffff;
  const date = (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xffff;
  return { time, date };
}

function buildZip(files) {
  const now = new Date();
  const { time, date } = dosDateTime(now);
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const file of files) {
    const name = Buffer.from(file.rel, "utf8");
    const raw = readFileSync(file.full);
    const deflated = deflateRawSync(raw, { level: 9 });
    // 圧縮して大きくなる場合は無圧縮(method 0)にする
    const useDeflate = deflated.length < raw.length;
    const data = useDeflate ? deflated : raw;
    const method = useDeflate ? 8 : 0;
    const sum = crc32(raw) >>> 0;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);            // version needed
    local.writeUInt16LE(0x0800, 6);        // UTF-8 フラグ
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(sum, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);          // version made by
    central.writeUInt16LE(20, 6);          // version needed
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(sum, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);

    offset += local.length + name.length + data.length;
  }

  const centralBuf = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, centralBuf, end]);
}

const version = JSON.parse(readFileSync(join(ROOT, "manifest.json"), "utf8")).version;
const files = collect(ROOT).sort((a, b) => a.rel.localeCompare(b.rel));
const zip = buildZip(files);

mkdirSync(join(ROOT, "dist"), { recursive: true });
const out = join(ROOT, "dist", "tb-spam-guard-" + version + ".xpi");
writeFileSync(out, zip);

console.log("収録 " + files.length + " ファイル:");
for (const f of files) console.log("  " + f.rel);
console.log("\n出力: " + out + " (" + zip.length + " bytes)");
