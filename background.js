/**
 * SpamGuard - バックグラウンド（MV3 イベントページ）
 *
 * Thunderbird の MV3 は service worker ではなく「制限付きイベントページ」を使う。
 * アイドルで終了し、イベント発生時に再起動されるため、
 *  - リスナー登録はトップレベルで同期的に行う
 *  - 状態はモジュールスコープに置かず storage に持つ
 * という制約を守る必要がある。
 */

import { ACTIONS, loadSettings, saveSettings } from "./src/config.js";
import { parseAddress } from "./src/extract.js";
import { VERDICT, classifyMessage } from "./src/classify.js";
import { appendLog } from "./src/log.js";

const TAG_SPAM_NAME = "SpamGuard:迷惑";
const TAG_SUSPECT_NAME = "SpamGuard:疑い";
const MENU_ID_ROOT = "spamguard-root";
const MENU_ID_CLASSIFY = "spamguard-classify-selected";
const MENU_ID_BLOCK = "spamguard-toggle-block";
const MENU_ID_ALLOW = "spamguard-toggle-allow";

/** 直列処理のためのキュー。大量着信時にJevへ同時接続しないようにする */
let queue = Promise.resolve();
function enqueue(task) {
  queue = queue.then(task).catch((e) => console.error("[SpamGuard]", e));
  return queue;
}

/**
 * MessageList を最後のページまでたどる。
 * 1ページは既定100件なので、1回の受信で100通を超えると
 * 先頭ページだけでは取りこぼす（100通/日規模では現実に起こりうる）。
 */
async function drainList(list) {
  const all = [...((list && list.messages) || [])];
  let id = list && list.id;
  while (id) {
    const page = await browser.messages.continueList(id);
    all.push(...(page.messages || []));
    id = page.id;
  }
  return all;
}

/**
 * 自アカウントのメールドメインを集める。
 * 外部から自分のドメインを名乗って届くメールは詐称なので、その判定に使う。
 */
async function collectSelfDomains() {
  const accounts = await browser.accounts.list(false);
  const domains = new Set();
  for (const account of accounts) {
    for (const identity of account.identities || []) {
      const at = String(identity.email || "").lastIndexOf("@");
      if (at > 0) domains.add(identity.email.slice(at + 1).toLowerCase());
    }
  }
  return [...domains];
}

/** 設定に、自動検出した自ドメインを足したものを返す */
async function loadEffectiveSettings() {
  const settings = await loadSettings();
  let auto = [];
  try {
    auto = await collectSelfDomains();
  } catch (e) {
    console.warn("[SpamGuard] 自ドメインの取得に失敗", e);
  }
  return { ...settings, selfDomains: [...new Set([...(settings.selfDomains || []), ...auto])] };
}

/** 判定に使うタグが無ければ作る */
async function ensureTags(settings) {
  const existing = await browser.messages.tags.list();
  const keys = new Set(existing.map((t) => t.key));
  if (!keys.has(settings.tagKeySpam)) {
    await browser.messages.tags.create(settings.tagKeySpam, TAG_SPAM_NAME, "#E53E3E");
  }
  if (!keys.has(settings.tagKeySuspect)) {
    await browser.messages.tags.create(settings.tagKeySuspect, TAG_SUSPECT_NAME, "#DD6B20");
  }
}

/** アカウント内の迷惑メールフォルダを探す */
async function findJunkFolder(accountId) {
  const folders = await browser.folders.query({ accountId, specialUse: ["junk"] });
  if (folders.length) return folders[0];
  // specialUse が付いていないPOPアカウント向けのフォールバック
  const byName = await browser.folders.query({ accountId, name: "Junk" });
  return byName.length ? byName[0] : null;
}

/** 既に付いているSpamGuardタグを取り除いた配列を返す */
function stripOwnTags(tags, settings) {
  return (tags || []).filter((t) => t !== settings.tagKeySpam && t !== settings.tagKeySuspect);
}

/**
 * 移動などで無効になったメッセージIDを Message-ID から引き直す。
 *
 * Thunderbird標準の迷惑フィルタは新着メールに対して独自に動いており、
 * SpamGuardが判定している最中にメールを迷惑メールフォルダへ移すことがある。
 * 移動するとメッセージIDが変わるため、こちらが持っているIDでの
 * update/move が失敗する（実運用で受信トレイにタグが付かない原因になっていた）。
 */
async function relocateMessage(headerMessageId) {
  const id = String(headerMessageId || "").replace(/^<|>$/g, "");
  if (!id) return null;
  try {
    const found = await drainList(await browser.messages.query({ headerMessageId: id }));
    return found.length ? found[0].id : null;
  } catch (e) {
    console.warn("[SpamGuard] メッセージの再取得に失敗", id, e);
    return null;
  }
}

/**
 * 判定結果をメールに反映する。
 * @returns {Promise<string>} 実際に行った操作の説明
 */
async function applyVerdict(messageId, result, settings) {
  if (settings.action === ACTIONS.LOG_ONLY) return "ログのみ";
  if (result.verdict === VERDICT.HAM) return "操作なし";

  const tagKey = result.verdict === VERDICT.SPAM ? settings.tagKeySpam : settings.tagKeySuspect;
  const wantsJunkMark =
    result.verdict === VERDICT.SPAM &&
    (settings.action === ACTIONS.MARK_JUNK || settings.action === ACTIONS.MARK_AND_MOVE);

  // メールが移動していた場合に備え、一度だけIDを引き直して再試行する
  let id = messageId;
  let meta = null;
  let relocated = false;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      meta = await browser.messages.get(id);
      const props = { tags: [...stripOwnTags(meta.tags, settings), tagKey] };
      if (wantsJunkMark) props.junk = true;
      await browser.messages.update(id, props);
      break;
    } catch (e) {
      if (attempt === 1) throw e;
      const again = await relocateMessage(result.headerMessageId);
      if (!again || again === id) throw e;
      id = again;
      relocated = true;
    }
  }

  const done = ["タグ付与(" + tagKey + ")"];
  if (wantsJunkMark) done.push("迷惑マーク");
  if (relocated) done.push("移動済みのため再取得");

  if (settings.action === ACTIONS.MARK_AND_MOVE && result.verdict === VERDICT.SPAM) {
    const accountId = meta && meta.folder && meta.folder.accountId;
    const junk = accountId ? await findJunkFolder(accountId) : null;
    if (!junk) {
      done.push("移動先フォルダが見つからず未移動");
    } else if (meta.folder && meta.folder.id === junk.id) {
      // 既に迷惑メールフォルダにある（Thunderbird側が先に移動済み）
      done.push("既に迷惑メールフォルダにあり移動不要");
    } else {
      await browser.messages.move([id], junk.id);
      done.push("迷惑メールフォルダへ移動");
    }
  }
  return done.join(" / ");
}

/**
 * 差出人アドレスを許可/拒否リストに出し入れする。
 *
 * 設定画面のテキストエリアでも編集できるが、
 * メールを見ている流れのまま登録・解除できるほうが運用しやすい。
 */
async function toggleListEntry(listKey, address) {
  const settings = await loadSettings();
  const list = [...(settings[listKey] || [])];
  const target = String(address || "").toLowerCase();
  if (!target) return null;
  const at = list.findIndex((a) => String(a).toLowerCase() === target);
  let added;
  if (at >= 0) {
    list.splice(at, 1);
    added = false;
  } else {
    list.push(target);
    added = true;
  }
  await saveSettings({ [listKey]: list });
  return { added, address: target, size: list.length };
}

/** メニューから選ばれているメールの差出人アドレスを取り出す */
async function selectedSender(info) {
  const list = info && info.selectedMessages;
  const first = list && list.messages && list.messages[0];
  if (!first) return "";
  const parsed = parseAddress(first.author || "");
  return parsed.address || "";
}

/** 操作結果を通知する（黙って変わると分かりにくいため） */
function notify(message) {
  try {
    browser.notifications.create({
      type: "basic",
      title: "SpamGuard",
      message,
      iconUrl: browser.runtime.getURL("icons/icon.svg")
    });
  } catch (e) {
    console.info("[SpamGuard]", message);
  }
}

/** 1通を判定してログに残す */
async function processMessage(messageId, settings, source) {
  const result = await classifyMessage(messageId, settings);
  let applied = "操作なし";
  try {
    applied = await applyVerdict(messageId, result, settings);
  } catch (e) {
    applied = "適用失敗: " + (e && e.message ? e.message : e);
  }
  await appendLog({ ...result, applied, source }, settings.logLimit);
  console.info("[SpamGuard]", result.verdict, result.score, result.subject, "->", applied);
  return result;
}

// --- リスナー登録（トップレベルで同期的に行う） -------------------------------

browser.messages.onNewMailReceived.addListener((folder, messages) => {
  enqueue(async () => {
    const settings = await loadEffectiveSettings();
    if (!settings.enabled) return;
    if (settings.action !== ACTIONS.LOG_ONLY) await ensureTags(settings);
    for (const message of await drainList(messages)) {
      try {
        await processMessage(message.id, settings, "onNewMailReceived");
      } catch (e) {
        console.error("[SpamGuard] 判定失敗", message.id, e);
      }
    }
  });
});

browser.menus.onClicked.addListener((info) => {
  if (info.menuItemId === MENU_ID_BLOCK || info.menuItemId === MENU_ID_ALLOW) {
    const listKey = info.menuItemId === MENU_ID_BLOCK ? "blockAddresses" : "allowAddresses";
    const listName = info.menuItemId === MENU_ID_BLOCK ? "拒否リスト" : "許可リスト";
    enqueue(async () => {
      const address = await selectedSender(info);
      if (!address) return;
      const res = await toggleListEntry(listKey, address);
      if (res) {
        notify(listName + (res.added ? "に追加しました: " : "から削除しました: ") +
          res.address + "（現在 " + res.size + " 件）");
      }
    });
    return;
  }
  if (info.menuItemId !== MENU_ID_CLASSIFY) return;
  const list = info.selectedMessages;
  if (!list || !list.messages || !list.messages.length) return;
  enqueue(async () => {
    const settings = await loadEffectiveSettings();
    if (settings.action !== ACTIONS.LOG_ONLY) await ensureTags(settings);
    for (const message of await drainList(list)) {
      try {
        await processMessage(message.id, settings, "manual");
      } catch (e) {
        console.error("[SpamGuard] 判定失敗", message.id, e);
      }
    }
  });
});

browser.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "classifyIds") {
    return (async () => {
      const settings = await loadEffectiveSettings();
      if (settings.action !== ACTIONS.LOG_ONLY) await ensureTags(settings);
      const results = [];
      for (const id of msg.ids) results.push(await processMessage(id, settings, "manual"));
      return results;
    })();
  }
  if (msg && msg.type === "ping") return Promise.resolve({ ok: true });
  return false;
});

// メニュー項目はイベントページ再起動のたびに登録が走るので、重複エラーは無視する
const ignoreDuplicate = () => void browser.runtime.lastError;

browser.menus.create(
  { id: MENU_ID_ROOT, title: "SpamGuard", contexts: ["message_list"] },
  ignoreDuplicate
);
browser.menus.create(
  { id: MENU_ID_CLASSIFY, parentId: MENU_ID_ROOT, title: "このメールを判定", contexts: ["message_list"] },
  ignoreDuplicate
);
browser.menus.create(
  { id: MENU_ID_BLOCK, parentId: MENU_ID_ROOT, title: "この差出人を拒否リストに追加", contexts: ["message_list"] },
  ignoreDuplicate
);
browser.menus.create(
  { id: MENU_ID_ALLOW, parentId: MENU_ID_ROOT, title: "この差出人を許可リストに追加", contexts: ["message_list"] },
  ignoreDuplicate
);

/*
 * メニューを開くたびに、選択中の差出人が既にリストに入っているかを見て
 * 「追加」と「削除」を切り替える。登録と解除を同じ場所で完結させるため。
 */
browser.menus.onShown.addListener(async (info) => {
  if (!info.contexts.includes("message_list")) return;
  const address = await selectedSender(info);
  const settings = await loadSettings();
  const has = (key) => (settings[key] || []).some((a) => String(a).toLowerCase() === address);

  const label = (key, addName, removeName) =>
    !address ? addName : (has(key) ? removeName + "（" + address + "）" : addName + "（" + address + "）");

  await browser.menus.update(MENU_ID_BLOCK, {
    title: label("blockAddresses", "この差出人を拒否リストに追加", "この差出人を拒否リストから削除"),
    enabled: Boolean(address)
  });
  await browser.menus.update(MENU_ID_ALLOW, {
    title: label("allowAddresses", "この差出人を許可リストに追加", "この差出人を許可リストから削除"),
    enabled: Boolean(address)
  });
  await browser.menus.refresh();
});
