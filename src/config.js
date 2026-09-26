/**
 * SpamGuard - 設定と辞書
 *
 * 既定値はすべてここに集約する。ユーザー変更分は storage.local の "settings" に
 * 差分として保存し、読み出し時に DEFAULT_SETTINGS とマージする。
 */

/** 判定後に行う動作 */
export const ACTIONS = {
  LOG_ONLY: "logOnly",       // ログのみ。メールには一切手を加えない
  TAG_ONLY: "tagOnly",       // タグ付与のみ（既定）
  MARK_JUNK: "markJunk",     // タグ付与 + Thunderbirdの迷惑マーク
  MARK_AND_MOVE: "markAndMove" // タグ付与 + 迷惑マーク + 迷惑メールフォルダへ移動
};

export const DEFAULT_SETTINGS = {
  /** 拡張機能全体の有効/無効 */
  enabled: true,

  /** 判定後の動作。初回導入時は誤検出を確認するため tagOnly から始める */
  action: ACTIONS.TAG_ONLY,

  /**
   * この点数以上を迷惑メールと判定する（0-100）。
   * 実際の受信データ（迷惑981通／受信トレイ750通）で調整した値。
   * 55点では詐称型の43.6%を検出し、受信トレイ側で55点以上かつ
   * SPF/DKIMがpassするメールは0通だった（＝正規メールの誤検出なし）。
   */
  spamThreshold: 55,

  /**
   * Jevへ問い合わせるグレーゾーン。
   * ローカルルールの点数が grayLow 未満なら「白」、grayHigh 以上なら「黒」として
   * 即断し、API呼び出しを節約する。間に入ったものだけJevへ送る。
   *
   * grayLow は実測で決めた値。25にすると受信トレイの12.9%がJevへ回るが、
   * 25-34点の帯からJevが救い出した詐称型は実測0件だった（その帯の検体は
   * Jev側も15-40点と低く評価していた）。35にすると4.2%まで下がり、
   * API呼び出しが約1/3になる。
   */
  grayLow: 35,
  /**
   * これ以上のローカル点は Jev を通さず迷惑と確定する。
   * 75だと、ローカルが構造的証拠で72点を付けたメールを Jev が
   * 「文面は普通の宣伝」と判断して合成33点まで引き下げ、見逃す例があった
   * （実データの BLACKCAS 系スパム）。Jev が見るのは文面だけなので、
   * ヘッダ構造で確信が持てている判定を覆させない。
   */
  grayHigh: 70,

  /**
   * 最終スコアの合成比率（ローカル : Jev）。合計が1になるよう正規化される。
   * 実測でJev側の分離幅（詐称型76.0 / 正規0.0）がローカル側（54.0 / 40.0）より
   * 大きかったため、Jevをやや重くしている。
   */
  weightLocal: 0.3,
  weightJev: 0.7,

  /** Jev(TypeSafe System One) 連携 */
  jevEnabled: false,
  jevEndpoint: "https://api.typesafe.ai/v1/systemone",
  jevApiKey: "",
  jevModel: "jev-latest",
  /** 1通あたりのタイムアウト(ms) */
  jevTimeoutMs: 20000,
  /** 429/529 のときの最大リトライ回数 */
  jevMaxRetries: 3,
  /** 本文をJevへ送る際の最大文字数 */
  jevBodyLimit: 1500,

  /** 判定対象外にする差出人ドメイン（登録可能ドメイン単位の後方一致） */
  allowDomains: [],
  /** 判定対象外にする差出人アドレス（完全一致・小文字） */
  allowAddresses: [],

  /**
   * 無条件で迷惑扱いにする差出人ドメイン／アドレス。
   * 「詐称ではないが読みたくない正規のメルマガ」を落とすための仕組み。
   * 内容で判定しようとすると本物の通知まで巻き込むため、名指しで拒否する。
   */
  blockDomains: [],
  blockAddresses: [],

  /**
   * 自分のアカウントのドメイン。外部から自ドメインを名乗って届くメールは詐称。
   * 起動時に accounts.list() から自動で埋まる（手動追加も可）。
   */
  selfDomains: [],

  /** 付与するタグのキー（messages.tags で作成される） */
  tagKeySpam: "spamguard_spam",
  tagKeySuspect: "spamguard_suspect",

  /** ログの保持件数 */
  logLimit: 500
};

/**
 * 詐称されやすい組織の辞書。
 * keywords が差出人表示名または件名に含まれるのに、実際の送信ドメインが
 * domains のいずれにも該当しない場合、なりすましの強い証拠とみなす。
 *
 * 【重要】domains には「その組織が実際に使う正規ドメイン」を漏れなく書くこと。
 * 書き漏らすと、本物のメールを詐称と誤判定する。
 * 例: PayPayカードの正規ドメインは paypay-card.co.jp であり、
 *     これを書き忘れると本物の利用明細が全件誤検出になる。
 */
export const BRANDS = [
  // --- 官公庁・公的機関 ---
  { name: "国税庁/e-Tax", keywords: ["国税庁", "e-tax", "etax", "イータックス", "税務署", "確定申告", "国税電子申告"], domains: ["nta.go.jp", "e-tax.nta.go.jp", "etax.nta.go.jp"] },
  { name: "日本年金機構", keywords: ["年金機構", "ねんきん"], domains: ["nenkin.go.jp"] },
  { name: "厚生労働省", keywords: ["厚生労働省"], domains: ["mhlw.go.jp"] },
  { name: "国民健康保険/自治体", keywords: ["国民健康保険", "市役所", "区役所"], domains: ["lg.jp", "go.jp"] },

  // --- 交通・航空 ---
  { name: "ANA", keywords: ["全日空", "全日本空輸", "anaマイレージ", "anaマイル", "ana予約", "ana公式", "anaカード", "マイレージクラブ", "ana card"], domains: ["ana.co.jp", "121.ana.co.jp", "amc.ana.co.jp"] },
  { name: "JAL", keywords: ["日本航空", "jalマイレージ", "jmb", "jalカード", "jal公式"], domains: ["jal.com", "jal.co.jp", "121.jal.co.jp"] },
  { name: "えきねっと", keywords: ["えきねっと", "jr東日本", "ビューカード", "view card"], domains: ["eki-net.com", "jreast.co.jp", "jr-east.co.jp", "viewsnet.jp", "jrview.co.jp"] },
  { name: "JR西日本", keywords: ["jr西日本", "e5489", "icoca"], domains: ["westjr.co.jp", "jr-odekake.net"] },
  { name: "ETC利用照会サービス", keywords: ["etc利用照会", "etcマイレージ", "etcサービス", "etc利用紹介"], domains: ["etc-meisai.jp", "smile-etc.jp"] },

  // --- 配送 ---
  { name: "日本郵便", keywords: ["日本郵便", "ゆうパック", "郵便局"], domains: ["japanpost.jp", "post.japanpost.jp"] },
  { name: "ヤマト運輸", keywords: ["ヤマト運輸", "クロネコ"], domains: ["kuronekoyamato.co.jp", "yamato-hd.co.jp"] },
  { name: "佐川急便", keywords: ["佐川急便", "sagawa"], domains: ["sagawa-exp.co.jp"] },

  // --- 通販・EC ---
  { name: "Amazon", keywords: ["amazon", "アマゾン", "amazonプライム", "prime video"], domains: ["amazon.co.jp", "amazon.com", "amazon.jp", "email.amazon.co.jp", "primevideo.com", "amazonmusic.com", "amazonbusiness.jp", "audible.co.jp", "audible.com", "aws.amazon.com"] },
  { name: "楽天", keywords: ["楽天", "rakuten"], domains: ["rakuten.co.jp", "rakuten.com", "rakuten-card.co.jp", "rakuten-bank.co.jp", "rakuten.ne.jp"] },
  { name: "メルカリ", keywords: ["メルカリ", "mercari"], domains: ["mercari.com", "mercari.jp"] },
  { name: "ヤフー", keywords: ["yahoo", "ヤフー", "yahoo!ショッピング", "paypayモール"], domains: ["yahoo.co.jp", "yahoo-net.jp", "mail.yahoo.co.jp", "yahoo-corp.jp"] },
  { name: "ヨドバシ", keywords: ["ヨドバシ", "yodobashi"], domains: ["yodobashi.com"] },

  // --- カード・金融 ---
  { name: "三井住友/Vpass", keywords: ["三井住友", "smbc", "vpass", "vポイント", "olive"], domains: ["smbc.co.jp", "smbc-card.com", "vpass.ne.jp", "vpoint.jp", "smbc-cf.com"] },
  { name: "三菱UFJ", keywords: ["三菱ufj", "mufg", "ufjニコス", "nicos"], domains: ["bk.mufg.jp", "mufg.jp", "cr.mufg.jp", "nicos.co.jp"] },
  { name: "みずほ", keywords: ["みずほ", "mizuho"], domains: ["mizuhobank.co.jp", "mizuho-fg.co.jp"] },
  { name: "JCB", keywords: ["jcb", "myjcb"], domains: ["jcb.co.jp", "qa.jcb.co.jp", "jcb-card.jp"] },
  { name: "PayPayカード", keywords: ["paypayカード", "paypay card", "paypay-card"], domains: ["paypay-card.co.jp", "paypay-card.jp", "paypay.ne.jp"] },
  { name: "PayPay", keywords: ["paypay", "ペイペイ"], domains: ["paypay.ne.jp", "paypay-bank.co.jp", "paypay-card.co.jp", "paypay-card.jp"] },
  { name: "クレディセゾン", keywords: ["クレディセゾン", "セゾンカード", "saison", "セゾン永久不滅", "ucカード"], domains: ["saisoncard.co.jp", "credit-saison.co.jp", "saisoncard.jp", "uccard.co.jp"] },
  { name: "エポスカード", keywords: ["エポスカード", "epos", "エポスネット"], domains: ["eposcard.co.jp", "01epos.jp", "0101.co.jp"] },
  { name: "イオンカード", keywords: ["イオンカード", "aeon", "イオン銀行"], domains: ["aeon.co.jp", "aeonbank.co.jp", "aeoncredit.co.jp"] },
  { name: "オリコ", keywords: ["オリコ", "orico"], domains: ["orico.co.jp"] },
  { name: "ポケットカード", keywords: ["ポケットカード", "p-one"], domains: ["pocketcard.co.jp"] },
  { name: "アメックス", keywords: ["アメリカン・エキスプレス", "american express", "アメックス", "amex"], domains: ["americanexpress.com", "aexp.com"] },
  { name: "ソニー銀行", keywords: ["ソニー銀行", "sony bank"], domains: ["sonybank.net", "sonybank.jp", "moneykit.net"] },
  { name: "住信SBI", keywords: ["住信sbi", "ネット銀行"], domains: ["netbk.co.jp", "sbigroup.co.jp"] },
  { name: "ゆうちょ銀行", keywords: ["ゆうちょ", "郵貯"], domains: ["jp-bank.japanpost.jp", "jp-bank.jp"] },

  // --- 通信・インフラ ---
  { name: "NTT/ドコモ", keywords: ["ntt", "ドコモ", "docomo", "dアカウント", "dカード", "dポイント"], domains: ["docomo.ne.jp", "nttdocomo.co.jp", "ntt.com", "ntt-east.co.jp", "ntt-west.co.jp", "d-card.jp", "dcard.docomo.ne.jp"] },
  { name: "au/KDDI", keywords: ["kddi", "auかんたん決済", "au pay", "aupay", "au id", "auひかり", "auマーケット", "povo"], domains: ["au.com", "kddi.com", "ezweb.ne.jp", "aupay.auone.jp", "auone.jp"] },
  { name: "ソフトバンク", keywords: ["ソフトバンク", "softbank", "ワイモバイル"], domains: ["softbank.jp", "softbank.ne.jp", "ymobile.jp", "ymobile.ne.jp"] },
  { name: "東京電力", keywords: ["東京電力", "tepco", "くらしtepco"], domains: ["tepco.co.jp", "tepco.com"] },
  { name: "関西電力", keywords: ["関西電力", "はぴeみる電"], domains: ["kepco.co.jp", "kepco.jp"] },
  { name: "東京ガス", keywords: ["東京ガス", "myTOKYOGAS"], domains: ["tokyo-gas.co.jp"] },
  { name: "NHK", keywords: ["nhk", "日本放送協会"], domains: ["nhk.or.jp"] },

  // --- プラットフォーム ---
  { name: "Apple", keywords: ["apple", "アップル", "icloud", "app store", "itunes"], domains: ["apple.com", "icloud.com", "email.apple.com", "itunes.com", "appleid.com", "apple.news"] },
  { name: "Microsoft", keywords: ["microsoft", "outlook", "office365", "マイクロソフト", "onedrive"], domains: ["microsoft.com", "outlook.com", "office.com", "accountprotection.microsoft.com", "microsoftonline.com"] },
  { name: "Google", keywords: ["google", "グーグル", "gmail", "google play"], domains: ["google.com", "gmail.com", "accounts.google.com", "youtube.com"] },
  { name: "LINE", keywords: ["ラインヤフー", "lineギフト", "line公式", "lineアカウント", "line pay", "linepay", "line証券"], domains: ["line.me", "linecorp.com", "line-apps.com", "lycorp.co.jp"] },
  { name: "Netflix", keywords: ["netflix", "ネットフリックス"], domains: ["netflix.com", "mailer.netflix.com"] }
];

/**
 * 個人向け回線・動的割当ホストのドメイン。
 * Received経路にこれらが現れる場合、正規の組織からの配信としては不自然。
 */
export const CONSUMER_ISP_DOMAINS = [
  "ymobile.ne.jp", "openmobile.ne.jp", "docomo.ne.jp", "spmode.ne.jp",
  "au-net.ne.jp", "ezweb.ne.jp", "ocn.ne.jp", "plala.or.jp", "so-net.ne.jp",
  "dion.ne.jp", "eonet.ne.jp", "bbtec.net", "commufa.jp", "asahi-net.or.jp",
  "zaq.ne.jp", "jcom.home.ne.jp", "vectant.ne.jp", "nuro.jp"
];

/**
 * 海外の家庭用回線の逆引き名。Received の括弧内（`from [ip] (逆引き名)`）に現れる。
 * 2026-09 に `info@kjehuf.cn-dqsb.com` 型の使い捨てドメインが大量に届いたが、
 * いずれも `c-69-180-*.hsd1.ga.comcast.net` から直接送られていた。
 * 企業の配信がケーブル回線の家庭用アドレスから出ることはまず無い。
 * 実データで確認できたものだけを置き、推測で広げない。
 */
export const RESIDENTIAL_HOST_PATTERNS = [
  /^c-\d+-\d+-\d+-\d+\.hsd1\.[a-z]{2}\.comcast\.net$/
];

/**
 * 送信ホストの先頭ラベルとして一般的な語。
 * これらが Return-Path のローカル部と一致しても、自動生成の証拠にはしない
 * （`mail@mail.adobe.com` や `no-reply@email.balmuda.com` のような正規配信があるため）。
 */
export const COMMON_SENDER_LABELS = [
  "mail", "email", "mailer", "news", "newsletter", "info", "noreply", "no-reply",
  "support", "contact", "notice", "notify", "service", "member", "members", "magazine",
  "mag", "bounce", "bounces", "return", "reply", "send", "sender", "marketing", "mailing"
];

/**
 * 迷惑メールに濫用されやすいTLD。
 * 日本語の業務メールでこれらが差出人になることはまずない。
 * （.com / .net / .jp のような一般的なTLDは当然含めない）
 */
export const ABUSED_TLDS = [
  "click", "shop", "top", "xyz", "icu", "cyou", "sbs", "buzz", "rest",
  "fit", "live", "work", "monster", "quest", "bar", "beauty", "hair",
  "makeup", "skin", "mom", "lol", "cfd", "bond", "autos", "boats",
  "cn", "ru", "su", "tk", "ml", "ga", "cf", "gq"
];

/**
 * 差出人が無料メール・携帯キャリアのドメインの場合、
 * 組織を名乗っていても正規の企業配信ではありえない。
 */
export const FREEMAIL_DOMAINS = [
  "gmail.com", "yahoo.co.jp", "ymail.ne.jp", "outlook.com", "outlook.jp",
  "hotmail.com", "hotmail.co.jp", "live.jp", "icloud.com", "me.com",
  "aol.com", "docomo.ne.jp", "ezweb.ne.jp", "au.com", "softbank.ne.jp",
  "i.softbank.jp", "ybb.ne.jp", "nifty.com", "excite.co.jp", "qq.com", "163.com"
];

/** 不安・緊急を煽る定型表現 */
export const URGENCY_PATTERNS = [
  "至急", "緊急", "重要なお知らせ", "本日中", "24時間以内", "48時間以内",
  "アカウントが停止", "利用停止", "制限されます", "凍結", "強制退会",
  "確認できない場合", "手続きを行わない", "自動的に削除", "失効",
  "未納", "滞納", "差押", "督促", "最終通告", "最終通知", "法的措置",
  "不正利用", "第三者による", "再認証", "本人確認", "異常ログイン",
  "お支払い方法の情報を更新", "情報を更新してください", "引き落としに失敗",
  "有効期限が迫", "期限までに", "至急ご確認"
];

/** 設定を読み出し、既定値とマージして返す */
export async function loadSettings() {
  const stored = await browser.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(stored.settings || {}) };
}

/** 設定を保存する（部分更新） */
export async function saveSettings(patch) {
  const current = await loadSettings();
  const next = { ...current, ...patch };
  await browser.storage.local.set({ settings: next });
  return next;
}
