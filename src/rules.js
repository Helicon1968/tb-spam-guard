/**
 * SpamGuard - ローカルルールによるスコアリング
 *
 * 外部APIを一切使わずにヘッダ構造の矛盾だけで点数を付ける。
 * ここで白黒はっきりしたものはJevへ送らないため、API呼び出し量を抑えられる。
 *
 * 設計方針:
 *  - 「本文が怪しい」ではなく「構造が矛盾している」ことだけを見る。
 *    日本語の文面判断はJev側の担当とし、ルール側は言語に依存しない証拠に絞る。
 *  - 1つの加点項目だけで閾値を超えないよう、配点は分散させる。
 */

import { isUnderDomain } from "./extract.js";

/**
 * 加点ルールの定義。
 * weight は 0-100 のスコアに対する加点。減点（ham寄りの証拠）は負値。
 */
const RULES = [
  {
    id: "brandMismatch",
    label: "表示名の組織と送信ドメインが不一致",
    weight: 35,
    test: (f) => f.brandMismatch && f.brandInDisplay
  },
  {
    // 件名にしか組織名が出てこない場合は「名乗っている」のか
    // 「言及しているだけ」なのか区別が付かないため、配点を大きく下げる。
    // 実データでは、食べログのVポイント付与通知や映画ニュースのNetflix言及が
    // これで誤検出になっていた。
    id: "brandMentionMismatch",
    label: "件名の組織名と送信ドメインが不一致（言及のみ）",
    weight: 26,
    test: (f) => f.brandMismatch && !f.brandInDisplay
  },
  {
    id: "randomFromHost",
    label: "送信ドメインが自動生成らしい文字列",
    weight: 15,
    test: (f) => f.randomFromHost
  },
  {
    id: "hiddenRandomText",
    label: "本文の不可視要素にランダム文字列",
    weight: 10,
    test: (f) => f.hiddenRandomText
  },
  {
    id: "consumerIspHop",
    label: "配信経路に個人向け回線ホスト",
    weight: 15,
    test: (f) => f.consumerIspHops.length > 0
  },
  {
    id: "messageIdMismatch",
    label: "Message-IDのドメインが送信ドメインと不一致",
    weight: 6,
    test: (f) => Boolean(f.messageIdDomain) && Boolean(f.fromDomain) &&
      f.messageIdDomain !== f.fromDomain
  },
  {
    id: "unsubThirdParty",
    label: "配信停止リンクが第三のドメイン",
    weight: 8,
    test: (f) => f.listUnsubDomains.length > 0 &&
      f.listUnsubDomains.every((d) => d !== f.fromDomain)
  },
  {
    id: "returnPathMismatch",
    label: "Return-Pathのドメインが送信ドメインと不一致",
    weight: 6,
    test: (f) => Boolean(f.returnPath.host) && Boolean(f.fromDomain) &&
      !isUnderDomain(f.returnPath.host, f.fromDomain)
  },
  {
    id: "replyToMismatch",
    label: "Reply-Toのドメインが送信ドメインと不一致",
    weight: 6,
    test: (f) => Boolean(f.replyTo.host) && Boolean(f.fromDomain) &&
      !isUnderDomain(f.replyTo.host, f.fromDomain)
  },
  {
    id: "brandLinkMismatch",
    label: "本文リンクが詐称組織の正規ドメインでない",
    weight: 15,
    test: (f) => f.brandMismatch && f.brandInDisplay && f.brandForeignLinkDomains.length > 0
  },
  {
    id: "hiddenTextWithBrand",
    label: "組織を詐称しつつ不可視要素にランダム文字列",
    weight: 15,
    test: (f) => f.brandMismatch && f.hiddenRandomText
  },
  {
    id: "urgency",
    label: "緊急性・不利益を煽る表現",
    weight: 10,
    test: (f) => f.urgencyHits.length >= 2
  },
  {
    id: "punycodeLink",
    label: "リンク先にpunycodeドメイン",
    weight: 10,
    test: (f) => f.linkDomains.some((d) => d.includes("xn--"))
  },
  {
    id: "rawIpLink",
    label: "リンク先がIPアドレス直指定",
    weight: 12,
    test: (f) => f.linkDomains.some((d) => /^\d{1,3}(\.\d{1,3}){3}$/.test(d))
  },
  {
    id: "noPlainText",
    label: "HTMLのみでテキスト版がない",
    weight: 4,
    test: (f) => f.hasHtml && !f.bodyText.trim()
  },
  // --- 以下、実際の迷惑メールフォルダ約1000通の分析で追加したルール ---
  {
    /**
     * 受信サーバ側の判定を証拠として取り込む（heteml の X-Spam-Status 等）。
     * 実データでは迷惑メール1879通の59.7%に付いている一方、受信トレイ1469通にも
     * 54通(3.7%)付いており、その中身はPayPayカードやYahoo!ショッピングの
     * 正規メルマガだった。つまり「強いが万能ではない」信号。
     *
     * 配点を振ったところ22と26の間に明確な崖があり、26にすると
     * 正規メルマガが一斉にしきい値を越えて誤検出が2通→22通に増える。
     * 単独ではしきい値(55)に届かず、他の証拠と重なったときだけ効く22を採用した。
     */
    id: "upstreamSpamFlag",
    label: "受信サーバがスパムと判定済み",
    weight: 22,
    test: (f) => Boolean(f.upstreamSpam && f.upstreamSpam.flagged)
  },
  {
    id: "vowellessDomain",
    label: "送信ドメインに母音を含まないラベルがある",
    weight: 18,
    test: (f) => f.vowellessDomain
  },
  {
    id: "bidiObfuscation",
    label: "件名・表示名に双方向制御文字を仕込んでいる",
    weight: 30,
    test: (f) => f.bidiObfuscation
  },
  {
    id: "zeroWidthObfuscation",
    label: "件名にゼロ幅文字を挟んで語句照合を妨害",
    weight: 22,
    test: (f) => f.zeroWidthObfuscation
  },
  {
    id: "selfDomainSpoof",
    label: "自分のドメインを名乗る外部からのメール",
    weight: 30,
    test: (f) => f.selfDomainSpoof
  },
  {
    id: "authFail",
    label: "SPFまたはDMARCが fail",
    weight: 18,
    test: (f) => f.auth.spf === "fail" || f.auth.dmarc === "fail"
  },
  {
    id: "authSoftfail",
    label: "SPFが softfail",
    weight: 12,
    test: (f) => f.auth.spf === "softfail"
  },
  {
    id: "displayNameIsAddress",
    label: "表示名がメールアドレスそのもの",
    weight: 16,
    test: (f) => f.displayNameIsAddress
  },
  {
    id: "displayNameIsOtherAddress",
    label: "表示名が実際の差出人と違うメールアドレス",
    weight: 20,
    test: (f) => f.displayNameIsOtherAddress
  },
  {
    id: "randomLocalPart",
    label: "差出人のローカル部が自動生成らしい文字列",
    weight: 12,
    test: (f) => f.randomLocalPart
  },
  {
    id: "unpronounceableDomain",
    label: "送信ドメインが発音できない自動生成らしい文字列",
    weight: 16,
    test: (f) => f.unpronounceableDomain
  },
  {
    id: "abusedTld",
    label: "迷惑メールに濫用されやすいTLD",
    weight: 16,
    test: (f) => Boolean(f.abusedTld)
  },
  {
    id: "freemailBrand",
    label: "無料メール・携帯ドメインから組織を名乗っている",
    weight: 20,
    test: (f) => f.freemailSender && f.brands.length > 0 && !f.brandMatched
  },
  {
    id: "freemailJapaneseBulk",
    label: "無料メールから日本語の宣伝メールが届いている",
    weight: 14,
    test: (f) => f.freemailSender && f.hasJapanese && f.linkDomains.length > 0 &&
      f.foreignLinkDomains.length > 0
  },
  // --- 以下は ham 寄りの証拠（減点） ---
  {
    // 「名乗る組織と送信ドメインが一致する」ことが正当性の証拠になるのは、
    // そのドメインが企業のものである場合に限る。
    // フリーメールでは誰でもそのドメインのアドレスを取れるため、
    // 迷惑メールが gmail.com / outlook.com / icloud.com から送られただけで
    // 「正規のGoogle/Microsoft/Apple」と判定されてしまう。
    // （実データでは表示名にアドレスをそのまま置いた宣伝メール86通が該当した）
    id: "brandMatched",
    label: "表示名の組織と送信ドメインが一致",
    weight: -30,
    test: (f) => f.brandMatched && !f.freemailSender
  },
  /*
   * かつて `sameDomainEverywhere`（From/Return-Path/Message-ID が同一ドメインなら −10）
   * というルールがあったが、撤去した。
   *
   * 自分でドメインを取れば誰でも満たせる条件であり、実運用ログでは
   * 使い捨てドメインのスパマー（info@jgdyyt.yunshang-china.com 等）を
   * 一律に利していた。「認証が通ること」を条件に加えても効果がない。
   * 攻撃者は自分の偽ドメインにSPF/DKIMを正しく設定するからで、
   * これはこのプロジェクトの出発点で確認した事実そのものだった。
   *
   * 実データで撤去の影響を測ると、詐称型の検出は 945→951 と増え、
   * 受信トレイの誤検出は 2通のまま変わらなかった。
   * 正の価値が実証できないルールなので残さない。
   */
];

/**
 * 差出人が許可リストに載っているか
 * @returns {string|null} 一致した許可理由。該当なしならnull
 */
export function matchAllowList(features, settings) {
  const addr = features.from.address;
  if (addr && settings.allowAddresses.some((a) => a.toLowerCase() === addr)) {
    return "allowAddresses: " + addr;
  }
  const hit = settings.allowDomains.find((d) => isUnderDomain(features.from.host, d));
  return hit ? "allowDomains: " + hit : null;
}

/**
 * 差出人が拒否リストに載っているか。
 *
 * 実データを見ると、迷惑メールフォルダの中身は
 *  (A) 組織を詐称するフィッシング
 *  (B) 詐称ではないが読みたくない正規のメルマガ・通知
 * の2種類が混在している。(B) を内容ルールで落とそうとすると
 * 同じ送信元の本物の重要通知まで巻き込むため、名指しで拒否する。
 *
 * @returns {string|null} 一致した拒否理由。該当なしならnull
 */
export function matchBlockList(features, settings) {
  const addr = features.from.address;
  if (addr && (settings.blockAddresses || []).some((a) => a.toLowerCase() === addr)) {
    return "blockAddresses: " + addr;
  }
  const hit = (settings.blockDomains || []).find((d) => isUnderDomain(features.from.host, d));
  return hit ? "blockDomains: " + hit : null;
}

/**
 * 自アカウントのドメインを名乗る外部メールかどうかを特徴量に足す。
 * 認証が通っていれば自分が送ったメールの可能性があるので除外する。
 */
export function markSelfDomainSpoof(features, settings) {
  const selfDomains = settings.selfDomains || [];
  const spoof = selfDomains.some((d) => isUnderDomain(features.from.host, d)) &&
    features.auth.spf !== "pass" && features.auth.dkim !== "pass";
  return { ...features, selfDomainSpoof: spoof };
}

/**
 * ローカルルールを適用する。
 * @returns {{score:number, hits:Array<{id:string,label:string,weight:number}>}}
 */
export function scoreByRules(features) {
  const hits = [];
  let raw = 0;
  for (const rule of RULES) {
    let matched = false;
    try {
      matched = Boolean(rule.test(features));
    } catch (e) {
      matched = false;
    }
    if (!matched) continue;
    hits.push({ id: rule.id, label: rule.label, weight: rule.weight });
    raw += rule.weight;
  }
  return { score: Math.max(0, Math.min(100, raw)), hits };
}

export { RULES };
