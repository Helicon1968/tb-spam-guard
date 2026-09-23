/**
 * SpamGuard - ローカルルールの自己検証
 *
 * Thunderbirdを起動せずに、特徴量抽出とルール配点の妥当性を確認する。
 * 実行: node test/selftest.mjs （プロジェクトルートから）
 *
 * 検体は、実際の迷惑メールフォルダ約1000通と受信トレイ750通の分析で
 * 見つかった代表パターンを、内容を差し替えて再現したもの。
 * 実データで見つかった誤検出パターン（正規のメルマガ）も回帰確認として含む。
 *
 * 検体を追加するときは messages.getFull() と同じ形
 * （headers はすべて小文字キー・値は配列）でヘッダと本文を並べる。
 */

import { extractFeatures } from "../src/extract.js";
import { scoreByRules } from "../src/rules.js";
import { DEFAULT_SETTINGS } from "../src/config.js";

/** getFull 形式のメッセージを組み立てる補助 */
function message({ headers, plain, html }) {
  const parts = [];
  if (plain) parts.push({ contentType: "text/plain", body: plain, parts: [] });
  if (html) parts.push({ contentType: "text/html", body: html, parts: [] });
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = Array.isArray(v) ? v : [v];
  return { contentType: "multipart/alternative", headers: lower, parts };
}

const SAMPLES = [
  {
    name: "e-Tax詐称フィッシング（引き継ぎ書の実例に相当）",
    expect: "spam",
    msg: message({
      headers: {
        From: '"国税庁" <info@ad4ch8896b.naphtalileylandfields.com>',
        Subject: "【国税庁】メッセージボックスのご確認",
        "Message-ID": "<20260921093000.ABC123@docomo.ne.jp>",
        "Return-Path": "<bounce@mailer-xyz.example.net>",
        "List-Unsubscribe": "<https://track.thirdpartymktg.example/u/abc123>",
        Received: [
          "from softbank126077.ymobile.ne.jp (softbank126077.ymobile.ne.jp [126.77.0.1]) by mail3.example.jp",
          "by api.postfix-bulk.example.net with SMTP id XYZ"
        ],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: [
        "<html><body>",
        '<span style="display:none">Qz7kP2mR9xLv4Tn8Wb3Yc6Hd1Fg5Js0</span>',
        "<p>国税庁からのお知らせです。未納の税金が確認されました。</p>",
        "<p>本日中にお手続きがない場合、差押えの手続きに移行いたします。</p>",
        '<p><a href="https://ad4ch8896b.naphtalileylandfields.com/etax/login">こちらからご確認ください</a></p>',
        "</body></html>"
      ].join("\n")
    })
  },
  {
    name: "発音できないランダムドメインからのセゾン詐称（実データ頻出パターン）",
    expect: "spam",
    msg: message({
      headers: {
        From: '"株式会社クレディセゾン" <pzflsuiw@fshmjx.com>',
        Subject: "＜重要＞セゾンカード会員規約に基づくポイント失効に関する事前のご案内",
        "Message-ID": "<zz@fshmjx.com>",
        "Return-Path": "<b@fshmjx.com>",
        Received: ["from mail.fshmjx.com (mail.fshmjx.com [1.2.3.4]) by mail3.example.jp"],
        "Authentication-Results": "spf=softfail dkim=none dmarc=fail"
      },
      html: '<html><body><p>保有ポイントの有効期限が迫っています。失効前にご確認ください。</p><a href="https://fshmjx.com/saison/login">確認する</a></body></html>'
    })
  },
  {
    name: "件名に双方向制御文字を仕込んだANA詐称（実データ18通に該当）",
    expect: "spam",
    msg: message({
      headers: {
        From: '"\u202EブラクジーレイマANA\u202C" <info@sqfengyu.com>',
        Subject: "【最終通知】\u202EANAマイル失効まであとわずか｜8月27日までにお手続きください",
        "Message-ID": "<a@sqfengyu.com>",
        "Return-Path": "<a@sqfengyu.com>",
        Received: ["from mail.sqfengyu.com by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: '<html><body><p>マイルの有効期限が迫っています。</p><a href="https://sqfengyu.com/ana/">手続きはこちら</a></body></html>'
    })
  },
  {
    name: "無料メールから表示名にアドレスを置いた宣伝（実データ86通に該当）",
    expect: "spam",
    msg: message({
      headers: {
        From: '"xavlhafdqotqd@outlook.com" <xavlhafdqotqd@outlook.com>',
        Subject: "今すぐLINE登録で特別クーポン進呈",
        "Message-ID": "<b@mailer99.example.net>",
        "Return-Path": "<bounce@mailer99.example.net>",
        "Reply-To": "<reply@another-domain.example>",
        Received: ["from mailer99.example.net by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: '<html><body><p>LINE友だち追加で超特価クーポンGET</p><a href="https://promo-site.example/lp">登録する</a></body></html>'
    })
  },
  {
    name: "濫用TLDからのAmazon Prime詐称",
    expect: "spam",
    msg: message({
      headers: {
        From: '"Amazon" <tgkpzqmv@arhrzgh.cn>',
        Subject: "お支払いに関する問題により、プライムの特典はご利用いただけません",
        "Message-ID": "<c@arhrzgh.cn>",
        "Return-Path": "<c@arhrzgh.cn>",
        Received: ["from arhrzgh.cn by mail3.example.jp"],
        "Authentication-Results": "spf=none dkim=none dmarc=none"
      },
      html: '<html><body><p>お支払い方法の情報を更新してください。24時間以内に手続きがない場合、アカウントが停止されます。</p><a href="https://arhrzgh.cn/ap/signin">今すぐ確認</a></body></html>'
    })
  },
  {
    name: "Vpassのタイポスクワット（実データにあった vpassard.co.jp 型）",
    expect: "spam",
    msg: message({
      headers: {
        From: '"三井住友カード" <info@vpassard.co.jp>',
        Subject: "【Vpass】カード情報の確認手続きのご案内",
        "Message-ID": "<d@mailer.example.org>",
        "Return-Path": "<d@bounce.example.org>",
        Received: ["from mailer.example.org by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: '<html><body><p>本人確認のためカード情報の再認証をお願いします。</p><a href="https://vpassard.co.jp/login">Vpassへログイン</a></body></html>'
    })
  },

  // --- 以下は正常系。実データで誤検出していたパターンの回帰確認 ---
  {
    name: "[回帰] 本物のPayPayカード利用速報（辞書に正規ドメインが無いと誤検出した）",
    expect: "ham",
    msg: message({
      headers: {
        From: "PayPayカード <paypaycard-info@mail.paypay-card.co.jp>",
        Subject: "PayPayカード（JCB）利用速報",
        "Message-ID": "<e@mail.paypay-card.co.jp>",
        "Return-Path": "<bounce@mail.paypay-card.co.jp>",
        Received: ["from mail.paypay-card.co.jp by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      plain: "ご利用内容をお知らせします。\nご利用金額 3,200円"
    })
  },
  {
    name: "[回帰] 本物の映画メルマガ（ESPのプリヘッダ隠し文字で誤検出した）",
    expect: "ham",
    msg: message({
      headers: {
        From: "MOVIE WALKER PRESS <info@moviewalker.jp>",
        Subject: "最新映画のムビチケ前売券が販売中！",
        "Message-ID": "<f@esp-delivery.example.net>",
        "Return-Path": "<bounce@esp-delivery.example.net>",
        "List-Unsubscribe": "<https://esp-delivery.example.net/u/xyz>",
        Received: ["from esp-delivery.example.net by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: '<html><body><div style="display:none">MW20260921ABCDEFGH12345678</div><p>今週の新作情報をお届けします。</p><a href="https://moviewalker.jp/news/">記事を読む</a></body></html>'
    })
  },
  {
    name: "[回帰] ジャン＝ポール・エヴァンのメルマガ（\"au\" が \"Paul\" に当たって誤検出した）",
    expect: "ham",
    msg: message({
      headers: {
        From: "JEAN-PAUL HEVIN <news@jph-japon.co.jp>",
        Subject: "【ジャン＝ポール・エヴァン ニュースレター】敬老の日に、秋の味覚を",
        "Message-ID": "<g@jph-japon.co.jp>",
        "Return-Path": "<bounce@jph-japon.co.jp>",
        Received: ["from mail.jph-japon.co.jp by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: '<html><body><p>秋の新作をご紹介します。</p><a href="https://jph-japon.co.jp/shop/">オンラインショップ</a></body></html>'
    })
  },
  {
    name: '[回帰] ドメイン取得サービスの案内（".online" が "line" に当たって誤検出した）',
    expect: "ham",
    msg: message({
      headers: {
        From: "ムームードメイン <info@muumuu-domain.com>",
        Subject: "対象ドメインの取得・更新をすると、「.online」「.site」ドメインが特価",
        "Message-ID": "<h@muumuu-domain.com>",
        "Return-Path": "<bounce@muumuu-domain.com>",
        Received: ["from mail.muumuu-domain.com by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: '<html><body><p>キャンペーンのお知らせです。</p><a href="https://muumuu-domain.com/campaign/">詳細</a></body></html>'
    })
  },
  {
    name: "正規のAmazon注文確認",
    expect: "ham",
    msg: message({
      headers: {
        From: "Amazon.co.jp <order-update@amazon.co.jp>",
        Subject: "Amazon.co.jp ご注文の発送のお知らせ",
        "Message-ID": "<i@amazon.co.jp>",
        "Return-Path": "<bounce@amazon.co.jp>",
        Received: ["from mx.amazon.co.jp by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      plain: "ご注文番号 249-1234567-1234567 の商品を発送しました。\nお届け予定日: 9月23日"
    })
  },
  {
    name: "取引先からの普通の業務メール",
    expect: "ham",
    msg: message({
      headers: {
        From: "山田太郎 <yamada@example-corp.co.jp>",
        Subject: "見積書送付の件",
        "Message-ID": "<j@example-corp.co.jp>",
        "Return-Path": "<yamada@example-corp.co.jp>",
        Received: ["from mail.example-corp.co.jp by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      plain: "お世話になっております。\n先日ご依頼いただいた見積書を添付いたします。"
    })
  }
];

const s = DEFAULT_SETTINGS;
let failures = 0;

console.log("しきい値: spam>=" + s.spamThreshold + " / グレーゾーン " + s.grayLow + "-" + s.grayHigh + "\n");

for (const sample of SAMPLES) {
  const f = extractFeatures(sample.msg);
  const { score, hits } = scoreByRules({ ...f, selfDomainSpoof: false });

  const verdict = score >= s.spamThreshold ? "spam" : score >= s.grayLow ? "suspect(要Jev)" : "ham";
  const gray = score >= s.grayLow && score < s.grayHigh;
  // spam検体: 最低でもグレーゾーンに入り、Jevへ回るか即断されること
  // ham検体 : 迷惑と判定されないこと。グレーゾーンに入るのは設計どおりで、
  //           そこはJevの legitimate_transactional で救う想定
  const ok = sample.expect === "spam" ? score >= s.grayLow : score < s.spamThreshold;
  if (!ok) failures++;

  console.log((ok ? "PASS" : "FAIL") + "  " + sample.name);
  console.log("      点数 " + score + " -> " + verdict + (gray ? " [Jevへ送る]" : " [ローカルで即断]"));
  console.log("      差出人ドメイン: " + (f.fromDomain || "-") + " / 詐称候補: " + (f.brands.join(",") || "なし"));
  for (const h of hits) console.log("      " + (h.weight > 0 ? "+" : "") + h.weight + "\t" + h.label);
  console.log("");
}

console.log(failures === 0 ? "すべて期待どおり" : failures + "件が期待と異なる");
process.exit(failures === 0 ? 0 : 1);
