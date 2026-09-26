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
  },
  // --- 2026-09-26 の実運用ログの見逃し2件と、その対策で巻き込みやすい正規メール ---
  {
    name: "[回帰] 使い捨てドメイン（ラベルをバウンス先に流用・家庭用回線から直接送信）",
    expect: "spam",
    minScore: 55,
    msg: message({
      headers: {
        From: "カスタマーサポート <info@kjehuf.cn-dqsb.example>",
        Subject: "発注ご商品の納品用意が整いました",
        "Message-ID": "<179023699900.5182.205329042316088253@kjehuf.cn-dqsb.example>",
        "Return-Path": "<kjehuf@kjehuf.cn-dqsb.example>",
        "List-Unsubscribe": "<https://kjehuf.cn-dqsb.example/unsubscribe/abc>",
        Received: [
          "from kjehuf.cn-dqsb.example (kjehuf.cn-dqsb.example [34.138.61.164]) by mx-proxy.example.jp (Postfix)",
          "from [172.30.157.21] (c-69-180-237-15.hsd1.ga.comcast.net [69.180.237.15]) by kjehuf.cn-dqsb.example (Postfix)"
        ],
        "Authentication-Results": "spf=pass dkim=pass header.s=kjehuf dmarc=pass",
        "X-Spam-Status": "Yes"
      },
      html: '<html><body><p>ご注文の商品の発送準備が整いました。</p><a href="https://czdebang.example/order">注文内容詳細を確認する</a></body></html>'
    })
  },
  {
    name: "[回帰] 件名で e-Tax に言及し、無関係な第三者ドメインへ誘導（グレーゾーンへ送る）",
    expect: "spam",
    msg: message({
      headers: {
        From: "お知らせ <ea@li.frankmathroom.example>",
        Subject: "e-Tax還付金の受取手続について",
        "Message-ID": "<Mj7WdDUGQvOoUeKtUFTRKg@geopod-ismtpd-6>",
        "Return-Path": "<bounces+1-fei=example.jp@em7772.li.frankmathroom.example>",
        Received: ["from s.wfbtzhsv.outbound-mail.sendgrid.net by mtrg.example.jp"]
      },
      html: '<html><body><p>還付金が確定いたしました。受取口座情報のご確認をお願いいたします。</p><a href="https://zhenglizhushou.example/etax">確認する</a></body></html>'
    })
  },
  {
    name: "[回帰] 送信ホストとバウンス先が一般語で一致する正規配信（mail@mail.～）",
    expect: "ham",
    mustNotHit: ["senderLabelEcho"],
    msg: message({
      headers: {
        From: "Adobe <mail@mail.adobe.example>",
        Subject: "PDFをWordやPowerPointに変換して、すぐ編集",
        "Message-ID": "<k@mail.adobe.example>",
        "Return-Path": "<mail@mail.adobe.example>",
        Received: ["from mail.adobe.example by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass header.s=mail dmarc=pass"
      },
      html: '<html><body><p>新機能のご案内です。</p><a href="https://www.adobe.example/acrobat">詳細</a></body></html>'
    })
  },
  {
    name: "[回帰] 件名で他社に言及し、自社の兄弟ドメインへ誘導する正規メルマガ（pia.co.jp → pia.jp）",
    expect: "ham",
    mustNotHit: ["mentionThirdPartyLinks"],
    msg: message({
      headers: {
        From: "チケットぴあ <tmail@pia.co.jp>",
        Subject: "Amazonプライム・ビデオ配信記念 コンサートのお知らせ",
        "Message-ID": "<l@mail.pia-mailer.example>",
        "Return-Path": "<bounce@pia-mailer.example>",
        "List-Unsubscribe": "<https://mailer-service.example/u/abc>",
        Received: ["from mail.pia-mailer.example by mail3.example.jp"],
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass"
      },
      html: '<html><body><p>公演情報のご案内です。</p><a href="https://t.pia.jp/event/123">チケット情報</a></body></html>'
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
  // minScore: 見逃しの回帰検体で、グレーゾーンではなく即断まで届くことを確かめる
  // mustNotHit: 対策ルールが正規メールに立たないことを確かめる
  const unexpected = (sample.mustNotHit || []).filter((id) => hits.some((h) => h.id === id));
  const ok = (sample.expect === "spam" ? score >= (sample.minScore ?? s.grayLow) : score < s.spamThreshold) &&
    unexpected.length === 0;
  if (!ok) failures++;
  if (unexpected.length) console.log("      立ってはいけないルールが立った: " + unexpected.join(", "));

  console.log((ok ? "PASS" : "FAIL") + "  " + sample.name);
  console.log("      点数 " + score + " -> " + verdict + (gray ? " [Jevへ送る]" : " [ローカルで即断]"));
  console.log("      差出人ドメイン: " + (f.fromDomain || "-") + " / 詐称候補: " + (f.brands.join(",") || "なし"));
  for (const h of hits) console.log("      " + (h.weight > 0 ? "+" : "") + h.weight + "\t" + h.label);
  console.log("");
}

console.log(failures === 0 ? "すべて期待どおり" : failures + "件が期待と異なる");
process.exit(failures === 0 ? 0 : 1);
