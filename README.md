# SpamGuard – AI-assisted Phishing Filter

Thunderbird 用のフィッシング・迷惑メール判定アドオンです。**TypeSafe の Jev（System One）に対応**しています。

> 本アドオンは個人が開発した非公式のツールで、TypeSafe AI, Inc. の公式製品ではありません。
> Jev は TypeSafe AI, Inc. の製品です。

> **English summary** — A Thunderbird MailExtension (Manifest V3, Thunderbird 128+) that flags
> phishing mail impersonating Japanese organizations (National Tax Agency / e-Tax, card companies,
> banks, e-commerce). It scores each incoming message with language-independent header rules
> (display-name vs. sender-domain mismatch, invisible characters, random domains, SPF/DMARC fail, etc.)
> and, only for borderline messages, optionally asks the TypeSafe System One API ("Jev") for a
> second opinion. It works with POP accounts and needs no server-side filtering.
> UI and documentation are in Japanese. Not affiliated with or endorsed by TypeSafe AI, Inc.

国税庁（e-Tax）・カード会社・銀行・通販サイトなどを騙るフィッシングメールに、
タグと迷惑マークを付ける Thunderbird 拡張機能です。

Thunderbird 標準の迷惑メールフィルタ（ベイズ学習）は文面で判断するため、
正規メールの文面を丸写しした詐称メールを止められません。
SpamGuard は文面ではなく **ヘッダの構造の矛盾** を見ます。
「表示名は国税庁なのに送信ドメインが無関係」「件名に不可視文字が仕込まれている」といった点です。

## 特徴

- **POP でも使える。** 受信した Thunderbird の中で判定するので、サーバ側のフィルタや IMAP は要りません。
- **外部送信なしで動く。** 既定はローカルルールだけで判定し、メールを外に出しません。
- **迷いどころだけ AI に聞く（任意）。** 点数がグレーゾーンに入ったメールだけを
  TypeSafe System One（Jev）に問い合わせます。作者の環境では受信トレイの約7%でした。
- **判定の根拠が残る。** どのルールが何点付けたかを判定ログに記録し、CSV で書き出せます。
- **右クリックで後追い判定。** 受信済みのメールも、選択して「SpamGuard → このメールを判定」で判定できます。

## 精度（作者の環境での実測値）

| 項目 | 値 |
| --- | --- |
| 詐称型フィッシングの検出率（ローカルルールのみ） | 66.5%（1432通中951通） |
| 同上（Jev 併用・想定） | 約71% |
| 受信トレイの誤検出 | 0.14%（1476通中2通） |

作者1人の受信データで測った値です。受信するメールの傾向が違えば数字も変わります。
迷惑メールフォルダには「詐称ではない不要なメルマガ」も混ざっていますが、それは母数から除いています。
不要なメルマガは内容では判定できないため、拒否リストで差出人を指定してください。

## 動作要件

- Thunderbird 128 以降（確認環境: 153.2.0 / Windows 10）
- Jev を使う場合のみ、TypeSafe の API キー（有料）。キーは利用者がそれぞれ TypeSafe と契約して取得してください

## インストール

1. [Releases](../../releases) から `tb-spam-guard-<バージョン>.xpi` をダウンロードします。
2. 未署名のアドオンなので、Thunderbird の `about:config`（設定 → 一般 → 設定エディター）で
   `xpinstall.signatures.required` を `false` にします。
3. アドオンマネージャ → 歯車アイコン → 「ファイルからアドオンをインストール」で xpi を選びます。

最初の数日は「判定後の動作」を「タグを付ける」のままにして、誤検出がないか判定ログで確かめてください。
段階的な導入手順は [SETUP.md](SETUP.md) の §3 にあります。

## プライバシー

- **Jev を無効にしている間（既定）、メールの内容は一切外部に送信されません。**
- Jev を有効にすると、グレーゾーンに入ったメールの件名・差出人情報・本文の先頭1500文字が
  `https://api.typesafe.ai/` に送信されます。業務メールを扱う場合は注意してください。
- API キーは Thunderbird のプロファイル内（`storage.local`）に平文で保存されます。
- 要求する権限は、メールの読み取り・更新・移動、タグ操作、アカウント情報の読み取りです。
  メールを送信する権限は要求しません。

## ドキュメント

- [SETUP.md](SETUP.md) — 導入手順、判定ロジックと配点、設定項目、ログの読み方、既知の制約

## 開発

ビルドとテストに Node.js が要ります（確認環境 v24）。外部パッケージは使いません。

```bash
node test/selftest.mjs   # Thunderbird なしでルールを検証
node tools/build.mjs     # dist/ に xpi を出力
```

開発中は Thunderbird の「ツール → 開発者ツール → アドオンのデバッグ →
一時的なアドオンを読み込む」で `manifest.json` を選ぶと、ビルドせずに試せます。

`tools/` には、手元の mbox を直接読んで精度を測るツールがあります（`analyze-mbox.mjs` ほか）。
使い方は各ファイルの先頭コメントを見てください。

## ライセンス

[MIT](LICENSE)

本アドオンは TypeSafe AI, Inc. とは無関係の個人プロジェクトです。
Jev の利用には、利用者と TypeSafe との契約（Master Customer Agreement など）が適用されます。
