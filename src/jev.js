/**
 * SpamGuard - Jev (TypeSafe System One) クライアント
 *
 * API: POST https://api.typesafe.ai/v1/systemone
 *      Authorization: Bearer <API_KEY>
 *
 * 独立した問いは1リクエストにまとめて並列評価させる。質問数を増やしても
 * レイテンシはほぼ変わらないため、迷惑メール判定を6つの小さな問いに分解し、
 * 重み付け合成はこちら側のコードで行う。
 */

/** Jevへ送るstateを特徴量から組み立てる */
export function buildState(features, bodyLimit) {
  const body = String(features.bodyText || "").replace(/\s+\n/g, "\n").slice(0, bodyLimit);
  return {
    from_display_name: features.from.display,
    from_address: features.from.address,
    from_domain: features.fromDomain,
    reply_to_address: features.replyTo.address,
    return_path_domain: features.returnPath.host,
    message_id_domain: features.messageIdDomain,
    list_unsubscribe_domains: features.listUnsubDomains,
    feedback_id: features.feedbackId,
    delivery_path_hosts: features.hops.slice(0, 12),
    subject: features.subject,
    body_excerpt: body,
    link_domains: features.linkDomains.slice(0, 20)
  };
}

/**
 * 質問セット。
 * 各問いは他の問いの答えを見られないので、前提は問いの中に書き切る。
 * id はコード側のキーであり、モデルには送られない。
 */
export const QUESTIONS = {
  sender_impersonation: {
    type: "noul",
    instructions:
      "差出人の表示名 `from_display_name` や件名 `subject` は特定の企業・官公庁・サービスを名乗っているが、" +
      "実際の送信ドメイン `from_domain` はその組織が実際に使うドメインではない。この記述は正しいか。",
    criteria: {
      true: "名乗っている組織と送信ドメインの所有者が明らかに別であり、組織を詐称している。",
      false: "組織を名乗っていない、または送信ドメインがその組織（もしくは正規の委託配信事業者）のものとして妥当である。"
    }
  },
  credential_phishing: {
    type: "noul",
    instructions:
      "本文 `body_excerpt` は、受信者にリンクを開かせて認証情報・個人情報・カード情報・支払い情報を入力させることを狙っているか。",
    criteria: {
      true: "ログイン、本人確認、支払い情報の更新、口座情報の入力などを誘導している。",
      false: "単なる案内・広告・通知であり、機微情報の入力を求めていない。"
    }
  },
  urgency_pressure: {
    type: "noul",
    instructions:
      "本文 `body_excerpt` は、期限・利用停止・法的措置・不正利用などを示して受信者に即座の行動を迫っているか。",
    criteria: {
      true: "行動しないと不利益が生じると示し、短い期限を切っている。",
      false: "期限や不利益による圧力はない、または通常の業務連絡の範囲。"
    }
  },
  link_domain_mismatch: {
    type: "noul",
    instructions:
      "本文中のリンク先ドメイン `link_domains` は、差出人が名乗っている組織の正規ドメインと異なるか。" +
      "組織を名乗っていない場合は false とする。",
    criteria: {
      true: "名乗っている組織とは無関係なドメインへ誘導している。",
      false: "組織を名乗っていない、またはリンク先がその組織の正規ドメイン（もしくは正規の計測・配信ドメイン）である。"
    }
  },
  /**
   * フィッシングの「口実の型」を判定する。
   *
   * 旧 bulk_delivery_path（配信経路が大量配信基盤らしいか）を置き換えたもの。
   * 実測では詐称型0.8 / 正規0.6 とほとんど差が出なかった。正規のメルマガも
   * 大量配信基盤を使うので、モデルの回答は正しく、問いの立て方が誤っていた。
   * 配信経路の構造的な矛盾はローカルルール側（consumerIspHop / unsubThirdParty /
   * messageIdMismatch）で見ているため、Jevには文面からしか分からない
   * 「どの手口で受信者を動かそうとしているか」を訊く。
   *
   * 選択肢は実測を経て9つに増やした。当初の5類型は「認証情報を盗む口実」に
   * 偏っており、60通での計測では**詐称型の28通が none** になっていた。
   * 取りこぼしていたのは次の3つで、いずれも実データに多数ある。
   *  - fake_transaction: 身に覚えのない取引通知を装うだけで何も要求しない型
   *    （「ご用命内訳をお確かめください」「お手続き状況をご照会ください」）
   *  - unsolicited_promotion: 単なる広告スパム（.click ドメインの「80% OFF」）
   *  - financial_offer: 融資・投資の勧誘
   *
   * 正規のメルマガも unsolicited_promotion に寄る可能性はあるが、
   * それらは ordinary_business_mail(-0.40) が強く立つので打ち消される。
   */
  phishing_pretext: {
    type: "choice",
    instructions:
      "件名 `subject` と本文 `body_excerpt` を読み、受信者を行動させるために使われている口実を選べ。" +
      "受信者が自分で購読・契約している事業者からの通常の連絡であれば none を選ぶこと。",
    criteria: {
      payment_problem:
        "支払いや請求に問題があるとして、カード情報や支払い方法の更新・確認を促している" +
        "（引き落とし失敗、料金未納、決済エラー、請求額の確認など）。",
      account_security:
        "アカウントの停止・制限・不正利用・本人確認を理由に、ログインや認証情報の入力を促している。",
      delivery_handling:
        "荷物の配送・再配達・通関・受け取り手続きを理由に、情報入力や手数料の支払いを促している。",
      benefit_expiry:
        "ポイント・マイル・クーポン・還付金・給付金が失効するとして、期限内の手続きを促している。",
      prize_campaign:
        "当選・抽選・限定特典を知らせて、受け取りのための登録や情報入力を促している。",
      fake_transaction:
        "受信者が申し込んだ覚えのない注文・手配・受領・納品などが進行中であるかのように知らせ、" +
        "内容確認のためにリンクを開かせようとしている。具体的な商品名や金額は書かれておらず、" +
        "「ご用命」「ご依頼内容」「お手続き状況」のように曖昧な言い回しで確認を促す。",
      unsolicited_promotion:
        "取引関係のない相手からの一方的な商品宣伝。大幅な割引率を前面に出して" +
        "購入サイトへ誘導するが、送信者が実在の事業者として特定できない。",
      financial_offer:
        "融資・投資・副業・高収入・借金解決などの金銭的な勧誘。",
      none:
        "上記のいずれにも当てはまらない。受信者が自分で購読・契約している事業者からの" +
        "通常の連絡や広告、あるいは個人間・業務上のやり取りであり、" +
        "行動を促すための口実が使われていない。"
    }
  },

  /**
   * 「ごく普通の商業メールらしさ」を測る減点材料。
   *
   * 旧 legitimate_transactional（実在の取引関係を示す固有情報があるか）を
   * 置き換えたもの。実測では詐称型0.1 / 正規0.2 とほぼ差が出なかった。
   * 理由は2つあり、(1) フィッシングは注文番号を捏造するので固有情報の有無では
   * 区別できず、(2) グレーゾーンに落ちる正規メールの大半は取引通知ではなく
   * メルマガで、そもそも注文番号を持たない。
   * そこで「取引の証拠」ではなく「事業内容そのものの具体性」を訊く。
   */
  ordinary_business_mail: {
    type: "noul",
    instructions:
      "このメールは、実在する事業者が自社の商品・サービス・コンテンツについて知らせる" +
      "通常のお知らせや広告か。受信者に手続きを迫るのではなく、情報提供や販促が主目的か。",
    criteria: {
      true:
        "作品名・商品名・イベント名・価格・日程・記事の内容など、その事業者の事業内容に" +
        "固有の具体的な情報が本文の中心を占めており、認証情報や支払い情報の入力を求めていない。",
      false:
        "手続きの催促・警告・確認要求が本文の中心であり、事業内容に固有の具体的な情報が" +
        "ほとんど含まれていない。"
    }
  }
};

const RETRYABLE_STATUS = new Set([408, 429, 500, 502, 503, 504, 529]);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Jevへ問い合わせる。
 * @param {object} state buildState() の戻り値
 * @param {object} settings 設定（jevApiKey / jevEndpoint / jevModel / jevTimeoutMs / jevMaxRetries）
 * @returns {Promise<{answers:object, usage:object, model:string}>}
 */
export async function askJev(state, settings) {
  if (!settings.jevApiKey) throw new Error("Jev APIキーが未設定です");

  const payload = {
    model: settings.jevModel,
    state,
    questions: QUESTIONS
  };

  let lastError = null;
  for (let attempt = 0; attempt <= settings.jevMaxRetries; attempt++) {
    // 2回目以降は指数バックオフ（ジッタ付き）
    if (attempt > 0) {
      await sleep(Math.min(8000, 500 * Math.pow(2, attempt)) + Math.random() * 250);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), settings.jevTimeoutMs);
    try {
      const res = await fetch(settings.jevEndpoint, {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + settings.jevApiKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      if (res.ok) return await res.json();

      const text = await res.text().catch(() => "");
      const err = new Error("Jev API " + res.status + ": " + text.slice(0, 300));
      err.status = res.status;
      // 401(キー誤り) や 422(リクエスト不正) は再試行しても直らない
      if (!RETRYABLE_STATUS.has(res.status)) throw err;
      lastError = err;
    } catch (e) {
      if (e.status && !RETRYABLE_STATUS.has(e.status)) throw e;
      // タイムアウト・ネットワーク断は再試行する
      lastError = e;
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError || new Error("Jev APIへの問い合わせに失敗しました");
}


/**
 * choice回答から「フィッシングの口実が使われている確率」を取り出す。
 * choice（最有力の1つ）だけを見ると、複数の型に確率が分散したときに
 * 取りこぼすため、none 以外に置かれた確率の合計を使う。
 */
function pretextProbability(answer) {
  const probs = answer && answer.probabilities;
  if (probs && typeof probs.none === "number") {
    return Math.max(0, Math.min(1, 1 - probs.none));
  }
  if (probs) {
    let sum = 0;
    for (const [key, value] of Object.entries(probs)) {
      if (key !== "none" && typeof value === "number") sum += value;
    }
    return Math.max(0, Math.min(1, sum));
  }
  // probabilities が返らない場合は choice で代用する
  if (answer && answer.choice) return answer.choice === "none" ? 0 : 1;
  return 0;
}

/**
 * Jevの回答を0-100のスパムスコアに合成する。
 * 重みはここに集約し、質問の意味が変わらない限り再問い合わせなしで調整できる。
 */
export function scoreFromJev(response) {
  const a = response?.answers || {};
  const noul = (key) => (typeof a[key]?.noul === "number" ? a[key].noul : 0);
  const pretext = pretextProbability(a.phishing_pretext);

  // 重みは実測の判別力（詐称型の平均 − 正規の平均）に合わせてある。
  // phishing_pretext は +0.85 で最も分離が良く、credential_phishing(+0.64) より強い。
  const positive =
    0.30 * noul("sender_impersonation") +
    0.26 * pretext +
    0.22 * noul("credential_phishing") +
    0.14 * noul("link_domain_mismatch") +
    0.08 * noul("urgency_pressure");

  const negative = 0.40 * noul("ordinary_business_mail");

  const value = Math.max(0, Math.min(1, positive - negative));
  return {
    score: Math.round(value * 100),
    detail: {
      sender_impersonation: noul("sender_impersonation"),
      credential_phishing: noul("credential_phishing"),
      phishing_pretext: pretext,
      link_domain_mismatch: noul("link_domain_mismatch"),
      urgency_pressure: noul("urgency_pressure"),
      ordinary_business_mail: noul("ordinary_business_mail")
    },
    // どの口実と判定されたかはログで見たいので別に持つ
    pretext: a.phishing_pretext?.choice || null,
    usage: response?.usage || null,
    model: response?.model || null
  };
}
