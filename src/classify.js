/**
 * SpamGuard - 判定パイプライン
 *
 * ローカルルール -> （必要なら）Jev -> 合成 という段階構成にする。
 * 100通/日規模でも、白黒がはっきりした大半はローカルで即断できるため
 * 外部API呼び出しはグレーゾーンに絞られる。
 */

import { extractFeatures } from "./extract.js";
import { markSelfDomainSpoof, matchAllowList, matchBlockList, scoreByRules } from "./rules.js";
import { askJev, buildState, scoreFromJev } from "./jev.js";

export const VERDICT = {
  SPAM: "spam",
  SUSPECT: "suspect",
  HAM: "ham"
};

/** 判定根拠の経路 */
export const PATH = {
  ALLOWLIST: "allowlist",
  BLOCKLIST: "blocklist",
  RULES_ONLY: "rules",
  RULES_AND_JEV: "rules+jev",
  JEV_FAILED: "rules(jev失敗)"
};

/**
 * メッセージ1通を判定する。
 * @param {number} messageId
 * @param {object} settings loadSettings() の戻り値
 * @returns {Promise<object>} 判定結果レコード
 */
export async function classifyMessage(messageId, settings) {
  const meta = await browser.messages.get(messageId);
  const full = await browser.messages.getFull(messageId);
  const features = markSelfDomainSpoof(extractFeatures(full, meta), settings);

  const base = {
    messageId,
    // Thunderbird標準の迷惑フィルタが先にメールを移動すると messageId が無効になる。
    // そのとき Message-ID で探し直せるよう持っておく。
    headerMessageId: meta.headerMessageId || "",
    date: (meta.date instanceof Date ? meta.date : new Date()).toISOString(),
    author: meta.author || features.from.address,
    subject: features.subject,
    fromDomain: features.fromDomain,
    brands: features.brands
  };

  // 1. 許可リストは無条件で通す（拒否リストより優先）
  const allowed = matchAllowList(features, settings);
  if (allowed) {
    return { ...base, verdict: VERDICT.HAM, score: 0, path: PATH.ALLOWLIST, reason: allowed, ruleHits: [], jev: null };
  }

  // 2. 拒否リストは無条件で迷惑扱い（読みたくない正規メルマガ用）
  const blocked = matchBlockList(features, settings);
  if (blocked) {
    return { ...base, verdict: VERDICT.SPAM, score: 100, path: PATH.BLOCKLIST, reason: blocked, ruleHits: [], jev: null };
  }

  // 3. ローカルルール
  const local = scoreByRules(features);

  // 4. グレーゾーンのみJevへ
  const inGrayZone = local.score >= settings.grayLow && local.score < settings.grayHigh;
  const useJev = settings.jevEnabled && Boolean(settings.jevApiKey) && inGrayZone;

  let finalScore = local.score;
  let path = PATH.RULES_ONLY;
  let jev = null;
  let error = null;

  if (useJev) {
    try {
      const response = await askJev(buildState(features, settings.jevBodyLimit), settings);
      jev = scoreFromJev(response);
      const wl = settings.weightLocal;
      const wj = settings.weightJev;
      const sum = wl + wj || 1;
      const blended = Math.round((wl * local.score + wj * jev.score) / sum);

      /*
       * Jevが点を「下げる」のは、積極的に正規メールだと判断したときだけに限る。
       *
       * Jevが見るのは文面だけなので、短い宣伝文のように文面が無害なスパムには
       * 何も言えず低い点を返す。それをそのまま合成すると、ヘッダ構造から
       * ローカルが付けた点を覆して見逃しになる
       * （実運用で BLACKCAS 系スパムがローカル60→Jev20→合成32で漏れた）。
       *
       * 「フィッシングの証拠が無い」ことと「正規メールである」ことは別なので、
       * ordinary_business_mail が積極的に立っているときだけ引き下げを認める。
       */
      const saysOrdinary = jev.detail && jev.detail.ordinary_business_mail >= 0.5;
      finalScore = (blended < local.score && !saysOrdinary) ? local.score : blended;
      path = PATH.RULES_AND_JEV;
    } catch (e) {
      error = String(e && e.message ? e.message : e);
      path = PATH.JEV_FAILED;
    }
  }

  const verdict =
    finalScore >= settings.spamThreshold ? VERDICT.SPAM :
    finalScore >= settings.grayLow ? VERDICT.SUSPECT :
    VERDICT.HAM;

  return {
    ...base,
    verdict,
    score: finalScore,
    localScore: local.score,
    jevScore: jev ? jev.score : null,
    path,
    ruleHits: local.hits,
    jev,
    error,
    evidence: {
      randomFromHost: features.randomFromHost,
      hiddenRandomText: features.hiddenRandomText,
      consumerIspHops: features.consumerIspHops,
      messageIdDomain: features.messageIdDomain,
      listUnsubDomains: features.listUnsubDomains,
      foreignLinkDomains: features.foreignLinkDomains.slice(0, 10),
      brandForeignLinkDomains: features.brandForeignLinkDomains.slice(0, 10),
      urgencyHits: features.urgencyHits.slice(0, 10)
    }
  };
}
