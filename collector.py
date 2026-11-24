"""주식 맞춤 뉴스 수집기.

사용법:
  python collector.py collect   # 뉴스만 새로 모으기 (대시보드용)
  python collector.py urgent    # 모으고 + 긴급 뉴스만 푸시 (장중 매시)
  python collector.py morning   # 07:30 아침 브리핑 (간밤 이슈 포함)
  python collector.py close     # 15:40 장 마감 정리
  python collector.py us        # 22:00 미국장 개장 전 점검
  python collector.py weekend   # 주말 아침 요약

뉴스는 구글 뉴스 검색(RSS)에서 가져옵니다. 매수·매도 권유는 하지 않습니다.
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

BASE = Path(__file__).parent
KST = timezone(timedelta(hours=9))

# ---------- 분류용 단어 ----------
POS = ["급등", "상승", "호실적", "흑자", "수주", "계약 체결", "승인", "사상 최대", "최대 실적", "돌파", "신고가",
       "개선", "확대", "목표가 상향", "투자 유치", "성장", "반등", "호재", "강세", "흑자전환", "기대",
       "surge", "soar", "jump", "rally", "beat", "record", "upgrade", "wins", "contract", "approval",
       "growth", "rises", "gains", "bullish", "partnership", "raises", "outperform", "breakthrough"]
NEG = ["급락", "하락", "적자", "손실", "부진", "우려", "리스크", "소송", "철회", "하향", "감소", "약세", "폭락",
       "취소", "제재", "조사", "리콜", "지연", "악화", "쇼크", "경고",
       "plunge", "fall", "drop", "slump", "miss", "downgrade", "lawsuit", "probe", "investigation", "cut",
       "decline", "layoff", "recall", "bearish", "delay", "warns", "sinks", "tumble", "short seller", "selloff"]

# 위험 신호: (단어, 설명, 초대형 여부)
RISK = [
    ("상장폐지", "상장폐지", True), ("상장 폐지", "상장폐지", True), ("상장적격성", "상장적격성 심사", False),
    ("거래정지", "거래정지", True), ("매매거래정지", "거래정지", True), ("매매정지", "거래정지", True),
    ("관리종목", "관리종목", False), ("투자주의환기", "투자주의환기종목", False),
    ("감사의견 거절", "감사의견 거절", False), ("의견거절", "감사의견 거절", False), ("감사의견 한정", "감사의견 한정", False),
    ("자본잠식", "자본잠식", False), ("횡령", "횡령", False), ("배임", "배임", False),
    ("불성실공시", "불성실공시", False), ("회생절차", "회생절차", False), ("부도", "부도", False),
    ("유상증자", "유상증자", False), ("전환사채", "전환사채(CB)", False), ("신주인수권부사채", "신주인수권부사채", False),
    ("어닝쇼크", "실적 쇼크", False), ("영업손실", "영업손실", False), ("적자전환", "적자 전환", False),
    ("실적 급락", "실적 급락", False),
    ("delisting", "상장폐지", True), ("delisted", "상장폐지", True), ("trading halt", "거래정지", True),
    ("trading suspended", "거래정지", True), ("going concern", "계속기업 불확실", False),
    ("bankruptcy", "파산", False), ("chapter 11", "파산", False), ("sec charges", "SEC 기소", False),
    ("fraud", "사기 의혹", False), ("nasdaq deficiency", "나스닥 요건 미달", False),
    ("minimum bid", "나스닥 최저가 요건 미달", False), ("reverse split", "주식병합", False),
    ("dilution", "주식 희석", False), ("convertible notes", "전환사채", False),
    ("restatement", "재무제표 정정", False), ("auditor resign", "감사인 사임", False),
]
RISK_SOFTENERS = ["해제", "재개", "해소", "취소", "벗어", "lifted", "resume", "regain", "cured"]


def now():
    return datetime.now(KST)


CI = bool(os.environ.get("GITHUB_ACTIONS"))
def _env(k):
    return os.environ.get(k, "").replace("﻿", "").strip()


PASSWORD = _env("DATA_PASSWORD")
DEFAULT_CFG = {"ntfy_topic": "", "야간_시작": 23, "야간_끝": 7, "야간_초대형_예외_허용": True,
               "뉴스_최대_보관_시간": 96, "종목당_최대_뉴스": 12, "대시보드_주소": ""}


def encrypt(obj):
    """암호(PBKDF2) → AES-GCM. 브라우저(WebCrypto)에서 같은 방식으로 풉니다."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, iv = os.urandom(16), os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, 200000, 32)
    ct = AESGCM(key).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode("utf-8"), None)
    b = lambda x: base64.b64encode(x).decode()
    return {"v": 1, "salt": b(salt), "iv": b(iv), "ct": b(ct)}


def decrypt(blob):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    d = lambda x: base64.b64decode(x)
    key = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), d(blob["salt"]), 200000, 32)
    return json.loads(AESGCM(key).decrypt(d(blob["iv"]), d(blob["ct"]), None).decode("utf-8"))


def load_cfg():
    cfg = dict(DEFAULT_CFG)
    p = BASE / "config.json"
    if p.exists():
        cfg.update(json.loads(p.read_text(encoding="utf-8-sig")))
    if _env("NTFY_TOPIC"):
        cfg["ntfy_topic"] = _env("NTFY_TOPIC")
    if _env("DASHBOARD_URL"):
        cfg["대시보드_주소"] = _env("DASHBOARD_URL")
    return cfg


def load_stocks():
    if _env("STOCKS_JSON"):
        return json.loads(_env("STOCKS_JSON"))
    return json.loads((BASE / "stocks.json").read_text(encoding="utf-8-sig"))


def load_state():
    p = BASE / ("state.enc.json" if PASSWORD else "state.json")
    if not p.exists():
        return {}
    blob = json.loads(p.read_text(encoding="utf-8"))
    return decrypt(blob) if PASSWORD else blob


def save_state(state, before):
    if state == before:
        return  # 바뀐 게 없으면 다시 쓰지 않음 (불필요한 저장 방지)
    p = BASE / ("state.enc.json" if PASSWORD else "state.json")
    p.write_text(json.dumps(encrypt(state) if PASSWORD else state, ensure_ascii=False), encoding="utf-8")


# ---------- 수집 ----------
def fetch_rss(query, lang, days):
    q = f"{query} when:{days}d"
    if lang == "ko":
        url = "https://news.google.com/rss/search?q=%s&hl=ko&gl=KR&ceid=KR:ko" % urllib.parse.quote(q)
    else:
        url = "https://news.google.com/rss/search?q=%s&hl=en-US&gl=US&ceid=US:en" % urllib.parse.quote(q)
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                root = ET.fromstring(r.read())
            break
        except Exception:
            time.sleep(1.5)
    else:
        return []
    items = []
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        pub = it.findtext("pubDate")
        src_el = it.find("source")
        source = src_el.text if src_el is not None and src_el.text else ""
        if source and title.endswith(" - " + source):
            title = title[: -len(source) - 3]
        try:
            ts = parsedate_to_datetime(pub).astimezone(KST)
        except Exception:
            continue
        items.append({"title": title, "link": link, "source": source, "time": ts})
    return items


def classify(title):
    low = title.lower()
    pos = sum(1 for w in POS if w.lower() in low)
    neg = sum(1 for w in NEG if w.lower() in low)
    sentiment = "긍정" if pos > neg else "부정" if neg > pos else "중립"
    risks, mega = [], False
    soft = any(w.lower() in low for w in RISK_SOFTENERS)
    for word, label, big in RISK:
        if word.lower() in low and label not in risks:
            risks.append(label)
            if big and not soft:
                mega = True
    if risks and soft:  # "거래정지 해제" 같은 해소 기사는 위험 표시를 약하게
        return sentiment, [], False, risks
    return sentiment, risks, mega, []


def collect_stock(stock, cfg):
    days = max(1, int(cfg["뉴스_최대_보관_시간"] / 24))
    cutoff = now() - timedelta(hours=cfg["뉴스_최대_보관_시간"])
    seen, out = set(), []
    for kw in stock["keywords"]:
        for it in fetch_rss(kw, stock["lang"], days):
            key = re.sub(r"\W+", "", it["title"])[:40]
            if key in seen or it["time"] < cutoff:
                continue
            seen.add(key)
            sent, risks, mega, softened = classify(it["title"])
            out.append({
                "title": it["title"], "link": it["link"], "source": it["source"],
                "time": it["time"].isoformat(timespec="minutes"),
                "sentiment": sent, "urgent": bool(risks), "risks": risks, "mega": mega,
            })
    out.sort(key=lambda a: a["time"], reverse=True)
    return out[: cfg["종목당_최대_뉴스"]]


def summarize(stock, articles, threshold):
    t = now()
    day_series = {}
    for i in range(5):
        d = (t - timedelta(days=4 - i)).strftime("%m-%d")
        day_series[d] = {"긍정": 0, "부정": 0, "중립": 0}
    for a in articles:
        d = a["time"][5:10]
        if d in day_series:
            day_series[d][a["sentiment"]] += 1
    pos = sum(1 for a in articles if a["sentiment"] == "긍정")
    neg = sum(1 for a in articles if a["sentiment"] == "부정")
    last24 = [a for a in articles if datetime.fromisoformat(a["time"]) > t - timedelta(hours=24)]
    last48 = [a for a in articles if datetime.fromisoformat(a["time"]) > t - timedelta(hours=48)]
    risk_reasons = sorted({r for a in articles if a["urgent"] for r in a["risks"]})
    if risk_reasons:
        risk = "위험"
    elif neg >= 3 and neg >= 2 * max(pos, 1):
        risk = "주의"
    else:
        risk = "보통"
    pnl = stock.get("사진기준_수익률")
    undervalued = pnl is not None and pnl <= threshold
    # 호재 누적: 최신 뉴스 중 긍정/부정만 보고, 최근 3건이 모두 긍정
    signal = [a for a in articles if a["sentiment"] != "중립"][:3]
    rising = undervalued and len(signal) == 3 and all(a["sentiment"] == "긍정" for a in signal)
    return {
        "name": stock["name"], "market": stock["market"], "ticker": stock["ticker"],
        "pnl": pnl, "value": stock.get("사진기준_평가금액"), "check": stock.get("확인필요"),
        "count": len(articles), "count24": len(last24), "pos": pos, "neg": neg, "neu": len(articles) - pos - neg,
        "risk": risk, "risk_reasons": risk_reasons, "rising": rising, "undervalued": undervalued,
        "quiet": len(last48) == 0, "last_time": articles[0]["time"] if articles else None,
        "series": day_series, "news": articles,
    }


def collect_issues(stocks_cfg, cfg):
    issues = []
    days = max(1, int(cfg["뉴스_최대_보관_시간"] / 24))
    cutoff = now() - timedelta(hours=cfg["뉴스_최대_보관_시간"])
    all_names = [s["name"] for s in stocks_cfg["stocks"]]
    for g in stocks_cfg["산업_세계이슈_검색어"]:
        if g["관련"] == "전체":
            related = all_names
        elif g["관련"] == "해외":
            related = [s["name"] for s in stocks_cfg["stocks"] if s["market"] == "해외"]
        else:
            related = g["관련"]
        for it in fetch_rss(g["검색어"], "ko", days)[:6]:
            if it["time"] < cutoff:
                continue
            sent, risks, mega, _ = classify(it["title"])
            issues.append({"group": g["이름"], "title": it["title"], "link": it["link"], "source": it["source"],
                           "time": it["time"].isoformat(timespec="minutes"), "sentiment": sent,
                           "related": related})
    issues.sort(key=lambda a: a["time"], reverse=True)
    return issues


# ---------- 푸시 ----------
def in_night(cfg, t=None):
    h = (t or now()).hour
    s, e = cfg["야간_시작"], cfg["야간_끝"]
    return h >= s or h < e


def push(cfg, title, message, urgent=False, priority=None):
    topic = cfg.get("ntfy_topic", "").strip()
    if not CI:  # 공개 저장소의 실행 기록에는 종목 내용을 남기지 않음
        print(f"\n[푸시{'(긴급)' if urgent else ''}] {title}\n{message}\n")
    if not topic:
        return False
    body = {"topic": topic, "title": title, "message": message, "priority": priority or (5 if urgent else 4),
            "tags": ["rotating_light"] if urgent else ["newspaper"]}
    if cfg.get("대시보드_주소"):
        body["click"] = cfg["대시보드_주소"]
    try:
        req = urllib.request.Request("https://ntfy.sh/", data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=20).read()
        return True
    except Exception as e:
        print("푸시 실패:", type(e).__name__)
        return False


def article_id(name, a):
    raw = name + "|" + re.sub(r"\W+", "", a["title"])[:40]
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def lines_for(summaries, only_new_ids=None, limit=8):
    lines = []
    for s in summaries:
        for a in s["news"]:
            if only_new_ids is not None and article_id(s["name"], a) not in only_new_ids:
                continue
            mark = {"긍정": "▲", "부정": "▼", "중립": "·"}[a["sentiment"]]
            lines.append((a["time"], f"{mark} [{s['name']}] {a['title']}"))
    lines.sort(reverse=True)
    return [l for _, l in lines[:limit]]


def run_push(mode, cfg, summaries, issues, state):
    pushed = set(state.get("pushed", []))
    held = state.get("held", [])  # 야간에 쌓인 알림
    t = now()
    night = in_night(cfg, t)
    new_urgent = []
    for s in summaries:
        for a in s["news"]:
            aid = article_id(s["name"], a)
            if a["urgent"] and aid not in pushed:
                new_urgent.append((s, a, aid))

    def urgent_text(s, a):
        return f"⚠️ [{s['name']}] {' / '.join(a['risks'])}\n{a['title']} ({a['time'][5:16].replace('T', ' ')})"

    if mode in ("urgent", "digest", "us", "close", "morning", "weekend"):
        for s, a, aid in new_urgent:
            if night and not (cfg["야간_초대형_예외_허용"] and a["mega"]):
                held.append(urgent_text(s, a))  # 아침 브리핑에 "간밤 이슈"로
                pushed.add(aid)
                continue
            push(cfg, f"긴급: {s['name']} 위험 신호", urgent_text(s, a), urgent=True)
            pushed.add(aid)

    if mode == "digest":
        if night:
            state["pushed"] = sorted(pushed)[-2000:]
            state["held"] = held
            return
        notified = set(state.get("notified", []))
        rank = {"위험": 0, "주의": 1, "보통": 2}
        rows, new_ids = [], []
        for s in sorted(summaries, key=lambda x: rank[x["risk"]]):
            for a in s["news"]:
                aid = article_id(s["name"], a)
                if aid in notified or aid in pushed:
                    continue
                new_ids.append(aid)
                mark = {"긍정": "▲", "부정": "▼", "중립": "·"}[a["sentiment"]]
                hhmm = a["time"][5:16].replace("T", " ")
                rows.append(f"{mark} [{s['name']}] {a['title']} ({hhmm})")
        parts = []
        had_held = bool(held)
        if held:
            parts.append("🌙 간밤 이슈\n" + "\n".join(held[:8]))
            held = []
        if rows:
            shown = rows[:15]
            extra = len(rows) - len(shown)
            parts.append("📰 새 뉴스\n" + "\n".join(shown) + (f"\n…외 {extra}건 (화면에서 확인)" if extra else ""))
        issue_new = []
        for i in issues:
            iid = hashlib.sha1(("issue|" + i["title"]).encode("utf-8")).hexdigest()[:16]
            if iid not in notified:
                new_ids.append(iid)
                issue_new.append(f"· {i['title']}")
        if issue_new:
            parts.append("🌍 세계·산업 이슈\n" + "\n".join(issue_new[:3]))
        if rows or had_held:
            title = f"새 뉴스 {len(rows)}건 · {t.strftime('%H:%M')} 기준"
            push(cfg, title, "\n\n".join(parts)[:3500], priority=4)
        notified.update(new_ids)
        state["notified"] = sorted(notified)[-4000:]
        state["pushed"] = sorted(pushed)[-2000:]
        state["held"] = held
        return

    if mode == "morning" or mode == "weekend":
        parts = []
        if held:
            parts.append("🌙 간밤 이슈\n" + "\n".join(held[:8]))
            held = []
        risky = [s["name"] for s in summaries if s["risk"] == "위험"]
        if risky:
            parts.append("🚨 위험 표시 종목: " + ", ".join(risky))
        rising = [s["name"] for s in summaries if s["rising"]]
        if rising:
            parts.append("📈 호재 증가 중: " + ", ".join(rising))
        top = lines_for(summaries, limit=8)
        if top:
            parts.append("📰 주요 뉴스\n" + "\n".join(top))
        if issues:
            parts.append("🌍 세계·산업 이슈\n" + "\n".join(f"· {i['title']}" for i in issues[:3]))
        push(cfg, "아침 브리핑" + (" (주말)" if mode == "weekend" else ""),
             "\n\n".join(parts) or "새 뉴스가 없습니다.")
    elif mode in ("close", "us"):
        pool = [s for s in summaries if (mode == "close" or s["market"] == "해외")]
        if mode == "us" and not pool:
            return
        new_ids = {article_id(s["name"], a) for s in pool for a in s["news"]
                   if datetime.fromisoformat(a["time"]) > t - timedelta(hours=8)}
        top = lines_for(pool, only_new_ids=new_ids, limit=8)
        title = "장 마감 정리" if mode == "close" else "미국장 개장 전 점검"
        push(cfg, title, "\n".join(top) or "오늘 새 뉴스가 없습니다.")

    state["pushed"] = sorted(pushed)[-2000:]
    state["held"] = held


# ---------- 메인 ----------
def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "collect"
    cfg = load_cfg()
    stocks_cfg = load_stocks()
    thr = stocks_cfg["저평가_기준_손실률"]
    with ThreadPoolExecutor(8) as ex:
        news = list(ex.map(lambda s: collect_stock(s, cfg), stocks_cfg["stocks"]))
        issues = collect_issues(stocks_cfg, cfg)
    summaries = [summarize(s, n, thr) for s, n in zip(stocks_cfg["stocks"], news)]
    data = {"updated": now().isoformat(timespec="minutes"), "stocks": summaries, "issues": issues,
            "settings": {"night": f"{cfg['야간_시작']}시~{cfg['야간_끝']}시",
                         "night_exception": cfg["야간_초대형_예외_허용"], "push_on": bool(cfg.get("ntfy_topic"))}}
    out = BASE / "docs"
    out.mkdir(exist_ok=True)
    if PASSWORD:
        (out / "data.enc.json").write_text(json.dumps(encrypt(data), ensure_ascii=False), encoding="utf-8")
    else:  # 내 PC에서 시험할 때만 (docs 밖, 깃에는 올라가지 않음)
        (BASE / "data.local.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    if mode != "collect":
        state = load_state()
        before = json.loads(json.dumps(state))
        run_push(mode, cfg, summaries, issues, state)
        save_state(state, before)
    print(f"완료: 모드 {mode}, 종목 {len(summaries)}개 ({data['updated']})")


if __name__ == "__main__":
    main()
