#!/usr/bin/env bash
# ==============================================================================
# nginx2root 防禦性安全盤點與異常日誌分析腳本
# 適用對象：Linux 伺服器本機檢測 (支援 Amazon Linux / Ubuntu / Debian / RHEL)
# ==============================================================================

set -u

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 檢查是否以 root 執行
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[錯誤] 請使用 root 或 sudo 權限執行此腳本，以便讀取完整 nginx 設定與系統連線狀態。${NC}"
   exit 1
fi

# 互動輸入網域 (支援從參數帶入或互動提示)
TARGET_DOMAIN="${1:-}"
if [[ -z "$TARGET_DOMAIN" ]]; then
    echo -e "${CYAN}=================================================================${NC}"
    echo -e "${CYAN}   nginx2root (CVE-2026-123007 等 5 項 RCE) 自動化防禦檢測工具   ${NC}"
    echo -e "${CYAN}=================================================================${NC}"
    read -rp "請輸入要檢測的對外網域 (例如 www.example.com，若無可按 Enter 跳過): " TARGET_DOMAIN
fi

# 設定詳細 Log 輸出檔案
HOSTNAME_STR=$(hostname -s)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="/tmp/nginx2root_audit_${HOSTNAME_STR}_${TIMESTAMP}.log"

# 同時輸出到螢幕與 Log 檔的輔助函式
log_raw() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log_section() {
    log_raw "\n${BLUE}=================================================================${NC}"
    log_raw "${BLUE}  $1${NC}"
    log_raw "${BLUE}=================================================================${NC}"
}

log_info()  { log_raw "${CYAN}[資訊]${NC} $1"; }
log_ok()    { log_raw "${GREEN}[安全]${NC} $1"; }
log_warn()  { log_raw "${YELLOW}[注意]${NC} $1"; }
log_crit()  { log_raw "${RED}[高風險]${NC} $1"; }

# 風險計數器
RISK_SCORE=0
SUSPICIOUS_EVENTS=0

log_raw "檢測時間: $(date '+%Y-%m-%d %H:%M:%S %Z')"
log_raw "主機名稱: $(hostname) ($(hostname -I | awk '{print $1}'))"
log_raw "檢測網域: ${TARGET_DOMAIN:-未指定}"
log_raw "詳細報告將儲存至: $LOG_FILE"

# ------------------------------------------------------------------------------
# 1. 作業系統與套件生命週期檢查
# ------------------------------------------------------------------------------
log_section "1. 作業系統與核心防護狀態 (Linux Kernel SCTP LPE)"

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    log_info "作業系統: ${PRETTY_NAME:-$NAME $VERSION}"
    if [[ -n "${SUPPORT_END:-}" ]]; then
        log_info "官方支援截止日 (SUPPORT_END): $SUPPORT_END"
        CURRENT_DATE=$(date +%Y-%m-%d)
        if [[ "$CURRENT_DATE" > "$SUPPORT_END" ]]; then
            log_warn "此作業系統已超過官方支援期限 (EOL)，可能無法取得官方安全修補！"
            ((RISK_SCORE++))
        else
            log_ok "作業系統仍在官方支援週期內。"
        fi
    fi
fi

KERNEL_VER=$(uname -r)
log_info "目前核心版本: $KERNEL_VER"

# 檢查 SCTP 模組狀態 (防禦本地提權鏈)
if lsmod | grep -q '^sctp'; then
    log_warn "偵測到 Linux 核心已載入 SCTP 模組！若遭 RCE 入侵可能被用於本地提權 (LPE)。"
    ((RISK_SCORE++))
else
    log_ok "SCTP 核心模組目前未載入。"
fi

if grep -rq "install sctp /bin/true" /etc/modprobe.d/ 2>/dev/null; then
    log_ok "已設定 modprobe 黑名單封鎖 SCTP 自動載入。"
else
    log_warn "尚未設定 SCTP 模組黑名單 (建議執行: echo 'install sctp /bin/true' > /etc/modprobe.d/disable-sctp.conf)。"
fi

# ------------------------------------------------------------------------------
# 2. Nginx 版本與編譯模組檢查
# ------------------------------------------------------------------------------
log_section "2. Nginx 版本與脆弱程式碼範圍檢查"

if ! command -v nginx >/dev/null 2>&1; then
    log_crit "系統中找不到 nginx 指令，終止後續檢測。"
    exit 1
fi

NGINX_VER_RAW=$(nginx -v 2>&1)
NGINX_VER=$(echo "$NGINX_VER_RAW" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
log_info "完整版本字串: $NGINX_VER_RAW"

# 版本區間比對 (1.9.5 <= ver <= 1.31.8 為受影響區間)
ver_le() {
    [ "$1" = "$(echo -e "$1\n$2" | sort -V | head -n1)" ]
}
ver_ge() {
    [ "$1" = "$(echo -e "$1\n$2" | sort -V | tail -n1)" ]
}

VULN_VERSION=0
if ver_ge "$NGINX_VER" "1.9.5" && ver_le "$NGINX_VER" "1.31.8"; then
    log_warn "版本 $NGINX_VER 落在官方受影響區間 (1.9.5 ~ 1.31.8)。若為發行版套件，需確認是否有 Backport 修補。"
    VULN_VERSION=1
elif ver_ge "$NGINX_VER" "1.31.9"; then
    log_ok "版本 $NGINX_VER 為 1.31.9 或更新版本，已包含官方修復。"
else
    log_ok "版本 $NGINX_VER 早於 1.9.5 (不支援 HTTP/2)，不受 CVE-2026-123007 影響。"
fi

# 檢查編譯參數
NGINX_ARGS=$(nginx -V 2>&1)
if echo "$NGINX_ARGS" | grep -q -- '--with-http_v2_module'; then
    log_info "編譯模組狀態: 包含 --with-http_v2_module"
    HAS_H2_MOD=1
else
    log_ok "編譯模組狀態: 未編譯 HTTP/2 模組 (免疫 CVE-2026-123007 與 CVE-2026-123633)"
    HAS_H2_MOD=0
fi

# 檢查套件庫來源與可用更新
if command -v rpm >/dev/null 2>&1; then
    PKG_INFO=$(rpm -q nginx 2>/dev/null || echo "非 RPM 安裝")
    log_info "RPM 套件資訊: $PKG_INFO"
    if command -v dnf >/dev/null 2>&1 && grep -q "2023" /etc/os-release 2>/dev/null; then
        log_info "正在檢查 Amazon Linux 2023 最新套件庫 (--releasever=latest)..."
        DNF_OUT=$(dnf check-update --releasever=latest nginx 2>&1 || true)
        if echo "$DNF_OUT" | grep -qE '^nginx\.'; then
            log_warn "發現可用的新版 nginx 套件更新：\n$(echo "$DNF_OUT" | grep -E '^nginx\.')"
        else
            log_info "目前 --releasever=latest 套件庫尚無比 $PKG_INFO 更新的 nginx 套件。"
        fi
    fi
elif command -v dpkg >/dev/null 2>&1; then
    PKG_INFO=$(dpkg -l nginx 2>/dev/null | awk '/^ii/ {print $2, $3}' || echo "非 DEB 安裝")
    log_info "DEB 套件資訊: $PKG_INFO"
fi

# ------------------------------------------------------------------------------
# 3. 5 個 CVE 組態設定檔深度掃描
# ------------------------------------------------------------------------------
log_section "3. Nginx 執行組態掃描 (針對全部 5 個 CVE)"

NGINX_CONF_DUMP=$(nginx -T 2>&1 | sed 's/#.*//')

# 3.1 檢查 HTTP/2 (CVE-2026-123007 & CVE-2026-123633)
H2_LINES=$(echo "$NGINX_CONF_DUMP" | grep -nE 'listen[[:space:]].*http2|^[[:space:]]*http2[[:space:]]+on[[:space:]]*;' || true)
if [[ -n "$H2_LINES" ]]; then
    log_crit "偵測到設定檔已啟用 HTTP/2！(觸發 CVE-2026-123007 / CVE-2026-123633 高風險條件)"
    log_raw "匹配的設定行：\n$H2_LINES"
    ((RISK_SCORE+=2))
    H2_ENABLED=1
else
    log_ok "設定檔未啟用 HTTP/2 (已阻斷 CVE-2026-123007 與 CVE-2026-123633 攻擊路徑)。"
    H2_ENABLED=0
fi

# 3.2 檢查 HTTP/3 / QUIC (CVE-2026-121810) - 排除 mime.types 的 quicktime 等字串
H3_LINES=$(echo "$NGINX_CONF_DUMP" | grep -nE 'listen[[:space:]].*(quic|http3)|^[[:space:]]*http3[[:space:]]+on[[:space:]]*;' || true)
if [[ -n "$H3_LINES" ]]; then
    log_crit "偵測到設定檔已啟用 HTTP/3 或 QUIC！(可能觸發 CVE-2026-121810)"
    log_raw "匹配的設定行：\n$H3_LINES"
    ((RISK_SCORE+=2))
else
    log_ok "設定檔未啟用 HTTP/3 / QUIC (已阻斷 CVE-2026-121810)。"
fi

# 3.3 檢查 Mirror / SSI 子請求功能 (CVE-2026-123634)
MIRROR_LINES=$(echo "$NGINX_CONF_DUMP" | grep -nE '^[[:space:]]*(mirror[[:space:]]+|ssi[[:space:]]+on[[:space:]]*;)' || true)
if [[ -n "$MIRROR_LINES" ]]; then
    log_warn "偵測到設定檔使用 mirror 或 ssi 功能！(若搭配 resolver 與動態 proxy_pass 可能觸發 CVE-2026-123634)"
    log_raw "匹配的設定行：\n$MIRROR_LINES"
    ((RISK_SCORE++))
else
    log_ok "設定檔未使用 mirror 或 ssi 子請求指令 (已阻斷 CVE-2026-123634)。"
fi

# 3.4 檢查 Mail Proxy auth_http (CVE-2026-113425)
MAIL_LINES=$(echo "$NGINX_CONF_DUMP" | grep -nE '^[[:space:]]*auth_http[[:space:]]+' || true)
if [[ -n "$MAIL_LINES" ]]; then
    log_crit "偵測到設定檔啟用 Mail Proxy auth_http！(可能觸發 CVE-2026-113425)"
    log_raw "匹配的設定行：\n$MAIL_LINES"
    ((RISK_SCORE+=2))
else
    log_ok "設定檔未啟用 Mail Proxy auth_http (已阻斷 CVE-2026-113425)。"
fi

# ------------------------------------------------------------------------------
# 4. 網路監聽埠與 TLS / ALPN 連通性實測
# ------------------------------------------------------------------------------
log_section "4. 網路監聽埠與 HTTP/2 (ALPN h2) 連通性實測"

LISTEN_PORTS=$(ss -tlpn | grep nginx || true)
log_info "目前 Nginx 監聽的 TCP 連接埠：\n$LISTEN_PORTS"

# 4.1 測試本機 127.0.0.1:443 (繞過 CDN/ALB 直測本機)
if echo "$LISTEN_PORTS" | grep -q ':443 '; then
    LOCAL_ALPN=$(openssl s_client -connect 127.0.0.1:443 -servername "${TARGET_DOMAIN:-localhost}" -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol:|No ALPN negotiated|connect:errno|handshake failure' || true)
    log_info "本機直連測試 (127.0.0.1:443) 結果: ${LOCAL_ALPN:-無回應}"
    if echo "$LOCAL_ALPN" | grep -q 'ALPN protocol: h2'; then
        log_crit "本機 443 埠直接接受 HTTP/2 連線！"
        ((RISK_SCORE+=2))
    else
        log_ok "本機 443 埠拒絕 HTTP/2 協商，直連安全。"
    fi
fi

# 4.2 測試使用者輸入的外部網域
if [[ -n "$TARGET_DOMAIN" ]]; then
    EXT_ALPN=$(openssl s_client -connect "${TARGET_DOMAIN}:443" -servername "$TARGET_DOMAIN" -alpn h2 </dev/null 2>&1 | grep -E 'ALPN protocol:|No ALPN negotiated|connect:errno|handshake failure' || true)
    log_info "外部網域測試 (${TARGET_DOMAIN}:443) 結果:\n$EXT_ALPN"
    if echo "$EXT_ALPN" | grep -q 'ALPN protocol: h2'; then
        if [[ "$H2_ENABLED" -eq 0 ]]; then
            log_ok "外部網域協商為 HTTP/2，但本機未啟用 HTTP/2。判定前方有 ALB / CloudFront 代理終止 TLS 並降級轉發，本機受保護。"
        else
            log_crit "外部網域可直接透過 HTTP/2 連入本機漏洞服務，請立即處理！"
            ((RISK_SCORE+=2))
        fi
    elif echo "$EXT_ALPN" | grep -q 'No ALPN negotiated'; then
        log_ok "外部網域未協商 HTTP/2 (No ALPN negotiated)，外部攻擊路徑已阻斷。"
    else
        log_warn "外部網域連線測試異常或發生交握錯誤，請確認網域解析與防火牆設定。"
    fi
fi

# ------------------------------------------------------------------------------
# 5. 入侵跡象深度分析 (連線異常、Worker 子程序、Crash Logs)
# ------------------------------------------------------------------------------
log_section "5. 入侵跡象深度排查 (Logs 與即時程序分析)"

# 5.1 檢查異常的長連線與流量不對稱 (WINDOW_UPDATE 攻擊特徵)
log_info "[5.1] 檢查 port 443 現有 TCP 連線統計 (尋找單一 IP 異常高接收量但極低發送量)..."
CONN_STATS=$(ss -tinp state established '( sport = :443 )' 2>/dev/null || true)
if [[ -n "$CONN_STATS" ]]; then
    # 解析 bytes_received > 1MB 且 bytes_sent < 10KB 的可疑連線
    SUSPICIOUS_CONNS=$(echo "$CONN_STATS" | awk '
        /ESTAB/ { line=$0; getline; info=$0;
            match(info, /bytes_received:([0-9]+)/, r);
            match(info, /bytes_sent:([0-9]+)/, s);
            if (r[1] > 1048576 && s[1] < 10240) {
                print line "\n  -> " info
            }
        }')
    if [[ -n "$SUSPICIOUS_CONNS" ]]; then
        log_crit "發現疑似 HTTP/2 控制幀洪水 (WINDOW_UPDATE) 異常連線特徵 (接收 >1MB 但發送 <10KB)：\n$SUSPICIOUS_CONNS"
        ((SUSPICIOUS_EVENTS++))
    else
        log_ok "目前 port 443 連線無明顯的流量不對稱攻擊特徵。"
    fi
else
    log_info "目前 port 443 無建立中的連線。"
fi

# 5.2 檢查 Nginx Worker 是否衍生異常子程序 (RCE 執行指令特徵)
log_info "[5.2] 檢查 Nginx Worker 程序樹 (正常情況下 Worker 不應有任何子程序)..."
WORKER_PIDS=$(pgrep -f "nginx: worker process" || true)
CHILD_PROCS=""
for pid in $WORKER_PIDS; do
    CHILDREN=$(ps --ppid "$pid" -o pid,user,lstart,cmd --no-headers 2>/dev/null || true)
    if [[ -n "$CHILDREN" ]]; then
        CHILD_PROCS+="\nWorker PID $pid 衍生了子程序：\n$CHILDREN"
    fi
done

if [[ -n "$CHILD_PROCS" ]]; then
    log_crit "警告！偵測到 Nginx Worker 衍生了子程序，這是 RCE 成功執行指令的強烈跡象！$CHILD_PROCS"
    ((SUSPICIOUS_EVENTS++))
else
    log_ok "所有 Nginx Worker 程序狀態乾淨，無任何異常子程序。"
fi

# 5.3 分析 Nginx Error Log 中的 Worker 崩潰 (SIGSEGV / signal 11) 與異常紀錄
log_info "[5.3] 分析 Nginx Error Log 尋找 Worker 崩潰 (漏洞觸發失敗或記憶體損毀跡象)..."
ERROR_LOGS=$(find /var/log/nginx/ -name "*error*.log*" 2>/dev/null || true)
if [[ -n "$ERROR_LOGS" ]]; then
    CRASH_HITS=$(zgrep -hE 'worker process [0-9]+ exited on signal (11|6|4|7)|SIGSEGV|SIGABRT' $ERROR_LOGS 2>/dev/null | tail -n 20 || true)
    if [[ -n "$CRASH_HITS" ]]; then
        log_warn "在 Error Log 中發現 Worker 異常崩潰紀錄 (可能為漏洞利用嘗試導致記憶體區段錯誤)：\n$CRASH_HITS"
        ((SUSPICIOUS_EVENTS++))
    else
        log_ok "Error Log 中未發現 Worker 異常崩潰 (Signal 11/6) 紀錄。"
    fi
else
    log_info "未在 /var/log/nginx/ 找到標準 error.log，請確認自訂日誌路徑。"
fi

# 5.4 分析 Access Log 中的 HTTP/2 異常請求與高頻短連線來源
log_info "[5.4] 分析 Nginx Access Log 統計 HTTP/2 請求與可疑高頻來源 IP..."
ACCESS_LOGS=$(find /var/log/nginx/ -name "*access*.log" 2>/dev/null || true)
if [[ -n "$ACCESS_LOGS" ]]; then
    H2_REQ_COUNT=$(grep -ch 'HTTP/2\.0"' $ACCESS_LOGS 2>/dev/null | awk '{s+=$1} END {print s+0}')
    log_info "近期 Access Log 中紀錄的 HTTP/2.0 請求總數: $H2_REQ_COUNT"
    if [[ "$H2_REQ_COUNT" -gt 0 ]]; then
        TOP_H2_IPS=$(grep -h 'HTTP/2\.0"' $ACCESS_LOGS 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 5)
        log_info "HTTP/2 請求量前 5 名來源 IP：\n$TOP_H2_IPS"
    fi

    # 檢查異常狀態碼 (如 400 Bad Request 大量出現，常見於協議層 Fuzzing 或攻擊探測)
    BAD_REQ_IPS=$(awk '$9 == 400 {print $1}' $ACCESS_LOGS 2>/dev/null | sort | uniq -c | sort -nr | awk '$1 > 50 {print $0}' | head -n 5 || true)
    if [[ -n "$BAD_REQ_IPS" ]]; then
        log_warn "發現送出大量 HTTP 400 異常請求的來源 IP (超過 50 次，疑似協議層探測)：\n$BAD_REQ_IPS"
    else
        log_ok "Access Log 中無單一 IP 大量異常 HTTP 400 請求。"
    fi
fi

# 5.5 檢查系統認證與核心日誌 (dmesg / journalctl) 是否有 segfault 或 SCTP 異常
log_info "[5.5] 檢查核心日誌 (dmesg) 是否有 nginx segfault 或 SCTP 載入紀錄..."
DMESG_HITS=$(dmesg -T 2>/dev/null | grep -iE 'nginx.*segfault|sctp' | tail -n 15 || true)
if [[ -n "$DMESG_HITS" ]]; then
    log_warn "核心日誌 (dmesg) 發現相關紀錄：\n$DMESG_HITS"
    ((SUSPICIOUS_EVENTS++))
else
    log_ok "核心日誌 (dmesg) 無 nginx segfault 或異常 SCTP 紀錄。"
fi

# ------------------------------------------------------------------------------
# 6. 最終風險總結與建議
# ------------------------------------------------------------------------------
log_section "6. 最終安全評估總結"

if [[ "$SUSPICIOUS_EVENTS" -gt 0 ]]; then
    log_crit "【緊急】偵測到 $SUSPICIOUS_EVENTS 項可疑入侵跡象或異常崩潰！請立即檢視上方標示為紅/黃色的 Log 細節，並隔離受影響主機進行鑑識。"
elif [[ "$RISK_SCORE" -gt 0 ]]; then
    log_warn "【中/高風險】目前未發現已遭入侵的跡象，但主機存在 $RISK_SCORE 項潛在暴露風險（例如版本未修補、啟用高危模組或 SCTP 未封鎖），建議依上方提示進行緩解與升級。"
else
    log_ok "【狀態良好】這台主機的組態已完全阻斷 nginx2root 的 5 個 RCE 攻擊路徑，且各項 Logs 均未發現異常入侵跡象。"
fi

log_raw "\n完整檢測報告已儲存至: ${CYAN}$LOG_FILE${NC}"
