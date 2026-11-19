#!/usr/bin/env bash
# ==============================================================================
# 跨平台 Linux 核心安全性與對外暴露面評估腳本
# 適用: Debian / Ubuntu / Amazon Linux 2 & 2023 / RHEL / CentOS / Rocky / Alma
# ==============================================================================

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "================================================================="
echo " Linux 核心安全性與對外暴露面評估報告 ($(hostname))"
echo " 檢測時間: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "================================================================="

# ------------------------------------------------------------------------------
# [1] 作業系統與核心版本偵測
# ------------------------------------------------------------------------------
OS_NAME="Unknown"
SUPPORT_END=""
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    OS_NAME="${PRETTY_NAME:-$NAME}"
    SUPPORT_END="${SUPPORT_END:-}"
fi

RUNNING_KERNEL=$(uname -r)
echo -e "${BLUE}[1] 系統與核心基本資訊:${NC}"
echo "    作業系統: $OS_NAME"
echo "    運行核心: $RUNNING_KERNEL"

OS_EOL=0
if [[ -n "$SUPPORT_END" ]]; then
    CURRENT_DATE=$(date -u +%Y-%m-%d)
    if [[ "$CURRENT_DATE" > "$SUPPORT_END" ]]; then
        echo -e "${RED}    [警告] 此作業系統已超過官方支援期限 (EOL: $SUPPORT_END)！${NC}"
        OS_EOL=1
    fi
fi

# ------------------------------------------------------------------------------
# [2] 跨發行版核心安全更新檢查 (APT / DNF / YUM)
# ------------------------------------------------------------------------------
echo "-----------------------------------------------------------------"
echo -e "${BLUE}[2] 核心套件更新狀態檢查:${NC}"

PKG_MGR="unknown"
NEED_UPGRADE=0
NEED_REBOOT=0
MINIMAL_CMD=""
CURRENT_PKG_VER="未知"
CANDIDATE_VER="無"

if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
    META_PKG=$(dpkg -l 'linux-image-*' 2>/dev/null | awk '/^ii/ && $2 ~ /^linux-image-(cloud-)?amd64$/ {print $2}' | head -n 1)
    [[ -z "$META_PKG" ]] && META_PKG="linux-image-amd64"

    CURRENT_PKG_VER=$(dpkg-query -W -f='${Version}\n' "$META_PKG" 2>/dev/null || echo "未知")
    apt-get update -o Acquire::http::Timeout="10" >/dev/null 2>&1 || true
    CANDIDATE_VER=$(apt-cache policy "$META_PKG" 2>/dev/null | awk '/Candidate:/ {print $2}')

    if [[ -n "$CANDIDATE_VER" && "$CANDIDATE_VER" != "(none)" && "$CURRENT_PKG_VER" != "$CANDIDATE_VER" ]]; then
        NEED_UPGRADE=1
        MINIMAL_CMD="apt-get install --only-upgrade -y $META_PKG linux-libc-dev"
    fi

elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PKG_MGR=$(command -v dnf >/dev/null 2>&1 && echo "dnf" || echo "yum")
    CURRENT_PKG_VER=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel 2>/dev/null | sort -V | tail -n 1 || echo "未知")

    if $PKG_MGR check-update kernel >/dev/null 2>&1; then
        CANDIDATE_VER="$CURRENT_PKG_VER"
    else
        EXIT_CODE=$?
        if [[ $EXIT_CODE -eq 100 ]]; then
            NEED_UPGRADE=1
            CANDIDATE_VER=$($PKG_MGR check-update kernel 2>/dev/null | awk '/^kernel\./ {print $2}' | tail -n 1)
            [[ -z "$CANDIDATE_VER" ]] && CANDIDATE_VER="有新版可用"
            MINIMAL_CMD="$PKG_MGR update -y kernel"
        fi
    fi
fi

echo "    套件管理器: $PKG_MGR | 已安裝核心套件: $CURRENT_PKG_VER"
if [[ $NEED_UPGRADE -eq 1 ]]; then
    echo -e "${YELLOW}    [發現更新] 官方套件庫有新版核心可用: $CANDIDATE_VER${NC}"
else
    echo -e "${GREEN}    [版本狀態] 目前套件庫無更新的核心版本。${NC}"
fi

LATEST_BOOT_IMG=$(ls -1 /boot/vmlinuz-* 2>/dev/null | grep -v 'rescue' | sed 's|/boot/vmlinuz-||' | sort -V | tail -n 1)
if [[ -n "$LATEST_BOOT_IMG" && "$RUNNING_KERNEL" != "$LATEST_BOOT_IMG" ]]; then
    echo -e "${YELLOW}    [待重啟] 硬碟已有新版核心 ($LATEST_BOOT_IMG)，但主機尚未重開機切換！${NC}"
    NEED_REBOOT=1
fi

# ------------------------------------------------------------------------------
# [3] 對外開放連接埠與軟體暴露面分析 (排除 127.0.0.1 / ::1)
# ------------------------------------------------------------------------------
echo "-----------------------------------------------------------------"
echo -e "${BLUE}[3] 對外監聽連接埠與啟用軟體分析 (排除 127.0.0.1 / ::1):${NC}"

EXPOSED_LIST=$(ss -tulnSp 2>/dev/null | awk '
NR>1 && ($2=="LISTEN" || $1=="udp") {
    addr=$5
    if (addr !~ /^127\./ && addr !~ /^\[::1\]:/ && addr !~ /^::1:/) {
        raw=$NF
        if (raw ~ /users:/) {
            match(raw, /\(\("([^"]+)"/, m)
            proc = (m[1] != "" ? m[1] : "unknown")
        } else {
            proc = "kernel/unknown"
        }
        print $1 "\t" addr "\t" proc
    }
}' | sort -u)

HIGH_EXPOSURE_SUMMARY=()

if [[ -z "$EXPOSED_LIST" ]]; then
    echo -e "${GREEN}    [安全] 未偵測到直接對外介面監聽的連接埠。${NC}"
else
    printf "    %-8s %-26s %-22s %s\n" "協定" "監聽位址:埠號" "對應軟體/程序" "暴露風險屬性"
    echo "    -------------------------------------------------------------------------"
    while IFS=$'\t' read -r proto addr proc; do
        [[ -z "$proto" ]] && continue
        risk_tag="一般網路服務"
        port="${addr##*:}"

        case "$proc" in
            *nginx*|*apache2*|*httpd*|*caddy*|*haproxy*|*envoy*|*node*|*php*|*java*|*python*|*gunicorn*|*uwsgi*)
                risk_tag="高互動 Web/應用層 (易成 RCE 第一道突破口)"
                HIGH_EXPOSURE_SUMMARY+=("${proc}:${port}")
                ;;
            *asterisk*|*freeswitch*|*turnserver*|*coturn*|*kamailio*|*opensips*)
                risk_tag="語音/WebRTC 信令與媒體服務 (對外開放高並行)"
                HIGH_EXPOSURE_SUMMARY+=("${proc}:${port}")
                ;;
            *sshd*)
                risk_tag="遠端管理介面 (建議限制來源 IP / 金鑰登入)"
                ;;
            *mysqld*|*mariadbd*|*postgres*|*redis*|*mongod*)
                risk_tag="核心資料庫 (極高危！請確認防火牆已阻擋公網)"
                HIGH_EXPOSURE_SUMMARY+=("${proc}:${port}")
                ;;
        esac
        printf "    %-8s %-26s %-22s %s\n" "$proto" "$addr" "$proc" "$risk_tag"
    done <<< "$EXPOSED_LIST"
fi

# 去重高風險服務摘要清單
UNIQUE_APPS=$(printf "%s\n" "${HIGH_EXPOSURE_SUMMARY[@]}" 2>/dev/null | sort -u | tr '\n' ' ')

# ------------------------------------------------------------------------------
# [4] 核心攻擊面與驅動相依性檢查 (SCTP / DAHDI / DKMS)
# ------------------------------------------------------------------------------
echo "-----------------------------------------------------------------"
echo -e "${BLUE}[4] 核心層攻擊面與第三方驅動相依性:${NC}"

SCTP_LOADED=0
if lsmod | grep -q '^sctp'; then
    SCTP_LOADED=1
    echo -e "${YELLOW}    [核心模組] SCTP 模組已載入記憶體 (若無業務需求應封鎖；若有需求則必須靠升級核心修補 LPE)。${NC}"
else
    if grep -rqE 'blacklist sctp|install sctp /bin/(false|true)' /etc/modprobe.d/ 2>/dev/null; then
        echo -e "${GREEN}    [核心模組] SCTP 未載入且已設定黑名單封鎖。${NC}"
    else
        echo -e "${YELLOW}    [核心模組] SCTP 目前未載入，但尚未設定黑名單防自動載入。${NC}"
    fi
fi

if lsmod | grep -qE '^dahdi|^nvidia|^zfs' || (command -v dkms >/dev/null 2>&1 && [[ -n "$(dkms status 2>/dev/null)" ]]); then
    echo -e "${YELLOW}    [驅動相依] 偵測到第三方核心模組 (DAHDI/DKMS/ZFS 等)，升級核心前請先建立快照備份。${NC}"
else
    echo -e "${GREEN}    [驅動相依] 無特殊第三方核心驅動，標準安全核心升級相容性極高。${NC}"
fi

# ------------------------------------------------------------------------------
# [5] 綜合風險評估與最小化升級指令
# ------------------------------------------------------------------------------
echo "================================================================="
echo -e "${BLUE}[5] 綜合安全評估與最小化處置建議${NC}"
echo "================================================================="

RISK_LEVEL="LOW"
if [[ $NEED_UPGRADE -eq 1 || $NEED_REBOOT -eq 1 ]]; then
    if [[ -n "$UNIQUE_APPS" && $SCTP_LOADED -eq 1 ]]; then
        RISK_LEVEL="HIGH"
    elif [[ -n "$UNIQUE_APPS" || $SCTP_LOADED -eq 1 ]]; then
        RISK_LEVEL="MEDIUM"
    fi
fi

case "$RISK_LEVEL" in
    HIGH)
        echo -e "${RED}【評估結果：高優先級建議排程升級】${NC}"
        echo "  原因分析：主機監聽了多個對外高互動服務 ($UNIQUE_APPS)，"
        echo "            且核心已載入敏感模組 (如 SCTP)。一旦前端應用遭突破，攻擊者可直接"
        echo "            利用未修補的核心漏洞提權至 root。必須透過升級核心補齊第二道防線。"
        ;;
    MEDIUM)
        echo -e "${YELLOW}【評估結果：中度風險，建議於例行維護窗口升級】${NC}"
        echo "  原因分析：主機有對外開放連接埠且存在新版核心安全更新 ($CANDIDATE_VER)。"
        echo "            雖無立即遭遠端直接打穿核心之風險，仍建議套用安全修補維持縱深防禦。"
        ;;
    LOW)
        if [[ $OS_EOL -eq 1 ]]; then
            echo -e "${YELLOW}【評估結果：系統已過期 (EOL)】${NC}"
            echo "  原因分析：作業系統已停止官方安全更新，無法透過套件庫修補核心，建議規劃升級 OS 版本。"
        elif [[ $NEED_UPGRADE -eq 1 || $NEED_REBOOT -eq 1 ]]; then
            echo -e "${CYAN}【評估結果：低風險，可按常規排程更新】${NC}"
        else
            echo -e "${GREEN}【評估結果：狀態良好】目前核心已是最新安全版本，無需執行核心升級。${NC}"
        fi
        ;;
esac

if [[ $NEED_UPGRADE -eq 1 ]]; then
    echo ""
    echo -e "${BLUE}▶ 最小化核心安全升級指令 (僅更新核心，完全不動業務軟體與其他模組):${NC}"
    echo -e "${GREEN}  $MINIMAL_CMD${NC}"
    echo ""
    echo -e "${BLUE}▶ 套用生效方式 (請於離峰無業務時段執行重開機):${NC}"
    echo -e "${GREEN}  reboot${NC}"
elif [[ $NEED_REBOOT -eq 1 ]]; then
    echo ""
    echo -e "${BLUE}▶ 新核心已下載就緒，僅需於離峰時段執行重開機切換:${NC}"
    echo -e "${GREEN}  reboot${NC}"
fi
echo "================================================================="
