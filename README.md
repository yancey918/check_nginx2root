# nginx2root Audit & Forensics Tool (`check_nginx2root.sh`)

一支專為 Linux 系統管理員設計的自動化防禦檢測與入侵鑑識腳本，用於盤點伺服器是否暴露於 **nginx2root**（包含 5 個無需身分驗證的 nginx 遠端程式碼執行漏洞與 1 個 Linux 核心 SCTP 本地權限提升漏洞）的風險之下，並深度分析歷史 Logs 以排查異常入侵跡象。

---

## 🔍 檢測涵蓋範圍

本腳本針對 Xint 資安團隊揭露的 **6 個漏洞**進行全自動化組態比對與連線實測：

| 漏洞編號 | 影響組件 | 腳本檢測機制 |
| :--- | :--- | :--- |
| **CVE-2026-123007** | nginx (HTTP/2) | 檢查版本區間 (`1.9.5`–`1.31.8`)、`--with-http_v2_module` 編譯參數、設定檔 `http2` 指令，並實測本機與外部 ALPN `h2` 協商狀態 |
| **CVE-2026-123633** | nginx (HTTP/2 + Upstream) | 透過 HTTP/2 組態與 ALPN 連線測試評估暴露風險 |
| **CVE-2026-123634** | nginx (`mirror` / `ssi`) | 掃描執行組態是否啟用 `mirror` 或 `ssi on` 子請求功能 |
| **CVE-2026-121810** | nginx (HTTP/3 / QUIC) | 掃描執行組態是否啟用 `http3` 或 `quic` 監聽埠（自動排除 `mime.types` 雜訊） |
| **CVE-2026-113425** | nginx (Mail Proxy) | 掃描執行組態是否啟用 `auth_http` |
| **Linux Kernel SCTP LPE** | Linux Kernel | 檢查作業系統 EOL 狀態、核心版本、`lsmod` 是否載入 `sctp` 模組，以及 `/etc/modprobe.d/` 黑名單設定 |

### 🛡️ 入侵跡象深度分析（Forensics & Log Analysis）
除了靜態組態盤點外，腳本也會執行五項即時與歷史日誌鑑識：
1. **TCP 流量不對稱偵測**：透過 `ss -tinp` 抓取接收量異常龐大（`>1MB`）但發送量極低（`<10KB`）的長連線（`WINDOW_UPDATE` 控制幀洪水特徵）。
2. **Worker 程序樹稽核**：檢查 `nginx: worker process` 是否衍生任何異常子程序（RCE 成功執行指令的直接證據）。
3. **Worker 崩潰紀錄掃描**：檢索 `error.log`（含 `.gz` 壓縮檔）中是否出現 `signal 11 (SIGSEGV)` 或 `SIGABRT` 等記憶體損毀跡象。
4. **Access Log 統計**：統計 `HTTP/2.0` 請求量與來源 IP 排行，並揪出大量送出 `HTTP 400` 異常封包的探測來源。
5. **核心日誌檢查**：比對 `dmesg` 是否存在 `nginx segfault` 或異常 `sctp` 模組載入紀錄。

---

## 🚀 快速開始

### 1. 下載並賦予執行權限
```bash
curl -O [https://raw.githubusercontent.com/](https://raw.githubusercontent.com/)<YOUR_ORG>/<YOUR_REPO>/main/check_nginx2root.sh
chmod +x check_nginx2root.sh
```

### 2. 執行檢測
腳本需要讀取完整 `nginx -T` 設定與核心連線狀態，請使用 `sudo` 或 `root` 權限執行：

```bash
# 方式 A：互動模式（執行後依提示輸入要測試的外部網域）
sudo ./check_nginx2root.sh

# 方式 B：非互動模式（直接透過參數帶入網域，適合批次自動化腳本）
sudo ./check_nginx2root.sh [www.example.com](https://www.example.com)
```

### 3. 檢視詳細報告
每次執行完畢後，腳本會在螢幕輸出彩色摘要，並自動將完整檢測報告儲存至 `/tmp/` 目錄：
```text
/tmp/nginx2root_audit_<HOSTNAME>_<YYYYMMDD_HHMMSS>.log
```

---

## 📋 檢測結果判讀與處理建議

### 情境 A：外部網域顯示 `ALPN protocol: h2`，但本機測試顯示 `No ALPN negotiated`
* **判讀**：表示您的網域前方掛有反向代理或負載平衡器（如 **AWS ALB**、**CloudFront** 或 **Cloudflare**），由前端服務終止 TLS 並協商 HTTP/2，再降級為 HTTP/1.1 轉發給後端 EC2/主機。
* **風險評估**：**安全**。前端代理已阻斷 HTTP/2 控制幀攻擊，本機 nginx 並未直接暴露於 HTTP/2 漏洞路徑。

### 情境 B：腳本提示版本位於受影響區間（`1.9.5` ~ `1.31.8`）
* **官方來源編譯**：請盡快升級至 **nginx 1.31.9** 或更高版本。
* **Amazon Linux 2023**：因套件庫預設鎖定發行版號，請使用 `--releasever=latest` 檢查並安裝 AWS 官方修補版本（例如 `1.30.7-1.amzn2023.0.1`）：
  ```bash
  sudo dnf upgrade --releasever=latest nginx -y
  sudo systemctl restart nginx
  ```
* **Ubuntu / Debian**：請透過 `apt update && apt upgrade nginx` 安裝發行版提供的 Backport 安全更新，並執行 `sudo systemctl restart nginx` 重啟服務（僅執行 `reload` 不會替換記憶體中的舊執行檔）。

### 情境 C：防禦 Linux 核心 SCTP 本地權限提升（LPE）
若伺服器無使用 SCTP 協定的業務需求，建議將其加入核心模組黑名單以阻斷提權鏈：
```bash
echo 'install sctp /bin/true' | sudo tee /etc/modprobe.d/disable-sctp.conf
```

---

## ⚠️ 注意事項
* 本工具僅進行**唯讀（Read-Only）**的本地組態盤點、日誌分析與標準 TLS ALPN 交握測試，不會對目標伺服器發送任何攻擊封包或修改現有系統設定。
* 升級 `nginx` 套件後，務必執行 `systemctl restart nginx` 或線上升級（Live Binary Upgrade），確保新的二進位執行檔正式生效。
