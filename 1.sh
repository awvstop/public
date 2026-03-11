#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  E2B Self-Hosted on AWS — Comprehensive Security Probe v4.0            ║
# ║  Target: Self-deployed E2B infrastructure on AWS                       ║
# ║  Coverage: R1–R15 risk matrix + all identified attack surfaces         ║
# ║  Run inside: E2B Sandbox (Firecracker guest)                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  去掉 set -e, 保留 -uo pipefail; 安全探测脚本不应因某条命令失败就中断
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
set -uo pipefail

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  全局配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MMDS="http://169.254.169.254"
TOKEN_EP="${MMDS}/latest/api/token"
TTL=21600
TIMEOUT=3
OUTDIR="/tmp/e2b_security_probe_v4"
LOGFILE="${OUTDIR}/probe.log"
JSONFILE="${OUTDIR}/results.json"
SEPARATOR="════════════════════════════════════════════════════════════════"
TOKEN=""

mkdir -p "$OUTDIR"
exec > >(tee -a "$LOGFILE") 2>&1

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  工具函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ts()      { date '+%Y-%m-%d %H:%M:%S'; }
header()  { echo -e "\n${SEPARATOR}\n  ◆ $1\n${SEPARATOR}"; }
info()    { echo "  ℹ  $1"; }
ok()      { echo "  ✅ $1"; }
fail()    { echo "  🚨 $1"; }
warn()    { echo "  ⚠️  $1"; }

# ── Findings 收集器 ──
declare -a FINDINGS_CRITICAL=()
declare -a FINDINGS_HIGH=()
declare -a FINDINGS_MEDIUM=()
declare -a FINDINGS_LOW=()
declare -a FINDINGS_PASS=()

finding_critical() { FINDINGS_CRITICAL+=("[${1}] ${2}"); fail "[${1}] ${2}"; }
finding_high()     { FINDINGS_HIGH+=("[${1}] ${2}"); fail "[${1}] ${2}"; }
finding_medium()   { FINDINGS_MEDIUM+=("[${1}] ${2}"); warn "[${1}] ${2}"; }
finding_low()      { FINDINGS_LOW+=("[${1}] ${2}"); info "[${1}] ${2}"; }
finding_pass()     { FINDINGS_PASS+=("[${1}] ${2}"); ok "[${1}] ${2}"; }

# 单次 curl 同时获取 body + HTTP code (避免 TOCTOU)
curl_get() {
  local url="$1"; shift
  local raw code body
  raw=$(curl -s --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -w "\n%{http_code}" "$@" "$url" 2>/dev/null) || true
  code=$(echo "$raw" | tail -1)
  body=$(echo "$raw" | sed '$d')
  echo "${code}|${body}"
}

# 带 MMDS token 的 GET
mmds_get() {
  local path="${1:-/}"
  local accept="${2:-}"
  local args=(-H "X-metadata-token: ${TOKEN}")
  [[ -n "$accept" ]] && args+=(-H "Accept: ${accept}")
  curl_get "${MMDS}${path}" "${args[@]}"
}

# 提取 code / body
get_code() { echo "$1" | head -1 | cut -d'|' -f1; }
get_body() { echo "$1" | head -1 | cut -d'|' -f2-; }

# TCP 端口探测
probe_port() {
  local host="$1" port="$2"
  (echo >/dev/tcp/"$host"/"$port") 2>/dev/null && echo "OPEN" || echo "CLOSED"
}

# 端口扫描辅助 — 并行批量
scan_ports() {
  local host="$1"; shift
  local ports=("$@")
  local open=()
  for port in "${ports[@]}"; do
    if [[ $(probe_port "$host" "$port") == "OPEN" ]]; then
      open+=("$port")
    fi
  done
  echo "${open[*]}"
}

echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║  E2B Self-Hosted on AWS — Security Probe v4.0                          ║"
echo "║  Time: $(ts)                                                ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 0: 基础信息收集 (为后续测试提供上下文)                              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 0: 基础环境信息收集"

info "内核: $(uname -a 2>/dev/null || echo 'N/A')"
info "主机名: $(hostname 2>/dev/null || echo 'N/A')"
info "用户: $(id 2>/dev/null || echo 'N/A')"
echo ""

# 网络接口
info "网络接口:"
ip -4 addr show 2>/dev/null | sed 's/^/    /' || ifconfig 2>/dev/null | sed 's/^/    /'
echo ""

# 推断关键 IP
MY_IP=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v 127.0.0.1 | head -1)
GW_IP=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
DNS_SERVERS=$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
MY_SUBNET=$(echo "$MY_IP" | cut -d'.' -f1-3 2>/dev/null)

info "自身 IP:    ${MY_IP:-unknown}"
info "默认网关:   ${GW_IP:-unknown}"
info "DNS 服务器: ${DNS_SERVERS:-unknown}"
info "子网:       ${MY_SUBNET:-unknown}.0/24 (推断)"

# 路由表
echo ""
info "路由表:"
ip route show 2>/dev/null | sed 's/^/    /'

# 进程列表 (后续多个 Phase 会引用)
echo ""
info "进程快照:"
ps aux 2>/dev/null | sed 's/^/    /' || ls /proc/*/cmdline 2>/dev/null | while read f; do
  pid=$(echo "$f" | cut -d'/' -f3)
  cmd=$(tr '\0' ' ' < "$f" 2>/dev/null || true)
  [[ -n "$cmd" ]] && printf "    PID %-6s %s\n" "$pid" "$cmd"
done | head -50

# 监听端口
echo ""
info "监听端口:"
ss -tlnp 2>/dev/null | sed 's/^/    /' || netstat -tlnp 2>/dev/null | sed 's/^/    /' || {
  info "ss/netstat 不可用, 从 /proc/net/tcp 解析:"
  awk '$4 == "0A" { split($2, a, ":"); port = strtonum("0x"a[2]); printf "    :%d\n", port }' \
    /proc/net/tcp 2>/dev/null || true
}


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 1: [R2] AWS IMDS/MMDS 凭据与元数据泄漏 — 最高优先级               ║
# ║  Sandbox → 169.254.169.254 → 若穿透至宿主 EC2 IMDS:                    ║
# ║    影响: 获取 IAM 临时凭据 → 调用 AWS API → 控制账户/数据/资源            ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 1 [R2]: AWS IMDS/MMDS 凭据泄漏检测 (CRITICAL)"

# IMDS/MMDS 检测影响速查 (每项 finding 会附带具体影响说明):
#   - IMDSv1 无 Token 可用 → 任意 SSRF/恶意代码可读元数据并拉取 IAM 凭据
#   - iam/security-credentials/* 可读 → 获得 AccessKeyId/SecretKey/SessionToken → 按角色策略调用 AWS API (S3/EC2/RDS/SSM/Lambda 等)
#   - user-data 可读 → 启动脚本/配置泄漏, 常含 DB 连接串、密钥、内部端点
#   - instance-identity/document 可读 → 可伪造实例身份或用于 AssumeRole/自定义策略
#   - 若同时存在公网出口 → 完整攻击链: 凭据 + 可达 AWS 端点 = 账户/资源被控
info "影响速查: IMDS 泄漏 → IAM 凭据 → AWS API 调用 → 账户/数据/资源被控 (S3/RDS/EC2/SSM 等)"

# ── 1a: MMDS 连通性 & IMDSv1 vs v2 ──
# Impact: IMDSv1 without token allows any process in guest to read metadata;
#         SSRF or compromised app can steal host IAM credentials.
info "1a. MMDS 连通性及 IMDSv1/v2 检测"
V1_RESULT=$(curl_get "${MMDS}/" )
V1_CODE=$(get_code "$V1_RESULT")
V1_BODY=$(get_body "$V1_RESULT")

echo "  无 Token 请求: HTTP ${V1_CODE}"
if echo "$V1_BODY" | grep -qi "token"; then
  finding_pass "R2" "IMDSv2 已启用, V1 无 Token 请求被拒绝 (HTTP ${V1_CODE}) — 影响: 无法仅靠 SSRF 直接读元数据"
else
  if [[ "$V1_CODE" == "200" ]]; then
    finding_critical "R2" "IMDSv1 可用! 无需 Token 即可查询元数据! HTTP ${V1_CODE} — 影响: 任意代码/SSRF 可读宿主 IAM 凭据, 进而调用 AWS API 控制账户"
    echo "    响应: ${V1_BODY:0:200}"
  else
    info "V1 请求返回 HTTP ${V1_CODE}: ${V1_BODY:0:100}"
  fi
fi

# ── 1b: 获取 MMDS Token ──
# Impact: Token required = one more step for attacker; token optional/long TTL = easier credential theft.
info "1b. 获取 MMDS Token"
TOKEN=$(curl -s -X PUT --connect-timeout "$TIMEOUT" \
  -H "X-metadata-token-ttl-seconds: ${TTL}" \
  "${TOKEN_EP}" 2>/dev/null) || true

if [[ -n "$TOKEN" && ${#TOKEN} -gt 10 ]]; then
  ok "Token 获取成功 (长度 ${#TOKEN})"
else
  warn "Token 获取失败, 后续使用空 Token 继续测试"
  TOKEN=""
fi

# ── 1c: 获取完整 MMDS 数据 (判断是 Firecracker MMDS 还是真实 EC2 IMDS) ──
info "1c. 区分 Firecracker MMDS vs 真实 EC2 IMDS"

# Firecracker MMDS 只返回 E2B 手动注入的字段 (envID, teamID 等)
# 真实 EC2 IMDS 会返回 ami-id, instance-type, iam/ 等
FULL_RESULT=$(mmds_get "/" "application/json")
FULL_CODE=$(get_code "$FULL_RESULT")
FULL_BODY=$(get_body "$FULL_RESULT")

echo "  根路径 JSON: HTTP ${FULL_CODE}"
echo "  响应:"
echo "$FULL_BODY" | python3 -m json.tool 2>/dev/null | head -30 | sed 's/^/    /' || echo "    ${FULL_BODY:0:300}"

# AWS-specific paths: if returned with EC2-like content = guest reached host EC2 IMDS.
# Impact per path: ami/instance-id/type → fingerprint & SSRF abuse; iam/ → credential theft; tags → env/pii.
declare -A IMDS_CHECKS=(
  ["/latest/meta-data/ami-id"]="^ami-"
  ["/latest/meta-data/instance-id"]="^i-"
  ["/latest/meta-data/instance-type"]="^[a-z][0-9]"
  ["/latest/meta-data/hostname"]="ec2|compute|internal"
  ["/latest/meta-data/local-ipv4"]="^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
  ["/latest/meta-data/mac"]="^[0-9a-f]{2}:"
  ["/latest/meta-data/placement/availability-zone"]="^[a-z]{2}-"
  ["/latest/meta-data/security-groups"]="."
  ["/latest/meta-data/profile"]="."
  ["/latest/meta-data/reservation-id"]="^r-"
  ["/latest/meta-data/services/domain"]="amazonaws"
  ["/latest/meta-data/services/partition"]="aws"
  ["/latest/meta-data/tags/instance"]="."
  ["/latest/meta-data/identity-credentials/"]="."
)

# Impact description for host IMDS leak (used in findings)
IMDS_IMPACT="影响: 可从 sandbox 内获取宿主 EC2 身份/凭据, 调用 AWS API 控制账户、读 S3/RDS、提权、横向移动"

IMDS_LEAKED=false
echo ""
info "1c-1. AWS-specific 元数据路径探测 (若命中则表明访问到宿主 IMDS):"
for path in "${!IMDS_CHECKS[@]}"; do
  pattern="${IMDS_CHECKS[$path]}"
  result=$(mmds_get "$path" "")
  code=$(get_code "$result")
  body=$(get_body "$result")

  if [[ "$code" == "200" && -n "$body" ]]; then
    if echo "$body" | grep -qiE "$pattern"; then
      finding_critical "R2" "宿主 IMDS 泄漏! ${path} → ${body:0:80} | ${IMDS_IMPACT}"
      IMDS_LEAKED=true
    else
      info "${path} → HTTP ${code}, 内容不匹配 EC2 模式: ${body:0:60}"
    fi
else
  ok "${path} → HTTP ${code} (不可达)"
  fi
done

# ── 1c-2: 网络接口与安全组 (若为宿主 IMDS 则暴露 ENI/SG, 用于后续利用) ──
# Impact: MAC list + per-MAC security-group-ids = map host to SGs; useful for firewall abuse or lateral movement.
echo ""
info "1c-2. 网络接口/安全组路径 (network/interfaces/macs/):"
MAC_LIST_RESULT=$(mmds_get "/latest/meta-data/network/interfaces/macs/" "")
MAC_LIST_CODE=$(get_code "$MAC_LIST_RESULT")
MAC_LIST_BODY=$(get_body "$MAC_LIST_RESULT")
if [[ "$MAC_LIST_CODE" == "200" && -n "$MAC_LIST_BODY" ]]; then
  if echo "$MAC_LIST_BODY" | grep -qE "([0-9a-f]{2}:){5}[0-9a-f]{2}"; then
    finding_critical "R2" "宿主网络接口 MAC 列表可读! | 影响: 可枚举 ENI, 进一步读 security-group-ids/local-ipv4 等, 用于网络拓扑与安全组滥用"
    IMDS_LEAKED=true
    echo "$MAC_LIST_BODY" | while read -r mac_line; do
      mac=$(echo "$mac_line" | tr -d '/')
      [[ -z "$mac" ]] && continue
      sg_result=$(mmds_get "/latest/meta-data/network/interfaces/macs/${mac}/security-group-ids" "")
      if [[ "$(get_code "$sg_result")" == "200" && -n "$(get_body "$sg_result")" ]]; then
        finding_high "R2" "该 MAC 的 security-group-ids 可读: $(get_body "$sg_result" | head -c 80)"
      fi
    done
  fi
else
  ok "network/interfaces/macs/ 不可达 (HTTP ${MAC_LIST_CODE})"
fi

# ── 1d: IAM 凭据直接获取 (最关键的检测) ──
# Impact: Attacker with these creds can call STS, S3, EC2, RDS, etc. per role policy; full account takeover if role is over-privileged.
echo ""
info "1d. IAM 凭据直接获取 (security-credentials/):"
IAM_PATH="/latest/meta-data/iam/security-credentials/"
iam_result=$(mmds_get "$IAM_PATH" "")
iam_code=$(get_code "$iam_result")
iam_body=$(get_body "$iam_result")

if [[ "$iam_code" == "200" && -n "$iam_body" && "$iam_body" != *"Not Found"* && "$iam_body" != *"404"* ]]; then
  finding_critical "R2" "IAM 角色可枚举! ${IAM_PATH} → ${iam_body:0:100} | 影响: 可列出宿主实例角色并逐角色拉取临时凭据, 按角色策略调用 AWS API (如 S3/EC2/RDS/SSM)"
  IMDS_LEAKED=true

  # 尝试获取每个角色的凭据
  echo "$iam_body" | tr ',' '\n' | tr -d ' "[]{}' | while read -r role; do
    [[ -z "$role" ]] && continue
    cred_result=$(mmds_get "${IAM_PATH}${role}" "")
    cred_code=$(get_code "$cred_result")
    cred_body=$(get_body "$cred_result")

    if [[ "$cred_code" == "200" ]] && echo "$cred_body" | grep -q "AccessKeyId"; then
      finding_critical "R2" "🔥 可获取 IAM 临时凭据! 角色: ${role} | 影响: 可直接用 AccessKeyId/SecretKey/SessionToken 调用 AWS CLI/SDK, 执行该角色权限内任意操作 (读写数据、创建资源、横向移动)"
      # 只打印键名和掩码值
      echo "$cred_body" | python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  for k in d:
    v = str(d[k])
    if len(v) > 12:
      print(f'      {k}: {v[:4]}****{v[-4:]}')
    else:
      print(f'      {k}: {v}')
except: print('      (解析失败)')
" 2>/dev/null
    elif [[ "$cred_code" == "200" ]]; then
      finding_high "R2" "IAM 角色 ${role} 返回数据但无标准凭据结构: ${cred_body:0:80} | 可能仍含敏感信息"
    fi
  done
else
  finding_pass "R2" "IAM 凭据路径不可达 (HTTP ${iam_code}) — 无法从 guest 获取宿主 IAM"
fi

# ── 1e: IAM info 端点 ──
# Impact: InstanceProfileArn reveals role name; attacker can then request credentials for that role via security-credentials/<role>.
echo ""
info "1e. IAM info 端点 (iam/info):"
iam_info_result=$(mmds_get "/latest/meta-data/iam/info" "")
iam_info_code=$(get_code "$iam_info_result")
iam_info_body=$(get_body "$iam_info_result")

if [[ "$iam_info_code" == "200" ]] && echo "$iam_info_body" | grep -q "InstanceProfileArn"; then
  finding_critical "R2" "IAM info 泄漏 Instance Profile: ${iam_info_body:0:150} | 影响: 暴露实例角色 ARN, 可据此请求该角色临时凭据并调用 AWS API"
  IMDS_LEAKED=true
else
  finding_pass "R2" "IAM info 不可达 (HTTP ${iam_info_code})"
fi

# ── 1f: user-data (可能含启动脚本/密码) ──
# Impact: user-data often contains bootstrap secrets, DB URLs, API keys; readable = credential/schema leak.
echo ""
info "1f. user-data 检查:"
ud_result=$(mmds_get "/latest/user-data" "")
ud_code=$(get_code "$ud_result")
ud_body=$(get_body "$ud_result")

if [[ "$ud_code" == "200" && -n "$ud_body" && ${#ud_body} -gt 10 ]]; then
  finding_high "R2" "user-data 可读 (${#ud_body} 字节) | 影响: 启动脚本/配置泄漏, 常含数据库连接串、密钥、内部端点"
  # 检查是否含敏感信息
  if echo "$ud_body" | grep -qiE "password|secret|key|token|aws_|AKIA|BEGIN.*PRIVATE"; then
    finding_critical "R2" "user-data 中包含疑似敏感信息! | 影响: 可直接获得密码/密钥, 用于登录数据库或调用外部服务"
  fi
  echo "    前 200 字节: ${ud_body:0:200}"
else
  finding_pass "R2" "user-data 不可达 (HTTP ${ud_code})"
fi

# ── 1f-2: 动态实例身份文档 (若为宿主 EC2 则可被用于 AssumeRole 等) ──
# Impact: Instance identity document is signed; if from host EC2, can be used to prove "I am this instance" for AWS APIs or custom auth.
echo ""
info "1f-2. 动态实例身份文档 (dynamic/instance-identity/document):"
DID_RESULT=$(mmds_get "/latest/dynamic/instance-identity/document" "")
DID_CODE=$(get_code "$DID_RESULT")
DID_BODY=$(get_body "$DID_RESULT")
if [[ "$DID_CODE" == "200" && -n "$DID_BODY" ]]; then
  if echo "$DID_BODY" | grep -q "availabilityZone\|instanceId\|region"; then
    finding_critical "R2" "实例身份文档可读 (含 availabilityZone/instanceId/region) | 影响: 可伪造实例身份、用于 AssumeRole 或自定义策略, 或泄露 VPC/区域/账户信息"
    IMDS_LEAKED=true
    echo "    文档摘要: ${DID_BODY:0:200}"
  else
    info "返回 200 但内容非 EC2 实例身份格式: ${DID_BODY:0:100}"
  fi
else
  ok "实例身份文档不可达 (HTTP ${DID_CODE})"
fi

# ── 1f-3: 块设备映射 (暴露 EBS 卷等, 可用于后续攻击) ──
# Impact: Block device mapping reveals volume IDs and attachment; combined with IAM could allow snapshot/volume manipulation.
echo ""
info "1f-3. 块设备映射 (block-device-mapping/):"
BDM_RESULT=$(mmds_get "/latest/meta-data/block-device-mapping/" "")
BDM_CODE=$(get_code "$BDM_RESULT")
BDM_BODY=$(get_body "$BDM_RESULT")
if [[ "$BDM_CODE" == "200" && -n "$BDM_BODY" ]]; then
  if echo "$BDM_BODY" | grep -qiE "ebs|ami|root|ephemeral|vol-"; then
    finding_high "R2" "块设备映射可读: ${BDM_BODY:0:120} | 影响: 暴露卷/AMI 挂载信息, 若同时获得 IAM 可操作 EBS 快照或卷"
    IMDS_LEAKED=true
  fi
else
  ok "block-device-mapping 不可达 (HTTP ${BDM_CODE})"
fi

# ── 1f-4: EC2 会话凭据 (identity-credentials/ec2/security-credentials/ec2-instance) ──
# Impact: Alternative path for instance credentials; same impact as security-credentials/<role>.
echo ""
info "1f-4. EC2 实例会话凭据路径 (identity-credentials/ec2/):"
EC2_CRED_RESULT=$(mmds_get "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance" "")
EC2_CRED_CODE=$(get_code "$EC2_CRED_RESULT")
EC2_CRED_BODY=$(get_body "$EC2_CRED_RESULT")
if [[ "$EC2_CRED_CODE" == "200" ]] && echo "$EC2_CRED_BODY" | grep -q "AccessKeyId"; then
  finding_critical "R2" "EC2 会话凭据 (identity-credentials/ec2) 可读! | 影响: 与 iam/security-credentials 等价, 可直接获取临时 AK/SK/Token 调用 AWS API"
  IMDS_LEAKED=true
else
  ok "identity-credentials/ec2 不可达或无凭据 (HTTP ${EC2_CRED_CODE})"
fi

# ── 1g: 最终 IMDS 判定 ──
echo ""
if [[ "$IMDS_LEAKED" == true ]]; then
  fail "═══ R2 结论: 🔥 宿主 EC2 IMDS 可从 sandbox 内访问! 凭据泄漏风险已确认! 影响: 攻击者可获取 IAM 凭据 → 调用 AWS API → 控制账户/数据/资源 (S3/RDS/SSM/EC2 等) ═══"
else
  ok "═══ R2 结论: Firecracker MMDS 正确隔离, 未发现宿主 IMDS 穿透 ═══"
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 2: [R1] VPC 横向移动 — 内网穿透                                  ║
# ║  Sandbox → 宿主 IP / VPC 内部服务 (Nomad, RDS, API Server)              ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 2 [R1]: VPC 横向移动检测 (CRITICAL)"

# ── 2a: 宿主 (网关) 端口扫描 ──
if [[ -n "$GW_IP" ]]; then
  info "2a. 网关/宿主 ${GW_IP} 端口扫描:"
  HOST_PORTS=(
    22    # SSH
    80    # HTTP
    443   # HTTPS
    2375  # Docker API (unencrypted)
    2376  # Docker API (TLS)
    4243  # Docker alt
    4646  # Nomad HTTP API ← R3 关键
    4647  # Nomad RPC
    4648  # Nomad Serf
    6443  # Kubernetes API
    8080  # 通用 HTTP / API Server
    8081  # 通用 HTTP
    8200  # Vault
    8300  # Consul Server RPC
    8301  # Consul Serf LAN
    8500  # Consul HTTP API
    8501  # Consul HTTPS
    8600  # Consul DNS
    9090  # Prometheus
    9100  # Node Exporter
    9200  # Elasticsearch
    10250 # Kubelet
    50051 # gRPC 常用
    3000  # Grafana / API
    5000  # 通用
    5432  # PostgreSQL ← R11 关键
    3306  # MySQL ← R11 关键
    6379  # Redis
    27017 # MongoDB
  )

  for port in "${HOST_PORTS[@]}"; do
    result=$(probe_port "$GW_IP" "$port")
    if [[ "$result" == "OPEN" ]]; then
      case $port in
        4646)
          finding_critical "R1/R3" "Nomad API ${GW_IP}:4646 从 sandbox 可达!"
          # 尝试访问 Nomad API
          nomad_resp=$(curl -s --connect-timeout 2 --max-time 3 "http://${GW_IP}:4646/v1/agent/self" 2>/dev/null || true)
          if echo "$nomad_resp" | grep -q "config\|member"; then
            finding_critical "R3" "Nomad API 无认证可访问! 可控制编排系统!"
            echo "    Nomad 响应 (前200字节): ${nomad_resp:0:200}"
          fi
          # 检查 Nomad jobs (sandbox 列表)
          nomad_jobs=$(curl -s --connect-timeout 2 --max-time 3 "http://${GW_IP}:4646/v1/jobs" 2>/dev/null || true)
          if echo "$nomad_jobs" | grep -q "ID\|Name"; then
            finding_critical "R3" "可列举 Nomad Jobs — 可看到/操纵其他 sandbox!"
            echo "    Jobs 数量: $(echo "$nomad_jobs" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null || echo 'N/A')"
          fi
          # 检查 Nomad 变量/secrets
          nomad_vars=$(curl -s --connect-timeout 2 --max-time 3 "http://${GW_IP}:4646/v1/vars" 2>/dev/null || true)
          if echo "$nomad_vars" | grep -qiE "token\|secret\|key\|password"; then
            finding_critical "R3" "Nomad 变量中包含敏感信息!"
          fi
          ;;
        4647)
          finding_high "R1/R3" "Nomad RPC ${GW_IP}:4647 可达"
          ;;
        4648)
          finding_medium "R1/R3" "Nomad Serf ${GW_IP}:4648 可达"
          ;;
        5432)
          finding_critical "R1/R11" "PostgreSQL ${GW_IP}:5432 从 sandbox 可达!"
          # 尝试无密码连接
          if command -v psql &>/dev/null; then
            pg_test=$(psql -h "$GW_IP" -U postgres -c "SELECT 1" 2>&1 || true)
            if echo "$pg_test" | grep -q " 1"; then
              finding_critical "R11" "PostgreSQL 无密码可连接!"
            fi
          fi
          ;;
        3306)
          finding_critical "R1/R11" "MySQL ${GW_IP}:3306 从 sandbox 可达!"
          ;;
        6379)
          finding_critical "R1" "Redis ${GW_IP}:6379 可达! 通常无认证!"
          redis_test=$(echo "INFO server" | nc -w2 "$GW_IP" 6379 2>/dev/null | head -5 || true)
          if echo "$redis_test" | grep -q "redis_version"; then
            finding_critical "R1" "Redis 无认证! 版本: $(echo "$redis_test" | grep redis_version)"
          fi
          ;;
        2375|4243)
          finding_critical "R1/R5" "Docker API ${GW_IP}:${port} 可达! 可能直接控制宿主!"
          docker_resp=$(curl -s --connect-timeout 2 "http://${GW_IP}:${port}/version" 2>/dev/null || true)
          if echo "$docker_resp" | grep -q "Version\|ApiVersion"; then
            finding_critical "R5" "Docker API 无认证! 可完全控制宿主容器!"
            echo "    Docker: ${docker_resp:0:200}"
          fi
          ;;
        8200)
          finding_high "R1" "Vault ${GW_IP}:8200 可达"
          vault_resp=$(curl -s --connect-timeout 2 "http://${GW_IP}:8200/v1/sys/health" 2>/dev/null || true)
          [[ -n "$vault_resp" ]] && echo "    Vault: ${vault_resp:0:150}"
          ;;
        8500)
          finding_high "R1" "Consul ${GW_IP}:8500 可达"
          consul_resp=$(curl -s --connect-timeout 2 "http://${GW_IP}:8500/v1/agent/self" 2>/dev/null || true)
          if echo "$consul_resp" | grep -q "Config\|Member"; then
            finding_high "R1" "Consul 无认证可访问"
          fi
          ;;
        9090)
          finding_medium "R1/R13" "Prometheus ${GW_IP}:9090 可达 — 监控数据泄漏"
          ;;
        9100)
          finding_medium "R1/R13" "Node Exporter ${GW_IP}:9100 可达 — 宿主指标泄漏"
          ;;
        22)
          finding_medium "R1" "SSH ${GW_IP}:22 可达"
          ;;
        *)
          finding_high "R1" "宿主端口 ${GW_IP}:${port} 可达"
          # 获取 banner
          banner=$(curl -s --connect-timeout 2 --max-time 3 "http://${GW_IP}:${port}/" 2>/dev/null | head -c 200 || true)
          [[ -n "$banner" ]] && echo "    HTTP 响应: ${banner:0:200}"
          ;;
      esac
    fi
  done
else
  warn "无法确定网关 IP, 跳过宿主端口扫描"
fi

# ── 2b: VPC 同子网存活探测 ──
echo ""
info "2b. 同子网存活主机探测 (${MY_SUBNET:-unknown}.0/24):"
if [[ -n "$MY_SUBNET" ]]; then
  VPC_LIVE_HOSTS=()
  # 采样关键地址
  SAMPLE_OCTETS=(1 2 3 4 5 10 20 50 100 150 200 250 254)
  for oct in "${SAMPLE_OCTETS[@]}"; do
    target="${MY_SUBNET}.${oct}"
    [[ "$target" == "$MY_IP" ]] && continue
    [[ "$target" == "$GW_IP" ]] && continue
    if ping -c1 -W1 "$target" &>/dev/null 2>&1; then
      VPC_LIVE_HOSTS+=("$target")
      warn "存活主机: ${target}"
    fi
  done
  if [[ ${#VPC_LIVE_HOSTS[@]} -gt 0 ]]; then
    finding_high "R1" "发现 ${#VPC_LIVE_HOSTS[@]} 个同子网存活主机 — 横向移动风险"
    # 对每个存活主机扫关键端口
    for host in "${VPC_LIVE_HOSTS[@]}"; do
      for port in 5432 3306 4646 8500 6379 22 80 443 8080; do
        if [[ $(probe_port "$host" "$port") == "OPEN" ]]; then
          finding_high "R1" "VPC 主机 ${host}:${port} 可达"
        fi
      done
    done
  else
    finding_pass "R1" "同子网未发现其他存活主机 (采样 ${#SAMPLE_OCTETS[@]} 个地址)"
  fi
fi

# ── 2c: 常见 VPC 内部服务端点 ──
echo ""
info "2c. 常见内部服务 DNS 解析:"
INTERNAL_NAMES=(
  "nomad" "nomad.service.consul" "consul" "vault"
  "api" "api-server" "rds" "database" "db"
  "redis" "elasticsearch" "grafana" "prometheus"
  "e2b-api" "orchestrator" "client-proxy"
)
for name in "${INTERNAL_NAMES[@]}"; do
  resolved=$(getent hosts "$name" 2>/dev/null | awk '{print $1}' || true)
  if [[ -n "$resolved" ]]; then
    finding_high "R1" "DNS 可解析: ${name} → ${resolved}"
  fi
done

# ── 2d: RDS 端点探测 (通常通过 DNS) ──
echo ""
info "2d. RDS 端点探测:"
# 从环境变量搜索数据库连接信息
DB_URLS=$(env 2>/dev/null | grep -iE "database|db_|rds|postgres|mysql|jdbc|conn" | head -10 || true)
if [[ -n "$DB_URLS" ]]; then
  finding_high "R1/R11" "环境变量中发现数据库配置:"
  echo "$DB_URLS" | sed 's/=.*/=***MASKED***/' | sed 's/^/    /'
fi

# 尝试直接连接常见 RDS 端口 (从 DNS)
RDS_PATTERNS=("*.rds.amazonaws.com" "*.cluster-*.*.rds.amazonaws.com")
rds_hosts=$(getent hosts 2>/dev/null | grep -i rds || true)
if [[ -n "$rds_hosts" ]]; then
  finding_high "R11" "可解析 RDS 主机: ${rds_hosts}"
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 3: [R3] Nomad 集群未授权访问                                      ║
# ║  (Phase 2 中已覆盖网关端口 4646; 此处补充公网 + 高级检查)                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 3 [R3]: Nomad 集群安全检测"

# ── 3a: 从 MMDS 数据推断 Nomad 配置 ──
info "3a. 从 MMDS/环境变量搜索 Nomad 信息:"
NOMAD_ADDR=$(env 2>/dev/null | grep -i NOMAD_ADDR | head -1 || true)
NOMAD_TOKEN=$(env 2>/dev/null | grep -i NOMAD_TOKEN | head -1 || true)

if [[ -n "$NOMAD_ADDR" ]]; then
  finding_high "R3" "环境变量包含 NOMAD_ADDR: $(echo "$NOMAD_ADDR" | cut -d'=' -f2)"
fi
if [[ -n "$NOMAD_TOKEN" ]]; then
  finding_critical "R3" "环境变量包含 NOMAD_TOKEN! Sandbox 持有 Nomad 凭据!"
fi

# ── 3b: Nomad API 功能探测 (如果可达) ──
NOMAD_ENDPOINTS=()
[[ -n "$GW_IP" ]] && NOMAD_ENDPOINTS+=("http://${GW_IP}:4646")
# 从环境变量获取额外 Nomad 地址
nomad_addr_val=$(echo "$NOMAD_ADDR" | cut -d'=' -f2- 2>/dev/null || true)
[[ -n "$nomad_addr_val" ]] && NOMAD_ENDPOINTS+=("$nomad_addr_val")

for nomad_base in "${NOMAD_ENDPOINTS[@]}"; do
  [[ -z "$nomad_base" ]] && continue
  info "3b. 测试 Nomad API: ${nomad_base}"

  # Agent self
  result=$(curl_get "${nomad_base}/v1/agent/self")
  code=$(get_code "$result")
  body=$(get_body "$result")
  if [[ "$code" == "200" ]]; then
    finding_critical "R3" "Nomad agent/self 可访问 — 集群信息泄漏"
  fi

  # 列举 jobs
  result=$(curl_get "${nomad_base}/v1/jobs")
  code=$(get_code "$result")
  body=$(get_body "$result")
  if [[ "$code" == "200" ]]; then
    job_count=$(echo "$body" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null || echo "?")
    finding_critical "R3" "可列举 Nomad Jobs (${job_count} 个) — 可查看/篡改所有 sandbox"
  fi

  # 列举 nodes
  result=$(curl_get "${nomad_base}/v1/nodes")
  code=$(get_code "$result")
  if [[ "$code" == "200" ]]; then
    finding_critical "R3" "可列举 Nomad Nodes — 集群拓扑泄漏"
  fi

  # 列举 allocations (可看到 sandbox 分配详情)
  result=$(curl_get "${nomad_base}/v1/allocations")
  code=$(get_code "$result")
  if [[ "$code" == "200" ]]; then
    finding_critical "R3" "可列举 Nomad Allocations — 所有 sandbox 运行状态泄漏"
  fi

  # 变量 (secrets)
  result=$(curl_get "${nomad_base}/v1/vars")
  code=$(get_code "$result")
  if [[ "$code" == "200" ]]; then
    finding_critical "R3" "可读取 Nomad Variables — 集群 secrets 泄漏!"
  fi

  # 尝试写入 (job 注入)
  info "3b-写入测试: 尝试提交伪造 Job (dry-run)..."
  write_result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" \
    -X POST "${nomad_base}/v1/jobs/parse" \
    -d '{"JobHCL": "job \"probe-test\" { type = \"batch\" group \"g\" { task \"t\" { driver = \"raw_exec\" config { command = \"/bin/echo\" args = [\"test\"] } } } }", "Canonicalize": true}' \
    2>/dev/null || echo "000")
  if [[ "$write_result" == "200" ]]; then
    finding_critical "R3" "Nomad 允许 Job 解析/提交 — 可注入恶意 sandbox!"
  else
    info "Job 解析被拒绝 (HTTP ${write_result})"
  fi
done

# ── 3c: Nomad UI ──
echo ""
info "3c. Nomad Dashboard 检测:"
for base in "${NOMAD_ENDPOINTS[@]}"; do
  [[ -z "$base" ]] && continue
  ui_result=$(curl_get "${base}/ui/")
  ui_code=$(get_code "$ui_result")
  ui_body=$(get_body "$ui_result")
  if [[ "$ui_code" == "200" ]] && echo "$ui_body" | grep -qi "nomad\|ember\|consul"; then
    finding_high "R3" "Nomad Dashboard UI 可访问: ${base}/ui/"
  fi
done


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 4: [R5] Sandbox 逃逸 / 宿主 Compromise                          ║
# ║  vsock + /dev + 内核模块 + capabilities + mount + Firecracker socket     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 4 [R5]: Sandbox 逃逸检测 (CRITICAL)"

# ── 4a: vsock 攻击面 ──
info "4a. vsock 攻击面:"
if [[ -e /dev/vsock ]]; then
  warn "/dev/vsock 存在"
  ls -la /dev/vsock 2>/dev/null | sed 's/^/    /'

  # 获取 guest CID
  GUEST_CID=$(cat /sys/devices/virtual/misc/vsock/cid 2>/dev/null || echo "unknown")
  info "Guest CID: ${GUEST_CID}"

  # 扫描宿主 (CID=2) 端口
  HOST_CID=2
  VSOCK_PORTS=(1 2 3 4 5 10 52 53 100 200 1024 2345 3000
               4000 4646 5000 8080 9090 10000 49982 49983 50051 50052)

  info "扫描宿主 (CID=${HOST_CID}) vsock 端口:"
  for port in "${VSOCK_PORTS[@]}"; do
    vsock_result=$(python3 -c "
import socket
try:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((${HOST_CID}, ${port}))
    s.close()
    print('OPEN')
except Exception as e:
    print('CLOSED')
" 2>/dev/null || echo "ERROR")

    if [[ "$vsock_result" == "OPEN" ]]; then
      finding_critical "R5" "vsock CID=${HOST_CID} port=${port} OPEN — 可连接宿主服务!"
      # 尝试读取 banner
      banner=$(python3 -c "
import socket
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.settimeout(3)
s.connect((${HOST_CID}, ${port}))
s.send(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
data = s.recv(1024)
s.close()
print(data[:300])
" 2>/dev/null || true)
      [[ -n "$banner" ]] && echo "    Banner: ${banner:0:200}"
    fi
  done

  # 探测相邻 CID (其他 sandbox, 测试 R14 跨会话隔离)
  echo ""
  info "4a-2. 相邻 CID 探测 (跨 sandbox 访问, R14):"
  for cid in 3 4 5 6 7 8 9 10 20 50 100; do
    [[ "$cid" == "$GUEST_CID" ]] && continue
    vsock_result=$(python3 -c "
import socket
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.settimeout(1)
s.connect(($cid, 52))
s.close()
print('OPEN')
" 2>/dev/null || echo "CLOSED")
    if [[ "$vsock_result" == "OPEN" ]]; then
      finding_critical "R5/R14" "vsock CID=${cid}:52 可达 — 跨 sandbox 访问!"
    fi
  done
else
  finding_pass "R5" "/dev/vsock 不存在"
fi

# ── 4b: 危险设备文件 ──
echo ""
info "4b. 危险设备检查:"
DANGEROUS_DEVS=(/dev/mem /dev/kmem /dev/port /dev/kcore
                /dev/sda /dev/vda /dev/loop-control
                /dev/kvm /dev/vhost-net /dev/vhost-vsock
                /dev/fuse /dev/btrfs-control)
for dev in "${DANGEROUS_DEVS[@]}"; do
  if [[ -e "$dev" ]]; then
    if [[ -r "$dev" ]]; then
      finding_high "R5" "${dev} 可读!"
    elif [[ -w "$dev" ]]; then
      finding_critical "R5" "${dev} 可写!"
    else
      info "${dev} 存在但不可读写"
    fi
  fi
done

# ── 4c: Capabilities 检查 ──
echo ""
info "4c. 进程 Capabilities:"
cap_status=$(grep -i cap /proc/self/status 2>/dev/null || true)
echo "$cap_status" | sed 's/^/    /'

# 解析 effective capabilities
cap_eff=$(echo "$cap_status" | grep CapEff | awk '{print $2}')
if [[ -n "$cap_eff" && "$cap_eff" != "0000000000000000" ]]; then
  # 检查危险 capabilities
  cap_eff_dec=$((16#${cap_eff}))
  # CAP_SYS_ADMIN = bit 21, CAP_NET_ADMIN = bit 12, CAP_SYS_PTRACE = bit 19
  if (( cap_eff_dec & (1 << 21) )); then
    finding_critical "R5" "CAP_SYS_ADMIN — 几乎等价于 root, 可逃逸!"
  fi
  if (( cap_eff_dec & (1 << 12) )); then
    finding_high "R5" "CAP_NET_ADMIN — 可修改网络配置, 潜在逃逸"
  fi
  if (( cap_eff_dec & (1 << 19) )); then
    finding_high "R5" "CAP_SYS_PTRACE — 可 ptrace 其他进程"
  fi
  if (( cap_eff_dec & (1 << 16) )); then
    finding_high "R5" "CAP_SYS_MODULE — 可加载内核模块!"
  fi
  if (( cap_eff_dec & (1 << 25) )); then
    finding_high "R5" "CAP_SYS_RAWIO — 可直接 I/O 访问"
  fi
  info "CapEff: 0x${cap_eff} (非全零 — 有特权 capabilities)"
else
  finding_pass "R5" "CapEff 为全零 — 无特权 capabilities"
fi

# ── 4d: seccomp 状态 ──
echo ""
info "4d. seccomp 状态:"
seccomp_status=$(grep -i seccomp /proc/self/status 2>/dev/null || true)
echo "$seccomp_status" | sed 's/^/    /'
seccomp_mode=$(echo "$seccomp_status" | grep "Seccomp:" | awk '{print $2}')
case "$seccomp_mode" in
  0) finding_medium "R5" "seccomp 未启用 (mode=0)" ;;
  1) finding_pass "R5" "seccomp strict mode (mode=1)" ;;
  2) finding_pass "R5" "seccomp filter mode (mode=2)" ;;
  *) info "seccomp 状态: ${seccomp_mode:-unknown}" ;;
esac

# ── 4e: 内核模块 & sysctl ──
echo ""
info "4e. 内核模块加载测试:"
modprobe_test=$(modprobe --dry-run dummy 2>&1 || true)
if echo "$modprobe_test" | grep -qv "denied\|not found\|not permitted\|ERROR\|FATAL"; then
  # modprobe 可能可用, 进一步确认
  insmod_test=$(insmod /dev/null 2>&1 || true)
  if echo "$insmod_test" | grep -qiE "invalid\|not a valid"; then
    finding_high "R5" "insmod 命令可执行 (虽然参数无效)"
  fi
else
  finding_pass "R5" "内核模块加载受限"
fi

echo ""
info "4e-2. sysctl 可写性:"
sysctl_test=$(sysctl -w kernel.hostname=probe-test 2>&1 || true)
if echo "$sysctl_test" | grep -q "= probe-test"; then
  finding_high "R5" "sysctl 可写! 可修改内核参数!"
  # 恢复
  sysctl -w kernel.hostname="$(hostname)" 2>/dev/null || true
else
  finding_pass "R5" "sysctl 不可写"
fi

# ── 4f: mount 权限 ──
echo ""
info "4f. mount 权限测试:"
test_mnt="/tmp/.probe_mount_test_$$"
mkdir -p "$test_mnt" 2>/dev/null || true
mount_test=$(mount -t tmpfs none "$test_mnt" 2>&1 || true)
if mountpoint -q "$test_mnt" 2>/dev/null; then
  finding_high "R5" "mount 可用! 可挂载文件系统!"
  umount "$test_mnt" 2>/dev/null || true
else
  finding_pass "R5" "mount 受限"
fi
rmdir "$test_mnt" 2>/dev/null || true

echo ""
info "4f-2. 当前挂载点:"
cat /proc/mounts 2>/dev/null | while read -r dev mnt fstype opts _rest; do
  if echo "$opts" | grep -q "rw"; then
    info "可写挂载: ${mnt} (${fstype}) on ${dev}"
  fi
done

# ── 4g: /proc 逃逸路径 ──
echo ""
info "4g. /proc 敏感路径:"
PROC_SENSITIVE=(
  /proc/1/root
  /proc/sysrq-trigger
  /proc/kcore
  /proc/kallsyms
  /proc/config.gz
  /proc/keys
  /proc/timer_list
)
for p in "${PROC_SENSITIVE[@]}"; do
  if [[ -r "$p" ]]; then
    finding_high "R5" "${p} 可读"
  elif [[ -w "$p" ]]; then
    finding_critical "R5" "${p} 可写!"
  else
    ok "${p} 不可访问"
  fi
done

# 特别检查: /proc/1/root 是否指向宿主根
if [[ -r /proc/1/root/etc/hostname ]]; then
  host_hostname=$(cat /proc/1/root/etc/hostname 2>/dev/null || true)
  my_hostname=$(hostname 2>/dev/null || true)
  if [[ -n "$host_hostname" && "$host_hostname" != "$my_hostname" ]]; then
    finding_critical "R5" "/proc/1/root 可访问, 且指向不同主机 (${host_hostname}) — 可能访问到宿主!"
  fi
fi

# ── 4h: Firecracker API socket 泄漏 ──
echo ""
info "4h. Firecracker API socket 搜索:"
SOCKET_SEARCH_PATHS=(
  /tmp/firecracker.socket /run/firecracker.socket
  /var/run/firecracker.socket /tmp/fc.sock /run/fc.sock
  /tmp/firecracker-*.socket
)
for sock_pattern in "${SOCKET_SEARCH_PATHS[@]}"; do
  for sock in $sock_pattern; do
    if [[ -S "$sock" ]]; then
      finding_critical "R5" "发现 Firecracker API socket: ${sock}"
      api_resp=$(curl -s --unix-socket "$sock" http://localhost/ 2>/dev/null || true)
      [[ -n "$api_resp" ]] && finding_critical "R5" "Firecracker API 可调用! 响应: ${api_resp:0:200}"
    fi
  done
done

# 搜索所有 unix socket
info "所有可见 unix socket:"
find / -type s 2>/dev/null | head -20 | while read -r sock; do
  echo "    ${sock}"
done

# ── 4i: sudo 权限 ──
echo ""
info "4i. sudo 权限:"
sudo_output=$(sudo -l 2>/dev/null || true)
if echo "$sudo_output" | grep -qiE "ALL|NOPASSWD"; then
  finding_high "R5" "sudo 可用! $(echo "$sudo_output" | grep -iE 'ALL|NOPASSWD' | head -3)"
else
  finding_pass "R5" "无危险 sudo 权限"
fi

# ── 4j: dmesg / 内核日志 ──
echo ""
info "4j. 内核日志可读性:"
dmesg_output=$(dmesg 2>/dev/null | head -5 || true)
if [[ -n "$dmesg_output" ]]; then
  finding_medium "R5" "dmesg 可读 — 内核信息泄漏"
  # 搜索有价值的信息
  dmesg 2>/dev/null | grep -iE "firecracker|amazon|kvm|hypervisor|virtio|error|panic|secret|token" | head -10 | sed 's/^/    /'
else
  finding_pass "R5" "dmesg 不可读"
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 5: [R4/R7] API 认证 & Sandbox URL 访问控制                       ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 5 [R4/R7]: API & Sandbox URL 认证检测"

# ── 5a: 从 MMDS/环境变量提取 E2B 配置 ──
info "5a. E2B 配置提取:"
MMDS_JSON="$FULL_BODY"

# 提取关键字段
E2B_ADDRESS=$(echo "$MMDS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('address',''))" 2>/dev/null || true)
E2B_ENV_ID=$(echo "$MMDS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('envID',''))" 2>/dev/null || true)
E2B_INSTANCE_ID=$(echo "$MMDS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('instanceID',''))" 2>/dev/null || true)
E2B_TEAM_ID=$(echo "$MMDS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('teamID',''))" 2>/dev/null || true)
E2B_TRACE_ID=$(echo "$MMDS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('traceID',''))" 2>/dev/null || true)

info "address:    ${E2B_ADDRESS:-N/A}"
info "envID:      ${E2B_ENV_ID:-N/A}"
info "instanceID: ${E2B_INSTANCE_ID:-N/A}"
info "teamID:     ${E2B_TEAM_ID:-N/A}"
info "traceID:    ${E2B_TRACE_ID:-N/A}"

# ── 5b: 检查 sandbox URL 是否需要认证 (R7) ──
echo ""
info "5b. Sandbox URL 认证检测 (R7):"
# 从地址推断 sandbox URL 格式
if [[ -n "$E2B_ADDRESS" ]]; then
  # 尝试无认证访问自身 sandbox
  for proto in "https" "http"; do
    url="${proto}://${E2B_ADDRESS}"
    auth_result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" "$url" 2>/dev/null || echo "000")
    if [[ "$auth_result" == "200" ]]; then
      finding_high "R7" "Sandbox URL ${url} 无认证可访问! HTTP ${auth_result}"
    elif [[ "$auth_result" == "401" || "$auth_result" == "403" ]]; then
      finding_pass "R7" "Sandbox URL 需要认证 (HTTP ${auth_result})"
    elif [[ "$auth_result" != "000" ]]; then
      info "Sandbox URL ${url} → HTTP ${auth_result}"
    fi
  done
fi

# ── 5c: E2B API Server 探测 ──
echo ""
info "5c. E2B API Server 探测 (R4):"
# 从环境变量或配置寻找 API server 地址
API_HOSTS=()
E2B_API=$(env 2>/dev/null | grep -iE "E2B_API|API_URL|API_HOST|API_SERVER" | head -5 || true)
if [[ -n "$E2B_API" ]]; then
  finding_medium "R4" "环境变量中发现 API 配置:"
  echo "$E2B_API" | sed 's/^/    /'
fi

# 尝试从网关和内网访问 API
API_PORTS=(3000 8000 8080 443 80)
for host in "$GW_IP" "api" "api-server" "e2b-api"; do
  [[ -z "$host" ]] && continue
  for port in "${API_PORTS[@]}"; do
    if [[ $(probe_port "$host" "$port" 2>/dev/null) == "OPEN" ]]; then
      for path in "/" "/health" "/api/health" "/api/v1/health" "/api/v1/sandboxes"; do
        api_result=$(curl_get "http://${host}:${port}${path}")
        api_code=$(get_code "$api_result")
        api_body=$(get_body "$api_result")
        if [[ "$api_code" == "200" ]]; then
          finding_high "R4" "API 端点可达: http://${host}:${port}${path} → HTTP ${api_code}"
          # 检查是否需要 API Key
          if echo "$api_body" | grep -qiE "sandbox\|instance\|env\|team"; then
            finding_critical "R4" "API 端点无认证返回数据: ${api_body:0:150}"
          fi
        fi
      done
    fi
  done
done


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 6: [R8] 环境变量凭据泄漏                                         ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 6 [R8]: 环境变量 & 凭据泄漏检测"

# ── 6a: 当前进程环境变量 ──
info "6a. 当前进程环境变量敏感信息检测:"
SENSITIVE_PATTERNS="(AWS_ACCESS_KEY|AWS_SECRET|AWS_SESSION_TOKEN|AKIA[0-9A-Z]{12}|DATABASE_URL|DB_PASS|NOMAD_TOKEN|CONSUL_TOKEN|VAULT_TOKEN|API_KEY|SECRET_KEY|PRIVATE_KEY|AUTH_TOKEN|BEARER|JWT_SECRET|SESSION_SECRET|CONN_STRING|REDIS_URL|POSTGRES|MYSQL)"

env 2>/dev/null | sort | while IFS='=' read -r key val; do
  [[ -z "$key" ]] && continue
  # 检查键名
  if echo "$key" | grep -qiE "token|secret|key|pass|auth|credential|private|jwt|bearer|session|database|conn|redis|postgres|mysql|nomad|consul|vault|aws"; then
    finding_high "R8" "敏感环境变量: ${key}=***MASKED*** (len=${#val})"
  fi
  # 检查值是否匹配 AWS key 模式
  if echo "$val" | grep -qoE "AKIA[0-9A-Z]{12,}"; then
    finding_critical "R8" "环境变量 ${key} 包含 AWS Access Key!"
  fi
done

# ── 6b: 所有进程环境变量 (如果可读) ──
echo ""
info "6b. 其他进程环境变量探测:"
for pid_dir in /proc/[0-9]*/environ; do
  pid=$(echo "$pid_dir" | cut -d'/' -f3)
  if [[ -r "$pid_dir" ]]; then
    cmd=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 80 || true)
    env_data=$(tr '\0' '\n' < "$pid_dir" 2>/dev/null || true)
    # 搜索 AWS 凭据
    if echo "$env_data" | grep -qoE "AKIA[0-9A-Z]{12,}"; then
      finding_critical "R8" "PID ${pid} (${cmd}) 环境变量包含 AWS Access Key!"
    fi
    if echo "$env_data" | grep -qiE "AWS_SECRET_ACCESS_KEY|NOMAD_TOKEN|CONSUL_TOKEN"; then
      finding_critical "R8" "PID ${pid} (${cmd}) 环境变量包含高敏感凭据!"
    fi
  fi
done 2>/dev/null

# ── 6c: MMDS 数据中的敏感信息 ──
echo ""
info "6c. MMDS 数据敏感信息审计:"
echo "$MMDS_JSON" | python3 -c "
import sys, json, re, math

data = sys.stdin.read()
# 检查 AWS 密钥模式
patterns = [
    (r'AKIA[0-9A-Z]{12,}', 'AWS Access Key'),
    (r'(?i)(password|passwd|secret|private.key)', 'Password/Secret'),
    (r'-----BEGIN', 'Private Key'),
    (r'(?i)(jdbc:|mysql://|postgres://|mongodb://|redis://)', 'Database Connection String'),
    (r'(?i)(Bearer |token[\":\s]=)', 'Token/Bearer'),
]
found = False
for pattern, label in patterns:
    matches = re.findall(pattern, data)
    if matches:
        print(f'  FINDING: {label} detected in MMDS data!')
        found = True

# 熵分析 — 高熵值可能是密钥
def entropy(s):
    if not s: return 0
    prob = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

try:
    d = json.loads(data)
    if isinstance(d, dict):
        for k, v in d.items():
            v_str = str(v)
            e = entropy(v_str)
            if e > 4.5 and len(v_str) > 24:
                print(f'  WARNING: High-entropy field [{k}]: entropy={e:.2f}, len={len(v_str)} — possible key/secret')
                found = True
except: pass

if not found:
    print('  OK: No obvious sensitive data in MMDS')
" 2>/dev/null || true

# ── 6d: 文件系统中的凭据搜索 ──
echo ""
info "6d. 文件系统凭据搜索:"
# 搜索常见凭据文件
CRED_FILES=(
  /root/.aws/credentials /root/.aws/config
  /home/*/.aws/credentials /home/*/.aws/config
  /etc/e2b/* /opt/e2b/*
  /run/secrets/* /tmp/*secret* /tmp/*token* /tmp/*credential*
  /var/run/secrets/*
  /root/.ssh/id_rsa /root/.ssh/id_ed25519
  /home/*/.ssh/id_rsa /home/*/.ssh/id_ed25519
  /etc/shadow
  /root/.env /home/*/.env
)
for pattern in "${CRED_FILES[@]}"; do
  for f in $pattern; do
    if [[ -r "$f" && -f "$f" ]]; then
      size=$(stat -c%s "$f" 2>/dev/null || echo "?")
      finding_high "R8" "可读敏感文件: ${f} (${size} bytes)"
      # 检查内容
      if grep -lqiE "AKIA|aws_secret|private.key|BEGIN.*PRIVATE" "$f" 2>/dev/null; then
        finding_critical "R8" "文件 ${f} 包含 AWS 凭据或私钥!"
      fi
    fi
  done 2>/dev/null
done


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 7: [R9] 资源滥用 & 出口流量                                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 7 [R9]: 资源限制 & 出口流量检测"

# ── 7a: cgroup 资源限制 ──
info "7a. cgroup 资源限制检查:"
# CPU 限制
CPU_QUOTA=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || \
            cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo "N/A")
CPU_PERIOD=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us 2>/dev/null || echo "N/A")
info "CPU quota: ${CPU_QUOTA}, period: ${CPU_PERIOD}"

# 内存限制
MEM_LIMIT=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || \
            cat /sys/fs/cgroup/memory.max 2>/dev/null || echo "N/A")
info "Memory limit: ${MEM_LIMIT}"

if [[ "$CPU_QUOTA" == "-1" || "$CPU_QUOTA" == "max" ]]; then
  finding_medium "R9" "CPU 无限制 (quota=${CPU_QUOTA})"
else
  finding_pass "R9" "CPU 有限制 (quota=${CPU_QUOTA})"
fi

if [[ "$MEM_LIMIT" == "9223372036854771712" || "$MEM_LIMIT" == "max" ]]; then
  finding_medium "R9" "内存无限制"
else
  mem_mb=$(( ${MEM_LIMIT:-0} / 1024 / 1024 )) 2>/dev/null || mem_mb="?"
  finding_pass "R9" "内存限制: ${mem_mb} MB"
fi

# PID 限制
PID_MAX=$(cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || \
          cat /sys/fs/cgroup/pids.max 2>/dev/null || echo "N/A")
info "PID max: ${PID_MAX}"

# ── 7b: 公网出口连通性 ──
echo ""
info "7b. 公网出口连通性:"
EGRESS_TARGETS=(
  "8.8.8.8|53|DNS"
  "1.1.1.1|53|DNS"
  "google.com|443|HTTPS"
  "api.e2b.dev|443|E2B API"
  "raw.githubusercontent.com|443|GitHub Raw"
  "pypi.org|443|PyPI"
  "registry.npmjs.org|443|npm"
)

for entry in "${EGRESS_TARGETS[@]}"; do
  IFS='|' read -r host port label <<< "$entry"
  if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
    info "出口可达: ${label} (${host}:${port})"
  else
    info "出口不可达: ${label} (${host}:${port})"
  fi
done

# ── 7c: 防火墙/egress 规则 ──
echo ""
info "7c. 防火墙规则:"
iptables -L -n -v 2>/dev/null | sed 's/^/    /' || echo "    iptables 不可用"
echo ""
nft list ruleset 2>/dev/null | head -30 | sed 's/^/    /' || echo "    nftables 不可用"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 8: [R10] 持久化控制 / 反弹 Shell                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 8 [R10]: 持久化控制 & TTL 执行检测"

# ── 8a: 检查 TTL 相关信号处理 ──
info "8a. TTL/销毁机制检查:"
# Nomad 通过 SIGTERM/SIGKILL 控制 sandbox 生命周期
# 如果 sandbox 能忽略 SIGTERM, 可能延迟销毁
signal_test=$(python3 -c "
import signal
try:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    print('SIGTERM_IGNORABLE')
except:
    print('SIGTERM_NOT_IGNORABLE')
" 2>/dev/null || echo "UNKNOWN")

if [[ "$signal_test" == "SIGTERM_IGNORABLE" ]]; then
  finding_medium "R10" "SIGTERM 可被忽略 — 恶意进程可延迟销毁"
else
  finding_pass "R10" "SIGTERM 处理正常"
fi

# ── 8b: 可用的网络工具 (反弹 shell 能力) ──
echo ""
info "8b. 网络/反弹 shell 工具可用性:"
SHELL_TOOLS=(nc ncat nmap socat python3 python perl ruby php wget curl ssh telnet
             bash zsh ksh dash busybox awk gawk openssl nohup screen tmux)
available_tools=()
for tool in "${SHELL_TOOLS[@]}"; do
  if command -v "$tool" &>/dev/null; then
    available_tools+=("$tool")
  fi
done
info "可用工具 (${#available_tools[@]}): ${available_tools[*]}"

# 关键工具告警
for critical_tool in nc ncat socat; do
  if command -v "$critical_tool" &>/dev/null; then
    finding_medium "R10" "反弹 shell 工具可用: ${critical_tool}"
  fi
done

# ── 8c: 后台进程能力 ──
echo ""
info "8c. 后台进程持久化能力:"
# 能否创建后台进程
if command -v nohup &>/dev/null; then
  info "nohup 可用"
fi

# crontab
crontab_test=$(crontab -l 2>&1 || true)
if echo "$crontab_test" | grep -qiE "no crontab|not allowed|denied"; then
  finding_pass "R10" "crontab 不可用"
else
  finding_medium "R10" "crontab 可能可用"
fi

# at 命令
if command -v at &>/dev/null; then
  finding_medium "R10" "at 调度命令可用"
fi

# systemd 用户服务
if command -v systemctl &>/dev/null; then
  if systemctl --user list-units 2>/dev/null | grep -q "loaded"; then
    finding_medium "R10" "systemd 用户服务可用"
  fi
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 9: [R6] Terraform State / 基础设施 Secrets 泄漏                   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 9 [R6/R11]: 基础设施 Secrets 泄漏检测"

# ── 9a: 文件系统搜索 Terraform state ──
info "9a. Terraform state 文件搜索:"
tf_files=$(find / -name "*.tfstate" -o -name "*.tfstate.backup" -o -name "terraform.tfvars" \
  -o -name "*.auto.tfvars" -o -name ".terraform" 2>/dev/null | head -20 || true)
if [[ -n "$tf_files" ]]; then
  finding_critical "R6" "发现 Terraform 文件!"
  echo "$tf_files" | sed 's/^/    /'
else
  finding_pass "R6" "未发现 Terraform state 文件"
fi

# ── 9b: S3 bucket 可达性 (Terraform remote state) ──
echo ""
info "9b. AWS S3 可达性 (Terraform remote state):"
if (echo >/dev/tcp/s3.amazonaws.com/443) 2>/dev/null; then
  info "S3 端点可达 — 如果获取到 IAM 凭据, 可尝试读取 remote state"
  # 如果 Phase 1 发现了 IAM 凭据泄漏, 这就是完整攻击链
  if [[ "$IMDS_LEAKED" == true ]]; then
    finding_critical "R6" "IMDS 凭据泄漏 + S3 可达 = 可能读取 Terraform remote state!"
  fi
else
  info "S3 不可达"
fi

# ── 9c: RDS 连通性详细检测 ──
echo ""
info "9c. RDS 详细检测 (R11):"
# 从环境变量提取数据库信息
DB_INFO=$(env 2>/dev/null | grep -iE "^(DATABASE|DB_|RDS_|PG|POSTGRES|MYSQL)" || true)
if [[ -n "$DB_INFO" ]]; then
  info "数据库相关环境变量:"
  echo "$DB_INFO" | sed 's/=.*/=***/' | sed 's/^/    /'
fi

# 扫描常见数据库端口 (宿主 + VPC)
DB_PORTS=(5432 3306 27017 6379 9200)
DB_HOSTS=("$GW_IP")
[[ -n "$MY_SUBNET" ]] && DB_HOSTS+=("${MY_SUBNET}.1" "${MY_SUBNET}.10" "${MY_SUBNET}.50" "${MY_SUBNET}.100")

for host in "${DB_HOSTS[@]}"; do
  [[ -z "$host" ]] && continue
  for port in "${DB_PORTS[@]}"; do
    if [[ $(probe_port "$host" "$port") == "OPEN" ]]; then
      case $port in
        5432) finding_critical "R11" "PostgreSQL ${host}:5432 可达!" ;;
        3306) finding_critical "R11" "MySQL ${host}:3306 可达!" ;;
        27017) finding_critical "R11" "MongoDB ${host}:27017 可达!" ;;
        6379)
          finding_critical "R11" "Redis ${host}:6379 可达!"
          # 无认证测试
          redis_resp=$(echo "PING" | nc -w2 "$host" 6379 2>/dev/null || true)
          if echo "$redis_resp" | grep -q "PONG"; then
            finding_critical "R11" "Redis ${host}:6379 无认证! 响应 PONG!"
          fi
          ;;
        9200) finding_high "R11" "Elasticsearch ${host}:9200 可达!" ;;
      esac
    fi
  done
done


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 10: [R14] 跨 Session/Sandbox 隔离                               ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 10 [R14]: 跨 Sandbox 隔离检测"

# ── 10a: 共享存储检查 ──
info "10a. 共享/持久存储检查:"
# 检查挂载点是否有共享卷
shared_mounts=$(cat /proc/mounts 2>/dev/null | grep -iE "nfs|cifs|shared|efs|fsx|overlay" || true)
if [[ -n "$shared_mounts" ]]; then
  finding_high "R14" "发现共享/网络存储挂载:"
  echo "$shared_mounts" | sed 's/^/    /'
fi

# 检查 /tmp 是否持久化 (不同 sandbox 之间)
echo ""
info "10a-2. 存储隔离验证:"
# 写一个唯一标记
PROBE_MARKER="e2b_probe_${RANDOM}_$(date +%s)"
echo "$PROBE_MARKER" > "/tmp/.isolation_test_$$" 2>/dev/null || true

# 检查是否有其他 probe 的残留
other_markers=$(find /tmp -name ".isolation_test_*" -not -name ".isolation_test_$$" 2>/dev/null || true)
if [[ -n "$other_markers" ]]; then
  finding_high "R14" "/tmp 中发现其他 session 的残留数据!"
  echo "$other_markers" | sed 's/^/    /'
fi
rm -f "/tmp/.isolation_test_$$" 2>/dev/null || true

# ── 10b: 网络隔离 — 其他 sandbox 的 IP ──
echo ""
info "10b. 其他 Sandbox 网络可达性:"
# 如果知道子网, 扫描相邻 IP
if [[ -n "$MY_IP" && -n "$MY_SUBNET" ]]; then
  my_last_octet=$(echo "$MY_IP" | cut -d'.' -f4)
  for offset in -5 -4 -3 -2 -1 1 2 3 4 5; do
    target_octet=$(( my_last_octet + offset ))
    (( target_octet < 1 || target_octet > 254 )) && continue
    target="${MY_SUBNET}.${target_octet}"
    if ping -c1 -W1 "$target" &>/dev/null 2>&1; then
      # 尝试连接常见 sandbox 端口
      for port in 49982 49983 3000 8080; do
        if [[ $(probe_port "$target" "$port") == "OPEN" ]]; then
          finding_critical "R14" "相邻 sandbox ${target}:${port} 可达! 跨 sandbox 访问!"
        fi
      done
    fi
  done
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 11: [R12/R15] 镜像安全 & 版本检测                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 11 [R12/R15]: 镜像安全 & 版本指纹"

# ── 11a: 系统版本信息 ──
info "11a. 系统版本:"
info "内核: $(uname -r 2>/dev/null || echo 'N/A')"
cat /etc/os-release 2>/dev/null | sed 's/^/    /'

echo ""
info "11a-2. 内核启动参数:"
cat /proc/cmdline 2>/dev/null | sed 's/^/    /'

# ── 11b: Firecracker 版本指纹 ──
echo ""
info "11b. Firecracker 版本指纹:"
# Server 头
server_header=$(curl -s -D- --connect-timeout "$TIMEOUT" \
  -H "X-metadata-token: ${TOKEN}" \
  "${MMDS}/" 2>/dev/null | grep -i "^Server:" | tr -d '\r' || true)
info "MMDS Server 头: ${server_header:-无}"

# DMI 信息
echo ""
info "11b-2. DMI/SMBIOS:"
for f in sys_vendor product_name product_version bios_vendor bios_version board_name; do
  val=$(cat /sys/class/dmi/id/${f} 2>/dev/null || echo "N/A")
  printf "    %-20s = %s\n" "$f" "$val"
done

# CPU hypervisor 检测
echo ""
info "11b-3. Hypervisor 信息:"
lscpu 2>/dev/null | grep -iE "hypervisor|vendor|model" | sed 's/^/    /' || true

# ── 11c: 已知漏洞快速检查 ──
echo ""
info "11c. 已知安全配置检查 (R15):"
# ASLR
aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "N/A")
if [[ "$aslr" == "2" ]]; then
  finding_pass "R15" "ASLR 已启用 (level=${aslr})"
elif [[ "$aslr" == "0" ]]; then
  finding_medium "R15" "ASLR 未启用!"
else
  info "ASLR level: ${aslr}"
fi

# NX (从 /proc/cpuinfo 检查)
if grep -q "nx" /proc/cpuinfo 2>/dev/null; then
  finding_pass "R15" "NX bit 已启用"
fi

# 包管理器可用的安全更新
if command -v apt &>/dev/null; then
  update_count=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
  if [[ "$update_count" -gt 0 ]]; then
    finding_low "R15" "${update_count} 个安全更新可用"
  fi
fi

# SUID 二进制
echo ""
info "11c-2. SUID/SGID 二进制文件:"
suid_files=$(find / -perm -4000 -type f 2>/dev/null | head -20 || true)
if [[ -n "$suid_files" ]]; then
  info "SUID 文件:"
  echo "$suid_files" | while read -r f; do
    echo "    ${f}"
    case "$f" in
      */nmap|*/gdb|*/python*|*/perl|*/ruby|*/vim|*/find|*/docker|*/strace)
        finding_high "R12/R5" "危险 SUID 二进制: ${f}" ;;
    esac
  done
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 12: [R13] 监控 & 审计能力检测                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 12 [R13]: 监控 & 审计能力"

# ── 12a: 日志可见性 ──
info "12a. 日志系统:"
echo ""
info "syslog:"
ls -la /var/log/syslog /var/log/messages /var/log/auth.log 2>/dev/null | sed 's/^/    /' || echo "    无标准日志文件"

echo ""
info "journald:"
journalctl --no-pager -n 5 2>/dev/null | sed 's/^/    /' || echo "    journald 不可用"

echo ""
info "审计系统 (auditd):"
if command -v auditctl &>/dev/null; then
  auditctl -l 2>/dev/null | sed 's/^/    /' || echo "    无审计规则"
else
  finding_low "R13" "auditd 未安装"
fi

# ── 12b: 检测能否清除自身痕迹 ──
echo ""
info "12b. 日志篡改能力:"
for logfile in /var/log/syslog /var/log/messages /var/log/auth.log; do
  if [[ -w "$logfile" ]]; then
    finding_medium "R13" "日志文件可写: ${logfile} — 攻击者可篡改日志"
  fi
done

# history 文件
if [[ -w "${HOME}/.bash_history" || -w "${HOME}/.history" ]]; then
  info "Shell history 可写 (可被清除)"
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 13: MMDS Token 安全 & 协议测试                                    ║
# ║  Impact focus: token theft/reuse, metadata poisoning, host file read  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 13: MMDS Token 安全与协议验证"

# ── 13a: Token TTL 边界 ──
# Impact: TTL > 21600 (6h) = stolen token valid longer; easier credential harvesting / replay.
info "13a. Token TTL 边界测试:"
TTL_VALUES=(0 1 21600 21601 86400 604800)
for ttl_val in "${TTL_VALUES[@]}"; do
  result=$(curl_get "${TOKEN_EP}" -X PUT -H "X-metadata-token-ttl-seconds: ${ttl_val}")
  code=$(get_code "$result")
  body=$(get_body "$result")
  if [[ "$code" == "200" ]]; then
    if [[ "$ttl_val" -gt 21600 ]]; then
      finding_medium "R2" "TTL=${ttl_val}s 超过 21600 仍被接受! | 影响: 窃取的 Token 有效期更长, 增加重放与凭据滥用窗口"
    else
      ok "TTL=${ttl_val}s → HTTP ${code}"
    fi
  else
    ok "TTL=${ttl_val}s → HTTP ${code} (被拒绝)"
  fi
done

# ── 13b: Token 过期验证 ──
# Impact: If expired token still accepted = session hijack / token reuse possible; weak revocation.
echo ""
info "13b. Token 过期验证:"
SHORT_TOKEN=$(curl -s -X PUT --connect-timeout "$TIMEOUT" \
  -H "X-metadata-token-ttl-seconds: 1" "${TOKEN_EP}" 2>/dev/null || true)
if [[ -n "$SHORT_TOKEN" && ${#SHORT_TOKEN} -gt 10 ]]; then
  sleep 3
  expired_result=$(curl_get "${MMDS}/" -H "X-metadata-token: ${SHORT_TOKEN}")
  expired_code=$(get_code "$expired_result")
  if [[ "$expired_code" != "200" ]]; then
    finding_pass "R2" "过期 Token 被正确拒绝 (HTTP ${expired_code}) — 无过期 Token 重放风险"
  else
    finding_high "R2" "过期 Token 仍被接受! HTTP ${expired_code} | 影响: 过期 Token 可被重放, 会话劫持或长期滥用已泄露 Token"
  fi
fi

# ── 13c: 伪造 Token ──
# Impact: Accepting fake/empty token = equivalent to IMDSv1; any process can read metadata without prior PUT.
echo ""
info "13c. 伪造 Token 测试:"
FAKE_TOKENS=("invalid_token" "$(head -c 48 /dev/urandom | base64 | head -c 48 || true)" "" "../../../etc/passwd")
FAKE_LABELS=("短字符串" "随机Base64" "空字符串" "路径遍历")
for i in "${!FAKE_TOKENS[@]}"; do
  ft="${FAKE_TOKENS[$i]}"
  label="${FAKE_LABELS[$i]}"
  result=$(curl_get "${MMDS}/" -H "X-metadata-token: ${ft}")
  code=$(get_code "$result")
  if [[ "$code" == "200" ]]; then
    finding_high "R2" "伪造 Token '${label}' 被接受! HTTP ${code} | 影响: 无需合法 Token 即可读元数据, 等同于 IMDSv1, SSRF/恶意代码可直接拉取凭据"
  else
    finding_pass "R2" "伪造 Token '${label}' 被拒绝 (HTTP ${code})"
  fi
done

# ── 13d: MMDS 写入保护 ──
# Impact: Guest can PUT/PATCH = metadata poisoning; downstream services may trust MMDS and get wrong config/creds; impersonation.
echo ""
info "13d. MMDS 写入保护验证:"
for method in PUT PATCH POST DELETE; do
  result=$(curl_get "${MMDS}/" -X "$method" \
    -H "X-metadata-token: ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"injected":"test"}')
  code=$(get_code "$result")
  if [[ "$code" == "200" || "$code" == "204" ]]; then
    finding_critical "R5" "MMDS ${method} 成功 (HTTP ${code}) — guest 可修改元数据! | 影响: 可篡改 MMDS 内容, 导致依赖元数据的服务读到错误配置/URL/凭据, 或用于冒充/投毒"
    # 验证是否真的写入
    verify_result=$(mmds_get "/injected" "")
    verify_body=$(get_body "$verify_result")
    if [[ "$verify_body" == "test" ]]; then
      finding_critical "R5" "确认: MMDS 写入已生效! guest 可修改自身元数据! | 影响: 下游逻辑若信任 MMDS 则可能使用被篡改数据, 引发配置注入或逻辑绕过"
    fi
  else
    finding_pass "R5" "MMDS ${method} 被拒绝 (HTTP ${code})"
  fi
done

# ── 13e: 关键路径遍历测试 ──
# Impact: Path traversal returning host file = guest can read host filesystem (e.g. /etc/passwd, SSH keys, env); full host compromise path.
echo ""
info "13e. MMDS 路径遍历 (高价值项):"
CRITICAL_PATHS=(
  "/../../../etc/passwd"
  "/..%2f..%2f..%2fetc%2fpasswd"
  "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  "/latest/meta-data/../../etc/passwd"
  "/latest/./meta-data/../../../etc/shadow"
)
for path in "${CRITICAL_PATHS[@]}"; do
  result=$(curl -s --connect-timeout "$TIMEOUT" --path-as-is -w "\n%{http_code}" \
    -H "X-metadata-token: ${TOKEN}" \
    "${MMDS}${path}" 2>/dev/null || true)
  code=$(echo "$result" | tail -1)
  body=$(echo "$result" | sed '$d')
  if [[ "$code" == "200" ]] && echo "$body" | grep -qiE "root:|bin/|passwd|shadow"; then
    finding_critical "R5" "MMDS 路径遍历成功! ${path} | 影响: Guest 可读宿主文件系统 (如 /etc/passwd/shadow), 进而可能获取密钥、配置或提权"
  else
    finding_pass "R5" "路径遍历被阻止: ${path} → HTTP ${code}"
  fi
done

# ── 13f: Token 请求方法限制 (仅 PUT 应返回 Token) ──
# Impact: GET/POST to token endpoint returning token = easier token harvesting via GET-only SSRF.
echo ""
info "13f. Token 端点方法限制 (仅 PUT 应成功):"
for method in GET POST; do
  tok_result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" -X "$method" "${TOKEN_EP}" 2>/dev/null || echo "000")
  if [[ "$tok_result" == "200" ]]; then
    finding_high "R2" "Token 端点接受 ${method} 且返回 200! | 影响: 仅支持 GET 的 SSRF 也可获取 Token, 扩大攻击面"
  else
    ok "Token 端点 ${method} → HTTP ${tok_result}"
  fi
done


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 14: 链路本地地址 & 备用元数据端点                                  ║
# ║  Impact: 169.254.170.2 = ECS task IAM; 169.254.169.253 = VPC DNS hijack  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 14: 链路本地地址与备用元数据端点"

# 169.254.170.2 = ECS task metadata; 169.254.169.253 = VPC DNS; 169.254.169.123 = Time Sync
LINK_LOCAL_IPS=(
  "169.254.170.2"      # ECS task metadata / container credentials
  "169.254.169.123"    # Amazon Time Sync
  "169.254.169.253"    # VPC DNS (Resolver)
  "169.254.0.1"
  "169.254.0.2"
  "169.254.1.1"
)

for ip in "${LINK_LOCAL_IPS[@]}"; do
  result=$(curl_get "http://${ip}/")
  code=$(get_code "$result")
  body=$(get_body "$result")
  if [[ "$code" != "000" && -n "$body" ]]; then
    case "$ip" in
      169.254.170.2)
        finding_high "R2" "链路本地 ${ip} (ECS 任务元数据) 有响应 HTTP ${code} | 影响: 若为宿主 ECS 则 guest 可访问任务 IAM 凭据, 与 IMDS 泄漏等价"
        ;;
      169.254.169.253)
        finding_high "R2" "链路本地 ${ip} (VPC DNS) 有响应 HTTP ${code} | 影响: 可探测或干扰 VPC DNS, 或结合其他漏洞进行 DNS 劫持/投毒"
        ;;
      169.254.169.123)
        finding_medium "R2" "链路本地 ${ip} (Time Sync) 有响应 | 影响: 时间同步服务暴露, 可能用于指纹或辅助攻击"
        ;;
      *)
        finding_high "R2" "链路本地地址 ${ip} 有响应 (HTTP ${code}) | 影响: 未预期服务暴露, 可能泄露配置或提供额外攻击面"
        ;;
    esac
    echo "    响应: ${body:0:150}"
    # 特别检查 ECS 凭据端点 (169.254.170.2)
    if [[ "$ip" == "169.254.170.2" ]]; then
      cred_result=$(curl_get "http://${ip}/v2/credentials/")
      cred_code=$(get_code "$cred_result")
      cred_body=$(get_body "$cred_result")
      if [[ "$cred_code" == "200" ]] && echo "$cred_body" | grep -q "AccessKeyId"; then
        finding_critical "R2" "ECS 任务凭据端点 ${ip}/v2/credentials/ 可达且返回 AccessKeyId! | 影响: 与宿主 EC2 IMDS 凭据泄漏等价, 攻击者可获任务角色临时凭据并调用 AWS API (S3/ECS/SSM 等)"
      fi
      # ECS task metadata (task role ARN, cluster, task id)
      task_meta=$(curl_get "http://${ip}/v2/metadata" "")
      if [[ "$(get_code "$task_meta")" == "200" ]]; then
        echo "    ECS v2/metadata 可读: $(get_body "$task_meta" | head -c 200)"
      fi
    fi
  fi
done


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 15: envd 守护进程安全                                             ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 15: envd 守护进程安全检测"

# ── 15a: envd 进程发现 ──
info "15a. envd / agent 进程搜索:"
envd_procs=$(ps aux 2>/dev/null | grep -iE "envd|e2b|agent|daemon|supervisor" | grep -v grep || true)
if [[ -n "$envd_procs" ]]; then
  echo "$envd_procs" | sed 's/^/    /'

  # 每个进程的详细信息
  echo "$envd_procs" | awk '{print $2}' | while read -r pid; do
    exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || echo 'N/A')
    cmd=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo 'N/A')
    echo "    PID ${pid}: ${exe}"
    echo "    CMD: ${cmd}"
    # 检查进程环境变量中的敏感信息
    proc_env=$(tr '\0' '\n' < "/proc/${pid}/environ" 2>/dev/null || true)
    if echo "$proc_env" | grep -qiE "AKIA|AWS_SECRET|NOMAD_TOKEN|password"; then
      finding_critical "R8" "envd 进程 (PID ${pid}) 环境变量包含敏感凭据!"
    fi
    echo ""
  done
fi

# ── 15b: envd 端口探测 & 认证检测 ──
echo ""
info "15b. envd 端口认证检测:"
ENVD_CANDIDATE_PORTS=(49982 49983 50051 50052 3000 8000)

for port in "${ENVD_CANDIDATE_PORTS[@]}"; do
  if [[ $(probe_port "127.0.0.1" "$port") == "OPEN" ]]; then
    info "127.0.0.1:${port} 开放"

    # HTTP 探测
    http_result=$(curl_get "http://127.0.0.1:${port}/")
    http_code=$(get_code "$http_result")
    http_body=$(get_body "$http_result")
    if [[ "$http_code" != "000" ]]; then
      echo "    HTTP: ${http_code} ${http_body:0:100}"
    fi

    # gRPC 反射 (如果有 grpcurl)
    if command -v grpcurl &>/dev/null; then
      services=$(grpcurl -plaintext "127.0.0.1:${port}" list 2>/dev/null || true)
      if [[ -n "$services" ]]; then
        info "gRPC 服务列表 (127.0.0.1:${port}):"
        echo "$services" | sed 's/^/    /'
        # 尝试无认证调用
        echo "$services" | while read -r svc; do
          [[ -z "$svc" ]] && continue
          methods=$(grpcurl -plaintext "127.0.0.1:${port}" list "$svc" 2>/dev/null || true)
          echo "$methods" | while read -r method; do
            [[ -z "$method" ]] && continue
            call_resp=$(grpcurl -plaintext "127.0.0.1:${port}" "$method" 2>&1 || true)
            if echo "$call_resp" | grep -qi "unauthenticated\|unauthorized"; then
              finding_pass "R7" "gRPC ${method} 需要认证"
            elif echo "$call_resp" | grep -qi "unimplemented"; then
              : # 忽略
            elif [[ -n "$call_resp" ]]; then
              finding_high "R7" "gRPC ${method} 无认证可调用!"
              echo "    响应: ${call_resp:0:200}"
            fi
          done
        done
      fi
    else
      # 无 grpcurl, HTTP/2 检测
      h2_resp=$(curl -s --connect-timeout 2 --http2-prior-knowledge \
        "http://127.0.0.1:${port}/" 2>/dev/null | head -c 200 || true)
      [[ -n "$h2_resp" ]] && info "HTTP/2 响应: ${h2_resp:0:100}"
    fi

    # 检查 0.0.0.0 绑定 (外部可达)
    if [[ $(probe_port "0.0.0.0" "$port") == "OPEN" ]]; then
      finding_high "R7" "端口 ${port} 绑定在 0.0.0.0 — 外部可达!"
    fi
  fi
done


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PHASE 16: AWS 服务端点可达性 (攻击链评估)                                ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "PHASE 16: AWS 服务端点可达性 (攻击链评估)"

info "如果 sandbox 同时获取到 IAM 凭据 (R2) 且可访问 AWS API, 构成完整攻击链"
echo ""

AWS_SERVICES=(
  "sts.amazonaws.com|443|STS (凭据验证)"
  "s3.amazonaws.com|443|S3 (数据/Terraform state)"
  "ec2.amazonaws.com|443|EC2 (实例控制)"
  "dynamodb.amazonaws.com|443|DynamoDB"
  "secretsmanager.amazonaws.com|443|Secrets Manager"
  "ssm.amazonaws.com|443|SSM (宿主命令执行)"
  "lambda.amazonaws.com|443|Lambda"
  "iam.amazonaws.com|443|IAM (权限提升)"
  "sqs.amazonaws.com|443|SQS"
  "sns.amazonaws.com|443|SNS"
  "rds.amazonaws.com|443|RDS API"
  "logs.amazonaws.com|443|CloudWatch Logs"
  "kms.amazonaws.com|443|KMS"
)

reachable_services=()
for entry in "${AWS_SERVICES[@]}"; do
  IFS='|' read -r host port label <<< "$entry"
  if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
    reachable_services+=("$label")
    info "可达: ${label} (${host}:${port})"
  fi
done

echo ""
if [[ ${#reachable_services[@]} -gt 0 ]]; then
  finding_medium "R2/R9" "${#reachable_services[@]} 个 AWS 服务端点可达"
  if [[ "$IMDS_LEAKED" == true ]]; then
    finding_critical "R2" "🔥 IMDS 凭据泄漏 + ${#reachable_services[@]} 个 AWS 端点可达 = 完整攻击链!"
    echo "    可达服务: ${reachable_services[*]}"
  fi
else
  finding_pass "R2" "无 AWS 服务端点可达"
fi


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  FINAL: 汇总报告                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝
header "FINAL: 安全评估汇总报告"

echo ""
echo "  ╔═══════════════════════════════════════════════════════════════════════╗"
echo "  ║  E2B Self-Hosted on AWS — Security Assessment Report                 ║"
echo "  ╠═══════════════════════════════════════════════════════════════════════╣"
echo "  ║  时间: $(ts)                                          ║"
echo "  ║  目标: Firecracker Sandbox (self-hosted E2B on AWS)                  ║"
printf "  ║  自身 IP: %-25s 网关: %-25s  ║\n" "${MY_IP:-N/A}" "${GW_IP:-N/A}"
echo "  ╠═══════════════════════════════════════════════════════════════════════╣"
echo "  ║                                                                       ║"
printf "  ║  🔴 CRITICAL findings: %-5d                                         ║\n" "${#FINDINGS_CRITICAL[@]}"
printf "  ║  🟠 HIGH findings:     %-5d                                         ║\n" "${#FINDINGS_HIGH[@]}"
printf "  ║  🟡 MEDIUM findings:   %-5d                                         ║\n" "${#FINDINGS_MEDIUM[@]}"
printf "  ║  🔵 LOW findings:      %-5d                                         ║\n" "${#FINDINGS_LOW[@]}"
printf "  ║  ✅ PASS checks:       %-5d                                         ║\n" "${#FINDINGS_PASS[@]}"
echo "  ║                                                                       ║"
echo "  ╚═══════════════════════════════════════════════════════════════════════╝"

# CRITICAL findings
if [[ ${#FINDINGS_CRITICAL[@]} -gt 0 ]]; then
  echo ""
  echo "  ┌─── 🔴 CRITICAL ──────────────────────────────────────────────────────┐"
  for f in "${FINDINGS_CRITICAL[@]}"; do
    echo "  │  $f"
  done
  echo "  └───────────────────────────────────────────────────────────────────────┘"
fi

# HIGH findings
if [[ ${#FINDINGS_HIGH[@]} -gt 0 ]]; then
  echo ""
  echo "  ┌─── 🟠 HIGH ──────────────────────────────────────────────────────────┐"
  for f in "${FINDINGS_HIGH[@]}"; do
    echo "  │  $f"
  done
  echo "  └───────────────────────────────────────────────────────────────────────┘"
fi

# MEDIUM findings
if [[ ${#FINDINGS_MEDIUM[@]} -gt 0 ]]; then
  echo ""
  echo "  ┌─── 🟡 MEDIUM ────────────────────────────────────────────────────────┐"
  for f in "${FINDINGS_MEDIUM[@]}"; do
    echo "  │  $f"
  done
  echo "  └───────────────────────────────────────────────────────────────────────┘"
fi

# LOW findings
if [[ ${#FINDINGS_LOW[@]} -gt 0 ]]; then
  echo ""
  echo "  ┌─── 🔵 LOW ───────────────────────────────────────────────────────────┐"
  for f in "${FINDINGS_LOW[@]}"; do
    echo "  │  $f"
  done
  echo "  └───────────────────────────────────────────────────────────────────────┘"
fi

# PASS checks
echo ""
echo "  ┌─── ✅ PASSED ──────────────────────────────────────────────────────────┐"
for f in "${FINDINGS_PASS[@]}"; do
  echo "  │  $f"
done
echo "  └───────────────────────────────────────────────────────────────────────┘"

# ── 风险矩阵对照 ──
echo ""
echo "  ┌─── Risk Matrix Coverage ───────────────────────────────────────────────┐"
echo "  │  R1  VPC 横向移动          Phase 2           $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R1' || echo 0) findings  │"
echo "  │  R2  IMDS 凭据泄漏         Phase 1,13,14,16  $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R2' || echo 0) findings  │"
echo "  │  R3  Nomad 未授权访问      Phase 2,3         $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R3' || echo 0) findings  │"
echo "  │  R4  API 弱认证            Phase 5           $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R4' || echo 0) findings  │"
echo "  │  R5  Sandbox 逃逸          Phase 4,13        $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R5' || echo 0) findings  │"
echo "  │  R6  Terraform State       Phase 9           $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R6' || echo 0) findings  │"
echo "  │  R7  Sandbox URL 访问      Phase 5,15        $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R7' || echo 0) findings  │"
echo "  │  R8  凭据泄漏              Phase 6           $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R8' || echo 0) findings  │"
echo "  │  R9  资源滥用              Phase 7,16        $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R9' || echo 0) findings  │"
echo "  │  R10 持久化控制            Phase 8           $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R10' || echo 0) findings │"
echo "  │  R11 RDS 暴露              Phase 2,9         $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R11' || echo 0) findings │"
echo "  │  R12 镜像安全              Phase 11          $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R12' || echo 0) findings │"
echo "  │  R13 监控审计              Phase 12          $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R13' || echo 0) findings │"
echo "  │  R14 跨会话隔离            Phase 4,10        $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R14' || echo 0) findings │"
echo "  │  R15 版本补丁              Phase 11          $(echo "${FINDINGS_CRITICAL[*]} ${FINDINGS_HIGH[*]}" | grep -c 'R15' || echo 0) findings │"
echo "  └────────────────────────────────────────────────────────────────────────┘"


# ── 导出 findings 供 Python 读取并保存结构化 JSON ──
export FINDINGS_CRITICAL_STR=$(IFS="|||"; echo "${FINDINGS_CRITICAL[*]}")
export FINDINGS_HIGH_STR=$(IFS="|||"; echo "${FINDINGS_HIGH[*]}")
export FINDINGS_MEDIUM_STR=$(IFS="|||"; echo "${FINDINGS_MEDIUM[*]}")
export FINDINGS_LOW_STR=$(IFS="|||"; echo "${FINDINGS_LOW[*]}")
export FINDINGS_PASS_STR=$(IFS="|||"; echo "${FINDINGS_PASS[*]}")
export MY_IP GW_IP DNS_SERVERS

python3 << 'PYEOF2'
import json, os, datetime

def split_findings(env_key):
    val = os.environ.get(env_key, "")
    return [x for x in val.split("|||") if x] if val else []

results = {
    "probe_version": "4.0",
    "timestamp": datetime.datetime.now().isoformat(),
    "target": "E2B Self-Hosted on AWS (Firecracker Sandbox)",
    "network": {
        "self_ip": os.environ.get("MY_IP", ""),
        "gateway": os.environ.get("GW_IP", ""),
        "dns": os.environ.get("DNS_SERVERS", ""),
    },
    "findings_summary": {
        "critical": len(split_findings("FINDINGS_CRITICAL_STR")),
        "high": len(split_findings("FINDINGS_HIGH_STR")),
        "medium": len(split_findings("FINDINGS_MEDIUM_STR")),
        "low": len(split_findings("FINDINGS_LOW_STR")),
        "pass": len(split_findings("FINDINGS_PASS_STR")),
    },
    "findings": {
        "critical": split_findings("FINDINGS_CRITICAL_STR"),
        "high": split_findings("FINDINGS_HIGH_STR"),
        "medium": split_findings("FINDINGS_MEDIUM_STR"),
        "low": split_findings("FINDINGS_LOW_STR"),
        "pass": split_findings("FINDINGS_PASS_STR"),
    },
}

outdir = "/tmp/e2b_security_probe_v4"
os.makedirs(outdir, exist_ok=True)
outpath = os.path.join(outdir, "results.json")
with open(outpath, "w") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"  JSON 结果: {outpath} ({os.path.getsize(outpath)} bytes)")
PYEOF2

echo ""
echo "  日志: ${LOGFILE}"
echo "  JSON: ${JSONFILE}"
echo ""
echo "  ════════════════════════════════════════════════════════"
echo "  探测完成: $(ts)"
echo "  ════════════════════════════════════════════════════════"
