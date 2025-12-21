# LSR (Lightweight Split Routing)

轻量级分流规则生成工具，用于将原始域名列表转换为多种格式的分流规则文件。

## 功能特性

- 将原始域名列表转换为多种格式的分流规则
- 自动去重和去除子域名
- 支持并行处理提高效率
- 通过 GitHub Actions 自动生成 MRS 和 SRS 文件
- 支持 sing-box 规则格式
- 定期自动更新（每天 UTC 00:00）

## 项目结构

```
lsr/
├── domains/           # 原始域名列表
│   ├── block.txt      # 需拦截的域名
│   ├── direct.txt     # 直连域名
│   └── proxy.txt      # 需代理的域名
├── rules/             # 生成的规则文件
│   ├── block/         # 拦截规则
│   ├── direct/        # 直连规则
│   └── proxy/         # 代理规则
├── converter.py       # 规则转换脚本
└── .github/workflows/ # GitHub Actions 配置
    └── ci.yml         # CI 工作流配置
```

## 支持的规则格式

### 由 converter.py 直接生成：
- `adblock.txt` - AdBlock 拦截规则格式
- `classical.yaml` - Clash Classical YAML 格式（包含文件头和 payload 前缀）
- `classical.txt` - Clash Classical 文本格式（不包含文件头）
- `domain.yaml` - Domain YAML 格式（仅包含域名）
- `domain.txt` - Domain 文本格式（仅包含域名）
- `ipcidr.yaml` - IPCIDR YAML 格式（仅包含 IP 地址和 CIDR 范围）
- `ipcidr.txt` - IPCIDR 文本格式（仅包含 IP 地址和 CIDR 范围）
- `singbox.json` - sing-box JSON 格式（支持 version 3）

### 由 GitHub Actions 自动生成：
- `domain.mrs` - Domain 格式的 MRS 文件
- `ipcidr.mrs` - IPCIDR 格式的 MRS 文件
- `singbox.srs` - sing-box SRS 格式（二进制规则集）

## MRS 和 SRS 文件生成

MRS 和 SRS 文件是通过 GitHub Actions 自动生成的，生成流程如下：

1. 每当有代码推送到 main 分支、创建 Pull Request 或定期（每天 UTC 00:00）
2. CI 工作流自动运行 converter.py 生成基础规则文件（包含 classical.yaml、domain.yaml、ipcidr.yaml 和 singbox.json）
3. 下载并使用 Mihomo 工具将 domain.yaml 转换为 domain.mrs
4. 下载并使用 Mihomo 工具将 ipcidr.yaml 转换为 ipcidr.mrs
5. 下载并使用 sing-box 工具将 singbox.json 转换为 singbox.srs
6. 验证生成的所有规则文件（YAML、JSON、MRS、SRS）
7. 提交并推送更改到仓库

## 使用方法

### 直接使用规则文件

您可以直接使用 `rules/` 目录下的规则文件，根据您使用的客户端选择合适的格式。

### 本地生成规则

如果您想在本地生成规则文件，可以运行以下命令：

```bash
python converter.py
```

## 更新频率

- 代码更新时自动触发
- 每天 UTC 00:00 自动更新
