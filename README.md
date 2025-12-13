# LSR (Lightweight Split Routing)

轻量级分流规则生成工具，用于将原始域名列表转换为多种格式的分流规则文件。

## 功能特性

- 将原始域名列表转换为多种格式的分流规则
- 支持 Clash、Loon 等客户端格式
- 通过 GitHub Actions 自动生成 MRS 文件
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

- `clash.yaml` - Clash 配置格式
- `clash.json` - Clash JSON 格式
- `loon.lsr` - Loon 规则格式
- `clash.mrs` - MRS 格式（由 GitHub Actions 自动生成）

## MRS 文件生成

MRS 文件是通过 GitHub Actions 自动生成的，生成流程如下：

1. 每当有代码推送到 main 分支或定期（每天 UTC 00:00）
2. CI 工作流自动运行 converter.py 生成基础规则文件
3. 下载并使用 Mihomo 工具将 Clash YAML 转换为 MRS 格式
4. 验证生成的文件并提交到仓库

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
