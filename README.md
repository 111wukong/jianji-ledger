# 简记 · 离线优先的统一账本

一个「断网也能记、联网自动同步、记下就改不了」的记账系统。主应用只有一套账本、一套界面和一条记录流程：无论是否联网，都先在浏览器完成加密、签名和本机封存；恢复网络后，待同步记录按顺序自动上传。

## 核心能力

- **离线优先**：首次成功打开或安装应用后，应用外壳可离线加载。新身份可以离线创建，记录写入 IndexedDB 待同步队列；断网刷新后仍可用助记词解开本机记录。
- **联网自动同步**：监听网络恢复、页面重新可见和定时连接检查，按每批最多 50 条上传。也可点击顶部同步状态立即执行。
- **幂等与重试安全**：服务端按记录哈希识别已有记录。即使“写入成功但响应丢失”，重试也只会确认原记录，不会重复入账。
- **分叉保护**：本机已确认记录必须仍是服务端历史的严格前缀；另一设备形成不同历史时暂停同步，绝不自动覆盖或合并。
- **客户端加密**：摘要在浏览器中用助记词派生的密钥加密后才进入本机数据库或服务端。明文只存在于当前页面内存，服务端只见密文、不可逆账本标签、哈希和签名。
- **只追加与红字冲销**：没有修改或删除路径。记错时追加一笔等额反向记录，原记录与冲销记录都永久留痕。
- **公开验证与外部锚定**：公开层只放哈希承诺、签名和 Merkle 根；可用 GitHub 独立提交历史发现服务端回滚或整体替换。
- **选择性共享**：可把指定账本的数据密钥用另一身份的公钥封装后授权，撤销只影响之后的读取。
- **统一专业 UI**：总览、记账、明细、验证、共享、身份备份六个区域；支持深色/浅色主题、桌面侧栏和手机底部导航。

## 快速开始

```bash
npm start                 # 等价于 node web/server.mjs
# 默认 http://127.0.0.1:3000
PORT=8080 npm start       # 自定义端口
```

服务只依赖 Node.js 内置模块。监听地址由 `HOST` 控制，默认 `127.0.0.1`（仅本机访问）；要从局域网其他设备访问，设 `HOST=0.0.0.0`。事件日志写入 `web/data/events.jsonl`，启动时重放，运行时使用持久文件描述符同步追加。**生产部署必须为 `web/data/` 配置持久卷。**

首次使用：

1. 生成并离线抄写 16 个助记词。这是唯一恢复方式，服务端无法找回。
2. 直接进入统一账本。网络不可用时也可以创建身份、记账和冲销。
3. 顶部状态显示“离线可用 / 待同步 / 正在同步 / 已同步 / 同步已暂停”。
4. 恢复网络后自动上传，不需要手动补录或导入。
5. 在「身份备份」定期导出加密账本，文件同时包含已同步与待同步记录。
6. `/verify.html?fp=<身份指纹>` 是无需登录的公开验证页，可交给对账方独立核验。

### 离线使用边界

- 浏览器第一次从未访问过应用时，无法凭空离线下载应用；至少需要成功打开过一次，或安装为 PWA。
- 本机 IndexedDB 只保存密文与签名，不保存解密后的摘要。刷新或重新打开后，需要助记词才能查看内容。
- 清除浏览器数据会删除尚未上传的记录。重要账目应同时保留加密导出文件。
- 同一身份在多台设备同时离线追加可能产生分叉。当前版本会检测并暂停，提供备份保护，但不提供自动合并。

## 本机部署（macOS 常驻运行）

不依赖云服务器，直接在一台 Mac 上常驻运行，浏览器打开 `http://127.0.0.1:3000/` 即可记账。

```bash
# 1. 取一份代码到固定目录（不要放在会被清理的位置）
mkdir -p ~/Applications && cp -R . ~/Applications/jianji-ledger

# 2. 注册为登录自启服务（launchd）
cat > ~/Library/LaunchAgents/com.wukong.jianji-ledger.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.wukong.jianji-ledger</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/node</string>
    <string>/Users/你的用户名/Applications/jianji-ledger/web/server.mjs</string>
  </array>
  <key>WorkingDirectory</key><string>/Users/你的用户名/Applications/jianji-ledger</string>
  <key>EnvironmentVariables</key>
  <dict><key>PORT</key><string>3000</string><key>HOST</key><string>127.0.0.1</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
PLIST

launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.wukong.jianji-ledger.plist
launchctl print gui/$(id -u)/com.wukong.jianji-ledger | grep -E 'state|pid'
curl -s http://127.0.0.1:3000/api/health
```

要点：

- 账本数据只有 `web/data/events.jsonl` 一个文件，**删了就没了**；建议每天复制一份到别处：`cp ~/Applications/jianji-ledger/web/data/events.jsonl ~/Documents/events-$(date +%F).jsonl`
- 登录后自动启动，进程异常退出由 launchd 拉起；`launchctl kickstart -k gui/$(id -u)/com.wukong.jianji-ledger` 手动重启
- 升级：覆盖代码但保留 `web/data/`，再重启服务
- 助记词仍是唯一恢复方式，服务端和本机都无法代为找回

详见仓库根目录 `部署说明.md`。

## 启用 GitHub 外部锚定

1. 把主应用部署到 GitHub Actions 可匿名访问的 HTTPS 地址。
2. 在仓库 **Settings → Secrets and variables → Actions → Variables** 新建 `LEDGER_URL`，值为服务地址，不带 `/api/...` 后缀。
3. 手动运行「发布简记外部锚点」，或等待每 15 分钟一次的定时任务。
4. 工作流生成并提交 `anchoring/latest.json`；锚点未变化时不会重复提交。
5. 打开 `/verify.html`，点击「一键核验 GitHub 锚点」，也可导入锚点 JSON 文件核对。

验证口径：

- **外部锚定有效**：GitHub 最新锚点与当前锚链头一致。
- **等待新锚点**：旧锚点仍在当前历史中，但之后还有事件未被定时任务收录；这是快照滞后，不是篡改告警。
- **核验失败**：字段不一致、跨账本引用、锚点不在当前历史中，或当前锚链自身无效。

锚点文件只含公开哈希、序号、时间和公开地址，不含密文、助记词、密钥包或账目明文。

## 开发与测试

```bash
npm run build   # 重新构建兼容旧版单文件工具
npm test        # 账本、外部锚定、同步计划等 19 项核心测试
npm start       # 启动统一应用
```

可选真实浏览器回归（需要本机安装 Playwright 与 Chromium）：

```bash
npm run test:browser
# 或指定现有环境：
PLAYWRIGHT_PATH=/path/to/playwright CHROMIUM_PATH=/usr/bin/chromium node tests/browser-offline.mjs
```

该回归覆盖：断网记账、断网刷新后助记词恢复、联网自动上传、重复同步去重、红字冲销、375px 手机端横向溢出和控制台错误。测试前应使用空白测试账本，不得对真实数据运行。

目录结构：

```text
.
├── web/
│   ├── server.mjs                     # 只追加事件日志、幂等同步、公开接口
│   └── public/
│       ├── index.html / style.css / app.js
│       ├── offline-store.js           # IndexedDB 密文记录与待同步队列
│       ├── sync-core.cjs              # 纯同步计划、前缀与分叉检测
│       ├── sw.js                      # 离线应用外壳；不缓存 API
│       ├── manifest.webmanifest       # PWA 配置
│       ├── verify.html / verify.js
│       └── anchor-core.cjs            # 浏览器 / Node 共用锚定校验
├── local/                             # 旧版单文件工具，仅作兼容保留
│   ├── index.html
│   └── src/
├── tests/
│   ├── ledger-core.test.mjs
│   ├── anchor-core.test.mjs
│   ├── sync-core.test.mjs
│   └── browser-offline.mjs            # 可选真实浏览器端到端回归
├── scripts/                           # 单文件构建与外部锚点发布
├── .github/workflows/                 # 核心测试与外部锚定
├── docs/                              # 开发与合伙对账说明
├── anchoring/                         # 自动生成的公开锚点
├── Dockerfile
└── LICENSE
```

`local/` 是早期单文件工具的兼容保留，不是与主应用并列的另一种使用方式；新功能围绕 `web/` 的统一离线优先账本开发。

## 统一应用 API

公开接口（无需登录，永不含密文）：

| 接口 | 说明 |
|---|---|
| `GET /api/health` | 状态、身份数、记录数、Merkle 根、锚链头 |
| `GET /api/anchors` | 全局哈希承诺、各身份链头、近期锚点 |
| `GET /api/anchors/:fp` | 指定身份的纯哈希链与公钥 |
| `GET /api/anchor-proof` | 自包含锚定证明 |
| `GET /api/pub/:fp` | 身份公钥 |
| `POST /api/verify` | 服务端辅助校验 |
| `POST /api/lookup` | 按助记词校验值找回加密私钥包 |

会话与写入：`POST /api/challenge` → `POST /api/session`，之后使用 `GET /api/me`、`GET /api/entries`、`POST /api/entries`、`POST /api/entries/sync`、授权和撤销接口。

`POST /api/entries/sync` 每批接收 1–50 条记录，逐条校验并顺序追加。响应包含每条 `accepted / existing` 结果；中途遇到错误时，也会返回已处理结果，便于客户端先落盘再暂停。

服务端事件只有 `identity / entry / grant / revoke / anchor` 五类，没有修改或删除事件。

## 安全模型

**能防**：记录被改、被删、被乱序插入；服务端单方面修改历史；同步响应丢失导致重复记录；服务端拖库直接泄露明文；密文大小泄露摘要长度（512 字节定长填充）。启用外部锚定后，还可通过独立提交历史发现整体替换或回滚。

**不能防**：

- 客户端设备被攻破、助记词被钓鱼或泄露。
- 服务端运营方同时替换存储、客户端证明和外部锚定仓库；外部仓库应独立控制。
- 时间、笔数、频率、IP、记录大小等元数据泄露。
- 撤销对方已经看过或保存的内容。
- 非持久托管环境导致服务端事件日志丢失；生产必须配置持久卷。
- 哈希承诺不能证明业务真实发生，也不能替代票据、合同或审计程序。

**这不是审计级会计系统**，请勿直接用于法定账簿、税务申报或需要法律效力的合规场景。

## 后续方向

- 多设备分叉的人工核对与显式重建工具（不做静默覆盖合并）
- 服务端存储层抽象与持久化备份
- 按月份或记录范围的选择性披露
- 除 GitHub 外的公开时间戳、多机构交叉签名
- 元数据混淆与小程序端

## 许可证

[MIT](LICENSE) · Copyright (c) 2026 111wukong

提交代码前请运行 `npm run build && npm test`，并确认没有把 `web/data/` 下的真实账本、测试身份、测试锚点、助记词或密钥文件加入版本库。
