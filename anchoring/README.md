# GitHub 外部锚点

`latest.json` 由 `.github/workflows/anchor.yml` 自动生成，不应手工编辑。

启用方法：在仓库 **Settings → Secrets and variables → Actions → Variables** 新建 `LEDGER_URL`，值为联网账本的公开地址，例如 `https://ledger.example.com`。该地址必须允许 GitHub Actions 匿名访问 `/api/anchor-proof`。

工作流每 15 分钟读取一次公开证明，重算锚链后只提交最新锚点。锚点没有前进时不会产生提交。也可以手动运行「发布简记外部锚点」工作流。

公开验证页默认读取本仓库 `main` 分支的 `anchoring/latest.json`。如果 fork 后更换仓库，请同步修改 `web/public/verify.js` 中的 `DEFAULT_ANCHOR_URL` 与 `ANCHOR_HISTORY_URL`。

锚点文件不包含密文、助记词、密钥包或账目明文。GitHub 提交时间由第三方平台保存，但 JSON 内的 `observedAt` 只是任务观察时间，不能替代 GitHub 提交历史本身。
