import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const templatePath = path.join(root, 'local/src/index.template.html');
const corePath = path.join(root, 'local/src/ledger-core.cjs');
const outputPath = path.join(root, 'local/index.html');
const marker = '/*__LEDGER_CORE__*/';
const template = fs.readFileSync(templatePath, 'utf8');
if (template.split(marker).length !== 2) throw new Error('模板必须且只能包含一个核心模块占位符');
const core = fs.readFileSync(corePath, 'utf8');
const html = template.replace(marker, () => core);
fs.writeFileSync(outputPath, html);
console.log(`已生成 ${path.relative(root, outputPath)}（${Buffer.byteLength(html)} 字节，无外部依赖）`);
