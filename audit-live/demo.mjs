#!/usr/bin/env node
// A fake audit that writes one file every few seconds, to watch the mod without running a real audit.
//   terminal 1: node demo.mjs          (prints the demo directory, then waits for Enter)
//   terminal 2: cd <demo directory> && claude --plugin-dir <this directory>, then /audit-live
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline/promises'

const root = join(tmpdir(), 'audit-live-demo')
const dir = join(root, '.security-audit')
const finding = (severity, status, title, source = 'auditor-auth') =>
  `---\nid: demo\ncategory: auth\nseverity: ${severity}\nstatus: ${status}\nsource_agent: ${source}\n---\n\n## Title\n${title}\n`
const ledger = (auditor, rows) => JSON.stringify({ schema_version: '1.0', entries: rows.map((r) => ({ auditor, target: '*', ...r })) })
const write = (path, text) => writeFileSync(join(dir, path), text)

const steps = [
  ['run starts', () => write('tools/workspace-mark.json', JSON.stringify({ at: new Date().toISOString() }))],
  ['pre-pass', () => write('prepass.md', 'demo')],
  ['recon', () => write('recon.md', 'demo')],
  ['finding: critical', () => write('findings/auth-101.md', finding('CRITICAL', 'raw', 'Any self-registered user becomes admin'))],
  ['finding: high', () => write('findings/auth-102.md', finding('HIGH', 'raw', 'Server action returns any organization invoice by id'))],
  ['verified safe', () => write('non-issues/non-auth-103.md', 'demo')],
  ['finding: medium', () => write('findings/config-301.md', finding('MEDIUM', 'raw', 'CORS reflects any origin', 'auditor-config'))],
  ['finding: high', () => write('findings/injection-201.md', finding('HIGH', 'raw', 'SSRF returns the response body', 'auditor-injection'))],
  ['auth auditor done', () => write('coverage/auditor-auth.json', ledger('auditor-auth', [
    { class: 'auth', status: 'checked', evidence: ['auth-101', 'auth-102'] },
    { class: 'upload', status: 'not_applicable', reason: 'no file uploads' },
    { class: 'concurrency', status: 'not_assessed', reason: 'needs the payment provider settings' },
  ]))],
  ['not assessed', () => write('not-assessed.md', '| Category | Check | Why |\n|---|---|---|\n| config | production env | not in the repo |\n')],
  ['verifier confirms one', () => write('findings/auth-101.md', finding('CRITICAL', 'verified', 'Any self-registered user becomes admin'))],
  ['verifier rejects one', () => write('findings/config-301.md', finding('MEDIUM', 'rejected', 'CORS reflects any origin', 'auditor-config'))],
  ['verifier confirms the rest', () => {
    write('findings/auth-102.md', finding('HIGH', 'verified', 'Server action returns any organization invoice by id'))
    write('findings/injection-201.md', finding('HIGH', 'verified', 'SSRF returns the response body', 'auditor-injection'))
  }],
  ['test quality', () => write('test-quality.md', 'demo')],
  ['report ready', () => write('report.html', '<p>demo</p>')],
]

rmSync(root, { recursive: true, force: true })
mkdirSync(join(dir, 'findings'), { recursive: true })
mkdirSync(join(dir, 'non-issues'), { recursive: true })
mkdirSync(join(dir, 'tools'), { recursive: true })
mkdirSync(join(dir, 'coverage'), { recursive: true })
console.log(`Demo directory: ${root}\nStart Claude Code there with this mod, type /audit-live, then press Enter here.`)
const rl = createInterface({ input: process.stdin })
await rl.question('')
rl.close()
const pause = Number(process.env.DEMO_PAUSE_MS ?? 4000)
for (const [label, run] of steps) {
  run()
  console.log(label)
  await new Promise((r) => setTimeout(r, pause))
}
console.log('done')
