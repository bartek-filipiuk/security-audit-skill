import { expect, mock, test } from 'claude-code/testing'
import { auditorLines, auditorRows, formatDuration, parseFinding, phaseTimes } from '../hooks/register.js'

const finding = (severity: string, status: string, title: string, source = 'auditor-auth') =>
  `---\nid: x\ncategory: auth\nseverity: ${severity}\nstatus: ${status}\nsource_agent: ${source}\n---\n\n## Title\n${title}\n\n## Evidence\n`

// An in-memory .security-audit/ that answers the mod's $.fs calls
// Claude Code resolves a relative path against the working directory before the call reaches a stub
const rel = (path: string) => path.slice(path.indexOf('.security-audit'))

// mtimes: path -> mtimeMs, as fs.list reports it; a file without one reports 0 (unknown)
function fakeAudit(on: any, files: Map<string, string>, mtimes = new Map<string, number>()) {
  on('fs.exists', ($: any, e: any) => ({ value: [...files.keys()].some((p) => p.startsWith(rel(e.path) + '/')) }))
  on('fs.read', ($: any, e: any) => ({ value: files.get(rel(e.path)) ?? '' }))
  on('fs.list', ($: any, e: any) => {
    const names = new Map<string, { name: string; kind: string; size: number; mtimeMs: number; isLink: boolean }>()
    for (const [path, text] of files) {
      if (!path.startsWith(rel(e.path) + '/')) continue
      const [name, ...rest] = path.slice(rel(e.path).length + 1).split('/')
      const kind = rest.length ? 'directory' : 'file'
      names.set(name, { name, kind, size: rest.length ? 0 : text.length, mtimeMs: rest.length ? 0 : mtimes.get(path) ?? 0, isLink: false })
    }
    return { value: [...names.values()] }
  })
}

const PANE = {
  plugin: 'audit-live',
  component: 'Pane',
  requestId: 'audit-live',
  surface: 'terminal',
  viewport: { columns: 160, rows: 40 },
  props: { title: 'Audit', isFocused: false, bodyColumns: 50, placement: 'dock', scroll: { offset: 0, bodyRows: 30 }, view: {} },
} as const

test('parseFinding reads severity, status and title, and survives a malformed file', () => {
  expect(parseFinding('auth-101.md', finding('HIGH', 'verified', 'BOLA in invoices'))).toEqual({
    id: 'auth-101', severity: 'HIGH', status: 'verified', source: 'auditor-auth', title: 'BOLA in invoices',
  })
  expect(parseFinding('x-1.md', 'no frontmatter at all')).toEqual({ id: 'x-1', severity: 'LOW', status: 'raw', source: '', title: 'x-1.md' })
})

test('counts findings, announces only new ones and reports the end of the audit', async ($, on) => {
  const clock = mock.clock(on)
  const files = new Map<string, string>([
    ['.security-audit/prepass.md', 'x'],
    ['.security-audit/recon.md', 'x'],
    ['.security-audit/findings/auth-101.md', finding('CRITICAL', 'raw', 'Anyone becomes admin')],
    ['.security-audit/non-issues/non-auth-102.md', 'safe'],
    ['.security-audit/not-assessed.md', '| Category | Check | Why |\n|---|---|---|\n| config | prod env | not in repo |\n'],
  ])
  fakeAudit(on, files)
  const toasts: string[] = []
  const opens: string[] = []
  on('ui.toast', ($: any, e: any) => { toasts.push(e.text); return { value: undefined } })
  on('ui.open', ($: any, e: any) => { opens.push(e.id); return { value: { isPlaced: true } } })
  on('ui.invalidate', () => ({ value: undefined }))
  on('command.register', () => ({ value: undefined }))
  on('session.start', ($: any, e: any) => e)

  await $.session.start({ cwd: '/project', source: 'startup' })
  await clock.advance(3000)
  // The backlog found on the first scan is not announced, and the pane opens once
  expect(toasts).toEqual([])
  expect(opens).toEqual(['audit-live'])

  files.set('.security-audit/findings/injection-201.md', finding('HIGH', 'raw', 'SSRF returns the body'))
  await clock.advance(3000)
  expect(toasts).toEqual(['high: SSRF returns the body'])

  let ui = await $.ui.mount(PANE)
  expect(await ui.find({ type: 'Text', text: 'Phase: Audit' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: '  1  critical' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: '1 verified safe' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: '1 not assessed' })).toBeDefined()
  await ui.unmount()

  // The verifier rejects one and confirms the other; a rejected finding leaves the severity counts
  files.set('.security-audit/findings/auth-101.md', finding('CRITICAL', 'rejected', 'Anyone becomes admin'))
  files.set('.security-audit/findings/injection-201.md', finding('HIGH', 'verified', 'SSRF returns the body'))
  files.set('.security-audit/test-quality.md', 'x')
  files.set('.security-audit/report.html', '<html>')
  await clock.advance(3000)
  expect(toasts).toEqual(['high: SSRF returns the body', 'Audit finished: .security-audit/report.html'])

  ui = await $.ui.mount(PANE)
  expect(await ui.find({ type: 'Text', text: 'Phase: Done' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: '  0  critical' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: '1 confirmed · 0 unverified · 1 filtered out' })).toBeDefined()
  await ui.unmount()
  expect(opens).toEqual(['audit-live'])
})

test('source_agent keeps digits and hyphens', () => {
  expect(parseFinding('a-1.md', finding('LOW', 'raw', 't', 'auditor-rate-limit2')).source).toBe('auditor-rate-limit2')
})

test('formatDuration and phaseTimes', () => {
  expect(formatDuration(45_000)).toBe('45s')
  expect(formatDuration(185_000)).toBe('3m 05s')
  expect(formatDuration(3_780_000)).toBe('1h 03m')
  const ends = { 'Pre-pass': 60_000, Recon: 180_000, Audit: null, Verification: null, 'Test quality': null, Report: null }
  // Audit is running: finished phases show their length, the current one the time since Recon ended
  expect(phaseTimes({ phase: 'Audit', startedAt: 0, ends, now: 300_000 })).toEqual({
    rows: [
      { phase: 'Pre-pass', ms: 60_000, running: false },
      { phase: 'Recon', ms: 120_000, running: false },
      { phase: 'Audit', ms: 120_000, running: true },
    ],
    total: 300_000,
  })
  // An unknown end leaves that phase and the next one unknown, and a file rewritten later never gives a negative length
  const done = phaseTimes({
    phase: 'Done',
    startedAt: 0,
    ends: { 'Pre-pass': 60_000, Recon: 50_000, Audit: 400_000, Verification: null, 'Test quality': 500_000, Report: 520_000 },
    now: 999_999,
  })
  expect(done.rows.map((r) => r.ms)).toEqual([60_000, null, 350_000, null, null, 20_000])
  expect(done.total).toBe(520_000)
})

test('auditorRows: running without a ledger, done with one, rejected findings left out', () => {
  const f = (severity: string, status: string, source: string) => ({ id: 'x', severity, status, source, title: 't' })
  const rows = auditorRows(
    [f('HIGH', 'raw', 'auditor-auth'), f('LOW', 'rejected', 'auditor-auth'), f('MEDIUM', 'raw', 'auditor-config'), f('LOW', 'raw', 'recon')],
    [
      { auditor: 'auditor-auth', status: 'checked' },
      { auditor: 'auditor-auth', status: 'checked' },
      { auditor: 'auditor-auth', status: 'not_assessed' },
    ],
    new Set(['auditor-auth']),
  )
  expect(rows.map((r: any) => r.name + ':' + r.state)).toEqual(['auditor-auth:done', 'auditor-config:running'])
  expect(auditorLines(rows[0])).toEqual(['auth          done     0c 1h 0m 0l', '  2 checked · 0 n/a · 1 not assessed'])
  expect(auditorLines(rows[1])).toEqual(['config        running  0c 0h 1m 0l'])
})

test('pane shows phase times, auditors and the session figure', async ($, on) => {
  const clock = mock.clock(on) // starts at 0
  const files = new Map<string, string>([
    ['.security-audit/tools/workspace-mark.json', JSON.stringify({ at: new Date(0).toISOString() })],
    ['.security-audit/prepass.md', 'x'],
    ['.security-audit/recon.md', 'x'],
    ['.security-audit/findings/auth-101.md', finding('CRITICAL', 'raw', 'Anyone becomes admin')],
    ['.security-audit/findings/config-301.md', finding('MEDIUM', 'raw', 'CORS reflects any origin', 'auditor-config')],
    ['.security-audit/coverage/auditor-auth.json', JSON.stringify({
      schema_version: '1.0',
      entries: [
        { class: 'auth', target: '*', status: 'checked', auditor: 'auditor-auth', evidence: ['auth-101'] },
        { class: 'upload', target: '*', status: 'not_applicable', auditor: 'auditor-auth', reason: 'none' },
      ],
    })],
    // rows of an earlier run: not this run's ledger
    ['.security-audit/coverage/carried.json', JSON.stringify({ schema_version: '1.0', entries: [{ class: 'crypto', target: '*', status: 'checked', auditor: 'auditor-crypto', evidence: ['a:1'] }] })],
  ])
  const mtimes = new Map<string, number>([
    ['.security-audit/prepass.md', 65_000],
    ['.security-audit/recon.md', 185_000],
    ['.security-audit/coverage/auditor-auth.json', 240_000],
    ['.security-audit/coverage/carried.json', 900_000],
  ])
  fakeAudit(on, files, mtimes)
  on('session.usage', () => ({ value: { startedAt: 'x', context: { tokens: 84_000, window: 200_000, percent: 42 }, rateLimits: [], cost: { usd: 1.234 } } }))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.invalidate', () => ({ value: undefined }))
  on('command.register', () => ({ value: undefined }))
  on('session.start', ($: any, e: any) => e)

  await $.session.start({ cwd: '/project', source: 'startup' })
  await clock.advance(300_000)

  let ui = await $.ui.mount(PANE)
  expect(await ui.find({ type: 'Text', text: 'Phase: Audit' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Pre-pass      1m 05s' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Recon         2m 00s' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Audit         running 1m 55s' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'auth          done     1c 0h 0m 0l' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: '  1 checked · 1 n/a · 0 not assessed' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'config        running  0c 0h 1m 0l' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Session (Claude Code): $1.23 · context 42%' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /^crypto/ })).toBeUndefined()
  await ui.unmount()

  // The verifier confirms both, then the last phases finish
  files.set('.security-audit/findings/auth-101.md', finding('CRITICAL', 'verified', 'Anyone becomes admin'))
  files.set('.security-audit/findings/config-301.md', finding('MEDIUM', 'verified', 'CORS reflects any origin', 'auditor-config'))
  mtimes.set('.security-audit/findings/auth-101.md', 330_000)
  mtimes.set('.security-audit/findings/config-301.md', 360_000)
  files.set('.security-audit/test-quality.md', 'x')
  mtimes.set('.security-audit/test-quality.md', 420_000)
  files.set('.security-audit/report.html', '<html>')
  mtimes.set('.security-audit/report.html', 450_000)
  await clock.advance(200_000)

  ui = await $.ui.mount(PANE)
  expect(await ui.find({ type: 'Text', text: 'Phase: Done' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Phases · 7m 30s' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Audit         55s' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Verification  2m 00s' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Test quality  1m 00s' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: 'Report        30s' })).toBeDefined()
  await ui.unmount()
})

test('without session.usage or timestamps the pane still renders, minus those lines', async ($, on) => {
  const clock = mock.clock(on)
  fakeAudit(on, new Map([['.security-audit/prepass.md', 'x']]))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.invalidate', () => ({ value: undefined }))
  on('command.register', () => ({ value: undefined }))
  on('session.start', ($: any, e: any) => e)
  await $.session.start({ cwd: '/project', source: 'startup' })
  await clock.advance(3000)
  const ui = await $.ui.mount(PANE)
  expect(await ui.find({ type: 'Text', text: 'Phase: Recon' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /^Session/ })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: /^Phases/ })).toBeUndefined()
  await ui.unmount()
  const out = await $.command.run({ command: 'audit-live' })
  expect(out.text).toBe('Recon · 0 critical, 0 high, 0 medium, 0 low · 0 verified safe · 0 not assessed')
})
