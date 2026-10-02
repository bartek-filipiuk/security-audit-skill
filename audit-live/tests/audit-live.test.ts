import { expect, mock, test } from 'claude-code/testing'
import { parseFinding } from '../hooks/register.js'

const finding = (severity: string, status: string, title: string) =>
  `---\nid: x\ncategory: auth\nseverity: ${severity}\nstatus: ${status}\n---\n\n## Title\n${title}\n\n## Evidence\n`

// An in-memory .security-audit/ that answers the mod's $.fs calls
// Claude Code resolves a relative path against the working directory before the call reaches a stub
const rel = (path: string) => path.slice(path.indexOf('.security-audit'))

function fakeAudit(on: any, files: Map<string, string>) {
  on('fs.exists', ($: any, e: any) => ({ value: [...files.keys()].some((p) => p.startsWith(rel(e.path) + '/')) }))
  on('fs.read', ($: any, e: any) => ({ value: files.get(rel(e.path)) ?? '' }))
  on('fs.list', ($: any, e: any) => {
    const names = new Map<string, { name: string; kind: string; size: number; isLink: boolean }>()
    for (const [path, text] of files) {
      if (!path.startsWith(rel(e.path) + '/')) continue
      const [name, ...rest] = path.slice(rel(e.path).length + 1).split('/')
      names.set(name, { name, kind: rest.length ? 'directory' : 'file', size: rest.length ? 0 : text.length, isLink: false })
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
    id: 'auth-101', severity: 'HIGH', status: 'verified', title: 'BOLA in invoices',
  })
  expect(parseFinding('x-1.md', 'no frontmatter at all')).toEqual({ id: 'x-1', severity: 'LOW', status: 'raw', title: 'x-1.md' })
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
