// Live view of a running security audit. Read-only: it only lists and reads files under
// .security-audit/ in the session's working directory. No network, no processes, no writes.

const PANE = 'audit-live'
const DIR = '.security-audit'
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const COLORS = { CRITICAL: 'red', HIGH: '#ff8700', MEDIUM: 'yellow', LOW: 'gray' }
const SCAN_MS = 3000
const LATEST = 6

// name -> { size, finding }: a file is read again only when its size changes or on a full rescan
const cache = new Map()
// Finding ids already announced. null until the first scan, so a resumed audit does not toast its backlog.
let announced = null
// null while the working directory has no audit
let audit = null
let ticks = 0
let wasDone = false
let opened = false

export function parseFinding(name, text) {
  const front = text.startsWith('---') ? text.slice(3, text.indexOf('\n---', 3)) : ''
  const field = (key) => (front.match(new RegExp('^' + key + ':\\s*([A-Za-z_]+)', 'm')) || [])[1] || ''
  const title = (text.match(/^## Title\s*\n+(.+)/m) || [])[1]
  const severity = field('severity').toUpperCase()
  return {
    id: name.replace(/\.md$/, ''),
    severity: SEVERITIES.includes(severity) ? severity : 'LOW',
    status: field('status').toLowerCase() || 'raw',
    title: (title || name).trim(),
  }
}

function phaseOf(files, findings) {
  if (files.has('report.html')) return 'Done'
  if (files.has('test-quality.md')) return 'Report'
  if (!files.has('recon.md')) return files.has('prepass.md') ? 'Recon' : 'Pre-pass'
  const raw = findings.filter((f) => f.status === 'raw').length
  if (raw === findings.length) return 'Audit'
  return raw > 0 ? 'Verification' : 'Test quality'
}

async function markdownIn($, dir) {
  try {
    return (await $.fs.list(dir)).filter((e) => e.kind === 'file' && e.name.endsWith('.md'))
  } catch {
    return [] // the directory appears later in the run
  }
}

async function scan($) {
  if (!(await $.fs.exists(DIR))) {
    audit = null
    return
  }
  const files = new Set((await $.fs.list(DIR)).map((e) => e.name))
  const entries = await markdownIn($, DIR + '/findings')
  const full = ticks++ % 10 === 0
  for (const entry of entries) {
    const hit = cache.get(entry.name)
    if (hit && hit.size === entry.size && !full) continue
    const text = await $.fs.read(DIR + '/findings/' + entry.name)
    cache.set(entry.name, { size: entry.size, finding: parseFinding(entry.name, text) })
  }
  const names = new Set(entries.map((e) => e.name))
  for (const name of cache.keys()) if (!names.has(name)) cache.delete(name)

  const findings = [...cache.values()].map((c) => c.finding)
  const open = findings.filter((f) => f.status !== 'rejected')
  const count = (status) => findings.filter((f) => f.status === status).length
  let notAssessed = 0
  if (files.has('not-assessed.md')) {
    const rows = (await $.fs.read(DIR + '/not-assessed.md')).split('\n').filter((l) => l.startsWith('|'))
    notAssessed = Math.max(0, rows.length - 2) // minus the table header and its rule
  }
  audit = {
    phase: phaseOf(files, findings),
    bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length])),
    confirmed: count('verified'),
    unverified: count('raw'),
    filtered: count('rejected'),
    safe: (await markdownIn($, DIR + '/non-issues')).length,
    notAssessed,
    latest: open.slice(-LATEST).reverse(),
  }

  if (announced) {
    for (const f of open) if (!announced.has(f.id)) $.ui.toast(f.severity.toLowerCase() + ': ' + f.title)
    if (audit.phase === 'Done' && !wasDone) $.ui.toast('Audit finished: ' + DIR + '/report.html')
  }
  announced = new Set(findings.map((f) => f.id))
  wasDone = audit.phase === 'Done'

  // Opened by the mod itself, so Claude Code shows it only in a wide terminal; /audit-live opens it anywhere.
  if (!opened && !wasDone) {
    opened = true
    await $.ui.open({ id: PANE, title: 'Audit' })
  }
  $.ui.invalidate('ui.render')
}

export function register(on) {
  on('session.start', async ($, e, next) => {
    await $.command.register({ name: 'audit-live', description: 'Show live progress of the security audit', immediate: true })
    $.clock.every(SCAN_MS, async () => {
      await scan($)
    })
    return next(e)
  })

  on('command.run', { command: 'audit-live' }, async ($) => {
    opened = true // the scan must not open it a second time
    await scan($)
    if (!audit) {
      opened = false
      return { text: 'No ' + DIR + '/ directory here. Start an audit with /security-audit first.' }
    }
    await $.ui.open({ id: PANE, title: 'Audit', closeOnEscape: true })
    const counts = SEVERITIES.map((s) => audit.bySeverity[s] + ' ' + s.toLowerCase()).join(', ')
    return { text: audit.phase + ' · ' + counts + ' · ' + audit.safe + ' verified safe · ' + audit.notAssessed + ' not assessed' }
  })

  on('ui.render', { component: 'Spinner' }, async ($, e, next) => {
    if (!audit || audit.phase === 'Done') return next(e)
    const counts = SEVERITIES.filter((s) => audit.bySeverity[s]).map((s) => audit.bySeverity[s] + ' ' + s.toLowerCase())
    const suffix = ' · audit: ' + [audit.phase, ...counts].join(' · ')
    return next({ ...e, props: { ...e.props, suffix: (e.props.suffix || '') + suffix } })
  })

  on('ui.render', { component: 'Pane' }, async ($, e, next) => {
    if (e.requestId !== PANE) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    const line = (text, props = {}) => Text({ ...props, children: [text] })
    if (!audit) return Box({ flexDirection: 'column', children: [line('No audit in this directory.', { dimColor: true })] })

    return Box({
      flexDirection: 'column',
      children: [
        line('Phase: ' + audit.phase, { bold: true, color: audit.phase === 'Done' ? 'green' : undefined }),
        line(' '),
        ...SEVERITIES.map((s) =>
          line(String(audit.bySeverity[s]).padStart(3) + '  ' + s.toLowerCase(), {
            color: COLORS[s],
            bold: s === 'CRITICAL',
            dimColor: audit.bySeverity[s] === 0,
          }),
        ),
        line(' '),
        line(audit.confirmed + ' confirmed · ' + audit.unverified + ' unverified · ' + audit.filtered + ' filtered out'),
        line(audit.safe + ' verified safe', { color: 'green' }),
        line(audit.notAssessed + ' not assessed', { dimColor: true }),
        ...(audit.latest.length ? [line(' '), line('Latest', { bold: true })] : []),
        ...audit.latest.map((f) =>
          Box({
            flexDirection: 'row',
            columnGap: 1,
            children: [line(f.severity.toLowerCase().padEnd(8), { color: COLORS[f.severity] }), line(f.title, { wrap: 'truncate-end' })],
          }),
        ),
        ...(audit.phase === 'Done' ? [line(' '), line('Report: ' + DIR + '/report.html', { color: 'green' })] : []),
      ],
    })
  })
}
