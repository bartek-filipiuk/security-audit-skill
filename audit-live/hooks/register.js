// Live view of a running security audit. Read-only: it only lists and reads files under
// .security-audit/ in the session's working directory, and asks Claude Code for the session's own
// cost and context figure. No network, no processes, no writes.

const PANE = 'audit-live'
const DIR = '.security-audit'
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const COLORS = { CRITICAL: 'red', HIGH: '#ff8700', MEDIUM: 'yellow', LOW: 'gray' }
const SCAN_MS = 3000
const LATEST = 6
const USAGE_EVERY = 5 // scans between two $.session.usage calls
export const PHASES = ['Pre-pass', 'Recon', 'Audit', 'Verification', 'Test quality', 'Report']

// name -> { size, mtimeMs, finding }: a file is read again only when its size changes or on a full rescan
const cache = new Map()
// coverage ledger name -> { size, mtimeMs, rows }: rows is the last list that parsed
const ledgers = new Map()
let startedAt = null
let usage = null
// Finding ids already announced. null until the first scan, so a resumed audit does not toast its backlog.
let announced = null
// null while the working directory has no audit
let audit = null
let ticks = 0
let wasDone = false
let opened = false

export function parseFinding(name, text) {
  const front = text.startsWith('---') ? text.slice(3, text.indexOf('\n---', 3)) : ''
  const field = (key) => (front.match(new RegExp('^' + key + ':\\s*([A-Za-z0-9_-]+)', 'm')) || [])[1] || ''
  const title = (text.match(/^## Title\s*\n+(.+)/m) || [])[1]
  const severity = field('severity').toUpperCase()
  return {
    id: name.replace(/\.md$/, ''),
    severity: SEVERITIES.includes(severity) ? severity : 'LOW',
    status: field('status').toLowerCase() || 'raw',
    source: field('source_agent').toLowerCase(),
    title: (title || name).trim(),
  }
}

export function formatDuration(ms) {
  const s = Math.round(ms / 1000)
  if (s < 60) return s + 's'
  const m = Math.floor(s / 60)
  if (m < 60) return m + 'm ' + String(s % 60).padStart(2, '0') + 's'
  return Math.floor(m / 60) + 'h ' + String(m % 60).padStart(2, '0') + 'm'
}

// The end of each phase is the mtime of the file that phase writes last; null when it is not known.
// A finished phase shows end minus the previous end, the current one shows the time since the previous end.
export function phaseTimes({ phase, startedAt, ends, now }) {
  const current = PHASES.indexOf(phase) // -1 once the audit is Done
  const last = current === -1 ? PHASES.length : current
  const rows = []
  let previous = startedAt
  for (let i = 0; i <= last && i < PHASES.length; i++) {
    const end = i < last ? ends[PHASES[i]] : now
    const ms = previous != null && end != null && end >= previous ? end - previous : null
    rows.push({ phase: PHASES[i], ms, running: i === current })
    previous = i < last ? end : previous
  }
  const finish = current === -1 ? ends.Report : now
  const total = startedAt != null && finish != null && finish >= startedAt ? finish - startedAt : null
  return { rows, total }
}

const ALL_STATES = ['checked', 'not_applicable', 'not_assessed']

// One row per auditor: its findings that are still open, by severity, and the rows of its coverage ledger.
// done: its ledger exists; running: findings but no ledger yet.
export function auditorRows(findings, ledgerRows, ledgerOwners) {
  const byName = new Map()
  const row = (name) => {
    if (!byName.has(name)) {
      byName.set(name, {
        name,
        bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, 0])),
        ledger: Object.fromEntries(ALL_STATES.map((s) => [s, 0])),
        state: '—',
      })
    }
    return byName.get(name)
  }
  for (const f of findings) {
    if (!f.source.startsWith('auditor-') || f.status === 'rejected') continue
    const r = row(f.source)
    r.bySeverity[f.severity]++
    if (r.state === '—') r.state = 'running'
  }
  for (const entry of ledgerRows) {
    const r = row(entry.auditor)
    if (ALL_STATES.includes(entry.status)) r.ledger[entry.status]++
  }
  for (const name of ledgerOwners) row(name).state = 'done'
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name))
}

export function phaseOf(files, findings) {
  if (files.has('report.html')) return 'Done'
  if (files.has('test-quality.md')) return 'Report'
  if (!files.has('recon.md')) return files.has('prepass.md') ? 'Recon' : 'Pre-pass'
  const raw = findings.filter((f) => f.status === 'raw').length
  if (raw === findings.length) return 'Audit'
  return raw > 0 ? 'Verification' : 'Test quality'
}

async function filesIn($, dir, ext) {
  try {
    return (await $.fs.list(dir)).filter((e) => e.kind === 'file' && e.name.endsWith(ext))
  } catch {
    return [] // the directory appears later in the run
  }
}
const markdownIn = ($, dir) => filesIn($, dir, '.md')

const newest = (entries) => (entries.length ? Math.max(...entries.map((e) => e.mtimeMs || 0)) || null : null)

async function readStart($, files) {
  if (startedAt != null || !files.has('tools')) return
  try {
    const at = Date.parse(JSON.parse(await $.fs.read(DIR + '/tools/workspace-mark.json')).at)
    if (Number.isFinite(at)) startedAt = at
  } catch {
    // not written yet: the pre-pass writes it first thing
  }
}

// Writer ledgers only: carried.json holds rows of an earlier run and says nothing about this one.
async function scanLedgers($) {
  const entries = (await filesIn($, DIR + '/coverage', '.json')).filter(
    (e) => e.name === 'coordinator.json' || e.name.startsWith('auditor-'),
  )
  for (const entry of entries) {
    const hit = ledgers.get(entry.name)
    if (hit && hit.size === entry.size && hit.mtimeMs === entry.mtimeMs) continue
    let rows = hit ? hit.rows : []
    try {
      const owner = entry.name.replace(/\.json$/, '')
      rows = JSON.parse(await $.fs.read(DIR + '/coverage/' + entry.name)).entries.map((r) => ({
        auditor: typeof r.auditor === 'string' ? r.auditor : owner,
        status: r.status,
      }))
    } catch {
      // half written: keep the last rows that parsed
    }
    ledgers.set(entry.name, { size: entry.size, mtimeMs: entry.mtimeMs, rows })
  }
  const names = new Set(entries.map((e) => e.name))
  for (const name of ledgers.keys()) if (!names.has(name)) ledgers.delete(name)
  return entries
}

async function readUsage($) {
  try {
    const u = await $.session.usage()
    const usd = u?.cost?.usd
    const percent = u?.context?.percent
    usage = {
      usd: typeof usd === 'number' ? usd : null,
      percent: typeof percent === 'number' ? percent : null,
    }
  } catch {
    usage = null // not offered by this Claude Code: the line is left out
  }
}

export function usageLine(u) {
  if (!u || (u.usd == null && u.percent == null)) return null
  const parts = []
  if (u.usd != null) parts.push('$' + u.usd.toFixed(2))
  if (u.percent != null) parts.push('context ' + Math.round(u.percent) + '%')
  return 'Session (Claude Code): ' + parts.join(' · ')
}

async function scan($) {
  if (!(await $.fs.exists(DIR))) {
    audit = null
    startedAt = null
    return
  }
  const top = await $.fs.list(DIR)
  const files = new Set(top.map((e) => e.name))
  const mtime = (name) => top.find((e) => e.name === name)?.mtimeMs || null
  const entries = await markdownIn($, DIR + '/findings')
  const tick = ticks++
  const full = tick % 10 === 0
  for (const entry of entries) {
    const hit = cache.get(entry.name)
    if (hit && hit.size === entry.size && !full) {
      hit.mtimeMs = entry.mtimeMs
      continue
    }
    const text = await $.fs.read(DIR + '/findings/' + entry.name)
    cache.set(entry.name, { size: entry.size, mtimeMs: entry.mtimeMs, finding: parseFinding(entry.name, text) })
  }
  const names = new Set(entries.map((e) => e.name))
  for (const name of cache.keys()) if (!names.has(name)) cache.delete(name)
  const ledgerEntries = files.has('coverage') ? await scanLedgers($) : []
  await readStart($, files)
  if (tick % USAGE_EVERY === 0) await readUsage($)

  const findings = [...cache.values()].map((c) => c.finding)
  const phase = phaseOf(files, findings)
  const ends = {
    'Pre-pass': mtime('prepass.md'),
    Recon: mtime('recon.md'),
    Audit: newest(ledgerEntries),
    Verification: newest([...cache.values()].filter((c) => c.finding.status !== 'raw')),
    'Test quality': mtime('test-quality.md'),
    Report: mtime('report.html'),
  }
  let now = null
  try {
    now = await $.clock.now()
  } catch {
    // no clock: the current phase shows no elapsed time
  }
  const open = findings.filter((f) => f.status !== 'rejected')
  const count = (status) => findings.filter((f) => f.status === status).length
  let notAssessed = 0
  if (files.has('not-assessed.md')) {
    const rows = (await $.fs.read(DIR + '/not-assessed.md')).split('\n').filter((l) => l.startsWith('|'))
    notAssessed = Math.max(0, rows.length - 2) // minus the table header and its rule
  }
  const ledgerRows = [...ledgers.values()].flatMap((l) => l.rows)
  const owners = new Set(ledgerRows.map((r) => r.auditor).filter((a) => a.startsWith('auditor-')))
  for (const name of ledgers.keys()) if (name.startsWith('auditor-')) owners.add(name.replace(/\.json$/, ''))
  audit = {
    phase,
    times: phaseTimes({ phase, startedAt, ends, now: typeof now === 'number' ? now : null }),
    auditors: auditorRows(findings, ledgerRows.filter((r) => r.auditor.startsWith('auditor-')), owners),
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

function timeLines(times, line) {
  if (!times.rows.some((r) => r.ms != null)) return []
  const out = [line(' '), line('Phases' + (times.total != null ? ' · ' + formatDuration(times.total) : ''), { bold: true })]
  for (const r of times.rows) {
    const value = r.ms == null ? '—' : r.running ? 'running ' + formatDuration(r.ms) : formatDuration(r.ms)
    out.push(line(r.phase.padEnd(14) + value, { dimColor: !r.running && r.ms == null }))
  }
  return out
}

// Two lines per auditor: name, state and open findings by severity; then its ledger rows once it is done
export function auditorLines(a) {
  const sev = SEVERITIES.map((s) => a.bySeverity[s] + s[0].toLowerCase()).join(' ')
  const head = a.name.replace(/^auditor-/, '').padEnd(14) + a.state.padEnd(9) + sev
  if (a.state !== 'done') return [head]
  const l = a.ledger
  return [head, '  ' + l.checked + ' checked · ' + l.not_applicable + ' n/a · ' + l.not_assessed + ' not assessed']
}

function auditorSection(auditors, line) {
  if (!auditors.length) return []
  return [
    line(' '),
    line('Auditors', { bold: true }),
    ...auditors.flatMap((a) => auditorLines(a).map((text, i) => line(text, { wrap: 'truncate-end', dimColor: i > 0 }))),
  ]
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
    const total = audit.times.total != null ? ' · ' + formatDuration(audit.times.total) : ''
    const cost = usageLine(usage)
    return {
      text:
        audit.phase + total + ' · ' + counts + ' · ' + audit.safe + ' verified safe · ' + audit.notAssessed + ' not assessed' +
        (cost ? ' · ' + cost : ''),
    }
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
        ...timeLines(audit.times, line),
        ...auditorSection(audit.auditors, line),
        ...(usageLine(usage) ? [line(' '), line(usageLine(usage), { dimColor: true })] : []),
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
