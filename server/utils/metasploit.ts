import { access, mkdir, readdir, readFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { join, relative } from 'node:path'
import { and, eq, inArray, ne } from 'drizzle-orm'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { matchExploitProduct } from '~/utils/exploitProductHints'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'
import { setMetadata } from './sqlite'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase
} from './import-progress'

const METASPLOIT_REPO_URL = 'https://github.com/rapid7/metasploit-framework.git'
const METASPLOIT_BRANCH = 'master'
const CACHE_DIR = join(process.cwd(), 'data', 'cache', 'metasploit')
const REPO_DIR = join(CACHE_DIR, 'metasploit-framework')
const MODULES_DIR = join(REPO_DIR, 'modules', 'exploits')

const RE_CVE_GENERIC = /CVE[-\s_]*(\d{4})[-\s_]?([0-9]{4,7})/gi
const RE_VENDOR_ADVISORY = /^[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{4}-\d{2,}$/i

type GitResult = { stdout: string; stderr: string }

const runGit = async (args: string[], cwd: string): Promise<GitResult> => {
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []

    child.stdout.on('data', chunk => stdoutChunks.push(Buffer.from(chunk)))
    child.stderr.on('data', chunk => stderrChunks.push(Buffer.from(chunk)))

    child.on('error', reject)
    child.on('close', code => {
      const stdout = Buffer.concat(stdoutChunks).toString('utf8').trim()
      const stderr = Buffer.concat(stderrChunks).toString('utf8').trim()
      if (code === 0) {
        resolve({ stdout, stderr })
      } else {
        const error = new Error(`git ${args.join(' ')} failed${stderr ? `: ${stderr}` : ''}`)
        reject(error)
      }
    })
  })
}

const pathExists = async (target: string): Promise<boolean> => {
  try {
    await access(target)
    return true
  } catch {
    return false
  }
}

const ensureCacheDir = async () => {
  await mkdir(CACHE_DIR, { recursive: true })
}

const syncRepository = async (
  options: { useCachedRepository?: boolean } = {}
): Promise<{ commit: string | null }> => {
  const { useCachedRepository = false } = options
  await ensureCacheDir()

  const repoExists = await pathExists(join(REPO_DIR, '.git'))

  if (!repoExists) {
    await runGit(
      ['clone', '--depth', '1', '--filter=blob:none', '--sparse', METASPLOIT_REPO_URL, REPO_DIR],
      process.cwd()
    )
    await runGit(['sparse-checkout', 'set', 'modules'], REPO_DIR)
  } else if (!useCachedRepository) {
    await runGit(['fetch', '--depth', '1', 'origin', METASPLOIT_BRANCH], REPO_DIR)
    await runGit(['reset', '--hard', `origin/${METASPLOIT_BRANCH}`], REPO_DIR)
    await runGit(['clean', '-fdx'], REPO_DIR)
    await runGit(['sparse-checkout', 'set', 'modules'], REPO_DIR)
  } else {
    await runGit(['sparse-checkout', 'set', 'modules'], REPO_DIR).catch(() => {})
  }

  const commitResult = await runGit(['rev-parse', 'HEAD'], REPO_DIR).catch(() => ({ stdout: '', stderr: '' }))
  return { commit: commitResult.stdout || null }
}

const unescapeRubyString = (value: string): string => {
  return value
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\'/g, "'")
    .replace(/\\\\/g, '\\')
}

type RubyValue =
  | { kind: 'string'; value: string; end: number }
  | { kind: 'array'; value: string; end: number }
  | { kind: 'hash'; value: string; end: number }
  | { kind: 'identifier'; value: string; end: number }
  | { kind: 'boolean'; value: boolean; end: number }
  | { kind: 'nil'; value: null; end: number }
  | { kind: 'number'; value: number; end: number }
  | { kind: 'raw'; value: string; end: number }

const parseQuotedString = (source: string, start: number): { value: string; end: number } => {
  const quote = source[start]
  let index = start + 1
  const chunks: string[] = []
  while (index < source.length) {
    const char = source[index]
    if (char === '\\') {
      const next = source[index + 1]
      if (next) {
        chunks.push(unescapeRubyString(`\\${next}`))
        index += 2
        continue
      }
      index += 1
      continue
    }
    if (char === quote) {
      return { value: chunks.join(''), end: index + 1 }
    }
    chunks.push(char)
    index += 1
  }
  return { value: chunks.join(''), end: source.length }
}

const matchClosingDelimiter = (open: string): string => {
  switch (open) {
    case '(': return ')'
    case '[': return ']'
    case '{': return '}'
    case '<': return '>'
    default: return open
  }
}

const parsePercentString = (source: string, start: number): { value: string; end: number } | null => {
  const typeChar = source[start + 1]
  const delimiter = source[start + 2]
  if (!delimiter) {
    return null
  }
  const closing = matchClosingDelimiter(delimiter)
  let depth = 1
  let index = start + 3
  const chunks: string[] = []
  while (index < source.length) {
    const char = source[index]
    if (char === '\\' && typeChar === 'Q') {
      const next = source[index + 1]
      if (next) {
        chunks.push(unescapeRubyString(`\\${next}`))
        index += 2
        continue
      }
      index += 1
      continue
    }
    if (char === delimiter && delimiter !== closing) {
      depth += 1
      chunks.push(char)
      index += 1
      continue
    }
    if (char === closing) {
      depth -= 1
      if (depth === 0) {
        return { value: chunks.join('').trim(), end: index + 1 }
      }
    }
    chunks.push(char)
    index += 1
  }
  return null
}

const parseDelimited = (source: string, start: number, open: string, close: string): { body: string; end: number } | null => {
  if (source[start] !== open) {
    return null
  }
  let depth = 1
  let index = start + 1
  const bodyStart = index
  let inString: string | null = null
  let escaped = false

  while (index < source.length) {
    const char = source[index]
    if (escaped) {
      escaped = false
      index += 1
      continue
    }
    if (inString) {
      if (char === '\\') {
        escaped = true
      } else if (char === inString) {
        inString = null
      }
      index += 1
      continue
    }
    if (char === '\'' || char === '"') {
      inString = char
      index += 1
      continue
    }
    if (char === open) {
      depth += 1
      index += 1
      continue
    }
    if (char === close) {
      depth -= 1
      if (depth === 0) {
        const body = source.slice(bodyStart, index)
        return { body, end: index + 1 }
      }
      index += 1
      continue
    }
    index += 1
  }
  return null
}

const parseRubyValue = (source: string, start: number): RubyValue | null => {
  let index = start
  while (index < source.length && /\s/.test(source[index]!)) {
    index += 1
  }
  if (index >= source.length) {
    return null
  }
  const char = source[index]
  if (char === '\'' || char === '"') {
    const parsed = parseQuotedString(source, index)
    return { kind: 'string', value: parsed.value, end: parsed.end }
  }
  if (char === '%' && index + 2 < source.length) {
    const parsed = parsePercentString(source, index)
    if (parsed) {
      return { kind: 'string', value: parsed.value, end: parsed.end }
    }
  }
  if (char === '[') {
    const parsed = parseDelimited(source, index, '[', ']')
    if (parsed) {
      return { kind: 'array', value: parsed.body, end: parsed.end }
    }
  }
  if (char === '{') {
    const parsed = parseDelimited(source, index, '{', '}')
    if (parsed) {
      return { kind: 'hash', value: parsed.body, end: parsed.end }
    }
  }
  if (/[-+]?\d/.test(char)) {
    const match = source.slice(index).match(/^[-+]?\d+(?:\.\d+)?/)
    if (match) {
      return { kind: 'number', value: Number(match[0]), end: index + match[0].length }
    }
  }
  if (source.startsWith('true', index)) {
    return { kind: 'boolean', value: true, end: index + 4 }
  }
  if (source.startsWith('false', index)) {
    return { kind: 'boolean', value: false, end: index + 5 }
  }
  if (source.startsWith('nil', index)) {
    return { kind: 'nil', value: null, end: index + 3 }
  }
  const identifier = source.slice(index).match(/^[A-Za-z_][A-Za-z0-9_:]*/)
  if (identifier) {
    return { kind: 'identifier', value: identifier[0], end: index + identifier[0].length }
  }
  const raw = source.slice(index, source.indexOf('\n', index) === -1 ? undefined : source.indexOf('\n', index))
  return { kind: 'raw', value: raw.trim(), end: index + raw.length }
}

const findKeyValue = (source: string, key: string): RubyValue | null => {
  const single = `'${key}'`
  const double = `"${key}"`
  const patterns = [single, double]
  for (const pattern of patterns) {
    const index = source.indexOf(`${pattern} =>`)
    if (index !== -1) {
      return parseRubyValue(source, index + pattern.length + 3)
    }
  }
  return null
}

const splitLines = (value: string): string[] =>
  value
    .split('\n')
    .map(line => line.trimEnd())
    .filter(line => line.length > 0)

const extractStringValue = (source: string, key: string): string | null => {
  const parsed = findKeyValue(source, key)
  if (!parsed) {
    return null
  }
  if (parsed.kind === 'string') {
    return parsed.value.trim()
  }
  if (parsed.kind === 'identifier' || parsed.kind === 'raw') {
    return parsed.value.trim()
  }
  return null
}

const extractMultilineString = (source: string, key: string): string | null => {
  const parsed = findKeyValue(source, key)
  if (!parsed) {
    return null
  }
  if (parsed.kind === 'string') {
    return splitLines(parsed.value).join('\n').trim()
  }
  return extractStringValue(source, key)
}

const extractArrayStrings = (source: string, key: string): string[] => {
  const parsed = findKeyValue(source, key)
  if (!parsed) {
    return []
  }
  if (parsed.kind === 'array') {
    const matches = parsed.value.match(/(['"])(.*?)\1/g) ?? []
    return matches
      .map(match => match.slice(1, -1))
      .map(unescapeRubyString)
      .map(item => item.trim())
      .filter(item => item.length > 0)
  }
  if (parsed.kind === 'string') {
    const value = parsed.value.trim()
    return value.length ? [value] : []
  }
  if (parsed.kind === 'identifier') {
    return [parsed.value.trim()]
  }
  return []
}

const extractBoolean = (source: string, key: string): boolean | null => {
  const parsed = findKeyValue(source, key)
  if (!parsed) {
    return null
  }
  if (parsed.kind === 'boolean') {
    return parsed.value
  }
  if (parsed.kind === 'identifier') {
    if (parsed.value === 'true') {
      return true
    }
    if (parsed.value === 'false') {
      return false
    }
  }
  return null
}

const normaliseCve = (value: string): string => {
  const trimmed = value.trim()
  const match = trimmed.match(/(\d{4})[-_]?([0-9]{4,7})/)
  if (match) {
    return `CVE-${match[1]}-${match[2]}`.toUpperCase()
  }
  return trimmed.toUpperCase()
}

const shouldFilterAlias = (alias: string): boolean => {
  if (!alias) {
    return true
  }
  const value = alias.trim()
  if (!value) {
    return true
  }
  if (value.toLowerCase().endsWith('.c')) {
    return true
  }
  if (RE_VENDOR_ADVISORY.test(value)) {
    return true
  }
  return false
}

const extractInlineAliases = (source: string): string[] => {
  const aliases = new Set<string>()
  const regex = /\[\s*['"]CVE['"]\s*,\s*['"][^'"]+['"]\s*\](.*)/g
  let match: RegExpExecArray | null
  while ((match = regex.exec(source)) !== null) {
    const rest = match[1] ?? ''
    const hashIndex = rest.indexOf('#')
    const slashIndex = rest.indexOf('//')
    let comment = ''
    if (hashIndex !== -1) {
      comment = rest.slice(hashIndex + 1)
    } else if (slashIndex !== -1) {
      comment = rest.slice(slashIndex + 2)
    }
    const cleaned = comment.trim()
    if (!cleaned) {
      continue
    }
    const name = cleaned.includes('-') ? cleaned.split('-', 1)[0]!.trim() : cleaned
    const alias = name.replace(/[\s,;:]+$/, '')
    if (alias && !shouldFilterAlias(alias)) {
      aliases.add(alias)
    }
  }
  return Array.from(aliases)
}

const STABILITY_DESCRIPTIONS: Record<string, string> = {
  CRASH_SAFE: 'Module should not crash the service or OS',
  CRASH_SERVICE_RESTARTS: 'Module may crash the service, but it will restart',
  CRASH_SERVICE_DOWN: 'Module may crash the service, and remain down',
  CRASH_OS_RESTARTS: 'Module may crash the OS, but it will restart',
  CRASH_OS_DOWN: 'Module may crash the OS, and remain down',
  SERVICE_RESOURCE_LOSS: 'Module causes a resource to be unavailable for the service',
  OS_RESOURCE_LOSS: 'Module causes a resource to be unavailable for the OS',
  UNKNOWN_STABILITY: 'Module stability is unknown'
}

const RELIABILITY_DESCRIPTIONS: Record<string, string> = {
  FIRST_ATTEMPT_FAIL: 'Module may fail on the first attempt',
  REPEATABLE_SESSION: 'Module is expected to get a session every time',
  UNRELIABLE_SESSION: 'Module is not expected to get a shell reliably',
  EVENT_DEPENDENT: 'Module may require an external event to trigger',
  UNKNOWN_RELIABILITY: 'Module reliability is unknown'
}

const SIDE_EFFECT_DESCRIPTIONS: Record<string, string> = {
  ARTIFACTS_ON_DISK: 'Leaves artifacts on disk',
  CONFIG_CHANGES: 'Modifies configuration files',
  IOC_IN_LOGS: 'Leaves indicators of compromise in logs',
  ACCOUNT_LOCKOUTS: 'May cause an account lockout',
  ACCOUNT_LOGOUT: 'May force a user session logout',
  SCREEN_EFFECTS: 'Produces visible screen effects',
  PHYSICAL_EFFECTS: 'May cause physical effects (light, sound, heat)',
  AUDIO_EFFECTS: 'May produce audio effects',
  UNKNOWN_SIDE_EFFECTS: 'Side effects are unknown'
}

const formatTrait = (value: string, descriptions: Record<string, string>): string => {
  const description = descriptions[value] ?? null
  const label = value
    .toLowerCase()
    .split('_')
    .map(chunk => chunk.charAt(0).toUpperCase() + chunk.slice(1))
    .join(' ')
  return description ? `${label} — ${description}` : label
}

const extractNotesBlock = (source: string): string | null => {
  const parsed = findKeyValue(source, 'Notes')
  if (parsed && parsed.kind === 'hash') {
    return parsed.value
  }
  return null
}

const extractAliasesFromNotes = (block: string): string[] => {
  const match = block.match(/['"]AKA['"]\s*(?:=>|:)\s*\[([^\]]*)\]/)
  if (!match) {
    return []
  }
  return match[1]
    .match(/(['"])(.*?)\1/g)
    ?.map(entry => entry.slice(1, -1))
    .map(unescapeRubyString)
    .map(alias => alias.trim())
    .filter(alias => alias.length > 0 && !shouldFilterAlias(alias)) ?? []
}

const extractTrait = (block: string, key: string): string | null => {
  const regex = new RegExp(`['"]${key}['"]\\s*(?:=>|:)\\s*([A-Z0-9_]+)`, 'i')
  const match = block.match(regex)
  return match ? match[1] : null
}

const extractTraitArray = (block: string, key: string): string[] => {
  const regex = new RegExp(`['"]${key}['"]\\s*(?:=>|:)\\s*\\[([^\]]*)\]`, 'i')
  const match = block.match(regex)
  if (!match) {
    const single = extractTrait(block, key)
    return single ? [single] : []
  }
  return match[1]
    .match(/[A-Z0-9_]+/g)
    ?.map(entry => entry.trim()) ?? []
}

const normalisePlatform = (value: string): string => {
  if (!value) {
    return ''
  }
  const trimmed = value.trim()
  if (!trimmed) {
    return ''
  }
  const parts = trimmed.split('::')
  const last = parts[parts.length - 1] ?? trimmed
  return last.toLowerCase()
}

const normaliseArchitecture = (value: string): string => {
  if (!value) {
    return ''
  }
  if (value.startsWith('ARCH_')) {
    return value.replace(/^ARCH_/, '').toLowerCase().replace(/_/g, '-')
  }
  return value.toLowerCase()
}

type ReferenceRecord = { type: string; value: string }

const extractReferences = (source: string): ReferenceRecord[] => {
  const parsed = findKeyValue(source, 'References')
  if (!parsed || parsed.kind !== 'array') {
    return []
  }
  const pairs = Array.from(parsed.value.matchAll(/\[\s*(['"])([^'"\]]+)\1\s*,\s*(['"])([^'"\]]+)\3\s*\]/g))
  return pairs.map(match => ({ type: match[2].trim(), value: match[4].trim() }))
}

const extractTargets = (source: string): string[] => {
  const parsed = findKeyValue(source, 'Targets')
  if (!parsed || parsed.kind !== 'array') {
    return []
  }
  const matches = parsed.value.match(/\[\s*(['"])([^'"\]]+)\1/g) ?? []
  return matches
    .map(entry => entry.replace(/^[^'"']*['"]/, '').replace(/['"]$/, ''))
    .map(unescapeRubyString)
    .map(item => item.trim())
    .filter((item, index, array) => item.length > 0 && array.indexOf(item) === index)
}

const extractRank = (source: string): string | null => {
  const match = source.match(/Rank\s*=\s*([A-Za-z]+Ranking)/)
  if (!match) {
    return null
  }
  const raw = match[1]
  const label = raw.replace(/Ranking$/, '')
  return label.charAt(0).toUpperCase() + label.slice(1)
}

type ModuleMetadata = {
  path: string
  name: string
  description: string
  authors: string[]
  references: ReferenceRecord[]
  rank: string | null
  privileged: boolean | null
  platforms: string[]
  architectures: string[]
  targets: string[]
  aliases: string[]
  stability: string | null
  reliability: string | null
  sideEffects: string[]
  disclosureDate: string | null
}

const parseModule = (source: string, relativePath: string): ModuleMetadata | null => {
  const name = extractStringValue(source, 'Name') ?? ''
  const description = extractMultilineString(source, 'Description') ?? ''
  if (!name && !description) {
    return null
  }
  const authors = extractArrayStrings(source, 'Author')
  const references = extractReferences(source)
  const rank = extractRank(source)
  const privileged = extractBoolean(source, 'Privileged')
  const platforms = extractArrayStrings(source, 'Platform').map(normalisePlatform).filter(Boolean)
  const architectures = extractArrayStrings(source, 'Arch').map(normaliseArchitecture).filter(Boolean)
  const targets = extractTargets(source)
  const notesBlock = extractNotesBlock(source)
  const aliasesFromNotes = notesBlock ? extractAliasesFromNotes(notesBlock) : []
  const inlineAliases = extractInlineAliases(source)
  const aliases = Array.from(new Set([...aliasesFromNotes, ...inlineAliases]))
  const stabilityToken = notesBlock ? extractTrait(notesBlock, 'Stability') : null
  const reliabilityToken = notesBlock ? extractTrait(notesBlock, 'Reliability') : null
  const sideEffectTokens = notesBlock ? extractTraitArray(notesBlock, 'SideEffects') : []
  const stability = stabilityToken
    ? formatTrait(stabilityToken, STABILITY_DESCRIPTIONS)
    : null
  const reliability = reliabilityToken
    ? formatTrait(reliabilityToken, RELIABILITY_DESCRIPTIONS)
    : null
  const sideEffects = sideEffectTokens.map(token => formatTrait(token, SIDE_EFFECT_DESCRIPTIONS))
  const disclosureRaw = extractStringValue(source, 'DisclosureDate')
  let disclosureDate: string | null = null
  if (disclosureRaw) {
    const parsed = new Date(disclosureRaw)
    if (!Number.isNaN(parsed.getTime())) {
      disclosureDate = parsed.toISOString()
    }
  }
  return {
    path: relativePath,
    name: name || 'Metasploit module',
    description: description.trim(),
    authors,
    references,
    rank,
    privileged,
    platforms,
    architectures,
    targets,
    aliases,
    stability,
    reliability,
    sideEffects,
    disclosureDate
  }
}

const gatherCves = (references: ReferenceRecord[], source: string): string[] => {
  const values = new Set<string>()
  for (const reference of references) {
    if (reference.type.toUpperCase() === 'CVE') {
      values.add(normaliseCve(reference.value))
    }
  }
  let match: RegExpExecArray | null
  while ((match = RE_CVE_GENERIC.exec(source)) !== null) {
    values.add(normaliseCve(match[0]))
  }
  RE_CVE_GENERIC.lastIndex = 0
  return Array.from(values)
}

const createNotes = (metadata: ModuleMetadata): string[] => {
  const notes: string[] = []
  if (metadata.rank) {
    notes.push(`Module rank: ${metadata.rank}`)
  }
  if (metadata.authors.length) {
    notes.push(`Authors: ${metadata.authors.join(', ')}`)
  }
  if (metadata.privileged !== null) {
    notes.push(`Requires privileges: ${metadata.privileged ? 'Yes' : 'No'}`)
  }
  if (metadata.platforms.length) {
    notes.push(`Platforms: ${metadata.platforms.join(', ')}`)
  }
  if (metadata.architectures.length) {
    notes.push(`Architectures: ${metadata.architectures.join(', ')}`)
  }
  if (metadata.targets.length) {
    notes.push(`Targets: ${metadata.targets.join('; ')}`)
  }
  if (metadata.stability) {
    notes.push(`Stability: ${metadata.stability}`)
  }
  if (metadata.reliability) {
    notes.push(`Reliability: ${metadata.reliability}`)
  }
  if (metadata.sideEffects.length) {
    notes.push(`Side effects: ${metadata.sideEffects.join('; ')}`)
  }
  if (metadata.aliases.length) {
    notes.push(`Also known as: ${metadata.aliases.join(', ')}`)
  }
  return notes
}

const normaliseReference = (record: ReferenceRecord): string => {
  const type = record.type.toUpperCase()
  if (type === 'URL') {
    return record.value
  }
  return `${type}: ${record.value}`
}

const unique = <T>(items: T[]): T[] => {
  return items.filter((item, index) => items.indexOf(item) === index)
}

type ModuleParseResult = {
  metadata: ModuleMetadata
  cveIds: string[]
  references: string[]
  aliases: string[]
}

const parseModuleFile = async (filePath: string, repoRoot: string): Promise<ModuleParseResult | null> => {
  const raw = await readFile(filePath, 'utf8')
  const relativePath = relative(repoRoot, filePath)
  const metadata = parseModule(raw, relativePath)
  if (!metadata) {
    return null
  }
  const aliasReferences = metadata.references
    .filter(reference => reference.type.toUpperCase() === 'AKA')
    .map(reference => reference.value.trim())
    .filter(value => value.length > 0 && !shouldFilterAlias(value))
  const referenceRecords = metadata.references.filter(
    reference => reference.type.toUpperCase() !== 'AKA'
  )
  const cveIds = gatherCves(referenceRecords, raw)
  if (!cveIds.length) {
    return null
  }
  const aliasCandidates = unique([...metadata.aliases, ...aliasReferences])
  const references = referenceRecords.map(normaliseReference)
  return {
    metadata,
    cveIds,
    references: unique(references),
    aliases: unique(aliasCandidates)
  }
}

const PLATFORM_VENDOR_MAP: Record<string, { vendor: string; product: string }> = {
  windows: { vendor: 'Microsoft', product: 'Windows' },
  win: { vendor: 'Microsoft', product: 'Windows' },
  linux: { vendor: 'Linux', product: 'Linux' },
  unix: { vendor: 'Unix', product: 'Unix' },
  osx: { vendor: 'Apple', product: 'macOS' },
  macos: { vendor: 'Apple', product: 'macOS' },
  mac: { vendor: 'Apple', product: 'macOS' },
  ios: { vendor: 'Apple', product: 'iOS' },
  android: { vendor: 'Google', product: 'Android' },
  solaris: { vendor: 'Oracle', product: 'Solaris' },
  aix: { vendor: 'IBM', product: 'AIX' },
  hpux: { vendor: 'Hewlett Packard Enterprise', product: 'HP-UX' },
  freebsd: { vendor: 'FreeBSD Project', product: 'FreeBSD' },
  netbsd: { vendor: 'NetBSD Project', product: 'NetBSD' },
  openbsd: { vendor: 'OpenBSD', product: 'OpenBSD' },
  junos: { vendor: 'Juniper Networks', product: 'Junos' }
}

const guessVendorProduct = (metadata: ModuleMetadata): { vendor: string | null; product: string | null } => {
  const referenceText = metadata.references.map(record => record.value).join(' ')
  const contextText = [
    metadata.name,
    metadata.description,
    metadata.path,
    metadata.targets.join(' '),
    metadata.aliases.join(' '),
    referenceText
  ]
    .filter(Boolean)
    .join(' ')

  const hinted = matchExploitProduct(contextText)
  if (hinted) {
    return hinted
  }

  const findMapping = (token: string | undefined): { vendor: string; product: string } | null => {
    if (!token) {
      return null
    }
    const mapping = PLATFORM_VENDOR_MAP[token.toLowerCase()]
    return mapping ?? null
  }

  for (const platform of metadata.platforms) {
    const mapping = findMapping(platform)
    if (mapping) {
      return mapping
    }
  }

  const pathSegments = metadata.path
    .split('/')
    .map(segment => segment.trim().toLowerCase())
    .filter(Boolean)

  for (const segment of pathSegments) {
    const mapping = findMapping(segment)
    if (mapping) {
      return mapping
    }
  }

  if (metadata.targets.length) {
    const joinedTargets = metadata.targets.join(' ').toLowerCase()
    if (joinedTargets.includes('windows')) {
      return { vendor: 'Microsoft', product: 'Windows' }
    }
    if (joinedTargets.includes('linux')) {
      return { vendor: 'Linux', product: 'Linux' }
    }
    if (joinedTargets.includes('mac os') || joinedTargets.includes('macos')) {
      return { vendor: 'Apple', product: 'macOS' }
    }
    if (joinedTargets.includes('ios')) {
      return { vendor: 'Apple', product: 'iOS' }
    }
    if (joinedTargets.includes('android')) {
      return { vendor: 'Google', product: 'Android' }
    }
    if (joinedTargets.includes('solaris')) {
      return { vendor: 'Oracle', product: 'Solaris' }
    }
    if (joinedTargets.includes('aix')) {
      return { vendor: 'IBM', product: 'AIX' }
    }
  }

  return { vendor: null, product: null }
}

const createBaseEntries = (moduleResult: ModuleParseResult, commit: string | null): KevBaseEntry[] => {
  const { metadata, cveIds, references, aliases } = moduleResult
  const moduleId = metadata.path.replace(/\.rb$/i, '')
  const modulePath = moduleId.replace(/^modules\//, '')
  const sourceRef = commit ?? METASPLOIT_BRANCH
  const sourceUrl = `https://github.com/rapid7/metasploit-framework/blob/${sourceRef}/${metadata.path}`
  const notes = createNotes(metadata)
  const guessedVendorProduct = guessVendorProduct(metadata)
  return cveIds.map(cveId => {
    const normalised = normaliseVendorProduct({
      vendor: guessedVendorProduct.vendor,
      product: guessedVendorProduct.product ?? metadata.name
    })
    const aliasList = unique([cveId, ...aliases])
    return {
      id: `metasploit:${moduleId}:${cveId}`,
      sources: ['metasploit'],
      cveId,
      vendor: normalised.vendor.label,
      vendorKey: normalised.vendor.key,
      product: normalised.product.label,
      productKey: normalised.product.key,
      vulnerabilityName: metadata.name || cveId,
      description: metadata.description,
      requiredAction: null,
      dateAdded: metadata.disclosureDate ?? '',
      dueDate: null,
      ransomwareUse: null,
      notes,
      cwes: [],
      cvssScore: null,
      cvssVector: null,
      cvssVersion: null,
      cvssSeverity: null,
      epssScore: null,
      assigner: null,
      datePublished: metadata.disclosureDate,
      dateUpdated: null,
      exploitedSince: metadata.disclosureDate,
      sourceUrl,
      references,
      aliases: aliasList,
      metasploitModulePath: modulePath,
      internetExposed: false
    }
  })
}

const applyVendorProductOverrides = (entries: KevBaseEntry[], db: DrizzleDatabase): KevBaseEntry[] => {
  if (!entries.length) {
    return entries
  }

  const cveIds = Array.from(new Set(entries.map(entry => entry.cveId).filter(Boolean)))
  if (!cveIds.length) {
    return entries
  }

  const rows = db
    .select({
      cveId: tables.vulnerabilityEntries.cveId,
      vendor: tables.vulnerabilityEntries.vendor,
      product: tables.vulnerabilityEntries.product,
      source: tables.vulnerabilityEntries.source
    })
    .from(tables.vulnerabilityEntries)
    .where(
      and(
        inArray(tables.vulnerabilityEntries.cveId, cveIds),
        ne(tables.vulnerabilityEntries.source, 'metasploit')
      )
    )
    .all()

  const priorities: Record<string, number> = { kev: 3, historic: 2, enisa: 1 }
  const overrides = new Map<
    string,
    { vendor: string; product: string; score: number }
  >()

  for (const row of rows) {
    if (!row.cveId) {
      continue
    }
    const vendor = (row.vendor ?? '').trim()
    const product = (row.product ?? '').trim()
    if (!vendor && !product) {
      continue
    }
    const score = priorities[row.source ?? ''] ?? 0
    const existing = overrides.get(row.cveId)
    if (!existing || score > existing.score) {
      overrides.set(row.cveId, { vendor, product, score })
      continue
    }
    if (score === existing.score) {
      const existingLength = existing.vendor.length + existing.product.length
      const candidateLength = vendor.length + product.length
      if (candidateLength > existingLength) {
        overrides.set(row.cveId, { vendor, product, score })
      }
    }
  }

  if (!overrides.size) {
    return entries
  }

  return entries.map(entry => {
    const override = overrides.get(entry.cveId)
    if (!override) {
      return entry
    }
    const normalised = normaliseVendorProduct({ vendor: override.vendor, product: override.product })
    if (normalised.vendor.label === entry.vendor && normalised.product.label === entry.product) {
      return entry
    }
    return {
      ...entry,
      vendor: normalised.vendor.label,
      vendorKey: normalised.vendor.key,
      product: normalised.product.label,
      productKey: normalised.product.key
    }
  })
}

const walkRubyFiles = async (dir: string): Promise<string[]> => {
  const entries = await readdir(dir, { withFileTypes: true })
  const files: string[] = []
  for (const entry of entries) {
    if (entry.name.startsWith('.')) {
      continue
    }
    const fullPath = join(dir, entry.name)
    if (entry.isDirectory()) {
      const nested = await walkRubyFiles(fullPath)
      files.push(...nested)
      continue
    }
    if (entry.isFile() && entry.name.endsWith('.rb')) {
      files.push(fullPath)
    }
  }
  return files
}

export const importMetasploitCatalog = async (
  db: DrizzleDatabase,
  options: { useCachedRepository?: boolean } = {}
): Promise<{ imported: number; commit: string | null; modules: number }> => {
  markTaskRunning('metasploit', 'Synchronising Metasploit modules')

  try {
    setImportPhase('fetchingMetasploit', {
      message: 'Synchronising Metasploit modules',
      completed: 0,
      total: 0
    })

    const { commit } = await syncRepository({ useCachedRepository: options.useCachedRepository })

    const modulesDirExists = await pathExists(MODULES_DIR)
    if (!modulesDirExists) {
      throw new Error('Metasploit modules directory not available after clone')
    }

    const rubyFiles = await walkRubyFiles(MODULES_DIR)

    setImportPhase('fetchingMetasploit', {
      message: 'Parsing Metasploit modules',
      completed: 0,
      total: rubyFiles.length
    })
    markTaskProgress('metasploit', 0, rubyFiles.length, 'Parsing Metasploit modules')

    const baseEntries: KevBaseEntry[] = []
    const processedModules = new Set<string>()
    const seenIds = new Set<string>()

    for (let index = 0; index < rubyFiles.length; index += 1) {
      const filePath = rubyFiles[index]
      try {
        const parsed = await parseModuleFile(filePath, REPO_DIR)
        if (!parsed) {
          continue
        }
        processedModules.add(parsed.metadata.path)
        const entries = createBaseEntries(parsed, commit)
        for (const entry of entries) {
          if (seenIds.has(entry.id)) {
            continue
          }
          seenIds.add(entry.id)
          baseEntries.push(entry)
        }
      } catch {
        // Ignore modules that fail to parse; they will be skipped.
      }
      if ((index + 1) % 50 === 0 || index + 1 === rubyFiles.length) {
        const message = `Parsing Metasploit modules (${index + 1} of ${rubyFiles.length})`
        setImportPhase('fetchingMetasploit', {
          message,
          completed: index + 1,
          total: rubyFiles.length
        })
        markTaskProgress('metasploit', index + 1, rubyFiles.length, message)
      }
    }

    if (!baseEntries.length) {
      const importedAt = new Date().toISOString()
      setMetadata('metasploit.lastImportAt', importedAt)
      setMetadata('metasploit.totalCount', '0')
      setMetadata('metasploit.moduleCount', String(processedModules.size))
      if (commit) {
        setMetadata('metasploit.lastCommit', commit)
      }
      markTaskComplete('metasploit', 'No Metasploit entries required an update')
      return { imported: 0, commit, modules: processedModules.size }
    }

    const vendorAdjustedEntries = applyVendorProductOverrides(baseEntries, db)
    const entries = vendorAdjustedEntries.map(entry => enrichEntry(entry))

    setImportPhase('savingMetasploit', {
      message: 'Saving Metasploit entries to the local cache',
      completed: 0,
      total: entries.length
    })
    markTaskProgress('metasploit', 0, entries.length, 'Saving Metasploit entries to the local cache')

    db.transaction(tx => {
      tx
        .delete(tables.vulnerabilityEntries)
        .where(eq(tables.vulnerabilityEntries.source, 'metasploit'))
        .run()

      for (let index = 0; index < entries.length; index += 1) {
        const entry = entries[index]
        tx
          .insert(tables.vulnerabilityEntries)
          .values({
            id: entry.id,
            cveId: entry.cveId,
            source: 'metasploit',
            vendor: entry.vendor,
            product: entry.product,
            vulnerabilityName: entry.vulnerabilityName,
            description: entry.description,
            requiredAction: entry.requiredAction,
            dateAdded: entry.dateAdded,
            dueDate: entry.dueDate,
            ransomwareUse: entry.ransomwareUse,
            notes: JSON.stringify(entry.notes),
            cwes: JSON.stringify(entry.cwes),
            cvssScore: entry.cvssScore,
            cvssVector: entry.cvssVector,
            cvssVersion: entry.cvssVersion,
            cvssSeverity: entry.cvssSeverity,
            epssScore: entry.epssScore,
            assigner: entry.assigner,
            datePublished: entry.datePublished,
            dateUpdated: entry.dateUpdated,
            exploitedSince: entry.exploitedSince,
            sourceUrl: entry.sourceUrl,
            referenceLinks: JSON.stringify(entry.references),
            aliases: JSON.stringify(entry.aliases),
            metasploitModulePath: entry.metasploitModulePath,
            internetExposed: entry.internetExposed ? 1 : 0
          })
          .run()

        const dimensionRecords: Array<{ entryId: string; categoryType: string; value: string; name: string }> = []

        const pushCategories = (values: string[], type: 'domain' | 'exploit' | 'vulnerability') => {
          for (const value of values) {
            dimensionRecords.push({ entryId: entry.id, categoryType: type, value, name: value })
          }
        }

        pushCategories(entry.domainCategories, 'domain')
        pushCategories(entry.exploitLayers, 'exploit')
        pushCategories(entry.vulnerabilityCategories, 'vulnerability')

        if (dimensionRecords.length) {
          tx.insert(tables.vulnerabilityEntryCategories).values(dimensionRecords).run()
        }

        if ((index + 1) % 25 === 0 || index + 1 === entries.length) {
          const message = `Saving Metasploit entries (${index + 1} of ${entries.length})`
          setImportPhase('savingMetasploit', {
            message,
            completed: index + 1,
            total: entries.length
          })
          markTaskProgress('metasploit', index + 1, entries.length, message)
        }
      }
    })

    const importedAt = new Date().toISOString()
    setMetadata('metasploit.lastImportAt', importedAt)
    setMetadata('metasploit.totalCount', String(entries.length))
    setMetadata('metasploit.moduleCount', String(processedModules.size))
    if (commit) {
      setMetadata('metasploit.lastCommit', commit)
    }

    markTaskComplete(
      'metasploit',
      `${entries.length.toLocaleString()} Metasploit entries across ${processedModules.size.toLocaleString()} modules cached`
    )

    return { imported: entries.length, commit, modules: processedModules.size }
  } catch (error) {
    const message =
      error instanceof Error ? error.message : typeof error === 'string' ? error : 'Metasploit import failed'
    markTaskError('metasploit', message)
    throw error instanceof Error ? error : new Error(message)
  }
}

