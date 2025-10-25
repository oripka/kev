import { readdir, readFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { and, eq, inArray, ne } from 'drizzle-orm'
import { enrichEntry } from '~/utils/classification'
import type { KevBaseEntry } from '~/utils/classification'
import { normaliseVendorProduct } from '~/utils/vendorProduct'
import { tables } from '../database/client'
import type { DrizzleDatabase } from './sqlite'
import { setMetadata } from './sqlite'
import {
  CVELIST_ENRICHMENT_CONCURRENCY,
  enrichBaseEntryWithCvelist,
  type VulnerabilityImpactRecord
} from './cvelist'
import {
  markTaskComplete,
  markTaskError,
  markTaskProgress,
  markTaskRunning,
  setImportPhase
} from './import-progress'
import { ensureDir, runGit, syncSparseRepo } from './git'
import { mapWithConcurrency } from './concurrency'

const METASPLOIT_REPO_URL = 'https://github.com/rapid7/metasploit-framework.git'
const METASPLOIT_BRANCH = 'master'
const CACHE_DIR = join(process.cwd(), 'data', 'cache', 'metasploit')
const REPO_DIR = join(CACHE_DIR, 'metasploit-framework')
const MODULES_DIR = join(REPO_DIR, 'modules', 'exploits')

const RE_CVE_GENERIC = /CVE[-\s_]*(\d{4})[-\s_]?([0-9]{4,7})/gi
const RE_VENDOR_ADVISORY = /^[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{4}-\d{2,}$/i

const syncRepository = async (
  options: { useCachedRepository?: boolean } = {}
): Promise<{ commit: string | null }> => {
  const { useCachedRepository = false } = options
  await ensureDir(CACHE_DIR)

  const { commit } = await syncSparseRepo({
    repoUrl: METASPLOIT_REPO_URL,
    branch: METASPLOIT_BRANCH,
    workingDir: REPO_DIR,
    sparsePaths: ['modules'],
    useCachedRepository
  })

  return { commit }
}

const collectModulePublishedDates = async (
  modulePaths: string[],
  onProgress?: (completed: number, total: number) => void,
  options: {
    allowNetworkFetch?: boolean
    existingDates?: Map<string, string | null>
  } = {}
): Promise<Map<string, string | null>> => {
  const { allowNetworkFetch = true, existingDates } = options
  const uniquePaths = Array.from(new Set(modulePaths))
  const total = uniquePaths.length
  const pending = new Set(uniquePaths)
  const results = new Map<string, string | null>()

  let completed = 0

  if (existingDates) {
    for (const path of uniquePaths) {
      if (!pending.has(path)) {
        continue
      }
      if (!existingDates.has(path)) {
        continue
      }
      results.set(path, existingDates.get(path) ?? null)
      pending.delete(path)
      completed += 1
    }
  }

  const reportProgress = () => {
    onProgress?.(completed, total)
  }

  reportProgress()

  const attemptResolve = async (paths: string[]) => {
    const queue = paths.filter(path => pending.has(path))
    if (!queue.length) {
      return
    }

    let index = 0
    const concurrency = Math.min(6, queue.length)

    const workers = Array.from({ length: concurrency }, () =>
      (async () => {
        while (index < queue.length) {
          const currentIndex = index
          index += 1
          const path = queue[currentIndex]
          if (!path || !pending.has(path)) {
            continue
          }

          const result = await runGit(
            ['log', '--diff-filter=A', '--follow', '--format=%aI', '-n', '1', '--', path],
            REPO_DIR
          ).catch(() => null)

          const output = result?.stdout?.trim()
          if (!output) {
            continue
          }

          const lines = output
            .split('\n')
            .map(line => line.trim())
            .filter(Boolean)

          const publishedAt = lines[lines.length - 1] ?? null
          if (!publishedAt) {
            continue
          }

          if (!pending.has(path)) {
            continue
          }

          pending.delete(path)
          results.set(path, publishedAt)
          completed += 1
          reportProgress()
        }
      })()
    )

    await Promise.all(workers)
  }

  await attemptResolve(Array.from(pending))

  if (!pending.size) {
    return results
  }

  if (allowNetworkFetch) {
    let currentDepth = 1
    const depthTargets = [64, 256, 512, 1024, 2048, 4096, 8192, 16384]

    for (const targetDepth of depthTargets) {
      if (!pending.size) {
        break
      }

      const deepenBy = targetDepth - currentDepth
      if (deepenBy > 0) {
        await runGit(['fetch', '--filter=blob:none', '--deepen', String(deepenBy)], REPO_DIR).catch(
          () => null
        )
        currentDepth = targetDepth
      }

      await attemptResolve(Array.from(pending))
    }
  }

  if (pending.size) {
    for (const path of Array.from(pending)) {
      results.set(path, null)
      pending.delete(path)
      completed += 1
      reportProgress()
    }
  }

  return results
}

const loadExistingModulePublishedDates = (db: DrizzleDatabase): Map<string, string | null> => {
  const rows = db
    .select({
      path: tables.vulnerabilityEntries.metasploitModulePath,
      publishedAt: tables.vulnerabilityEntries.metasploitModulePublishedAt
    })
    .from(tables.vulnerabilityEntries)
    .where(eq(tables.vulnerabilityEntries.source, 'metasploit'))
    .all()

  const map = new Map<string, string | null>()

  for (const row of rows) {
    if (!row.path) {
      continue
    }
    const trimmedPath = row.path.trim()
    if (!trimmedPath) {
      continue
    }
    const withPrefix = trimmedPath.startsWith('modules/') ? trimmedPath : `modules/${trimmedPath}`
    const normalisedPath = withPrefix.endsWith('.rb') ? withPrefix : `${withPrefix}.rb`
    if (!map.has(normalisedPath)) {
      const publishedAt =
        typeof row.publishedAt === 'string' && row.publishedAt.length > 0 ? row.publishedAt : null
      map.set(normalisedPath, publishedAt)
    }
  }

  return map
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
    name: name || 'Metasploit entry',
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

const createBaseEntries = (
  moduleResult: ModuleParseResult,
  commit: string | null,
  modulePublishedAt: string | null
): KevBaseEntry[] => {
  const { metadata, cveIds, references, aliases } = moduleResult
  const moduleId = metadata.path.replace(/\.rb$/i, '')
  const modulePath = moduleId.replace(/^modules\//, '')
  const sourceRef = commit ?? METASPLOIT_BRANCH
  const sourceUrl = `https://github.com/rapid7/metasploit-framework/blob/${sourceRef}/${metadata.path}`
  const notes = createNotes(metadata)
  return cveIds.map(cveId => {
    const aliasList = unique([cveId, ...aliases])
    const normalised = normaliseVendorProduct(
      { vendor: null, product: null },
      undefined,
      undefined,
      undefined,
      { allowOverrides: false, allowInference: false }
    )
    return {
      id: `metasploit:${moduleId}:${cveId}`,
      sources: ['metasploit'],
      cveId,
      vendor: normalised.vendor.label,
      vendorKey: normalised.vendor.key,
      product: normalised.product.label,
      productKey: normalised.product.key,
      affectedProducts: [],
      problemTypes: [],
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
      metasploitModulePublishedAt: modulePublishedAt,
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
  options: { useCachedRepository?: boolean; offline?: boolean; reprocessCachedEntries?: boolean } = {}
): Promise<{ imported: number; commit: string | null; modules: number }> => {
  markTaskRunning('metasploit', 'Synchronising Metasploit catalog')

  try {
    setImportPhase('fetchingMetasploit', {
      message: 'Synchronising Metasploit catalog',
      completed: 0,
      total: 0
    })

    const { commit } = await syncRepository({ useCachedRepository: options.useCachedRepository })

    const modulesDirExists = await pathExists(MODULES_DIR)
    if (!modulesDirExists) {
      throw new Error('Metasploit repository directory not available after clone')
    }

    const rubyFiles = await walkRubyFiles(MODULES_DIR)

    const moduleRelativePaths = rubyFiles.map(file => relative(REPO_DIR, file))
    const existingPublishedDates = loadExistingModulePublishedDates(db)

    if (moduleRelativePaths.length) {
      setImportPhase('fetchingMetasploit', {
        message: 'Resolving Metasploit publish dates',
        completed: 0,
        total: moduleRelativePaths.length
      })
      markTaskProgress(
        'metasploit',
        0,
        moduleRelativePaths.length,
        'Resolving Metasploit publish dates'
      )
    }

    const publishedDateMap = await collectModulePublishedDates(
      moduleRelativePaths,
      (completed, total) => {
        if (!total) {
          return
        }
        if (completed === total || completed % 50 === 0) {
          const message = `Resolving Metasploit publish dates (${completed} of ${total})`
          setImportPhase('fetchingMetasploit', { message, completed, total })
          markTaskProgress('metasploit', completed, total, message)
        }
      },
      {
        allowNetworkFetch: options.offline !== true,
        existingDates: existingPublishedDates
      }
    )

    setImportPhase('fetchingMetasploit', {
      message: 'Parsing Metasploit data',
      completed: 0,
      total: rubyFiles.length
    })
    markTaskProgress('metasploit', 0, rubyFiles.length, 'Parsing Metasploit data')

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
        const modulePublishedAt = publishedDateMap.get(parsed.metadata.path) ?? null
        const entries = createBaseEntries(parsed, commit, modulePublishedAt)
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
        const message = `Parsing Metasploit data (${index + 1} of ${rubyFiles.length})`
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

    const offline = options.offline ?? false
    const reprocessCachedEntries = options.reprocessCachedEntries ?? false
    const preferCache = offline && !reprocessCachedEntries

    const cvelistResults = await mapWithConcurrency(
      baseEntries,
      CVELIST_ENRICHMENT_CONCURRENCY,
      async base => {
        try {
          return await enrichBaseEntryWithCvelist(base, {
            preferCache
          })
        } catch {
          return { entry: base, impacts: [], hit: false }
        }
      }
    )

    let cvelistHits = 0
    let cvelistMisses = 0
    for (const result of cvelistResults) {
      if (result.hit) {
        cvelistHits += 1
      } else {
        cvelistMisses += 1
      }
    }

    if (cvelistHits > 0 || cvelistMisses > 0) {
      const message = `Metasploit CVEList enrichment (${cvelistHits} hits, ${cvelistMisses} misses)`
      markTaskProgress('metasploit', 0, 0, message)
    }

    const impactRecordMap = new Map<string, VulnerabilityImpactRecord[]>()
    for (const result of cvelistResults) {
      if (result.impacts.length) {
        impactRecordMap.set(result.entry.id, result.impacts)
      }
    }

    const vendorAdjustedEntries = applyVendorProductOverrides(
      cvelistResults.map(result => result.entry),
      db
    )
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
            vendorKey: entry.vendorKey,
            productKey: entry.productKey,
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
            affectedProducts: JSON.stringify(entry.affectedProducts),
            problemTypes: JSON.stringify(entry.problemTypes),
            metasploitModulePath: entry.metasploitModulePath,
            metasploitModulePublishedAt: entry.metasploitModulePublishedAt,
            internetExposed: entry.internetExposed ? 1 : 0
          })
          .run()

        const entryImpacts = impactRecordMap.get(entry.id) ?? []
        if (entryImpacts.length) {
          for (const impact of entryImpacts) {
            tx
              .insert(tables.vulnerabilityEntryImpacts)
              .values({
                entryId: impact.entryId,
                vendor: impact.vendor,
                vendorKey: impact.vendorKey,
                product: impact.product,
                productKey: impact.productKey,
                status: impact.status,
                versionRange: impact.versionRange,
                source: impact.source
              })
              .run()
          }
        }

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

