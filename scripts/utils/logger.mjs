import { createConsola } from 'consola'

const formatTimestamp = (date = new Date()) => {
  const iso = date.toISOString()
  const [day, time] = iso.split('T')
  return `${day} ${time.replace('Z', ' UTC')}`
}

const stringifyArg = (value) => {
  if (typeof value === 'string') {
    return value
  }
  if (value instanceof Error) {
    return value.stack || value.message
  }
  return String(value)
}

const joinArgs = (args) => args.map(stringifyArg).join(' ')

const normalizeArgs = (input) => (Array.isArray(input) ? input : [input])

const resolveStream = (instance) => instance?.options?.stdout ?? process.stdout

const createProgressState = (base, withTimestamp, stream, initialMessage, baseOptions = {}) => {
  let appendMode = Boolean(baseOptions.append)
  let active = true
  let clearedLine = appendMode

  const write = (message, options = {}) => {
    if (!active) {
      return
    }

    if (typeof options.append === 'boolean') {
      appendMode = options.append
    }

    const tokens = withTimestamp(...normalizeArgs(message))

    if (appendMode) {
      base.info(...tokens)
      clearedLine = true
      return
    }

    stream.write(`\r\u001B[2K${joinArgs(tokens)}`)
    clearedLine = false
  }

  if (typeof initialMessage !== 'undefined') {
    write(initialMessage, baseOptions)
  }

  const complete = (status, message) => {
    if (!active) {
      return
    }

    active = false

    if (!appendMode && !clearedLine) {
      stream.write('\r\u001B[2K')
    }

    if (typeof message === 'undefined') {
      if (!appendMode && !clearedLine) {
        stream.write('\n')
      }
      return
    }

    const method = typeof base[status] === 'function' ? base[status] : base.info
    method(...withTimestamp(...normalizeArgs(message)))
  }

  return {
    update(message, options) {
      write(message, options)
    },
    finish({ status = 'success', message } = {}) {
      complete(status, message)
    },
    succeed(message) {
      complete('success', message)
    },
    fail(message) {
      complete('error', message)
    }
  }
}

export const createCliLogger = ({ tag, level } = {}) => {
  const base = createConsola({
    defaults: tag ? { tag } : undefined,
    level
  })

  const stream = resolveStream(base)
  const useColor = base.options?.fancy !== false && stream?.isTTY !== false && !process.env.NO_COLOR
  const dim = useColor ? (value) => `\u001B[2m${value}\u001B[0m` : (value) => value

  const withTimestamp = (...args) => {
    const timestamp = dim(`[${formatTimestamp()}]`)
    return [timestamp, ...args]
  }

  const proxy = {}
  const methods = [
    'trace',
    'debug',
    'info',
    'log',
    'warn',
    'error',
    'fatal',
    'fail',
    'start',
    'success',
    'ready',
    'box'
  ]

  for (const method of methods) {
    if (typeof base[method] === 'function') {
      proxy[method] = (...args) => base[method](...withTimestamp(...args))
    }
  }

  proxy.progress = (...args) => {
    let options = {}
    if (
      args.length > 0 &&
      typeof args[args.length - 1] === 'object' &&
      args[args.length - 1] !== null &&
      !Array.isArray(args[args.length - 1])
    ) {
      options = args.pop()
    }

    const initialMessage = args.length > 0 ? args : undefined
    return createProgressState(base, withTimestamp, stream, initialMessage, options)
  }

  proxy.withTag = (nextTag) => createCliLogger({ tag: nextTag, level: base.options.level })

  return proxy
}
