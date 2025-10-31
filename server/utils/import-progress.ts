import type {
  ImportProgressEvent,
  ImportProgressEventStatus,
  ImportTaskKey,
  ImportTaskProgress,
  ImportTaskStatus
} from '~/types'
import { describeTaskKey } from '~/utils/exploitProductHints'

type ImportPhase =
  | 'idle'
  | 'preparing'
  | 'fetchingCvss'
  | 'fetchingEnisa'
  | 'fetchingHistoric'
  | 'fetchingCustom'
  | 'fetchingMetasploit'
  | 'fetchingPoc'
  | 'fetchingMarket'
  | 'enriching'
  | 'resolvingPocHistory'
  | 'saving'
  | 'savingEnisa'
  | 'savingHistoric'
  | 'savingCustom'
  | 'savingMetasploit'
  | 'savingPoc'
  | 'savingMarket'
  | 'complete'
  | 'error'

type ImportProgressState = {
  phase: ImportPhase
  completed: number
  total: number
  message: string
  startedAt: string | null
  updatedAt: string | null
  error: string | null
  activeSources: ImportTaskKey[]
  tasks: ImportTaskProgress[]
  events: ImportProgressEvent[]
}

const TASK_ORDER: ImportTaskKey[] = [
  'kev',
  'historic',
  'custom',
  'enisa',
  'epss',
  'metasploit',
  'poc',
  'market'
]
const EVENT_LIMIT = 50

type InternalImportProgressState = ImportProgressState & {
  eventCounter: number
  lastTaskMessages: Partial<Record<ImportTaskKey, string>>
  lastTaskProgress: Partial<Record<ImportTaskKey, { completed: number; total: number }>>
}

const createTaskState = (
  key: ImportTaskKey,
  status: ImportTaskStatus,
  message = '',
  completed = 0,
  total = 0
): ImportTaskProgress => ({
  key,
  label: describeTaskKey(key),
  status,
  message,
  completed,
  total
})

const createTaskList = (activeSources: ImportTaskKey[]): ImportTaskProgress[] => {
  if (!activeSources.length) {
    return TASK_ORDER.map(key => createTaskState(key, 'pending'))
  }
  const activeSet = new Set(activeSources)
  return TASK_ORDER.map(key =>
    activeSet.has(key)
      ? createTaskState(key, 'pending')
      : createTaskState(key, 'skipped', 'Not scheduled this run')
  )
}

const defaultState: ImportProgressState = {
  phase: 'idle',
  completed: 0,
  total: 0,
  message: '',
  startedAt: null,
  updatedAt: null,
  error: null,
  activeSources: [],
  tasks: createTaskList([]),
  events: []
}

const createInternalState = (): InternalImportProgressState => ({
  ...defaultState,
  eventCounter: 0,
  lastTaskMessages: {},
  lastTaskProgress: {}
})

declare global {
  // eslint-disable-next-line no-var
  var __kevImportProgress: InternalImportProgressState | undefined
}

const getState = (): InternalImportProgressState => {
  if (!globalThis.__kevImportProgress) {
    globalThis.__kevImportProgress = createInternalState()
  }

  return globalThis.__kevImportProgress
}

const commit = (patch: Partial<InternalImportProgressState>) => {
  const state = getState()
  const timestamp = new Date().toISOString()

  const nextPhase = patch.phase ?? state.phase
  const resetState = nextPhase === 'idle'

  const baseState: InternalImportProgressState = resetState
    ? createInternalState()
    : {
        ...state,
        updatedAt: timestamp,
        startedAt:
          nextPhase !== 'idle' && state.phase !== nextPhase
            ? state.startedAt ?? timestamp
            : state.startedAt,
        phase: nextPhase,
        completed: patch.completed ?? state.completed,
        total: patch.total ?? state.total,
        message: patch.message ?? state.message,
        error: patch.error ?? state.error,
        activeSources: patch.activeSources ?? state.activeSources,
        tasks: patch.tasks ?? state.tasks,
        events: patch.events ?? state.events,
        eventCounter: patch.eventCounter ?? state.eventCounter,
        lastTaskMessages: patch.lastTaskMessages ?? state.lastTaskMessages
      }

  globalThis.__kevImportProgress = {
    ...baseState,
    ...(resetState
      ? {}
      : {
          updatedAt: timestamp
        })
  }
}

const getTask = (key: ImportTaskKey): ImportTaskProgress | undefined => {
  return getState().tasks.find(task => task.key === key)
}

const updateTask = (key: ImportTaskKey, patch: Partial<ImportTaskProgress>) => {
  const state = getState()
  const tasks = state.tasks.map(task => (task.key === key ? { ...task, ...patch } : task))
  commit({ tasks })
}

const updateRemainingTasks = (status: ImportTaskStatus, message?: string) => {
  const state = getState()
  const tasks = state.tasks.map(task => {
    if (task.status === 'pending' || task.status === 'running') {
      return {
        ...task,
        status,
        message: message ?? task.message,
        completed: status === 'complete' ? task.total || task.completed : 0,
        total: status === 'complete' ? task.total || task.completed : task.total
      }
    }
    return task
  })
  commit({ tasks })
}

export const resetImportProgress = () => {
  globalThis.__kevImportProgress = createInternalState()
}

type EventPayload = {
  message: string
  status: ImportProgressEventStatus
  taskKey?: ImportTaskKey | null
  phase?: ImportPhase | null
}

const pushEvent = ({ message, status, taskKey = null, phase = null }: EventPayload) => {
  const state = getState()
  const timestamp = new Date().toISOString()
  const id = `${timestamp}-${state.eventCounter + 1}`
  const resolvedTaskKey = taskKey ?? null
  const taskLabel = resolvedTaskKey ? describeTaskKey(resolvedTaskKey) : null

  const event: ImportProgressEvent = {
    id,
    timestamp,
    message,
    status,
    taskKey: resolvedTaskKey,
    taskLabel,
    phase
  }

  const nextEvents = state.events.concat(event)
  const trimmedEvents = nextEvents.length > EVENT_LIMIT ? nextEvents.slice(nextEvents.length - EVENT_LIMIT) : nextEvents

  globalThis.__kevImportProgress = {
    ...state,
    events: trimmedEvents,
    eventCounter: state.eventCounter + 1,
    updatedAt: timestamp
  }
}

const rememberTaskMessage = (key: ImportTaskKey, message: string | null) => {
  const state = getState()
  if (!message) {
    if (state.lastTaskMessages[key]) {
      delete state.lastTaskMessages[key]
    }
    return
  }
  state.lastTaskMessages[key] = message
}

const resetTaskMessages = () => {
  const state = getState()
  state.lastTaskMessages = {}
}

const rememberTaskProgress = (key: ImportTaskKey, completed: number, total: number) => {
  const state = getState()
  state.lastTaskProgress[key] = { completed, total }
}

const forgetTaskProgress = (key: ImportTaskKey) => {
  const state = getState()
  if (state.lastTaskProgress[key]) {
    delete state.lastTaskProgress[key]
  }
}

const resetTaskProgress = () => {
  const state = getState()
  state.lastTaskProgress = {}
}

const shouldLogTaskMessage = (key: ImportTaskKey, message?: string, force = false) => {
  const state = getState()
  const trimmed = message?.trim() ?? ''
  if (!trimmed && !force) {
    return false
  }
  if (!force && state.lastTaskMessages[key] === trimmed) {
    return false
  }
  rememberTaskMessage(key, trimmed || null)
  return trimmed.length > 0 || force
}

const shouldEmitTaskProgress = (key: ImportTaskKey, completed: number, total: number) => {
  if (total <= 0) {
    forgetTaskProgress(key)
    return true
  }

  const state = getState()
  const previous = state.lastTaskProgress[key]
  const isFinal = completed >= total
  const interval = Math.max(1, Math.ceil(total / 50))

  rememberTaskProgress(key, completed, total)

  if (!previous) {
    return true
  }

  if (completed === 0) {
    return true
  }

  if (isFinal) {
    return true
  }

  const progressDelta = completed - previous.completed
  return progressDelta >= interval
}

export const startImportProgress = (
  message: string,
  sources: ImportTaskKey[] = TASK_ORDER
) => {
  resetTaskMessages()
  resetTaskProgress()
  const state = getState()
  state.events = []
  state.eventCounter = 0
  commit({
    phase: 'preparing',
    message,
    completed: 0,
    total: 0,
    error: null,
    activeSources: sources.slice(),
    tasks: createTaskList(sources)
  })
  pushEvent({ message, status: 'info', phase: 'preparing' })
}

export const setImportPhase = (phase: ImportPhase, payload: Partial<ImportProgressState> = {}) => {
  commit({
    ...payload,
    phase
  })
}

export const updateImportProgress = (
  phase: ImportPhase,
  completed: number,
  total: number,
  message?: string
) => {
  commit({
    phase,
    completed,
    total,
    message: message ?? getState().message
  })
}

export const markTaskPending = (key: ImportTaskKey, message?: string) => {
  updateTask(key, { status: 'pending', message: message ?? '', completed: 0, total: 0 })
  forgetTaskProgress(key)
  if (message) {
    rememberTaskMessage(key, null)
    pushEvent({ message, status: 'info', taskKey: key, phase: getState().phase })
  }
}

export const markTaskRunning = (key: ImportTaskKey, message?: string) => {
  const existing = getTask(key)
  updateTask(key, {
    status: 'running',
    message: message ?? existing?.message ?? '',
    completed: existing?.completed ?? 0,
    total: existing?.total ?? 0
  })
  const existingCompleted = existing?.completed ?? 0
  const existingTotal = existing?.total ?? 0
  if (existingCompleted === 0) {
    forgetTaskProgress(key)
  } else {
    rememberTaskProgress(key, existingCompleted, existingTotal)
  }
  const logMessage = message ?? existing?.message ?? describeTaskKey(key)
  if (shouldLogTaskMessage(key, logMessage, true)) {
    pushEvent({ message: logMessage, status: 'running', taskKey: key, phase: getState().phase })
  }
}

export const markTaskProgress = (
  key: ImportTaskKey,
  completed: number,
  total: number,
  message?: string
) => {
  const existing = getTask(key)
  updateTask(key, {
    status: 'running',
    completed,
    total,
    message: message ?? existing?.message ?? ''
  })
  if (!shouldEmitTaskProgress(key, completed, total)) {
    return
  }
  if (shouldLogTaskMessage(key, message)) {
    pushEvent({ message: message ?? '', status: 'running', taskKey: key, phase: getState().phase })
  }
}

export const markTaskSkipped = (key: ImportTaskKey, message?: string) => {
  updateTask(key, {
    status: 'skipped',
    message: message ?? 'Skipped this run',
    completed: 0,
    total: 0
  })
  const eventMessage = message ?? 'Skipped this run'
  rememberTaskMessage(key, null)
  forgetTaskProgress(key)
  pushEvent({ message: eventMessage, status: 'skipped', taskKey: key, phase: getState().phase })
}

export const markTaskComplete = (key: ImportTaskKey, message?: string) => {
  const existing = getTask(key)
  updateTask(key, {
    status: 'complete',
    message: message ?? existing?.message ?? '',
    completed: existing?.total ?? existing?.completed ?? 0,
    total: existing?.total ?? existing?.completed ?? 0
  })
  const eventMessage = message ?? existing?.message ?? `Completed ${describeTaskKey(key)}`
  rememberTaskMessage(key, null)
  forgetTaskProgress(key)
  pushEvent({ message: eventMessage, status: 'complete', taskKey: key, phase: getState().phase })
}

export const markTaskError = (key: ImportTaskKey, message?: string) => {
  const existing = getTask(key)
  updateTask(key, {
    status: 'error',
    message: message ?? existing?.message ?? ''
  })
  const eventMessage = message ?? existing?.message ?? `Error in ${describeTaskKey(key)}`
  rememberTaskMessage(key, null)
  forgetTaskProgress(key)
  pushEvent({ message: eventMessage, status: 'error', taskKey: key, phase: getState().phase })
}

export const completeImportProgress = (message: string) => {
  updateRemainingTasks('complete')
  commit({
    phase: 'complete',
    completed: getState().total,
    message,
    error: null
  })
  pushEvent({ message, status: 'info', phase: 'complete' })
}

export const failImportProgress = (message: string) => {
  updateRemainingTasks('error', message)
  commit({
    phase: 'error',
    message,
    error: message
  })
  pushEvent({ message, status: 'error', phase: 'error' })
}

export const getImportProgress = (): ImportProgressState => {
  const state = getState()
  const { eventCounter, lastTaskMessages, ...publicState } = state
  return {
    ...publicState,
    tasks: publicState.tasks.map(task => ({ ...task })),
    events: publicState.events.map(event => ({ ...event }))
  }
}

export const publishTaskEvent = (
  key: ImportTaskKey,
  message: string,
  status: ImportProgressEventStatus = 'info'
) => {
  pushEvent({ message, status, taskKey: key, phase: getState().phase })
}
