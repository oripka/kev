import type { ImportTaskKey, ImportTaskProgress, ImportTaskStatus } from '~/types'
import { describeTaskKey } from '~/utils/exploitProductHints'

type ImportPhase =
  | 'idle'
  | 'preparing'
  | 'fetchingCvss'
  | 'fetchingEnisa'
  | 'fetchingHistoric'
  | 'fetchingMetasploit'
  | 'fetchingMarket'
  | 'enriching'
  | 'saving'
  | 'savingEnisa'
  | 'savingHistoric'
  | 'savingMetasploit'
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
}

const TASK_ORDER: ImportTaskKey[] = ['kev', 'historic', 'enisa', 'metasploit', 'market']

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
  tasks: createTaskList([])
}

declare global {
  // eslint-disable-next-line no-var
  var __kevImportProgress: ImportProgressState | undefined
}

const getState = (): ImportProgressState => {
  if (!globalThis.__kevImportProgress) {
    globalThis.__kevImportProgress = { ...defaultState }
  }

  return globalThis.__kevImportProgress
}

const commit = (patch: Partial<ImportProgressState>) => {
  const state = getState()
  const timestamp = new Date().toISOString()

  globalThis.__kevImportProgress = {
    ...state,
    ...patch,
    updatedAt: timestamp,
    startedAt:
      patch.phase && patch.phase !== state.phase && patch.phase !== 'idle'
        ? state.startedAt ?? timestamp
        : patch.phase === 'idle'
          ? null
          : state.startedAt,
    ...(patch.phase === 'idle'
      ? { completed: 0, total: 0, error: null, message: '', activeSources: [], tasks: createTaskList([]) }
      : {})
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
  globalThis.__kevImportProgress = { ...defaultState }
}

export const startImportProgress = (
  message: string,
  sources: ImportTaskKey[] = TASK_ORDER
) => {
  commit({
    phase: 'preparing',
    message,
    completed: 0,
    total: 0,
    error: null,
    activeSources: sources.slice(),
    tasks: createTaskList(sources)
  })
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
}

export const markTaskRunning = (key: ImportTaskKey, message?: string) => {
  const existing = getTask(key)
  updateTask(key, {
    status: 'running',
    message: message ?? existing?.message ?? '',
    completed: existing?.completed ?? 0,
    total: existing?.total ?? 0
  })
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
}

export const markTaskSkipped = (key: ImportTaskKey, message?: string) => {
  updateTask(key, {
    status: 'skipped',
    message: message ?? 'Skipped this run',
    completed: 0,
    total: 0
  })
}

export const markTaskComplete = (key: ImportTaskKey, message?: string) => {
  const existing = getTask(key)
  updateTask(key, {
    status: 'complete',
    message: message ?? existing?.message ?? '',
    completed: existing?.total ?? existing?.completed ?? 0,
    total: existing?.total ?? existing?.completed ?? 0
  })
}

export const markTaskError = (key: ImportTaskKey, message?: string) => {
  const existing = getTask(key)
  updateTask(key, {
    status: 'error',
    message: message ?? existing?.message ?? ''
  })
}

export const completeImportProgress = (message: string) => {
  updateRemainingTasks('complete')
  commit({
    phase: 'complete',
    completed: getState().total,
    message,
    error: null
  })
}

export const failImportProgress = (message: string) => {
  updateRemainingTasks('error', message)
  commit({
    phase: 'error',
    message,
    error: message
  })
}

export const getImportProgress = (): ImportProgressState => {
  return { ...getState(), tasks: getState().tasks.map(task => ({ ...task })) }
}
