import { computed, onMounted, onScopeDispose, ref, watch } from 'vue'
import { useRequestFetch } from '#app'
import type { TrackedProduct } from '~/types'

const PRODUCTS_STORAGE_KEY = 'kev.trackedProducts'
const SESSION_STORAGE_KEY = 'kev.sessionId'
const SHOW_ONLY_STORAGE_KEY = 'kev.showOwnedOnly'

const dedupeProducts = (items: TrackedProduct[]): TrackedProduct[] => {
  const map = new Map<string, TrackedProduct>()
  for (const item of items) {
    map.set(item.productKey, item)
  }
  return Array.from(map.values())
}

export const useTrackedProducts = () => {
  const requestFetch = useRequestFetch()
  const isClient = typeof window !== 'undefined'

  const trackedProducts = ref<TrackedProduct[]>([])
  const showOwnedOnly = ref(false)
  const sessionId = ref<string | null>(null)
  const isSaving = ref(false)
  const saveError = ref<string | null>(null)
  const isReady = ref(false)
  let saveTimer: ReturnType<typeof setTimeout> | null = null

  const trackedProductSet = computed(
    () => new Set(trackedProducts.value.map(item => item.productKey))
  )

  const persistProducts = (items: TrackedProduct[]) => {
    if (!isClient) {
      return
    }
    try {
      window.localStorage.setItem(PRODUCTS_STORAGE_KEY, JSON.stringify(items))
    } catch {
      // Ignore storage failures to keep UX smooth.
    }
  }

  const persistShowOwnedOnly = (value: boolean) => {
    if (!isClient) {
      return
    }
    try {
      window.localStorage.setItem(SHOW_ONLY_STORAGE_KEY, value ? '1' : '0')
    } catch {
      // Ignore storage failures.
    }
  }

  const loadFromStorage = () => {
    if (!isClient) {
      return
    }

    try {
      const storedProducts = window.localStorage.getItem(PRODUCTS_STORAGE_KEY)
      if (storedProducts) {
        const parsed = JSON.parse(storedProducts) as TrackedProduct[]
        trackedProducts.value = dedupeProducts(parsed)
      }
    } catch {
      trackedProducts.value = []
    }

    try {
      const storedSession = window.localStorage.getItem(SESSION_STORAGE_KEY)
      if (storedSession) {
        sessionId.value = storedSession
      }
    } catch {
      sessionId.value = null
    }

    try {
      const storedShowOnly = window.localStorage.getItem(SHOW_ONLY_STORAGE_KEY)
      if (storedShowOnly === '1') {
        showOwnedOnly.value = true
      }
    } catch {
      showOwnedOnly.value = false
    }
  }

  const ensureSession = async (): Promise<string | null> => {
    if (!isClient) {
      return null
    }

    if (sessionId.value) {
      return sessionId.value
    }

    const response = await requestFetch<{ sessionId: string }>('/api/session', {
      method: 'POST'
    })

    sessionId.value = response.sessionId

    try {
      window.localStorage.setItem(SESSION_STORAGE_KEY, response.sessionId)
    } catch {
      // Ignore storage failures.
    }

    return response.sessionId
  }

  const saveToServer = async () => {
    if (!isClient || !isReady.value) {
      return
    }

    const session = await ensureSession()
    if (!session) {
      return
    }

    isSaving.value = true

    try {
      await requestFetch('/api/user-filters', {
        method: 'POST',
        body: {
          sessionId: session,
          products: trackedProducts.value
        }
      })
      saveError.value = null
    } catch (error) {
      saveError.value = error instanceof Error ? error.message : 'Unable to save filters'
    } finally {
      isSaving.value = false
    }
  }

  const scheduleSave = () => {
    if (!isClient || !isReady.value) {
      return
    }

    if (saveTimer) {
      clearTimeout(saveTimer)
    }

    saveTimer = setTimeout(() => {
      void saveToServer()
    }, 400)
  }

  const addTrackedProduct = (product: TrackedProduct) => {
    trackedProducts.value = dedupeProducts([
      ...trackedProducts.value,
      product
    ])
  }

  const removeTrackedProduct = (productKey: string) => {
    trackedProducts.value = trackedProducts.value.filter(
      item => item.productKey !== productKey
    )
  }

  const clearTrackedProducts = () => {
    trackedProducts.value = []
  }

  const setTrackedProducts = (items: TrackedProduct[]) => {
    trackedProducts.value = dedupeProducts(items)
  }

  if (isClient) {
    watch(
      trackedProducts,
      value => {
        persistProducts(value)
        scheduleSave()
      },
      { deep: true }
    )

    watch(
      showOwnedOnly,
      value => {
        persistShowOwnedOnly(value)
      }
    )
  }

  onMounted(() => {
    loadFromStorage()
    isReady.value = true
    scheduleSave()
  })

  onScopeDispose(() => {
    if (saveTimer) {
      clearTimeout(saveTimer)
    }
  })

  return {
    trackedProducts,
    trackedProductSet,
    addTrackedProduct,
    removeTrackedProduct,
    clearTrackedProducts,
    setTrackedProducts,
    showOwnedOnly,
    setShowOwnedOnly: (value: boolean) => {
      showOwnedOnly.value = value
    },
    toggleShowOwnedOnly: () => {
      showOwnedOnly.value = !showOwnedOnly.value
    },
    isSaving,
    saveError,
    isReady,
    sessionId,
    ensureSession,
    saveToServer
  }
}
