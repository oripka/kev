import { createError, deleteCookie, getCookie, getHeader } from 'h3'
import type { H3Event } from 'h3'
import { useRuntimeConfig } from '#imports'

const resolveCookieName = (event: H3Event): string => {
  const config = useRuntimeConfig(event)
  return config.public?.adminCookieName || 'admin-access'
}

export const requireAdminKey = (event: H3Event) => {
  const config = useRuntimeConfig(event)
  const expectedKey = config.admin?.apiKey

  if (!expectedKey) {
    return
  }

  const cookieName = resolveCookieName(event)
  const headerKey = getHeader(event, 'x-admin-key')

  if (headerKey && headerKey === expectedKey) {
    return
  }

  const cookieValue = getCookie(event, cookieName)
  if (cookieValue === expectedKey) {
    return
  }

  if (cookieValue) {
    deleteCookie(event, cookieName)
  }

  throw createError({ statusCode: 403, statusMessage: 'Forbidden' })
}

