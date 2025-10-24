import { createError, deleteCookie, getCookie, setCookie } from 'h3'

export default defineNuxtRouteMiddleware(to => {
  if (process.client) {
    return
  }

  const event = useRequestEvent()
  if (!event) {
    return
  }

  const runtimeConfig = useRuntimeConfig()
  const requiredKey = runtimeConfig.admin?.apiKey
  if (!requiredKey) {
    return
  }

  const cookieName = runtimeConfig.public?.adminCookieName || 'admin-access'
  const rawKey = to.query.key
  const providedKey = Array.isArray(rawKey) ? rawKey[0] : rawKey

  if (providedKey && providedKey === requiredKey) {
    setCookie(event, cookieName, requiredKey, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      path: '/',
    })
    return
  }

  const cookieValue = getCookie(event, cookieName)
  if (cookieValue === requiredKey) {
    return
  }

  deleteCookie(event, cookieName)
  throw createError({ statusCode: 403, statusMessage: 'Forbidden' })
})

