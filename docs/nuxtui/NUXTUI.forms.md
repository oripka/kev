# NUXT UI Form Patterns

Guidance and composable examples for building validated forms with Nuxt UI 4.

## Basic Form Validation

Create validated forms with schema support.

```vue
<script setup lang="ts">
import { useForm, useField } from '@nuxt/ui'
import * as yup from 'yup'

const schema = yup.object({
  email: yup.string().email().required(),
  password: yup.string().min(6).required()
})

const { handleSubmit, errors } = useForm({ validationSchema: schema })

const { value: email } = useField('email')
const { value: password } = useField('password')

const onSubmit = handleSubmit((values) => {
  console.log('Submitted:', values)
})
</script>

<template>
  <UForm @submit="onSubmit">
    <UFormField label="Email" :error="errors.email">
      <UInput v-model="email" type="email" />
    </UFormField>
    <UFormField label="Password" :error="errors.password">
      <UInput v-model="password" type="password" />
    </UFormField>
    <UButton type="submit" color="primary">Submit</UButton>
  </UForm>
</template>
```

## Composite Profile Form

Combine `UForm`, `UPageCard`, and supporting inputs to build richer, validated settings forms.

```vue
<script setup lang="ts">
import { reactive, ref } from 'vue'
import { z } from 'zod'
import type { FormSubmitEvent } from '@nuxt/ui'

const avatarInput = ref<HTMLInputElement>()

const profileSchema = z.object({
  name: z.string().min(2, 'Name is too short'),
  email: z.string().email('Enter a valid email'),
  username: z.string().min(2, 'Username is too short'),
  avatar: z.string().optional(),
  bio: z.string().max(280).optional()
})

type ProfileForm = z.infer<typeof profileSchema>

const profile = reactive<ProfileForm>({
  name: 'Alex Doe',
  email: 'alex@example.com',
  username: 'alexd',
  avatar: undefined,
  bio: ''
})

const toast = useToast()

function onSubmit(event: FormSubmitEvent<ProfileForm>) {
  toast.add({
    title: 'Profile saved',
    description: 'Your information is now up to date.',
    color: 'success',
    icon: 'i-lucide-check'
  })
  console.log(event.data)
}

function onAvatarChange(event: Event) {
  const input = event.target as HTMLInputElement
  if (!input.files?.length) return
  profile.avatar = URL.createObjectURL(input.files[0]!)
}

function selectAvatar() {
  avatarInput.value?.click()
}
</script>

<template>
  <UForm id="profile-form" :schema="profileSchema" :state="profile" @submit="onSubmit">
    <UPageCard
      title="Profile"
      description="These details are visible to your learners."
      orientation="horizontal"
      variant="naked"
      class="mb-4"
    >
      <UButton form="profile-form" type="submit" color="primary" label="Save" class="w-fit lg:ms-auto" />
    </UPageCard>

    <UPageCard variant="subtle">
      <UFormField
        name="name"
        label="Name"
        description="Shown on invoices and emails."
        class="flex max-sm:flex-col items-start justify-between gap-4"
        required
      >
        <UInput v-model="profile.name" autocomplete="off" />
      </UFormField>
      <USeparator />

      <UFormField
        name="email"
        label="Email"
        description="Used for notifications and sign-in."
        class="flex max-sm:flex-col items-start justify-between gap-4"
        required
      >
        <UInput v-model="profile.email" type="email" autocomplete="off" />
      </UFormField>
      <USeparator />

      <UFormField
        name="username"
        label="Username"
        description="Appears in URLs and invitations."
        class="flex max-sm:flex-col items-start justify-between gap-4"
        required
      >
        <UInput v-model="profile.username" autocomplete="off" />
      </UFormField>
      <USeparator />

      <UFormField
        name="avatar"
        label="Avatar"
        description="JPG, PNG, or GIF. 1 MB max."
        class="flex max-sm:flex-col justify-between sm:items-center gap-4"
      >
        <div class="flex flex-wrap items-center gap-3">
          <UAvatar :src="profile.avatar" :alt="profile.name" size="lg" />
          <UButton label="Choose" color="neutral" @click="selectAvatar" />
          <input
            ref="avatarInput"
            type="file"
            class="hidden"
            accept="image/*"
            @change="onAvatarChange"
          />
        </div>
      </UFormField>
      <USeparator />

      <UFormField
        name="bio"
        label="Bio"
        description="Brief description for your profile."
        class="flex max-sm:flex-col items-start justify-between gap-4"
        :ui="{ container: 'w-full' }"
      >
        <UTextarea v-model="profile.bio" :rows="4" autoresize class="w-full" />
      </UFormField>
    </UPageCard>
  </UForm>
</template>
```

## Modal Management Form

Use a Nuxt UI modal with `#body` / `#footer` slots to host CRUD forms. Keep the form in a grid so fields align cleanly in two columns and force the inputs to stretch with `class="w-full"`.

```vue
<script setup lang="ts">
const isOpen = ref(false)
const mode = ref<'create' | 'edit'>('create')
const form = reactive({
  id: '',
  name: '',
  email: '',
  notes: ''
})

const title = computed(() => mode.value === 'create' ? 'Provider anlegen' : 'Provider bearbeiten')

function open(provider?: Provider) {
  if (provider) {
    Object.assign(form, provider)
    mode.value = 'edit'
  } else {
    Object.assign(form, { id: '', name: '', email: '', notes: '' })
    mode.value = 'create'
  }
  isOpen.value = true
}

async function onSubmit() {
  // submit logic
  isOpen.value = false
}
</script>

<template>
  <UModal
    v-model:open="isOpen"
    :title="title"
    prevent-close
    :ui="{ content: 'max-w-3xl', body: 'p-6 space-y-6', footer: 'p-6 justify-end gap-2' }"
  >
    <template #body>
      <UForm id="provider-form" :state="form" @submit.prevent="onSubmit" class="grid gap-4 md:grid-cols-2">
        <UFormField label="Interne ID" name="id" :required="true">
          <UInput class="w-full" v-model="form.id" :disabled="mode === 'edit'" placeholder="z. B. fast-lane" />
        </UFormField>
        <UFormField label="Name" name="name" :required="true">
          <UInput class="w-full" v-model="form.name" placeholder="Providername" />
        </UFormField>
        <UFormField label="E-Mail" name="email">
          <UInput class="w-full" v-model="form.email" type="email" placeholder="kontakt@example.com" />
        </UFormField>
        <UFormField label="Notizen" name="notes" class="md:col-span-2">
          <UTextarea class="w-full" v-model="form.notes" placeholder="Interne Hinweise" />
        </UFormField>
      </UForm>
    </template>

    <template #footer>
      <UButton color="neutral" variant="soft" @click="isOpen = false">Abbrechen</UButton>
      <UButton form="provider-form" type="submit" color="primary">
        {{ mode === 'create' ? 'Anlegen' : 'Speichern' }}
      </UButton>
    </template>
  </UModal>
</template>
```

## Notification Preferences

Group related toggles with shared headings to mirror complex settings pages.

```vue
<script setup lang="ts">
import { reactive } from 'vue'

const state = reactive<{ [key: string]: boolean }>({
  email: true,
  desktop: false,
  product_updates: true,
  weekly_digest: false,
  important_updates: true
})

const sections = [
  {
    title: 'Notification channels',
    description: 'Where can we notify you?',
    fields: [
      { name: 'email', label: 'Email', description: 'Receive a daily email digest.' },
      { name: 'desktop', label: 'Desktop', description: 'Receive desktop notifications.' }
    ]
  },
  {
    title: 'Account updates',
    description: 'Receive updates about Nuxt UI.',
    fields: [
      { name: 'weekly_digest', label: 'Weekly digest', description: 'Weekly digest of news.' },
      { name: 'product_updates', label: 'Product updates', description: 'Monthly summary of new features.' },
      { name: 'important_updates', label: 'Important updates', description: 'Security fixes and maintenance notices.' }
    ]
  }
]

async function onChange() {
  console.log(state)
}
</script>

<template>
  <div v-for="section in sections" :key="section.title" class="space-y-4">
    <UPageCard
      :title="section.title"
      :description="section.description"
      variant="naked"
    />

    <UPageCard variant="subtle" :ui="{ container: 'divide-y divide-default' }">
      <UFormField
        v-for="field in section.fields"
        :key="field.name"
        :name="field.name"
        :label="field.label"
        :description="field.description"
        class="flex items-center justify-between gap-4"
      >
        <USwitch v-model="state[field.name]" @update:model-value="onChange" />
      </UFormField>
    </UPageCard>
  </div>
</template>
```

## Password & Closure

Mix per-field validation with a destructive account action card.

```vue
<script setup lang="ts">
import { reactive } from 'vue'
import { z } from 'zod'
import type { FormError } from '@nuxt/ui'

const passwordSchema = z.object({
  current: z.string().min(8, 'Must be at least 8 characters'),
  new: z.string().min(8, 'Must be at least 8 characters')
})

type PasswordSchema = z.infer<typeof passwordSchema>

const password = reactive<Partial<PasswordSchema>>({
  current: undefined,
  new: undefined
})

const validate = (state: Partial<PasswordSchema>): FormError[] => {
  const errors: FormError[] = []
  if (state.current && state.new && state.current === state.new) {
    errors.push({ name: 'new', message: 'Passwords must be different' })
  }
  return errors
}
</script>

<template>
  <div class="space-y-4">
    <UPageCard
      title="Password"
      description="Confirm your current password before setting a new one."
      variant="subtle"
    >
      <UForm
        :schema="passwordSchema"
        :state="password"
        :validate="validate"
        class="flex flex-col gap-4 max-w-xs"
      >
        <UFormField name="current">
          <UInput v-model="password.current" type="password" placeholder="Current password" />
        </UFormField>

        <UFormField name="new">
          <UInput v-model="password.new" type="password" placeholder="New password" />
        </UFormField>

        <UButton label="Update" type="submit" class="w-fit" />
      </UForm>
    </UPageCard>

    <UPageCard
      title="Account"
      description="Delete your account permanently. This cannot be undone."
      color="error"
      variant="soft"
    >
      <template #footer>
        <UButton label="Delete account" color="error" variant="solid" />
      </template>
    </UPageCard>
  </div>
</template>
```

## Form Field Wrapper

Wrap inputs with labels, descriptions, and validation messages.

```vue
<UFormField
  label="Username"
  description="Your username."
  :error="'Required.'"
>
  <UInput v-model="username" />
</UFormField>
```
