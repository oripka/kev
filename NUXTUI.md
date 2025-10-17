# NUXT UI 4 Usage

There were major api changes from nuxt ui 2 to 3 and recently nuxt ui4 was release being mostly compatible with nuxt ui 3.
Make sure to always use the correct nuxt ui 3/4 apis.

> **Note:** Examples may show multiple props for demonstration so the LLM learns available options. This does not mean all props must be used at once in real usage.

> Note: Keep examples minimal. Show only enough data to illustrate shape, API, props, and slots. Avoid redundant or verbose example data to save tokens in LLM usage. Future edits should follow this principle.

> **General Principles:**  
> - Avoid using custom styling classes like `text-neutral-400`, `text-neutral-300`, `bg-neutral-900/40`, etc. These are not compatible with Nuxt UI 3/4.  
> - Do not apply arbitrary `div`, `span`, `p`, or `table` wrappers with custom Tailwind classes.  
> - Always prefer Nuxt UI 3/4 components and props for styling and layout.  
> - Use the provided design system elements instead of ad‑hoc colors or backgrounds.  
> - When building cards (e.g., company profile or directory card), use proper Nuxt UI 4 components and variants without custom text/background colors.
> - Use Lucide icons (via `UIcon` / Iconify) instead of Heroicons or other sets.

## Changes from v3

	•	Renamed Components:
	•	UButtonGroup → UFieldGroup
	•	UPageMarquee → UMarquee
	•	UPageAccordion → UAccordion (add unmount-on-hide="false" + custom ui if needed)
	•	Forms:
	•	Transformations apply only on @submit (not state).
	•	Nested forms require nested + name.
	•	useChat → new Chat().
	•	content → parts.
	

## Colors

Always ensure that only the seven Nuxt UI v3 design system colors are used: primary (green), secondary (blue), success (green), info (blue), warning (yellow), error (red), neutral (slate).

## Variants

Most components support both **variants** and **colors**.

Available variants are:
- `solid`
- `outline`
- `soft`
- `subtle`
- `ghost`
- `link` (for links only)

  <UAlert
    color="neutral"
    variant="subtle"
    title="Heads up!"
    description="Change primary color."
    icon="i-lucide-terminal"
  />

## Alert

A callout to draw the user's attention.

```vue
<UAlert
  color="primary"
  variant="solid"
  title="Info"
  description="Alert msg"
  icon="i-lucide-info"
/>
```

## Badge

A short text to represent a status or a category.

```vue
<UBadge color="success" variant="soft">
  Success
</UBadge>
```

## Button

```vue
<UButton color="primary" variant="solid">
  Primary
</UButton>

<UButton color="secondary" variant="outline" icon="i-lucide-check">
  Confirm
</UButton>
```

## Card

Display content in a card with a header, body and footer.

```vue
<UCard>
  <template #header>
    Header
  </template>
  <template #body>
    Card body
  </template>
  <template #footer>
    Footer
  </template>
</UCard>
```

## File Upload

Upload files with drag and drop support.

```vue
<UFileUpload
  v-model="files"
  multiple
  drag
  accept="image/*"
  :maxSize="1024 * 1024 * 5"  // 5 MB
/>
```


## Form Recipes

Extended form walkthroughs now live in `NUXTUI.forms.md` to keep this reference lean. That file covers:

- Schema-driven validation with `useForm`
- Composite profile layout combining `UForm`, `UPageCard`, and media inputs
- Notification preference toggles grouped by section
- Password update forms with custom validation plus destructive account actions
- `UFormField` wrapper usage

## Table Recipes

Table-specific guidance has moved to `NUXTUI.tables.md`. Refer there for the TanStack-powered API and a minimal actions table example.

## Accordion


```
<script setup lang="ts">
const items = ref([
  { label: 'Q?', content: 'Yes!' }
])
</script>

<template>
  <UAccordion :items="items" />
</template>
```

## TIMELINE

```
<script setup lang="ts">
const items = ref([
  {
    date: 'Mar 15, 2025',
    title: 'Start',
    description: 'Project',
    icon: 'i-lucide-rocket'
  }
])
</script>

<template>
  <UTimeline :items="items" orientation="horizontal" />
</template>
```

## Tabs

```
<script setup lang="ts">
import type { TabsItem } from '@nuxt/ui'

const items: TabsItem[] = [
  { label: 'Account' },
  { label: 'Password' }
]
</script>

<template>
  <UTabs :items="items">
    <template #content="{ item }">
      <p>{{ item.label }} tab.</p>
    </template>
  </UTabs>
</template>
```

## Context menu

```
<script setup lang="ts">
const items = ref([
  [
    { label: 'Appearance', children: [{ label: 'Light' }, { label: 'Dark' }] }
  ],
  [
    { label: 'Refresh' }
  ]
])
</script>

<template>
  <UContextMenu :items="items">
    <div class="w-72 h-20 flex items-center justify-center border border-dashed rounded-md text-sm">
      Right click
    </div>
  </UContextMenu>
</template>
```

## RadioGroup

```vue
<script setup lang="ts">
import type { RadioGroupItem } from '@nuxt/ui'

const items = ref<RadioGroupItem[]>([
  { label: 'System', description: 'System theme', value: 'system' },
  { label: 'Light', description: 'Light theme', value: 'light' },
  { label: 'Dark', description: 'Dark theme', value: 'dark' }
])

const value = ref('system')
</script>

<template>
  <URadioGroup v-model="value" :items="items" />
</template>
```

## Select

A select element to choose from a list of options.


```vue
<script setup lang="ts">
import type { SelectItem } from '@nuxt/ui'

const items = ref<SelectItem[]>([
  { label: 'Backlog', value: 'backlog' },
  { label: 'Todo', value: 'todo' },
  { label: 'In Progress', value: 'in_progress' },
  { label: 'Done', value: 'done' }
])

const value = ref('backlog')
</script>

<template>
  <USelect v-model="value" :items="items" class="w-48" />
</template>
```

## SelectMenu

An advanced searchable select element.

```vue
<script setup lang="ts">
import type { SelectMenuItem } from '@nuxt/ui'

const items = ref<SelectMenuItem[]>([
  { label: 'Backlog', icon: 'i-lucide-circle-help' },
  { label: 'Todo', icon: 'i-lucide-circle-plus' },
  { label: 'In Progress', icon: 'i-lucide-circle-arrow-up' },
  { label: 'Done', icon: 'i-lucide-circle-check' }
])

const value = ref({
  label: 'Backlog',
  icon: 'i-lucide-circle-help'
})
</script>

<template>
  <USelectMenu
    v-model="value"
    :search-input="{
      placeholder: 'Filter...',
      icon: 'i-lucide-search'
    }"
    :items="items"
    class="w-48"
  />
</template>
```

## Slider

```vue
<template>
  <USlider :min="0" :max="50" :default-value="50" />
</template>
```

## Switch

```vue
<template>
  <USwitch label="Check me" />
</template>
```

## Textarea

```vue
<template>
  <UTextarea placeholder="Type..." />
</template>
```

## DropdownMenu

```vue
<script setup lang="ts">
const items = ref([
  [
    {
      label: 'Benjamin',
      avatar: { src: 'https://github.com/benjamincanac.png' },
      type: 'label'
    }
  ],
  [
    { label: 'Profile', icon: 'i-lucide-user' },
    { label: 'Billing', icon: 'i-lucide-credit-card' },
    { label: 'Settings', icon: 'i-lucide-cog', kbds: [','] },
    { label: 'Keyboard shortcuts', icon: 'i-lucide-monitor' }
  ],
  [
    { label: 'Team', icon: 'i-lucide-users' },
    {
      label: 'Invite users',
      icon: 'i-lucide-user-plus',
      children: [
        [
          { label: 'Email', icon: 'i-lucide-mail' },
          { label: 'Message', icon: 'i-lucide-message-square' }
        ],
        [
          { label: 'More', icon: 'i-lucide-circle-plus' }
        ]
      ]
    },
    { label: 'New team', icon: 'i-lucide-plus', kbds: ['meta', 'n'] }
  ],
  [
    { label: 'GitHub', icon: 'i-simple-icons-github', to: '/nuxt/ui', target: '_blank' },
    { label: 'Support', icon: 'i-lucide-life-buoy', to: '/docs/components/dropdown-menu' },
    { label: 'API', icon: 'i-lucide-cloud', disabled: true }
  ],
  [
    { label: 'Logout', icon: 'i-lucide-log-out', kbds: ['shift', 'meta', 'q'] }
  ]
])
</script>

<template>
  <UDropdownMenu :items="items">
    <UButton icon="i-lucide-menu" color="neutral" variant="outline" />
  </UDropdownMenu>
</template>
```


## Modal

<template>
  <UModal
    title="Modal desc"
    description="Lorem ipsum."
  >
    <UButton label="Open" color="neutral" variant="subtle" />

    <template #body>
      <Placeholder class="h-48" />
    </template>
  </UModal>
</template>

## Modal

A dialog window that can be used to display a message or request user input.

```
<template>
  <UModal
    title="Modal desc"
    description="Lorem ipsum."
  >
    <UButton label="Open" color="neutral" variant="subtle" />

    <template #body>
      <Placeholder class="h-48" />
    </template>
  </UModal>
</template>
```

### Wide modal

The normal modal is sometimes to narrow to show stuff

```
<UModal :ui="{ 
  content: 'w-full max-w-7xl rounded-xl shadow-lg', 
  body: 'p-6 text-base text-muted' 
}">
  <UButton label="Open" color="neutral" variant="subtle" />
  <template #content>
    <Placeholder class="h-48 m-4" />
  </template>
</UModal>
```

## Modal with actions / footer

```
<script setup lang="ts">
const open = ref(false)
</script>

<template>
  <UModal v-model:open="open" title="Modal with footer" description="This is useful when you want a form in a Modal." :ui="{ footer: 'justify-end' }">
    <UButton label="Open" color="neutral" variant="subtle" />

    <template #body>
      <Placeholder class="h-48" />
    </template>

    <template #footer="{ close }">
      <UButton label="Cancel" color="neutral" variant="outline" @click="close" />
      <UButton label="Submit" color="neutral" />
    </template>
  </UModal>
</template>
```

## Toast

A simple toast notification.

```vue
<script setup lang="ts">
const props = defineProps<{
  title: string
}>()

const toast = useToast()

function showToast() {
  toast.add(props)
}
</script>

<template>
  <UButton label="Show toast" color="neutral" variant="outline" @click="showToast" />
</template>
```

## Tooltip

A simple tooltip example.

```vue
<template>
  <UTooltip text="Open GitHub">
    <UButton label="Open" color="neutral" variant="subtle" />
  </UTooltip>
</template>
```

## BlogPost / BlogPosts

Although this component is called **BlogPost**, it is also useful for displaying cards with an image, such as company cards or similar content. You can use it to highlight items with a title, description, and image.

```vue
<template>
  <UBlogPost
    title="Nuxt Icon v1"
    description="Discover Nuxt"
    image="https://nuxt.com/assets/blog/nuxt-icon/cover.png"
    date="2024-11-25"
  />
</template>
```

You can also render multiple cards at once:

```vue
<template>
  <UBlogPosts>
    <UBlogPost
      v-for="(post, index) in posts"
      :key="index"
      v-bind="post"
    />
  </UBlogPosts>
</template>
```

### Slots

The `UBlogPost` component provides several slots for customization:

| Slot        | Type |
|-------------|------|
| `date`      | {}   |
| `badge`     | {}   |
| `title`     | {}   |
| `description` | {} |
| `authors`   | {}   |
| `header`    | {}   |
| `body`      | {}   |
| `footer`    | {}   |

Note: All props are also available as slots for further customization.

## PageCard

A pre-styled card component that displays a title, description, and optional link.

```vue
<template>
  <UPageCard
    title="Tailwind"
    description="v4"
    icon="i-simple-icons-tailwindcss"
    to="https://tailwindcss.com/docs/v4-beta"
    target="_blank"
    variant="soft"
  />
</template>
```

### PageGrid with multiple PageCards

```vue
<script setup lang="ts">
const cards = ref([
  {
    title: 'Icons',
    description: 'Nuxt UI',
    icon: 'i-lucide-smile',
    to: '/icons/'
  },
  {
    title: 'Fonts',
    description: 'Nuxt UI',
    icon: 'i-lucide-a-large-small',
    to: '/fonts/'
  }
])
</script>

<template>
  <UPageGrid>
    <UPageCard
      v-for="(card, index) in cards"
      :key="index"
      v-bind="card"
    />
  </UPageGrid>
</template>
```

## PageHeader

A responsive page header with title, description, and actions.

```vue
<template>
  <UPageHeader
    title="PageHeader"
    description="Responsive header"
  />
</template>
```

## PageList

A vertical list layout for displaying content in a stacked format.

```vue
<script setup lang="ts">
const users = ref([
  {
    name: 'Benjamin Canac',
    description: 'benjamincanac',
    to: 'https://github.com/b',
    target: '_blank',
    avatar: {
      src: 'https://github.com/b.png',
      alt: 'benjamincanac'
    }
  }
])
</script>

<template>
  <UPageList divide>
    <UPageCard
      v-for="(user, index) in users"
      :key="index"
      variant="ghost"
      :to="user.to"
      :target="user.target"
    >
      <template #body>
        <UUser :name="user.name" :description="user.description" :avatar="user.avatar" size="xl" />
      </template>
    </UPageCard>
  </UPageList>
</template>
```
