# NUXT UI Table Patterns

> **Note:** Nuxt UI 4 wraps TanStack Table under the hood. Always bind table datasets through the new `:data` prop—`:rows` was removed with the v4 upgrade. When migrating, rename any computed `rows` arrays to `data` (or pass a ref/computed directly) so Nuxt UI can keep the TanStack instance in sync.

## Basic Table with Actions

```vue
<script setup lang="ts">
import { h, resolveComponent, ref } from 'vue'
import type { TableColumn } from '@nuxt/ui'

const UButton = resolveComponent('UButton')
const UBadge = resolveComponent('UBadge')
const UDropdownMenu = resolveComponent('UDropdownMenu')

const data = ref([
  { id: '1', status: 'paid', email: 'user@example.com', amount: 100 }
])

const columns: TableColumn<typeof data.value[0]>[] = [
  {
    accessorKey: 'id',
    header: '#',
    cell: ({ row }) => `#${row.getValue('id')}`
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => {
      const color = row.getValue('status') === 'paid' ? 'success' : 'neutral'
      return h(UBadge, { variant: 'subtle', color }, () => row.getValue('status'))
    }
  },
  {
    id: 'actions',
    cell: ({ row }) =>
      h(
        UDropdownMenu,
        { items: [{ label: 'Action' }], 'aria-label': 'Actions dropdown' },
        () =>
          h(UButton, {
            icon: 'i-lucide-ellipsis-vertical',
            color: 'neutral',
            variant: 'ghost',
            'aria-label': 'Actions dropdown'
          })
      )
  }
]
</script>

<template>
  <UTable :data="data" :columns="columns" />
</template>
```

