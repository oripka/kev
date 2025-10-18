<script setup lang="ts">
import { computed, ref } from 'vue'
import { VisAxis, VisGroupedBar, VisTooltip, VisXYContainer } from '@unovis/vue'
import { useKevData } from '~/composables/useKevData'

const { vendors, products, domainCategories, exploitLayers, vulnerabilityCategories } = useKevData()

const topCountOptions = [5, 10, 15, 20]
const topCountItems = topCountOptions.map(value => ({
  label: `Top ${value}`,
  value
}))

const topCount = ref(5)

const vendorData = computed(() => vendors.value.slice(0, topCount.value))
const productData = computed(() => products.value.slice(0, topCount.value))
const domainData = computed(() => domainCategories.value.slice(0, 10))
const exploitLayerData = computed(() => exploitLayers.value.slice(0, 10))
const vulnerabilityData = computed(() => vulnerabilityCategories.value.slice(0, 10))

const x = (_: { count: number }, index: number) => index
const y = (datum: { count: number }) => datum.count

const vendorTicks = (index: number) => vendorData.value[index]?.name ?? ''
const productTicks = (index: number) => productData.value[index]?.name ?? ''
const domainTicks = (index: number) => domainData.value[index]?.name ?? ''
const exploitLayerTicks = (index: number) => exploitLayerData.value[index]?.name ?? ''
const vulnerabilityTicks = (index: number) => vulnerabilityData.value[index]?.name ?? ''

const tooltip = (datum: { name: string; count: number }) => `${datum.name}: ${datum.count}`
</script>

<template>
  <UPage>
    <UPageHeader
      title="Catalog statistics"
      description="Explore the most impacted vendors, products, and categories"
    />

    <UPageBody>
      <div class="flex justify-end">
        <UFormField label="Show">
          <USelectMenu
            v-model="topCount"
            :items="topCountItems"
            value-key="value"
            size="sm"
          />
        </UFormField>
      </div>

      <UPageSection>
        <UPageGrid>
          <UCard>
            <template #header>
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Top vendors
              </p>
            </template>

            <VisXYContainer :data="vendorData" class="h-96">
              <VisGroupedBar :x="x" :y="y" color="var(--ui-primary)" />
              <VisAxis type="x" :x="x" :tick-format="vendorTicks" />
              <VisAxis type="y" :y="y" />
              <VisTooltip :template="tooltip" />
            </VisXYContainer>
          </UCard>

          <UCard>
            <template #header>
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Top products
              </p>
            </template>

            <VisXYContainer :data="productData" class="h-96">
              <VisGroupedBar :x="x" :y="y" color="var(--ui-secondary)" />
              <VisAxis type="x" :x="x" :tick-format="productTicks" />
              <VisAxis type="y" :y="y" />
              <VisTooltip :template="tooltip" />
            </VisXYContainer>
          </UCard>

          <UCard>
            <template #header>
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Domain categories
              </p>
            </template>

            <VisXYContainer :data="domainData" class="h-96">
              <VisGroupedBar :x="x" :y="y" color="var(--ui-info)" />
              <VisAxis type="x" :x="x" :tick-format="domainTicks" />
              <VisAxis type="y" :y="y" />
              <VisTooltip :template="tooltip" />
            </VisXYContainer>
          </UCard>

          <UCard>
            <template #header>
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Exploit profiles
              </p>
            </template>

            <VisXYContainer :data="exploitLayerData" class="h-96">
              <VisGroupedBar :x="x" :y="y" color="var(--ui-warning)" />
              <VisAxis type="x" :x="x" :tick-format="exploitLayerTicks" />
              <VisAxis type="y" :y="y" />
              <VisTooltip :template="tooltip" />
            </VisXYContainer>
          </UCard>

          <UCard>
            <template #header>
              <p class="text-lg font-semibold text-neutral-900 dark:text-neutral-50">
                Vulnerability categories
              </p>
            </template>

            <VisXYContainer :data="vulnerabilityData" class="h-96">
              <VisGroupedBar :x="x" :y="y" color="var(--ui-warning)" />
              <VisAxis type="x" :x="x" :tick-format="vulnerabilityTicks" />
              <VisAxis type="y" :y="y" />
              <VisTooltip :template="tooltip" />
            </VisXYContainer>
          </UCard>
        </UPageGrid>
      </UPageSection>
    </UPageBody>
  </UPage>
</template>
