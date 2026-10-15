export default {
  props: {
    columns: Array,
    editingBusy: Boolean,
  },
  template: `
    <q-table ref="qRef" :columns="columns">
      <template #body-cell="props">
        <q-td :props="props" :class="{'interface-unavailable': !props.row.editable}">
          {{ props.value }}
        </q-td>
      </template>
      <template #body-selection="props">
        <q-checkbox v-model="props.selected" :disable="!props.row.editable || props.row.editing_disabled"
          :aria-label="'Select ' + props.row.interface">
          <q-tooltip v-if="!props.row.editable">{{ props.row.blocked_reason }}</q-tooltip>
        </q-checkbox>
      </template>
      <template #header-selection>
        <div class="row no-wrap" style="gap:0">
          <q-btn icon="done_all" flat round dense :disable="editingBusy"
            aria-label="Select available filtered interfaces" @click="$emit('select_available', {clear: false})">
            <q-tooltip>Select available filtered interfaces</q-tooltip>
          </q-btn>
          <q-btn icon="deselect" flat round dense :disable="editingBusy"
            aria-label="Clear interface selection" @click="$emit('select_available', {clear: true})">
            <q-tooltip>Clear interface selection</q-tooltip>
          </q-btn>
        </div>
      </template>
      <template #body-cell-proposed="props">
        <q-td :props="props" :class="{'interface-unavailable': !props.row.editable}">
          <div class="row items-center no-wrap" style="min-width:300px;gap:4px">
            <q-input :key="'description-' + props.row.interface" v-model="props.row.proposed"
              outlined dense class="col" style="min-width:180px"
              :aria-label="'New description for ' + props.row.interface"
              :disable="!props.row.editable || props.row.editing_disabled"
              :error="!!props.row.edit_error" :error-message="props.row.edit_error" hide-bottom-space
              @click.stop @keydown.enter="$event.target.blur()" @update:model-value="value => edit(props.row, value)" />
            <q-btn icon="delete_outline" flat round dense :disable="!props.row.editable || props.row.editing_disabled"
              :aria-label="'Clear description for ' + props.row.interface" @click.stop="action(props.row, 'clear')">
              <q-tooltip>Clear description</q-tooltip>
            </q-btn>
            <q-btn icon="undo" flat round dense :disable="!props.row.editable || props.row.editing_disabled || !props.row.change"
              :aria-label="'Discard change for ' + props.row.interface" @click.stop="action(props.row, 'reset')">
              <q-tooltip>Discard change</q-tooltip>
            </q-btn>
          </div>
        </q-td>
      </template>
    </q-table>
  `,
  methods: {
    edit(row, value) {
      row.proposed = value;
      row.change = value === '' ? '' : 'SET';
      row.edit_error = '';
      this.$emit('description_edit', {interface: row.interface, value, action: 'edit'});
    },
    action(row, action) {
      row.proposed = '';
      row.change = action === 'clear' ? 'CLEAR' : '';
      row.edit_error = '';
      this.$emit('description_edit', {interface: row.interface, action});
    },
  },
};