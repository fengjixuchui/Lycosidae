# Manual for VM protection

## Virtualize functions

### ScyllaHideDetector

- khash

- ntdll_restore

- kernelbase_restore

- user32_restore

### Lycosidae

- nt_close_invalide_handle_helper

- nt_close_invalide_handle

- set_handle_informatiom_protected_handle_helper

- set_handle_informatiom_protected_handle

### Notes

For strong import protection add virtualization to hash_ functions

![hash.png](img/hash.png)