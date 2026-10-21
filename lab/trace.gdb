# Proof of the mechanism: watch BG(serialize) across the request boundary.
#
# Layout (from objdump of php_var_serialize_init, PHP 8.5.11):
#   basic_globals+848 = BG(serialize_lock)   (u32)
#   basic_globals+856 = BG(serialize).data   (ptr, 64-byte emalloc)
#   basic_globals+864 = BG(serialize).level  (u32)
#
# Run:  gdb -q -batch -x trace.gdb --args php -n -d memory_limit=8M \
#           -d session.upload_progress.enabled=1 -d session.save_path=/tmp/s -S 127.0.0.1:9401 -t .
# then arm + fire from another shell.
#
# Observed (see notes/journal.md):
#   R1: HIT init level=0 data=(nil)      -> fresh alloc, level=1
#       HIT init level=1 data=0x...8040  -> nested reuse, level=2
#       HIT destroy level=2              -> level=1, NOT freed (level != 1)
#       ... memory_limit fatal, destroy never runs -> level stays 1, data dangles
#   R2: HIT init level=1 data=0x...8040  <-- SAME pointer, next request
#       -> reuse branch taken, zend_hash_init() is never called
#   R3: HIT init level=0 data=(nil)      <-- RINIT(basic) memset cleared it again
set pagination off
set confirm off

break php_var_serialize_init
commands
silent
printf "HIT init    level=%u data=%p lock=%u\n", *(unsigned int*)((char*)&basic_globals+864), *(void**)((char*)&basic_globals+856), *(unsigned int*)((char*)&basic_globals+848)
continue
end

break php_var_serialize_destroy
commands
silent
printf "HIT destroy level=%u data=%p\n", *(unsigned int*)((char*)&basic_globals+864), *(void**)((char*)&basic_globals+856)
continue
end

run
