
#pragma once

#include <stdlib.h>
#include <memory>
#include <stddef.h> // do not remove - needed for old gcc versions

template <class TYPE, int ALIGNMENT>
class aligned_allocator
{
	inline void* aligned_malloc(size_t size, size_t alignment)
	{
		void * pm = NULL;
		int errcode = posix_memalign(&pm, alignment, size);
        if(0 != errcode)
        {
        	pm = NULL;
        	//char errmsg[256];
        	//std::cerr << "posix_memalign error " << errcode << " : " << strerror_r(errcode, errmsg, 256) << std::endl;
        	//std::cerr << "size = " << size << "; alignment = " << alignment << std::endl;
        }
        return pm;
	}

	inline void aligned_free(void* ptr) { free(ptr); }

public:

	typedef TYPE value_type;
	typedef TYPE& reference;
	typedef const TYPE& const_reference;
	typedef TYPE* pointer;
	typedef const TYPE* const_pointer;
	typedef size_t size_type;
	typedef ptrdiff_t difference_type;

	template <class U>
	struct rebind
	{
		typedef aligned_allocator<U,ALIGNMENT> other;
	};

	inline aligned_allocator() throw() {}
	inline aligned_allocator(const aligned_allocator&) throw() {}

	template <class U>
	inline aligned_allocator(const aligned_allocator<U,ALIGNMENT>&) throw() {}

	inline ~aligned_allocator() throw() {}

	inline pointer address(reference r) { return &r; }
	inline const_pointer address(const_reference r) const { return &r; }

	pointer allocate(size_type n, typename std::allocator<void>::const_pointer hint = 0)
	{
		pointer res = reinterpret_cast<pointer>(aligned_malloc(sizeof(TYPE)*n,ALIGNMENT));
		if(res == 0)
			throw std::bad_alloc();
		return res;
	}
	inline void deallocate(pointer p, size_type) { aligned_free(p); }

	inline void construct(pointer p, const_reference value) { new (p) value_type(value); }
	inline void destroy(pointer p) { p->~value_type(); }

	inline size_type max_size() const throw() { return size_type(-1) / sizeof(TYPE); }

	inline bool operator==(const aligned_allocator&) { return true; }
	inline bool operator!=(const aligned_allocator& rhs) { return !operator==(rhs); }
};
