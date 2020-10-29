#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <semaphore.h>

template<class item>
class lfq {
	size_t data_size;
	item * data_;
	sem_t sem_push, sem_pop;
	size_t read_ofs, write_ofs;
public:
	lfq(const size_t size) :
		data_size(size), data_(new item[size]), read_ofs(0), write_ofs(0) {
		sem_init(&sem_push, 0, size);
		sem_init(&sem_pop, 0, 0);
	}
	~lfq() {
		sem_destroy(&sem_pop);
		sem_destroy(&sem_push);
		delete[] data_;
		data_ = NULL;
		read_ofs = write_ofs = 0;
	}

	int push(const item & x) {
		if(0 == sem_wait(&sem_push)) {
			data_[write_ofs] = x;
			write_ofs = (write_ofs + 1)%data_size;
			sem_post(&sem_pop);
			return 0;
		} else {
			return -1;
		}
	}
	int pop(item & x) {
		if(0 == sem_wait(&sem_pop)) {
			x = data_[read_ofs];
			read_ofs = (read_ofs + 1)%data_size;
			sem_post(&sem_push);
			return 0;
		} else {
			return -1;
		}
	}

	int push_wait(const item & x, const struct timespec *abs_timeout) {
		if(0 == sem_timedwait(&sem_push, abs_timeout)) {
			data_[write_ofs] = x;
			write_ofs = (write_ofs + 1)%data_size;
			sem_post(&sem_pop);
			return 0;
		} else {
			return -1;
		}
	}
	int pop_wait(item & x, const struct timespec *abs_timeout) {
		if(0 == sem_timedwait(&sem_pop, abs_timeout)) {
			x = data_[read_ofs];
			read_ofs = (read_ofs + 1)%data_size;
			sem_post(&sem_push);
			return 0;
		} else {
			return -1;
		}
	}

	bool full() {
		int value;
		sem_getvalue(&sem_push, &value);
		return (value == 0);
	}
	bool empty() {
		int value;
		sem_getvalue(&sem_pop, &value);
		return (value == 0);
	}
};
