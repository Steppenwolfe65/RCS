#ifndef QSCTEST_TIMER_H
#define QSCTEST_TIMER_H

#include "common.h"
#include <time.h>

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
clock_t qsctest_timer_start();

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The timke difference in milliseconds
*/
uint64_t qsctest_timer_elapsed(clock_t start);

#endif