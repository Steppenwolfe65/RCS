/**
* \file symmetric_benchmark.h
* \brief <b>AES and RHX performance benchmarking</b> \n
* Tests the CBC, CTR, AND HBA modes for timimng performance.
* \author John Underhill
* \date October 12, 2020
*/

#ifndef QSCTEST_CIPHER_SPEED_H
#define QSCTEST_CIPHER_SPEED_H

#include "common.h"

/**
* \brief Tests the RCS implementations performance.
* Tests the RCS authenticated stream cipher for performance timing.
*/
void qsctest_rcs_speed_run();

#endif